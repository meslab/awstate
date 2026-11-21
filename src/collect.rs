//! Service-independent collection of metrics and logs for resource specs.

use anyhow::{Context, Result};
use futures::{StreamExt, stream};
use serde_json::Value;

use crate::model::{Ctx, MetricSeries, Resource, Spec};
use crate::{logs, metrics};

/// Collects all specs with bounded concurrency, returning resources sorted
/// by kind and identifier.
pub async fn collect_all(ctx: &Ctx, specs: Vec<Spec>) -> Vec<Resource> {
    let mut resources: Vec<Resource> = stream::iter(specs)
        .map(|spec| collect_one(ctx, spec))
        .buffer_unordered(ctx.concurrency)
        .collect()
        .await;
    resources.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    resources
}

/// Collects metrics and `CloudWatch` logs for one resource. Failures are
/// recorded as issues so the rest of the resource is still captured.
pub async fn collect_one(ctx: &Ctx, spec: Spec) -> Resource {
    let rel_dir = spec.rel_dir();
    let scope = format!("{}/{}/{}", spec.service, spec.kind, spec.id);
    tracing::info!(resource = %scope, "collecting");

    let mut resource = Resource {
        service: spec.service,
        kind: spec.kind,
        id: spec.id,
        details: spec.details,
        metrics_file: None,
        metrics: Vec::new(),
        logs: Vec::new(),
        notes: spec.notes,
    };

    if ctx.metrics && !spec.metric_sources.is_empty() {
        let collected = async {
            let mut series = Vec::new();
            for source in &spec.metric_sources {
                series.extend(metrics::collect(ctx, source).await?);
            }
            series.sort_by(|a, b| {
                (&a.head.namespace, &a.head.name, &a.head.dimensions).cmp(&(
                    &b.head.namespace,
                    &b.head.name,
                    &b.head.dimensions,
                ))
            });
            let file = write_metrics(ctx, &rel_dir, &series).await?;
            anyhow::Ok((series, file))
        }
        .await;
        match collected {
            Ok((series, file)) => {
                resource.metrics_file = file;
                resource.metrics = series.into_iter().map(|s| s.head).collect();
            }
            Err(err) => ctx.issues.record(format!("{scope} metrics"), &err),
        }
    }

    if ctx.logs_enabled {
        for source in &spec.log_sources {
            match logs::capture_group(ctx, source, &rel_dir).await {
                Ok(capture) => resource.logs.push(capture),
                Err(err) => ctx
                    .issues
                    .record(format!("{scope} logs {}", source.group), &err),
            }
        }
    }

    if ctx.logs_enabled && ctx.max_access_log_bytes > 0 {
        for source in &spec.access_log_sources {
            match ctx.access_logs.capture(ctx, source, &rel_dir).await {
                Ok(capture) => resource.logs.push(capture),
                Err(err) => ctx
                    .issues
                    .record(format!("{scope} access logs {}", source.label), &err),
            }
        }
    }

    resource
}

async fn write_metrics(
    ctx: &Ctx,
    rel_dir: &str,
    series: &[MetricSeries],
) -> Result<Option<String>> {
    if series.is_empty() {
        return Ok(None);
    }
    let rel = format!("{rel_dir}/metrics.json");
    write_json(ctx, &rel, series).await?;
    Ok(Some(rel))
}

/// Serializes `value` to `rel` under the output root, creating directories.
pub async fn write_json<T: serde::Serialize + ?Sized>(
    ctx: &Ctx,
    rel: &str,
    value: &T,
) -> Result<()> {
    let value = serde_json::to_value(value).with_context(|| format!("serializing {rel}"))?;
    let mut body = String::new();
    write_compact_pretty(&mut body, &value, 0);
    body.push('\n');
    write_file(ctx, rel, body.as_bytes()).await
}

/// Indented JSON that keeps arrays of scalars on one line, so a metric row
/// costs one line instead of six for whoever reads the file.
fn write_compact_pretty(out: &mut String, value: &Value, depth: usize) {
    let items: Vec<(Option<&String>, &Value)> = match value {
        Value::Array(items) if !items.iter().all(is_scalar) => {
            items.iter().map(|v| (None, v)).collect()
        }
        Value::Object(map) if !map.is_empty() => map.iter().map(|(k, v)| (Some(k), v)).collect(),
        _ => {
            out.push_str(&value.to_string());
            return;
        }
    };
    let (open, close) = if value.is_array() {
        ('[', ']')
    } else {
        ('{', '}')
    };
    out.push(open);
    for (i, (key, item)) in items.iter().enumerate() {
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str(&"  ".repeat(depth + 1));
        if let Some(key) = key {
            out.push_str(&Value::from(key.as_str()).to_string());
            out.push_str(": ");
        }
        write_compact_pretty(out, item, depth + 1);
    }
    out.push('\n');
    out.push_str(&"  ".repeat(depth));
    out.push(close);
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

/// Writes `body` to `rel` under the output root, creating directories.
pub async fn write_file(ctx: &Ctx, rel: &str, body: &[u8]) -> Result<()> {
    let path = ctx.root.join(rel);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    tokio::fs::write(&path, body)
        .await
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn compact_pretty_inlines_scalar_arrays_only() {
        let value = json!({
            "name": "CPU",
            "rows": [["t0", 1.5, null, 2.0], ["t1", 2.0, 1.0, 3.0]],
            "columns": ["time", "avg"],
            "empty": {},
            "events": [{"a": 1}]
        });
        let mut out = String::new();
        write_compact_pretty(&mut out, &value, 0);
        assert_eq!(
            out,
            r#"{
  "name": "CPU",
  "rows": [
    ["t0",1.5,null,2.0],
    ["t1",2.0,1.0,3.0]
  ],
  "columns": ["time","avg"],
  "empty": {},
  "events": [
    {
      "a": 1
    }
  ]
}"#
        );
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), value);
    }
}

//! Service-independent collection of metrics and logs for resource specs.

use anyhow::{Context, Result};
use futures::{StreamExt, stream};

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

    if let (true, Some((namespace, dimension))) = (ctx.metrics, spec.metric_source) {
        let collected = async {
            let series = metrics::collect(ctx, namespace, dimension, &resource.id).await?;
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
        for group in &spec.log_groups {
            match logs::capture_group(ctx, group, &rel_dir).await {
                Ok(capture) => resource.logs.push(capture),
                Err(err) => ctx.issues.record(format!("{scope} logs {group}"), &err),
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
    let body = serde_json::to_vec_pretty(value).with_context(|| format!("serializing {rel}"))?;
    write_file(ctx, rel, &body).await
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

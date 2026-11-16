//! Final output: `manifest.json`, per-service `events.json`, and the
//! `summary.md` digest meant to be read first by a human or a model.

use std::fmt::Write as _;

use anyhow::Result;
use serde::Serialize;

use crate::collect::{write_file, write_json};
use crate::model::{Ctx, Event, Issue, MetricHead, Resource, ServiceReport, Window, iso_chrono};

/// Events listed per service in `summary.md`; the JSON file has all of them.
const SUMMARY_EVENT_LIMIT: usize = 300;

#[derive(Serialize)]
struct Manifest<'a> {
    tool: &'static str,
    version: &'static str,
    generated_at: String,
    region: &'a str,
    window: Window,
    metric_period_seconds: i32,
    services: Vec<ServiceManifest<'a>>,
    issues: &'a [Issue],
}

#[derive(Serialize)]
struct ServiceManifest<'a> {
    service: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    events_file: Option<String>,
    event_count: usize,
    resources: &'a [Resource],
}

/// Writes the manifest, event files, and summary for all services.
pub async fn write(ctx: &Ctx, region: &str, services: &[(&str, ServiceReport)]) -> Result<()> {
    let issues = ctx.issues.snapshot();

    let mut manifests = Vec::with_capacity(services.len());
    for (name, report) in services {
        let events_file = if report.events.is_empty() {
            None
        } else {
            let rel = format!("{name}/events.json");
            write_json(ctx, &rel, &report.events).await?;
            Some(rel)
        };
        manifests.push(ServiceManifest {
            service: name,
            events_file,
            event_count: report.events.len(),
            resources: &report.resources,
        });
    }

    let manifest = Manifest {
        tool: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        generated_at: iso_chrono(chrono::Utc::now()),
        region,
        window: ctx.window,
        metric_period_seconds: ctx.metric_period,
        services: manifests,
        issues: &issues,
    };
    write_json(ctx, "manifest.json", &manifest).await?;

    let summary = render_summary(ctx, region, services, &issues);
    write_file(ctx, "summary.md", summary.as_bytes()).await
}

// `write!` into a `String` is infallible, so its results are discarded.
fn render_summary(
    ctx: &Ctx,
    region: &str,
    services: &[(&str, ServiceReport)],
    issues: &[Issue],
) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# AWS state snapshot\n");
    let _ = writeln!(md, "- Region: `{region}`");
    let _ = writeln!(
        md,
        "- Window: {} to {} (UTC)",
        iso_chrono(ctx.window.start),
        iso_chrono(ctx.window.end)
    );
    let _ = writeln!(md, "- Metric period: {}s", ctx.metric_period);
    md.push_str(
        "\nHow to read this snapshot:\n\n\
         - Metric tables summarize the whole window: `avg` is the mean of per-period averages, \
         `min`/`max` are the extremes of per-period minimums/maximums, `p95` is the 95th \
         percentile of per-period averages, `first`/`last` are the per-period averages at the \
         window edges, and `max at` is when the maximum occurred.\n\
         - Values are in the metric's native CloudWatch unit (bytes, seconds, percent, count). \
         `k`/`M`/`G`/`T` suffixes are decimal multipliers.\n\
         - Full time series are in each resource's `metrics.json`; complete resource details \
         and file paths are in `manifest.json`; all paths are relative to this directory.\n",
    );

    for (name, report) in services {
        let _ = writeln!(md, "\n## {name}\n");
        if report.resources.is_empty() {
            md.push_str("No resources found.\n\n");
        }
        for resource in &report.resources {
            render_resource(&mut md, resource);
        }
        render_events(&mut md, name, &report.events, ctx.events);
    }

    if !issues.is_empty() {
        md.push_str("\n## Collection issues\n\nThese parts could not be collected; the data above is incomplete for them.\n\n");
        for issue in issues {
            let _ = writeln!(md, "- **{}**: {}", issue.scope, one_line(&issue.error));
        }
    }
    md
}

fn render_resource(md: &mut String, r: &Resource) {
    let _ = writeln!(md, "### {} `{}`\n", r.kind, r.id);
    let _ = writeln!(md, "```json\n{}\n```\n", r.details);
    for note in &r.notes {
        let _ = writeln!(md, "- Note: {note}");
    }

    if let Some(file) = &r.metrics_file {
        let _ = writeln!(md, "\nMetrics (series in `{file}`):\n");
        md.push_str(
            "| namespace | metric | dimensions | avg | min | max | p95 | first | last | max at |\n",
        );
        md.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
        for m in &r.metrics {
            let s = &m.summary;
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                m.namespace,
                m.name,
                extra_dimensions(m, &r.id),
                fmt_num(s.avg),
                fmt_num(s.min),
                fmt_num(s.max),
                fmt_num(s.p95),
                fmt_num(s.first),
                fmt_num(s.last),
                s.max_at,
            );
        }
    } else {
        md.push_str("\nNo metric data.\n");
    }

    if !r.logs.is_empty() {
        md.push_str("\nLogs:\n\n");
        for log in &r.logs {
            let location = log
                .file
                .as_ref()
                .map_or_else(|| "nothing captured".to_owned(), |f| format!("`{f}`"));
            let truncated = if log.truncated {
                ", truncated by limit"
            } else {
                ""
            };
            let _ = writeln!(
                md,
                "- {}: {} lines, {} bytes{truncated} -> {location}",
                log.source, log.lines, log.bytes
            );
        }
    }
    md.push('\n');
}

fn render_events(md: &mut String, service: &str, events: &[Event], enabled: bool) {
    let _ = writeln!(md, "### {service} events\n");
    if !enabled {
        md.push_str("Skipped.\n");
        return;
    }
    if events.is_empty() {
        md.push_str("No events in the window.\n");
        return;
    }
    let _ = writeln!(
        md,
        "{} events (all in `{service}/events.json`).\n",
        events.len()
    );
    md.push_str("| time | source | categories | message |\n|---|---|---|---|\n");
    for e in events.iter().take(SUMMARY_EVENT_LIMIT) {
        let source = match (&e.source_type, &e.source) {
            (Some(t), Some(s)) => format!("{t} {s}"),
            (None, Some(s)) => s.clone(),
            (Some(t), None) => t.clone(),
            (None, None) => String::new(),
        };
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} |",
            e.time.as_deref().unwrap_or_default(),
            cell(&source),
            cell(&e.categories.join(", ")),
            cell(e.message.as_deref().unwrap_or_default()),
        );
    }
    if events.len() > SUMMARY_EVENT_LIMIT {
        let _ = writeln!(
            md,
            "\n{} more events omitted here.",
            events.len() - SUMMARY_EVENT_LIMIT
        );
    }
}

/// Dimensions other than those naming the resource itself (identifiers
/// like `cluster/service` name it with several).
fn extra_dimensions(m: &MetricHead, resource_id: &str) -> String {
    m.dimensions
        .iter()
        .filter(|(_, v)| resource_id.split('/').all(|part| part != v.as_str()))
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Makes text safe inside a markdown table cell.
fn cell(text: &str) -> String {
    one_line(text).replace('|', "\\|")
}

/// Compact number formatting for summary tables.
fn fmt_num(v: f64) -> String {
    let abs = v.abs();
    if abs == 0.0 || !v.is_finite() {
        return if v.is_finite() {
            "0".to_owned()
        } else {
            v.to_string()
        };
    }
    if abs < 0.01 {
        return format!("{v:.2e}");
    }
    let (scaled, suffix) = match abs {
        a if a >= 1e12 => (v / 1e12, "T"),
        a if a >= 1e9 => (v / 1e9, "G"),
        a if a >= 1e6 => (v / 1e6, "M"),
        a if a >= 1e4 => (v / 1e3, "k"),
        _ => (v, ""),
    };
    let digits = if scaled.abs() < 100.0 { 3 } else { 1 };
    let text = format!("{scaled:.digits$}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    format!("{text}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_num_is_compact() {
        assert_eq!(fmt_num(0.0), "0");
        assert_eq!(fmt_num(42.0), "42");
        assert_eq!(fmt_num(2.71849), "2.718");
        assert_eq!(fmt_num(0.0004), "4.00e-4");
        assert_eq!(fmt_num(1234.5), "1234.5");
        assert_eq!(fmt_num(15_000.0), "15k");
        assert_eq!(fmt_num(2_500_000_000.0), "2.5G");
        assert_eq!(fmt_num(-7_300_000.0), "-7.3M");
    }

    #[test]
    fn cell_escapes_pipes_and_newlines() {
        assert_eq!(cell("a | b\nc"), "a \\| b c");
    }
}

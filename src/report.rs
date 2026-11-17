//! Final output: `manifest.json`, `findings.json`, per-service
//! `events.json`, and the `summary.md` digest meant to be read first by a human or a model.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::Result;
use serde::Serialize;

use crate::cli::Severity;
use crate::collect::{write_file, write_json};
use crate::findings::Finding;
use crate::model::{Ctx, Event, Issue, MetricHead, Resource, ServiceReport, Window, iso_chrono};

/// Event groups listed per service in `summary.md`; the JSON file has all
/// events.
const SUMMARY_EVENT_LIMIT: usize = 300;

const FINDINGS_FILE: &str = "findings.json";

#[derive(Serialize)]
struct Manifest<'a> {
    tool: &'static str,
    version: &'static str,
    generated_at: String,
    region: &'a str,
    window: Window,
    metric_period_seconds: i32,
    findings_file: &'static str,
    finding_count: usize,
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
pub async fn write(
    ctx: &Ctx,
    region: &str,
    services: &[(&str, ServiceReport)],
    findings: &[Finding],
) -> Result<()> {
    let issues = ctx.issues.snapshot();
    write_json(ctx, FINDINGS_FILE, findings).await?;

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
        findings_file: FINDINGS_FILE,
        finding_count: findings.len(),
        services: manifests,
        issues: &issues,
    };
    write_json(ctx, "manifest.json", &manifest).await?;

    let summary = render_summary(ctx, region, services, findings, &issues);
    write_file(ctx, "summary.md", summary.as_bytes()).await
}

// `write!` into a `String` is infallible, so its results are discarded.
fn render_summary(
    ctx: &Ctx,
    region: &str,
    services: &[(&str, ServiceReport)],
    findings: &[Finding],
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
    render_findings(&mut md, findings);

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

fn render_findings(md: &mut String, findings: &[Finding]) {
    md.push_str("\n## Findings\n\n");
    if findings.is_empty() {
        md.push_str("No checks raised anything.\n");
        return;
    }
    md.push_str(
        "Automated checks over the data below, most severe first (also in `findings.json`). \
         They point at where to look; they are not a full analysis.\n\n\
         | severity | service | resource | check | finding |\n|---|---|---|---|---|\n",
    );
    for f in findings {
        let severity = match f.severity {
            Severity::Critical => "**critical**",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        let _ = writeln!(
            md,
            "| {severity} | {} | {} | {} | {} |",
            f.service,
            cell(&f.resource),
            f.check,
            cell(&f.message)
        );
    }
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
    let groups = group_events(events);
    let _ = writeln!(
        md,
        "{} events in {} groups (all events in `{service}/events.json`). Events that differ \
         only in ids, numbers, and times are grouped; `message` is the latest occurrence.\n",
        events.len(),
        groups.len()
    );
    md.push_str(
        "| first | last | count | source | categories | message |\n|---|---|---|---|---|---|\n",
    );
    for g in groups.iter().take(SUMMARY_EVENT_LIMIT) {
        let e = g.latest;
        let source = match (&e.source_type, &e.source) {
            (Some(t), Some(s)) => format!("{t} {s}"),
            (None, Some(s)) => s.clone(),
            (Some(t), None) => t.clone(),
            (None, None) => String::new(),
        };
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} |",
            g.first.unwrap_or_default(),
            e.time.as_deref().unwrap_or_default(),
            g.count,
            cell(&source),
            cell(&e.categories.join(", ")),
            cell(e.message.as_deref().unwrap_or_default()),
        );
    }
    if groups.len() > SUMMARY_EVENT_LIMIT {
        let _ = writeln!(
            md,
            "\n{} more groups omitted here.",
            groups.len() - SUMMARY_EVENT_LIMIT
        );
    }
}

/// Events sharing a source, categories, and message template.
struct EventGroup<'a> {
    first: Option<&'a str>,
    latest: &'a Event,
    count: usize,
}

/// Source type, source, categories, and message template.
type GroupKey<'a> = (&'a Option<String>, &'a Option<String>, &'a [String], String);

/// Groups events by [`template`], ordered by first occurrence. `events`
/// must be sorted by time.
fn group_events(events: &[Event]) -> Vec<EventGroup<'_>> {
    let mut index: HashMap<GroupKey, usize> = HashMap::new();
    let mut groups: Vec<EventGroup> = Vec::new();
    for e in events {
        let key = (
            &e.source_type,
            &e.source,
            e.categories.as_slice(),
            template(e.message.as_deref().unwrap_or_default()),
        );
        if let Some(&i) = index.get(&key) {
            groups[i].latest = e;
            groups[i].count += 1;
        } else {
            index.insert(key, groups.len());
            groups.push(EventGroup {
                first: e.time.as_deref(),
                latest: e,
                count: 1,
            });
        }
    }
    groups
}

/// A message with every alphanumeric run that contains a digit replaced by
/// `#`, so instance ids, task ids, counts, and timestamps compare equal.
fn template(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.bytes().any(|b| b.is_ascii_digit()) {
            out.push('#');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in message.chars() {
        if c.is_ascii_alphanumeric() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
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
    fn template_masks_ids_and_numbers() {
        assert_eq!(
            template("Terminating EC2 instance: i-09028f1ed00963261 at 2026-11-11T08:01:29Z"),
            "Terminating # instance: i-# at #-#-#:#:#"
        );
        assert_eq!(
            template("(service app) reached a steady state."),
            "(service app) reached a steady state."
        );
    }

    #[test]
    fn group_events_counts_repeats_in_first_seen_order() {
        let event = |time: &str, source: &str, message: &str| Event {
            time: Some(time.to_owned()),
            source_type: None,
            source: Some(source.to_owned()),
            categories: Vec::new(),
            message: Some(message.to_owned()),
        };
        let events = [
            event("t1", "a", "started 1 tasks: (task 1f2e)"),
            event("t2", "b", "started 1 tasks: (task 9a8b)"),
            event("t3", "a", "started 2 tasks: (task 3c4d)"),
            event("t4", "a", "reached a steady state."),
        ];
        let groups = group_events(&events);
        assert_eq!(groups.len(), 3);
        assert_eq!((groups[0].first, groups[0].count), (Some("t1"), 2));
        assert_eq!(groups[0].latest.time.as_deref(), Some("t3"));
        assert_eq!(groups[1].count, 1);
        assert_eq!(groups[2].first, Some("t4"));
    }

    #[test]
    fn cell_escapes_pipes_and_newlines() {
        assert_eq!(cell("a | b\nc"), "a \\| b c");
    }
}

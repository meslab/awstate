//! Shared data model: the collection context and everything that ends up in
//! the output directory.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use aws_sdk_cloudwatch::primitives::DateTime as AwsDateTime;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

/// The time window being collected.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Window {
    pub fn aws_start(&self) -> AwsDateTime {
        AwsDateTime::from_millis(self.start.timestamp_millis())
    }

    pub fn aws_end(&self) -> AwsDateTime {
        AwsDateTime::from_millis(self.end.timestamp_millis())
    }
}

/// Formats an AWS timestamp as RFC 3339 (second precision, UTC).
pub fn iso(ts: &AwsDateTime) -> String {
    DateTime::<Utc>::from_timestamp(ts.secs(), ts.subsec_nanos())
        .map_or_else(|| ts.secs().to_string(), iso_chrono)
}

pub fn iso_chrono(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Formats epoch milliseconds as RFC 3339 with millisecond precision.
pub fn iso_millis(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms).map_or_else(
        || ms.to_string(),
        |t| t.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}

/// Everything a collector needs besides its own service client.
pub struct Ctx {
    pub window: Window,
    pub cw: aws_sdk_cloudwatch::Client,
    pub logs: aws_sdk_cloudwatchlogs::Client,
    pub root: PathBuf,
    pub metric_period: i32,
    pub max_log_events: usize,
    pub log_filter_pattern: Option<String>,
    pub max_log_file_bytes: usize,
    pub concurrency: usize,
    pub filter: Vec<String>,
    pub metrics: bool,
    pub logs_enabled: bool,
    pub events: bool,
    pub issues: Issues,
}

impl Ctx {
    /// Whether a resource identifier passes the user's `--filter`.
    pub fn wanted(&self, id: &str) -> bool {
        self.filter.is_empty() || self.filter.iter().any(|f| id.contains(f.as_str()))
    }
}

/// Non-fatal problems hit during collection. A missing permission on one
/// log group should not cost the user the rest of the snapshot.
#[derive(Default)]
pub struct Issues(Mutex<Vec<Issue>>);

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub scope: String,
    pub error: String,
}

impl Issues {
    pub fn record(&self, scope: impl Into<String>, err: &anyhow::Error) {
        let issue = Issue {
            scope: scope.into(),
            error: format!("{err:#}"),
        };
        tracing::warn!(scope = %issue.scope, error = %issue.error, "collection issue");
        self.lock().push(issue);
    }

    pub fn snapshot(&self) -> Vec<Issue> {
        let mut issues = self.lock().clone();
        issues.sort_by(|a, b| a.scope.cmp(&b.scope));
        issues
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Issue>> {
        // A poisoned lock only means another task panicked mid-push; the
        // list itself is still valid.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What to collect for one resource, produced by a service's inventory pass.
pub struct Spec {
    pub service: &'static str,
    pub kind: &'static str,
    pub id: String,
    pub details: Value,
    /// `CloudWatch` namespace and the dimension name that identifies this
    /// resource; every metric carrying that dimension is collected.
    pub metric_source: Option<(&'static str, &'static str)>,
    pub log_groups: Vec<String>,
    pub notes: Vec<String>,
}

impl Spec {
    /// Directory of this resource relative to the output root.
    pub fn rel_dir(&self) -> String {
        format!("{}/{}/{}", self.service, self.kind, sanitize(&self.id))
    }
}

/// Makes an identifier safe to use as a single path component.
pub fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '_' || c == '.');
    if trimmed.is_empty() {
        "_".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// One collected resource as it appears in `manifest.json`.
#[derive(Debug, Serialize)]
pub struct Resource {
    pub service: &'static str,
    pub kind: &'static str,
    pub id: String,
    pub details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_file: Option<String>,
    pub metrics: Vec<MetricHead>,
    pub logs: Vec<LogCapture>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Identity and summary statistics of one metric, without its datapoints.
#[derive(Debug, Clone, Serialize)]
pub struct MetricHead {
    pub name: String,
    pub dimensions: BTreeMap<String, String>,
    pub summary: MetricSummary,
}

/// Statistics over the whole window, derived from per-period datapoints.
#[derive(Debug, Clone, Serialize)]
pub struct MetricSummary {
    pub datapoints: usize,
    /// Mean of the per-period averages.
    pub avg: f64,
    /// Lowest per-period minimum.
    pub min: f64,
    /// Highest per-period maximum.
    pub max: f64,
    /// When the highest maximum occurred.
    pub max_at: String,
    /// 95th percentile of the per-period averages.
    pub p95: f64,
    /// Per-period average at the start and end of the window.
    pub first: f64,
    pub last: f64,
}

/// One period of a series: `(time, avg, min, max)`.
pub type MetricRow = (String, Option<f64>, Option<f64>, Option<f64>);

/// A metric with its full time series, as written to `metrics.json`.
#[derive(Debug, Serialize)]
pub struct MetricSeries {
    #[serde(flatten)]
    pub head: MetricHead,
    pub period_seconds: i32,
    pub columns: [&'static str; 4],
    /// `[time, avg, min, max]` per period.
    pub rows: Vec<MetricRow>,
}

/// One log source captured to a file.
#[derive(Debug, Serialize)]
pub struct LogCapture {
    pub source: String,
    /// Path relative to the output root; absent when nothing was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub lines: usize,
    pub bytes: usize,
    /// True when a limit cut the capture short.
    pub truncated: bool,
}

/// A service event (failover, maintenance, parameter change, ...).
#[derive(Debug, Serialize)]
pub struct Event {
    pub time: Option<String>,
    pub source_type: Option<String>,
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    pub message: Option<String>,
}

/// Everything collected for one service.
#[derive(Debug, Default)]
pub struct ServiceReport {
    pub resources: Vec<Resource>,
    pub events: Vec<Event>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_flattens_log_group_paths() {
        assert_eq!(
            sanitize("/aws/rds/instance/db-1/error"),
            "aws_rds_instance_db-1_error"
        );
    }

    #[test]
    fn sanitize_never_returns_empty_or_dot_components() {
        assert_eq!(sanitize(".."), "_");
        assert_eq!(sanitize(""), "_");
    }

    #[test]
    fn iso_formats_utc_seconds() {
        assert_eq!(iso(&AwsDateTime::from_secs(0)), "1970-01-01T00:00:00Z");
        assert_eq!(iso_millis(1_500), "1970-01-01T00:00:01.500Z");
    }
}

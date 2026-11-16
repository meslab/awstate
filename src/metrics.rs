//! `CloudWatch` metric discovery and retrieval.
//!
//! Rather than hard-coding metric names per engine, every metric that
//! carries the resource's identifying dimension is discovered with
//! `ListMetrics` and then fetched with `GetMetricData`.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use aws_sdk_cloudwatch::types::{DimensionFilter, Metric, MetricDataQuery, MetricStat, ScanBy};

use crate::model::{Ctx, MetricHead, MetricSeries, MetricSource, MetricSummary, iso};

/// Statistics requested per metric, with their query-id suffix and the
/// column they fill.
const STATS: [(&str, &str); 3] = [("Average", "a"), ("Minimum", "n"), ("Maximum", "x")];

/// `GetMetricData` accepts at most 500 queries per request.
const METRICS_PER_REQUEST: usize = 500 / STATS.len();

/// Fetches every metric matching `source`. Metrics without datapoints in
/// the window are dropped.
pub async fn collect(ctx: &Ctx, source: &MetricSource) -> Result<Vec<MetricSeries>> {
    let metrics = discover(ctx, source).await?;
    let mut out = Vec::with_capacity(metrics.len());
    for chunk in metrics.chunks(METRICS_PER_REQUEST) {
        out.extend(fetch(ctx, chunk).await?);
    }
    Ok(out)
}

async fn discover(ctx: &Ctx, source: &MetricSource) -> Result<Vec<Metric>> {
    let namespace = source.namespace;
    let filters = source
        .dimensions
        .iter()
        .map(|(name, value)| DimensionFilter::builder().name(*name).value(value).build())
        .collect();
    let value = source
        .dimensions
        .iter()
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join("/");
    let mut pages = ctx
        .cw
        .list_metrics()
        .namespace(namespace)
        .set_dimensions(Some(filters))
        .into_paginator()
        .send();
    let mut metrics = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("listing {namespace} metrics for {value}"))?;
        metrics.extend(page.metrics.unwrap_or_default());
    }
    if source.exact {
        metrics.retain(|m| m.dimensions().len() == source.dimensions.len());
    }
    Ok(metrics)
}

/// Per-timestamp `[avg, min, max]`, keyed by epoch seconds.
type Points = BTreeMap<i64, [Option<f64>; 3]>;

async fn fetch(ctx: &Ctx, metrics: &[Metric]) -> Result<Vec<MetricSeries>> {
    let mut queries = Vec::with_capacity(metrics.len() * STATS.len());
    for (idx, metric) in metrics.iter().enumerate() {
        for (stat, suffix) in STATS {
            let metric_stat = MetricStat::builder()
                .metric(metric.clone())
                .period(ctx.metric_period)
                .stat(stat)
                .build();
            queries.push(
                MetricDataQuery::builder()
                    .id(format!("m{idx}{suffix}"))
                    .metric_stat(metric_stat)
                    .return_data(true)
                    .build(),
            );
        }
    }

    let mut pages = ctx
        .cw
        .get_metric_data()
        .start_time(ctx.window.aws_start())
        .end_time(ctx.window.aws_end())
        .scan_by(ScanBy::TimestampAscending)
        .set_metric_data_queries(Some(queries))
        .into_paginator()
        .send();

    let mut points: Vec<Points> = vec![Points::new(); metrics.len()];
    while let Some(page) = pages.next().await {
        let page = page.context("fetching metric data")?;
        for result in page.metric_data_results() {
            let Some((idx, column)) = result.id().and_then(parse_query_id) else {
                continue;
            };
            let Some(series) = points.get_mut(idx) else {
                continue;
            };
            for (ts, value) in result.timestamps().iter().zip(result.values()) {
                series.entry(ts.secs()).or_default()[column] = Some(*value);
            }
        }
    }

    Ok(metrics
        .iter()
        .zip(points)
        .filter_map(|(metric, points)| build_series(metric, &points, ctx.metric_period))
        .collect())
}

/// Splits a query id like `m12x` into the metric index and stat column.
fn parse_query_id(id: &str) -> Option<(usize, usize)> {
    let body = id.strip_prefix('m')?;
    let split = body.len().checked_sub(1)?;
    let (idx, suffix) = body.split_at_checked(split)?;
    let column = STATS.iter().position(|(_, s)| *s == suffix)?;
    Some((idx.parse().ok()?, column))
}

fn build_series(metric: &Metric, points: &Points, period: i32) -> Option<MetricSeries> {
    let summary = summarize(points)?;
    let dimensions = metric
        .dimensions()
        .iter()
        .filter_map(|d| Some((d.name()?.to_owned(), d.value()?.to_owned())))
        .collect();
    let rows = points
        .iter()
        .map(|(secs, [avg, min, max])| (iso_secs(*secs), *avg, *min, *max))
        .collect();
    Some(MetricSeries {
        head: MetricHead {
            namespace: metric.namespace().unwrap_or_default().to_owned(),
            name: metric.metric_name().unwrap_or_default().to_owned(),
            dimensions,
            summary,
        },
        period_seconds: period,
        columns: ["time", "avg", "min", "max"],
        rows,
    })
}

fn iso_secs(secs: i64) -> String {
    iso(&aws_sdk_cloudwatch::primitives::DateTime::from_secs(secs))
}

/// Summarizes a series; `None` when it has no average datapoints.
fn summarize(points: &Points) -> Option<MetricSummary> {
    let avgs: Vec<f64> = points.values().filter_map(|p| p[0]).collect();
    let (first, last) = (*avgs.first()?, *avgs.last()?);

    // Fall back to the average column if a min/max stat is missing.
    let min = points
        .values()
        .filter_map(|p| p[1].or(p[0]))
        .fold(f64::INFINITY, f64::min);
    let (max_at, max) = points
        .iter()
        .filter_map(|(ts, p)| Some((*ts, p[2].or(p[0])?)))
        .fold((0, f64::NEG_INFINITY), |best, cur| {
            if cur.1 > best.1 { cur } else { best }
        });

    let mut sorted = avgs.clone();
    sorted.sort_by(f64::total_cmp);
    #[allow(clippy::cast_precision_loss)] // datapoint counts are far below 2^52
    let mean = avgs.iter().sum::<f64>() / avgs.len() as f64;

    Some(MetricSummary {
        datapoints: avgs.len(),
        avg: mean,
        min,
        max,
        max_at: iso_secs(max_at),
        p95: percentile(&sorted, 95),
        first,
        last,
    })
}

/// Nearest-rank percentile of an ascending, non-empty slice.
fn percentile(sorted: &[f64], pct: usize) -> f64 {
    let rank = (sorted.len() * pct).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_ids_round_trip() {
        assert_eq!(parse_query_id("m0a"), Some((0, 0)));
        assert_eq!(parse_query_id("m137x"), Some((137, 2)));
        assert_eq!(parse_query_id("m"), None);
        assert_eq!(parse_query_id("m5z"), None);
        assert_eq!(parse_query_id("x5a"), None);
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let values: Vec<f64> = (1..=100).map(f64::from).collect();
        assert!((percentile(&values, 95) - 95.0).abs() < f64::EPSILON);
        assert!((percentile(&[7.0], 95) - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summarize_combines_stat_columns() {
        let mut points = Points::new();
        points.insert(0, [Some(1.0), Some(0.5), Some(2.0)]);
        points.insert(300, [Some(3.0), Some(2.0), Some(9.0)]);
        points.insert(600, [Some(2.0), Some(1.0), Some(4.0)]);

        let s = summarize(&points).unwrap();
        assert_eq!(s.datapoints, 3);
        assert!((s.avg - 2.0).abs() < 1e-9);
        assert!((s.min - 0.5).abs() < 1e-9);
        assert!((s.max - 9.0).abs() < 1e-9);
        assert_eq!(s.max_at, "1970-01-01T00:05:00Z");
        assert!((s.first - 1.0).abs() < 1e-9);
        assert!((s.last - 2.0).abs() < 1e-9);
    }

    #[test]
    fn summarize_rejects_empty_series() {
        assert!(summarize(&Points::new()).is_none());
    }
}

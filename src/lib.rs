//! `awstate` snapshots the recent state of RDS and `ElastiCache` resources
//! (inventory, `CloudWatch` metrics, logs, and service events) into a
//! directory designed to be handed to an AI model for analysis.

pub mod cli;
mod collect;
mod elasticache;
mod logs;
mod metrics;
mod model;
mod rds;
mod report;

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use aws_config::{BehaviorVersion, Region};
use chrono::Utc;

use cli::{Args, DataKind, Service};
use model::{Ctx, Issues, ServiceReport, Window};

/// Runs a full collection and returns the output directory.
///
/// # Errors
///
/// Fails on invalid arguments, a missing AWS region, or when the output
/// directory cannot be written. Per-resource AWS failures are not fatal;
/// they are recorded in the snapshot's "Collection issues".
pub async fn run(args: Args) -> Result<PathBuf> {
    let window = resolve_window(&args)?;
    let metric_period = resolve_metric_period(&args, window)?;

    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(region) = &args.region {
        loader = loader.region(Region::new(region.clone()));
    }
    if let Some(profile) = &args.profile {
        loader = loader.profile_name(profile);
    }
    let config = loader.load().await;
    let Some(region) = config.region().map(ToString::to_string) else {
        bail!("no AWS region configured; pass --region or set AWS_REGION");
    };

    let root = args.output.clone().unwrap_or_else(|| {
        PathBuf::from(format!("awstate-{}", Utc::now().format("%Y%m%dT%H%M%SZ")))
    });
    tokio::fs::create_dir_all(&root)
        .await
        .with_context(|| format!("creating output directory {}", root.display()))?;

    let ctx = Ctx {
        window,
        cw: aws_sdk_cloudwatch::Client::new(&config),
        logs: aws_sdk_cloudwatchlogs::Client::new(&config),
        root,
        metric_period,
        max_log_events: args.max_log_events,
        log_filter_pattern: args.log_filter_pattern.clone(),
        max_log_file_bytes: args.max_log_file_bytes,
        concurrency: usize::from(args.concurrency),
        filter: args.filter.clone(),
        metrics: !args.skip.contains(&DataKind::Metrics),
        logs_enabled: !args.skip.contains(&DataKind::Logs),
        events: !args.skip.contains(&DataKind::Events),
        issues: Issues::default(),
    };

    let want_rds = args.services.contains(&Service::Rds);
    let want_elasticache = args.services.contains(&Service::Elasticache);
    let rds_client = aws_sdk_rds::Client::new(&config);
    let elasticache_client = aws_sdk_elasticache::Client::new(&config);

    let (rds_report, elasticache_report) = tokio::join!(
        async {
            if want_rds {
                Some(rds::collect(&ctx, &rds_client).await)
            } else {
                None
            }
        },
        async {
            if want_elasticache {
                Some(elasticache::collect(&ctx, &elasticache_client).await)
            } else {
                None
            }
        }
    );

    let services: Vec<(&str, ServiceReport)> =
        [("rds", rds_report), ("elasticache", elasticache_report)]
            .into_iter()
            .filter_map(|(name, report)| Some((name, report?)))
            .collect();

    report::write(&ctx, &region, &services).await?;

    for (name, report) in &services {
        println!(
            "{name}: {} resources, {} events",
            report.resources.len(),
            report.events.len()
        );
    }
    let issues = ctx.issues.snapshot().len();
    if issues > 0 {
        println!("{issues} collection issue(s); see summary.md");
    }
    Ok(ctx.root)
}

fn resolve_window(args: &Args) -> Result<Window> {
    let end = args.end.unwrap_or_else(Utc::now);
    let start = if let Some(start) = args.start {
        start
    } else {
        let span = chrono::Duration::from_std(args.last).context("--last is too large")?;
        end.checked_sub_signed(span)
            .context("--last is too large")?
    };
    ensure!(
        start < end,
        "window start ({start}) must be before its end ({end})"
    );
    Ok(Window { start, end })
}

fn resolve_metric_period(args: &Args, window: Window) -> Result<i32> {
    let period = args.metric_period.unwrap_or_else(|| {
        if window.end - window.start <= chrono::Duration::hours(48) {
            300
        } else {
            3600
        }
    });
    ensure!(
        period % 60 == 0,
        "--metric-period must be a multiple of 60 seconds, got {period}"
    );
    Ok(period)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn args(extra: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("awstate").chain(extra.iter().copied())).unwrap()
    }

    #[test]
    fn default_window_is_last_24_hours() {
        let w = resolve_window(&args(&["--end", "2026-11-16T00:00:00Z"])).unwrap();
        assert_eq!(w.end - w.start, chrono::Duration::hours(24));
    }

    #[test]
    fn explicit_start_overrides_last() {
        let w = resolve_window(&args(&[
            "--start",
            "2026-11-10T00:00:00Z",
            "--end",
            "2026-11-12T12:00:00Z",
        ]))
        .unwrap();
        assert_eq!(w.end - w.start, chrono::Duration::hours(60));
    }

    #[test]
    fn rejects_inverted_window() {
        let err = resolve_window(&args(&[
            "--start",
            "2026-11-12T00:00:00Z",
            "--end",
            "2026-11-10T00:00:00Z",
        ]));
        assert!(err.is_err());
    }

    #[test]
    fn start_conflicts_with_last() {
        let parsed =
            Args::try_parse_from(["awstate", "--last", "2h", "--start", "2026-11-10T00:00:00Z"]);
        assert!(parsed.is_err());
    }

    #[test]
    fn metric_period_scales_with_window_and_must_align_to_minutes() {
        let a = args(&["--last", "7d"]);
        assert_eq!(
            resolve_metric_period(&a, resolve_window(&a).unwrap()).unwrap(),
            3600
        );
        let a = args(&[]);
        assert_eq!(
            resolve_metric_period(&a, resolve_window(&a).unwrap()).unwrap(),
            300
        );
        let a = args(&["--metric-period", "90"]);
        assert!(resolve_metric_period(&a, resolve_window(&a).unwrap()).is_err());
    }

    #[test]
    fn services_and_skips_parse_as_comma_lists() {
        let a = args(&["--services", "rds", "--skip", "logs,events"]);
        assert_eq!(a.services, [Service::Rds]);
        assert_eq!(a.skip, [DataKind::Logs, DataKind::Events]);
    }
}

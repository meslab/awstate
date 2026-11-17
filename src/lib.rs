//! `awstate` snapshots the recent state of RDS, `ElastiCache`, EC2 Auto
//! Scaling, and ECS resources
//! (inventory, `CloudWatch` metrics, logs, and service events) into a
//! directory designed to be handed to an AI model for analysis.

mod asg;
pub mod cli;
mod collect;
mod ecr;
mod ecs;
mod elasticache;
mod findings;
mod logs;
mod metrics;
mod model;
mod rds;
mod report;

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use aws_config::retry::RetryConfig;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::provider::ProvideCredentials;
use chrono::Utc;

use cli::{Args, DataKind, Service, Severity};
use model::{Ctx, Issues, ServiceReport, Window};

/// What a finished run produced.
pub struct Snapshot {
    /// The output directory.
    pub root: PathBuf,
    /// Severity of the most severe finding, if any.
    pub worst: Option<Severity>,
}

/// Runs a full collection and returns where it was written.
///
/// # Errors
///
/// Fails on invalid arguments, a missing AWS region, or when the output
/// directory cannot be written. Per-resource AWS failures are not fatal;
/// they are recorded in the snapshot's "Collection issues".
pub async fn run(args: Args) -> Result<Snapshot> {
    let window = resolve_window(&args)?;
    let metric_period = resolve_metric_period(&args, window)?;

    let (config, region) = load_aws_config(&args).await?;

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

    let want_asg = args.services.contains(&Service::Asg);
    let want_ecs = args.services.contains(&Service::Ecs);
    let asg_client = aws_sdk_autoscaling::Client::new(&config);
    let ecs_client = aws_sdk_ecs::Client::new(&config);
    let registry_client = aws_sdk_ecr::Client::new(&config);

    let (rds_report, elasticache_report, asg_report, ecs_report) = tokio::join!(
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
        },
        async {
            if want_asg {
                Some(asg::collect(&ctx, &asg_client).await)
            } else {
                None
            }
        },
        async {
            if want_ecs {
                let images = ecr::ImageChecker::new(registry_client, &region);
                Some(ecs::collect(&ctx, &ecs_client, &images).await)
            } else {
                None
            }
        }
    );

    let services: Vec<(&str, ServiceReport)> = [
        ("rds", rds_report),
        ("elasticache", elasticache_report),
        ("asg", asg_report),
        ("ecs", ecs_report),
    ]
    .into_iter()
    .filter_map(|(name, report)| Some((name, report?)))
    .collect();

    let findings = findings::evaluate(&services, &ctx.issues.snapshot());
    report::write(&ctx, &region, &services, &findings).await?;

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
    let count = |severity| findings.iter().filter(|f| f.severity == severity).count();
    println!(
        "findings: {} critical, {} warning, {} info",
        count(Severity::Critical),
        count(Severity::Warning),
        count(Severity::Info)
    );
    Ok(Snapshot {
        root: ctx.root,
        worst: findings.first().map(|f| f.severity),
    })
}

/// Loads AWS configuration and verifies that a region and working
/// credentials are available.
async fn load_aws_config(args: &Args) -> Result<(SdkConfig, String)> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(region) = &args.region {
        loader = loader.region(Region::new(region.clone()));
    }
    if let Some(profile) = &args.profile {
        loader = loader.profile_name(profile);
    }
    // Collection fans out many CloudWatch calls at once; the default three
    // attempts are not enough to ride out throttling.
    let config = loader
        .retry_config(RetryConfig::adaptive().with_max_attempts(10))
        .load()
        .await;
    let Some(region) = config.region().map(ToString::to_string) else {
        bail!("no AWS region configured; pass --region or set AWS_REGION");
    };

    // Fail fast on unusable credentials (an expired SSO session, say);
    // otherwise every call would fail and yield an empty snapshot.
    let Some(credentials) = config.credentials_provider() else {
        bail!("no AWS credentials configured; pass --profile or set AWS_PROFILE");
    };
    credentials.provide_credentials().await.context(
        "could not load AWS credentials; if you use SSO, run `aws sso login` for this profile",
    )?;
    Ok((config, region))
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

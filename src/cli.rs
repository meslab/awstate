//! Command-line interface.

// Doc comments here are rendered verbatim as `--help` text, so they carry
// no markdown backticks.
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};

/// Pull RDS, ElastiCache, EC2 Auto Scaling, and ECS metrics, logs, and events for a time window
/// into a directory laid out for AI analysis.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    /// Length of the window ending now (or at --end), e.g. 24h, 90m, 7d.
    #[arg(long, default_value = "24h", value_parser = humantime::parse_duration, conflicts_with = "start")]
    pub last: Duration,

    /// Explicit window start (RFC 3339, e.g. 2026-11-15T00:00:00Z).
    #[arg(long)]
    pub start: Option<DateTime<Utc>>,

    /// Window end (RFC 3339). Defaults to now.
    #[arg(long)]
    pub end: Option<DateTime<Utc>>,

    /// AWS region. Defaults to the region from the environment/profile.
    #[arg(long)]
    pub region: Option<String>,

    /// AWS shared-config profile name.
    #[arg(long)]
    pub profile: Option<String>,

    /// Services to collect.
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [Service::Rds, Service::Elasticache, Service::Asg, Service::Ecs])]
    pub services: Vec<Service>,

    /// Data kinds to skip.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub skip: Vec<DataKind>,

    /// Only collect resources whose identifier contains one of these
    /// substrings (repeatable or comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub filter: Vec<String>,

    /// Output directory. Defaults to ./awstate-<UTC timestamp>.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// CloudWatch metric period in seconds. Defaults to 300 for windows up
    /// to 48h, 3600 beyond that.
    #[arg(long, value_parser = clap::value_parser!(i32).range(1..))]
    pub metric_period: Option<i32>,

    /// Maximum events to pull per CloudWatch log group (earliest first).
    #[arg(long, default_value_t = 5000)]
    pub max_log_events: usize,

    /// CloudWatch Logs filter pattern applied to every log group,
    /// e.g. ?ERROR ?FATAL ?deadlock.
    #[arg(long)]
    pub log_filter_pattern: Option<String>,

    /// Byte budget per DB instance for log files downloaded through the RDS
    /// API (used when an instance does not export logs to CloudWatch).
    /// 0 disables these downloads.
    #[arg(long, default_value_t = 1_048_576)]
    pub max_log_file_bytes: usize,

    /// Number of resources collected concurrently.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
    pub concurrency: u16,

    /// Verbose progress logging (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// An AWS service this tool knows how to collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Service {
    /// Amazon RDS / Aurora.
    Rds,
    /// Amazon ElastiCache.
    Elasticache,
    /// EC2 Auto Scaling groups.
    Asg,
    /// Amazon ECS clusters and services.
    Ecs,
}

/// A kind of data collected per resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DataKind {
    /// CloudWatch metrics.
    Metrics,
    /// CloudWatch Logs and RDS log files.
    Logs,
    /// Service events.
    Events,
}

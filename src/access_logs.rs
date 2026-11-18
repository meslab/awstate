//! Access logs that load balancers and `CloudFront` write to S3 as
//! (usually gzipped) files, a few per node every few minutes.
//!
//! A busy window holds far more log data than is worth downloading, so the
//! newest files are taken first until a compressed-byte budget is spent, and
//! by default only lines recording failed requests are kept.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read as _;

use anyhow::{Context, Result};
use aws_config::{Region, SdkConfig};
use aws_sdk_s3::types::BucketLocationConstraint;
use chrono::{DateTime, NaiveDate, Utc};
use futures::{StreamExt, stream};

use crate::cli::AccessLogLines;
use crate::logs::write_log;
use crate::model::{Ctx, LogCapture};

/// Where one resource's access logs live and how to read them.
pub struct AccessLogSource {
    pub bucket: String,
    /// Shown in the snapshot as where the logs came from.
    pub label: String,
    /// Key prefixes to list, together covering the window.
    pub prefixes: Vec<String>,
    /// Whether an object, judging by its key, holds requests from the window.
    pub in_window: Box<dyn Fn(&str) -> bool + Send + Sync>,
    /// Whether a log line records a failed request.
    pub is_error: fn(&str) -> bool,
    /// Column names for formats whose files carry no header.
    pub fields: Option<&'static str>,
}

/// Reads access logs, with one S3 client per bucket region.
pub struct AccessLogReader {
    config: SdkConfig,
    /// `GetBucketLocation` answers for any bucket from us-east-1.
    locator: aws_sdk_s3::Client,
    clients: futures::lock::Mutex<HashMap<String, aws_sdk_s3::Client>>,
}

impl AccessLogReader {
    pub fn new(config: &SdkConfig, us_east_1: &SdkConfig) -> Self {
        Self {
            config: config.clone(),
            locator: aws_sdk_s3::Client::new(us_east_1),
            clients: futures::lock::Mutex::default(),
        }
    }

    /// Captures the window's access log lines into `<rel_dir>/logs/`.
    pub async fn capture(
        &self,
        ctx: &Ctx,
        source: &AccessLogSource,
        rel_dir: &str,
    ) -> Result<LogCapture> {
        let client = self.client_for(&source.bucket).await;
        let mut objects = list_objects(&client, source).await?;
        objects.sort_by(|a, b| b.0.cmp(&a.0));
        let in_window = objects.len();
        let selected = newest_within_budget(&objects, ctx.max_access_log_bytes);

        let errors_only = ctx.access_log_lines == AccessLogLines::Errors;
        let mut header = source.fields.map(str::to_owned);
        let mut files: Vec<Vec<String>> = Vec::new();
        let mut lines = 0usize;
        let mut line_limit_hit = false;
        let mut downloads = stream::iter(selected)
            .map(|key| download(&client, &source.bucket, key))
            .buffered(ctx.concurrency);
        while let Some(text) = downloads.next().await {
            let text = text?;
            let mut kept = Vec::new();
            for line in text.lines() {
                if let Some(fields) = line.strip_prefix("#Fields:") {
                    header.get_or_insert_with(|| fields.trim().to_owned());
                    continue;
                }
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if errors_only && !(source.is_error)(line) {
                    continue;
                }
                if lines >= ctx.max_log_events {
                    line_limit_hit = true;
                    break;
                }
                kept.push(line.to_owned());
                lines += 1;
            }
            files.push(kept);
            if line_limit_hit {
                break;
            }
        }
        let downloaded = files.len();

        let mut text = String::new();
        if lines > 0
            && let Some(header) = &header
        {
            let _ = writeln!(text, "#Fields: {header}");
        }
        for line in files.iter().rev().flatten() {
            text.push_str(line);
            text.push('\n');
        }

        let file = write_log(ctx, rel_dir, "access", &text).await?;
        let filter = if errors_only {
            ", failed requests only"
        } else {
            ""
        };
        Ok(LogCapture {
            source: format!(
                "{} ({downloaded} newest of {in_window} files in the window{filter})",
                source.label
            ),
            file,
            lines,
            bytes: text.len(),
            truncated: line_limit_hit || downloaded < in_window,
        })
    }

    async fn client_for(&self, bucket: &str) -> aws_sdk_s3::Client {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(bucket) {
            return client.clone();
        }
        let mut config = aws_sdk_s3::config::Builder::from(&self.config);
        // Without the lookup (no permission, say) the home region is tried;
        // a wrong guess then fails the listing with a redirect error.
        if let Ok(location) = self
            .locator
            .get_bucket_location()
            .bucket(bucket)
            .send()
            .await
        {
            config = config.region(Region::new(bucket_region(location.location_constraint())));
        }
        let client = aws_sdk_s3::Client::from_conf(config.build());
        clients.insert(bucket.to_owned(), client.clone());
        client
    }
}

/// Every UTC day from `start`'s through `end`'s, for log stores that file
/// objects under per-day key prefixes.
pub fn days(start: DateTime<Utc>, end: DateTime<Utc>) -> impl Iterator<Item = NaiveDate> {
    let last = end.date_naive();
    start
        .date_naive()
        .iter_days()
        .take_while(move |day| *day <= last)
}

/// `GetBucketLocation` reports us-east-1 as no constraint and eu-west-1 as
/// the legacy `EU`.
fn bucket_region(constraint: Option<&BucketLocationConstraint>) -> String {
    match constraint.map(BucketLocationConstraint::as_str) {
        None | Some("") => "us-east-1".to_owned(),
        Some("EU") => "eu-west-1".to_owned(),
        Some(region) => region.to_owned(),
    }
}

/// Keys and sizes of the objects in the window.
async fn list_objects(
    client: &aws_sdk_s3::Client,
    source: &AccessLogSource,
) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for prefix in &source.prefixes {
        let mut pages = client
            .list_objects_v2()
            .bucket(&source.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page.with_context(|| format!("listing s3://{}/{prefix}", source.bucket))?;
            for object in page.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                if (source.in_window)(key) {
                    let size = object.size().and_then(|s| u64::try_from(s).ok());
                    out.push((key.to_owned(), size.unwrap_or(0)));
                }
            }
        }
    }
    Ok(out)
}

/// The leading objects whose sizes fit in `budget`, always at least one.
fn newest_within_budget(objects: &[(String, u64)], budget: u64) -> Vec<&str> {
    let mut spent = 0u64;
    objects
        .iter()
        .take_while(|(_, size)| {
            let fits = spent == 0 || spent + size <= budget;
            spent += size;
            fits
        })
        .map(|(key, _)| key.as_str())
        .collect()
}

async fn download(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Result<String> {
    let object = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("downloading s3://{bucket}/{key}"))?;
    let body = object
        .body
        .collect()
        .await
        .with_context(|| format!("reading s3://{bucket}/{key}"))?
        .into_bytes();
    if !key.to_ascii_lowercase().ends_with(".gz") {
        return Ok(String::from_utf8_lossy(&body).into_owned());
    }
    let mut raw = Vec::new();
    flate2::read::MultiGzDecoder::new(&body[..])
        .read_to_end(&mut raw)
        .with_context(|| format!("decompressing s3://{bucket}/{key}"))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_takes_newest_objects_and_at_least_one() {
        let objects = [
            ("c".to_owned(), 60),
            ("b".to_owned(), 30),
            ("a".to_owned(), 30),
        ];
        assert_eq!(newest_within_budget(&objects, 100), ["c", "b"]);
        assert_eq!(newest_within_budget(&objects, 10), ["c"]);
        assert_eq!(newest_within_budget(&[], 10), [] as [&str; 0]);
    }

    #[test]
    fn bucket_region_maps_legacy_constraints() {
        assert_eq!(bucket_region(None), "us-east-1");
        assert_eq!(
            bucket_region(Some(&BucketLocationConstraint::from("EU"))),
            "eu-west-1"
        );
        assert_eq!(
            bucket_region(Some(&BucketLocationConstraint::from("eu-central-1"))),
            "eu-central-1"
        );
    }
}

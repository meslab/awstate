//! `CloudWatch` Logs capture.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context, Result};

use crate::collect::write_file;
use crate::model::{Ctx, LogCapture, LogSource, iso_millis, sanitize};

/// Pulls the window's events from a log source into
/// `<rel_dir>/logs/<group>.log`, one `timestamp [stream] message` line per
/// event, earliest first.
pub async fn capture_group(ctx: &Ctx, source: &LogSource, rel_dir: &str) -> Result<LogCapture> {
    let group = source.group.as_str();
    let mut pages = ctx
        .logs_for(source.us_east_1)
        .filter_log_events()
        .log_group_name(group)
        .set_log_stream_name_prefix(source.stream_prefix.clone())
        .start_time(ctx.window.start.timestamp_millis())
        .end_time(ctx.window.end.timestamp_millis())
        .set_filter_pattern(ctx.log_filter_pattern.clone())
        .into_paginator()
        .send();

    let mut text = String::new();
    let mut lines = 0usize;
    let mut truncated = false;
    'pages: while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("reading log group {group}"))?;
        for event in page.events() {
            if lines >= ctx.max_log_events {
                truncated = true;
                break 'pages;
            }
            let time = event.timestamp().map_or_default(iso_millis);
            let stream = event.log_stream_name().unwrap_or("-");
            let message = event.message().unwrap_or_default().trim_end();
            // Writing to a String cannot fail.
            let _ = writeln!(text, "{time} [{stream}] {message}");
            lines += 1;
        }
    }

    let name = match &source.stream_prefix {
        Some(prefix) => format!("{group}__{prefix}"),
        None => group.to_owned(),
    };
    let file = write_log(ctx, rel_dir, &name, &text).await?;
    Ok(LogCapture {
        source: match &source.stream_prefix {
            Some(prefix) => format!("cloudwatch-logs:{group} (streams {prefix}*)"),
            None => format!("cloudwatch-logs:{group}"),
        },
        file,
        lines,
        bytes: text.len(),
        truncated,
    })
}

/// Writes captured log text under the resource's `logs/` directory and
/// returns the path relative to the output root. Empty captures write nothing.
pub async fn write_log(ctx: &Ctx, rel_dir: &str, name: &str, text: &str) -> Result<Option<String>> {
    if text.is_empty() {
        return Ok(None);
    }
    let rel = format!("{rel_dir}/logs/{}.log", sanitize(name));
    write_file(ctx, &rel, text.as_bytes()).await?;
    Ok(Some(rel))
}

/// A log delivery configured through `CloudWatch` Logs (`CloudFront`
/// standard logging v2, for one): the source resource sends one log type to
/// a log group, S3 bucket, or Firehose stream.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub log_type: String,
    pub destination_type: String,
    pub destination_arn: String,
}

impl Delivery {
    /// The destination log group's name, when the destination is one.
    pub fn log_group(&self) -> Option<&str> {
        let name = self.destination_arn.split_once(":log-group:")?.1;
        Some(name.strip_suffix(":*").unwrap_or(name))
    }
}

/// Every delivery visible to `client`, keyed by the source resource ARN.
pub async fn deliveries(
    client: &aws_sdk_cloudwatchlogs::Client,
) -> Result<HashMap<String, Vec<Delivery>>> {
    let mut sources: HashMap<String, (Vec<String>, String)> = HashMap::new();
    let mut pages = client.describe_delivery_sources().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.context("describing log delivery sources")?;
        for source in page.delivery_sources() {
            if let Some(name) = source.name() {
                sources.insert(
                    name.to_owned(),
                    (
                        source.resource_arns().to_vec(),
                        source.log_type().unwrap_or_default().to_owned(),
                    ),
                );
            }
        }
    }
    if sources.is_empty() {
        return Ok(HashMap::new());
    }

    let mut destinations: HashMap<String, String> = HashMap::new();
    let mut pages = client
        .describe_delivery_destinations()
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        let page = page.context("describing log delivery destinations")?;
        for d in page.delivery_destinations() {
            if let (Some(arn), Some(config)) = (d.arn(), d.delivery_destination_configuration()) {
                destinations.insert(arn.to_owned(), config.destination_resource_arn().to_owned());
            }
        }
    }

    let mut out: HashMap<String, Vec<Delivery>> = HashMap::new();
    let mut pages = client.describe_deliveries().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.context("describing log deliveries")?;
        for d in page.deliveries() {
            let Some((resources, log_type)) = d.delivery_source_name().and_then(|n| sources.get(n))
            else {
                continue;
            };
            let Some(destination_arn) = d
                .delivery_destination_arn()
                .and_then(|arn| destinations.get(arn))
            else {
                continue;
            };
            let delivery = Delivery {
                log_type: log_type.clone(),
                destination_type: d
                    .delivery_destination_type()
                    .map_or_default(|t| t.as_str().to_owned()),
                destination_arn: destination_arn.clone(),
            };
            for resource in resources {
                out.entry(resource.clone())
                    .or_default()
                    .push(delivery.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_log_group_strips_arn_and_wildcard() {
        let delivery = |arn: &str| Delivery {
            log_type: "ACCESS_LOGS".to_owned(),
            destination_type: "CWL".to_owned(),
            destination_arn: arn.to_owned(),
        };
        assert_eq!(
            delivery("arn:aws:logs:us-east-1:123456789012:log-group:/cf/site:*").log_group(),
            Some("/cf/site")
        );
        assert_eq!(delivery("arn:aws:s3:::bucket").log_group(), None);
    }
}

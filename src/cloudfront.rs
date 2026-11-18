//! Amazon `CloudFront` collection: distributions, their `CloudWatch`
//! metrics, standard logs (legacy S3 logging, and v2 logging delivered to
//! `CloudWatch` Logs), and configuration changes from `CloudTrail`.
//!
//! `CloudFront` is global: its metrics, v2 log deliveries, and `CloudTrail`
//! events all live in us-east-1, whatever the home region.

use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_cloudfront::Client;
use aws_sdk_cloudfront::types::{
    Aliases, CustomOriginConfig, Distribution, DistributionSummary, Origin, OriginGroups, Origins,
};
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use serde_json::Value;
use serde_json::json;

use crate::access_logs::{AccessLogSource, days};
use crate::cloudtrail::{self, Owner};
use crate::collect::collect_all;
use crate::logs::{self, Delivery};
use crate::model::{Ctx, LogSource, MetricSource, ServiceReport, Spec, iso};

const SERVICE: &str = "cloudfront";
const NAMESPACE: &str = "AWS/CloudFront";
const EVENT_SOURCE: &str = "cloudfront.amazonaws.com";

/// Collects inventory, metrics, logs, and configuration changes for
/// `CloudFront` distributions.
pub async fn collect(
    ctx: &Ctx,
    client: &Client,
    trail: &aws_sdk_cloudtrail::Client,
) -> ServiceReport {
    let summaries = list_distributions(client).await.unwrap_or_else(|err| {
        ctx.issues.record("cloudfront inventory", &err);
        Vec::new()
    });
    let wanted: Vec<&DistributionSummary> = summaries
        .iter()
        .filter(|d| {
            ctx.wanted(d.id())
                || ctx.wanted(d.domain_name())
                || d.aliases()
                    .is_some_and(|a| a.items().iter().any(|n| ctx.wanted(n)))
        })
        .collect();

    let deliveries = if ctx.logs_enabled && !wanted.is_empty() {
        logs::deliveries(&ctx.logs_us_east_1)
            .await
            .unwrap_or_else(|err| {
                ctx.issues.record("cloudfront log deliveries", &err);
                HashMap::new()
            })
    } else {
        HashMap::new()
    };

    let specs: Vec<Spec> = stream::iter(&wanted)
        .map(|summary| distribution_spec(ctx, client, summary, &deliveries))
        .buffer_unordered(ctx.concurrency)
        .collect()
        .await;
    let owners: Vec<Owner> = wanted
        .iter()
        .map(|d| Owner {
            token: d.id().to_owned(),
            resource: d.id().to_owned(),
        })
        .collect();

    let (resources, events) = tokio::join!(collect_all(ctx, specs), async {
        if !ctx.events {
            return Vec::new();
        }
        cloudtrail::changes(ctx, trail, EVENT_SOURCE, "cloudfront-change", &owners)
            .await
            .unwrap_or_else(|err| {
                ctx.issues.record("cloudfront configuration changes", &err);
                Vec::new()
            })
    });
    ServiceReport { resources, events }
}

async fn list_distributions(client: &Client) -> Result<Vec<DistributionSummary>> {
    let mut pages = client.list_distributions().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("listing distributions")?;
        if let Some(list) = page.distribution_list {
            out.extend(list.items.unwrap_or_default());
        }
    }
    Ok(out)
}

async fn get_distribution(client: &Client, id: &str) -> Result<Option<Distribution>> {
    let out = client
        .get_distribution()
        .id(id)
        .send()
        .await
        .with_context(|| format!("getting distribution {id}"))?;
    Ok(out.distribution)
}

/// Whether additional metrics (error rates per status, origin latency,
/// cache hit rate) are enabled.
async fn additional_metrics(client: &Client, id: &str) -> Result<bool> {
    match client
        .get_monitoring_subscription()
        .distribution_id(id)
        .send()
        .await
    {
        Ok(out) => Ok(out
            .monitoring_subscription()
            .and_then(|m| m.realtime_metrics_subscription_config())
            .is_some_and(|c| c.realtime_metrics_subscription_status().as_str() == "Enabled")),
        Err(err)
            if err
                .as_service_error()
                .is_some_and(aws_sdk_cloudfront::operation::get_monitoring_subscription::GetMonitoringSubscriptionError::is_no_such_monitoring_subscription) =>
        {
            Ok(false)
        }
        Err(err) => Err(err).with_context(|| format!("getting monitoring subscription of {id}")),
    }
}

async fn distribution_spec(
    ctx: &Ctx,
    client: &Client,
    d: &DistributionSummary,
    deliveries: &HashMap<String, Vec<Delivery>>,
) -> Spec {
    let id = d.id();
    let scope = format!("cloudfront/distribution/{id}");
    let (distribution, additional) =
        tokio::join!(get_distribution(client, id), additional_metrics(client, id));
    let distribution = distribution.unwrap_or_else(|err| {
        ctx.issues.record(format!("{scope} config"), &err);
        None
    });
    let additional = additional
        .map_err(|err| {
            ctx.issues
                .record(format!("{scope} monitoring subscription"), &err);
        })
        .ok();

    let mut notes = Vec::new();
    if additional == Some(false) {
        notes.push(
            "additional metrics are off, so per-status error rates, origin latency, and cache \
             hit rate are absent"
                .to_owned(),
        );
    }

    let logging = distribution
        .as_ref()
        .and_then(|x| x.distribution_config())
        .and_then(|c| c.logging())
        .filter(|l| l.enabled());
    let mut access_log_sources = Vec::new();
    if let Some(logging) = logging {
        let bucket = logging
            .bucket()
            .split_once(".s3.")
            .map_or(logging.bucket(), |(name, _)| name);
        access_log_sources.push(access_log_source(
            id,
            bucket,
            logging.prefix(),
            (ctx.window.start, ctx.window.end),
        ));
    }

    let own_deliveries = deliveries.get(d.arn()).map_or(&[][..], Vec::as_slice);
    let log_sources = delivered_log_groups(own_deliveries, &mut notes);
    if logging.is_none() && own_deliveries.is_empty() {
        notes.push(
            "standard logging is off, so individual failed requests cannot be seen".to_owned(),
        );
    }

    let details = json!({
        "domain_name": d.domain_name(),
        "aliases": d.aliases().map_or_default(Aliases::items),
        "comment": d.comment(),
        "status": d.status(),
        "enabled": d.enabled(),
        "staging": d.staging(),
        "price_class": d.price_class().as_str(),
        "http_version": d.http_version().as_str(),
        "web_acl": Some(d.web_acl_id()).filter(|w| !w.is_empty()),
        "origins": d
            .origins()
            .map_or_default(Origins::items)
            .iter()
            .map(origin_details)
            .collect::<Vec<_>>(),
        "origin_groups": d.origin_groups().map(OriginGroups::quantity),
        "certificate": d.viewer_certificate().map(|c| json!({
            "acm_certificate": c.acm_certificate_arn(),
            "minimum_protocol_version": c.minimum_protocol_version().map(|v| v.as_str().to_owned()),
        })),
        "in_progress_invalidations": distribution
            .as_ref()
            .map(Distribution::in_progress_invalidation_batches),
        "logging": {
            "s3": logging.map(|l| json!({"bucket": l.bucket(), "prefix": l.prefix()})),
            "deliveries": own_deliveries.iter().map(|x| json!({
                "log_type": x.log_type,
                "destination_type": x.destination_type,
                "destination": x.destination_arn,
            })).collect::<Vec<_>>(),
        },
        "additional_metrics": additional,
        "last_modified": iso(d.last_modified_time()),
    });

    Spec {
        service: SERVICE,
        kind: "distribution",
        id: id.to_owned(),
        details,
        metric_sources: vec![
            MetricSource::by(NAMESPACE, "DistributionId", id)
                .in_us_east_1()
                .summing(summed),
        ],
        log_sources,
        access_log_sources,
        notes,
    }
}

/// Log groups that v2 standard logging delivers to, noting deliveries to
/// destinations this tool cannot read.
fn delivered_log_groups(deliveries: &[Delivery], notes: &mut Vec<String>) -> Vec<LogSource> {
    let mut out = Vec::new();
    for delivery in deliveries {
        match delivery.log_group() {
            Some(group) => out.push(LogSource {
                group: group.to_owned(),
                stream_prefix: None,
                us_east_1: true,
            }),
            None => notes.push(format!(
                "{} logs are delivered to {} ({}), which this tool cannot read",
                delivery.log_type, delivery.destination_type, delivery.destination_arn
            )),
        }
    }
    out
}

fn origin_details(o: &Origin) -> Value {
    json!({
        "id": o.id(),
        "domain_name": o.domain_name(),
        "path": o.origin_path(),
        "protocol_policy": o
            .custom_origin_config()
            .map(|c| c.origin_protocol_policy().as_str().to_owned()),
        "read_timeout_s": o
            .custom_origin_config()
            .and_then(CustomOriginConfig::origin_read_timeout),
    })
}

/// Legacy standard logs are stored as
/// `<prefix><distribution id>.<YYYY-MM-DD-HH>.<unique>.gz`, one or more
/// files per hour of requests.
fn access_log_source(
    id: &str,
    bucket: &str,
    prefix: &str,
    (start, end): (DateTime<Utc>, DateTime<Utc>),
) -> AccessLogSource {
    let stem = format!("{prefix}{id}.");
    let prefixes = days(start, end)
        .map(|day| format!("{stem}{}-", day.format("%Y-%m-%d")))
        .collect();
    let earliest = start.format("%Y-%m-%d-%H").to_string();
    let latest = end.format("%Y-%m-%d-%H").to_string();
    AccessLogSource {
        bucket: bucket.to_owned(),
        label: format!("s3://{bucket}/{stem}*"),
        prefixes,
        in_window: Box::new(move |key| {
            key.strip_prefix(&stem)
                .and_then(|rest| rest.get(..earliest.len()))
                .is_some_and(|hour| *hour >= *earliest && *hour <= *latest)
        }),
        is_error: failed_request,
        fields: None,
    }
}

/// A request answered with 4xx or 5xx, or not answered at all (status 000,
/// or an edge result of `Error`).
fn failed_request(line: &str) -> bool {
    let fields: Vec<&str> = line.split('\t').collect();
    let status = fields.get(8).and_then(|s| s.parse::<u16>().ok());
    status.is_some_and(|s| s == 0 || s >= 400) || fields.get(13) == Some(&"Error")
}

/// Request and byte counts, which `CloudFront` reports per minute.
fn summed(name: &str) -> bool {
    matches!(name, "Requests" | "BytesDownloaded" | "BytesUploaded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_log_source_filters_by_hour() {
        let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        let source = access_log_source(
            "E2ABC",
            "logs",
            "cf/",
            (at("2026-11-16T22:30:00Z"), at("2026-11-17T01:10:00Z")),
        );
        assert_eq!(
            source.prefixes,
            ["cf/E2ABC.2026-11-16-", "cf/E2ABC.2026-11-17-"]
        );
        assert!((source.in_window)("cf/E2ABC.2026-11-16-22.a1b2.gz"));
        assert!((source.in_window)("cf/E2ABC.2026-11-17-01.a1b2.gz"));
        assert!(!(source.in_window)("cf/E2ABC.2026-11-16-21.a1b2.gz"));
        assert!(!(source.in_window)("cf/E2ABC.2026-11-17-02.a1b2.gz"));
    }

    #[test]
    fn failed_request_reads_status_and_edge_result() {
        let line = |status: &str, result: &str| {
            format!(
                "2026-11-17\t00:00:00\tFRA56\t100\t1.2.3.4\tGET\td.cloudfront.net\t/\t{status}\t-\tUA\t-\t-\t{result}\tid"
            )
        };
        assert!(!failed_request(&line("200", "Hit")));
        assert!(failed_request(&line("503", "Error")));
        assert!(failed_request(&line("000", "Error")));
        assert!(failed_request(&line("200", "Error")));
        assert!(failed_request(&line("403", "Error")));
    }
}

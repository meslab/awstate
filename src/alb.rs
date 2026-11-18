//! Application Load Balancer collection: load balancers with their
//! listeners and target groups, `CloudWatch` metrics, access logs from S3,
//! and configuration changes from `CloudTrail`.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use aws_sdk_elasticloadbalancingv2::Client;
use aws_sdk_elasticloadbalancingv2::types::{
    Listener, LoadBalancer, LoadBalancerTypeEnum, TargetGroup, TargetHealthDescription,
};
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use serde_json::{Value, json};

use crate::access_logs::{AccessLogSource, days};
use crate::cloudtrail::{self, Owner};
use crate::collect::collect_all;
use crate::model::{Ctx, MetricSource, ServiceReport, Spec, iso};

const SERVICE: &str = "alb";
const NAMESPACE: &str = "AWS/ApplicationELB";
const EVENT_SOURCE: &str = "elasticloadbalancing.amazonaws.com";

/// Columns of an ALB access log line; the files have no header.
const ACCESS_LOG_FIELDS: &str = "type time elb client:port target:port \
    request_processing_time target_processing_time response_processing_time \
    elb_status_code target_status_code received_bytes sent_bytes \"request\" \
    \"user_agent\" ssl_cipher ssl_protocol target_group_arn \"trace_id\" \
    \"domain_name\" \"chosen_cert_arn\" matched_rule_priority \
    request_creation_time \"actions_executed\" \"redirect_url\" \"error_reason\" \
    \"target:port_list\" \"target_status_code_list\" \"classification\" \
    \"classification_reason\" conn_trace_id ...";

/// Access log files are written every five minutes, named by the end of
/// the interval they cover.
const ACCESS_LOG_INTERVAL_MINUTES: i64 = 5;

/// Collects inventory, metrics, access logs, and configuration changes for
/// Application Load Balancers.
pub async fn collect(
    ctx: &Ctx,
    client: &Client,
    trail: &aws_sdk_cloudtrail::Client,
) -> ServiceReport {
    let load_balancers = list_load_balancers(client).await.unwrap_or_else(|err| {
        ctx.issues.record("alb inventory", &err);
        Vec::new()
    });
    let described: Vec<(Spec, Vec<Owner>)> = stream::iter(
        load_balancers
            .iter()
            .filter(|lb| lb.r#type() == Some(&LoadBalancerTypeEnum::Application))
            .filter(|lb| lb.load_balancer_name().is_some_and(|n| ctx.wanted(n))),
    )
    .map(|lb| describe(ctx, client, lb))
    .buffer_unordered(ctx.concurrency)
    .collect()
    .await;
    let (specs, owners): (Vec<Spec>, Vec<Vec<Owner>>) = described.into_iter().unzip();
    let owners: Vec<Owner> = owners.into_iter().flatten().collect();

    let (resources, events) = tokio::join!(collect_all(ctx, specs), async {
        if !ctx.events {
            return Vec::new();
        }
        cloudtrail::changes(ctx, trail, EVENT_SOURCE, "alb-change", &owners)
            .await
            .unwrap_or_else(|err| {
                ctx.issues.record("alb configuration changes", &err);
                Vec::new()
            })
    });
    ServiceReport { resources, events }
}

async fn list_load_balancers(client: &Client) -> Result<Vec<LoadBalancer>> {
    let mut pages = client.describe_load_balancers().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing load balancers")?;
        out.extend(page.load_balancers.unwrap_or_default());
    }
    Ok(out)
}

/// Builds the spec of one load balancer, plus the `CloudTrail` tokens that
/// identify it and its target groups.
async fn describe(ctx: &Ctx, client: &Client, lb: &LoadBalancer) -> (Spec, Vec<Owner>) {
    let name = lb.load_balancer_name().unwrap_or_default();
    let arn = lb.load_balancer_arn().unwrap_or_default();
    let scope = format!("alb/load-balancer/{name}");

    let (attributes, listeners, target_groups) = tokio::join!(
        attributes(client, arn),
        listeners(client, arn),
        target_groups(client, arn),
    );
    let attributes = attributes.unwrap_or_else(|err| {
        ctx.issues.record(format!("{scope} attributes"), &err);
        BTreeMap::new()
    });
    let listeners = listeners.unwrap_or_else(|err| {
        ctx.issues.record(format!("{scope} listeners"), &err);
        Vec::new()
    });
    let target_groups = target_groups.unwrap_or_else(|err| {
        ctx.issues.record(format!("{scope} target groups"), &err);
        Vec::new()
    });

    let mut owners: Vec<Owner> = target_groups
        .iter()
        .filter_map(|(g, _)| g.target_group_arn())
        .map(|tg| Owner {
            token: tg.to_owned(),
            resource: name.to_owned(),
        })
        .collect();
    let arn_parts = AlbArn::parse(arn);
    if let Some(parts) = &arn_parts {
        owners.push(Owner {
            token: parts.resource_id.to_owned(),
            resource: name.to_owned(),
        });
    }

    let mut notes = Vec::new();
    let mut access_log_sources = Vec::new();
    if attributes.get("access_logs.s3.enabled").map(String::as_str) == Some("true") {
        if let (Some(parts), Some(bucket)) = (&arn_parts, attributes.get("access_logs.s3.bucket")) {
            let prefix = attributes
                .get("access_logs.s3.prefix")
                .map_or("", String::as_str);
            access_log_sources.push(access_log_source(
                parts,
                bucket,
                prefix,
                (ctx.window.start, ctx.window.end),
            ));
        }
    } else {
        notes.push(
            "access logs are disabled, so individual failed requests cannot be seen".to_owned(),
        );
    }

    let details = json!({
        "dns_name": lb.dns_name(),
        "scheme": lb.scheme().map(|s| s.as_str().to_owned()),
        "state": lb.state().and_then(|s| s.code()).map(|c| c.as_str().to_owned()),
        "state_reason": lb.state().and_then(|s| s.reason()),
        "vpc": lb.vpc_id(),
        "availability_zones": lb
            .availability_zones()
            .iter()
            .filter_map(|z| z.zone_name())
            .collect::<Vec<_>>(),
        "security_groups": lb.security_groups(),
        "ip_address_type": lb.ip_address_type().map(|t| t.as_str().to_owned()),
        "attributes": attributes,
        "listeners": listeners.iter().map(listener_details).collect::<Vec<_>>(),
        "target_groups": target_groups
            .iter()
            .map(|(g, health)| target_group_details(g, health))
            .collect::<Vec<_>>(),
        "created": lb.created_time().map(iso),
    });

    let metric_source_value = arn_parts.as_ref().map_or(name, |p| p.resource_id);
    let spec = Spec {
        service: SERVICE,
        kind: "load-balancer",
        id: name.to_owned(),
        details,
        metric_sources: vec![
            MetricSource::by(NAMESPACE, "LoadBalancer", metric_source_value).summing(summed),
        ],
        log_sources: Vec::new(),
        access_log_sources,
        notes,
    };
    (spec, owners)
}

async fn attributes(client: &Client, arn: &str) -> Result<BTreeMap<String, String>> {
    let out = client
        .describe_load_balancer_attributes()
        .load_balancer_arn(arn)
        .send()
        .await
        .context("describing load balancer attributes")?;
    Ok(out
        .attributes()
        .iter()
        .filter_map(|a| Some((a.key()?.to_owned(), a.value()?.to_owned())))
        .collect())
}

async fn listeners(client: &Client, arn: &str) -> Result<Vec<Listener>> {
    let mut pages = client
        .describe_listeners()
        .load_balancer_arn(arn)
        .into_paginator()
        .send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing listeners")?;
        out.extend(page.listeners.unwrap_or_default());
    }
    Ok(out)
}

async fn target_groups(
    client: &Client,
    arn: &str,
) -> Result<Vec<(TargetGroup, Vec<TargetHealthDescription>)>> {
    let mut pages = client
        .describe_target_groups()
        .load_balancer_arn(arn)
        .into_paginator()
        .send();
    let mut groups = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing target groups")?;
        groups.extend(page.target_groups.unwrap_or_default());
    }

    let mut out = Vec::with_capacity(groups.len());
    for group in groups {
        let health = client
            .describe_target_health()
            .set_target_group_arn(group.target_group_arn().map(str::to_owned))
            .send()
            .await
            .with_context(|| {
                format!(
                    "describing target health of {}",
                    group.target_group_name().unwrap_or_default()
                )
            })?;
        out.push((group, health.target_health_descriptions.unwrap_or_default()));
    }
    Ok(out)
}

fn listener_details(l: &Listener) -> Value {
    let actions: Vec<_> = l
        .default_actions()
        .iter()
        .map(|a| {
            json!({
                "type": a.r#type().map(|t| t.as_str().to_owned()),
                "target_group": a.target_group_arn().map(target_group_name),
            })
        })
        .collect();
    json!({
        "port": l.port(),
        "protocol": l.protocol().map(|p| p.as_str().to_owned()),
        "ssl_policy": l.ssl_policy(),
        "certificates": l
            .certificates()
            .iter()
            .filter_map(|c| c.certificate_arn())
            .collect::<Vec<_>>(),
        "default_actions": actions,
    })
}

fn target_group_details(g: &TargetGroup, health: &[TargetHealthDescription]) -> Value {
    let targets: Vec<_> = health
        .iter()
        .map(|h| {
            let target = h.target();
            let state = h.target_health();
            json!({
                "id": target.and_then(|t| t.id()),
                "port": target.and_then(aws_sdk_elasticloadbalancingv2::types::TargetDescription::port),
                "availability_zone": target.and_then(|t| t.availability_zone()),
                "state": state.and_then(|s| s.state()).map(|s| s.as_str().to_owned()),
                "reason": state.and_then(|s| s.reason()).map(|r| r.as_str().to_owned()),
                "description": state.and_then(|s| s.description()),
            })
        })
        .collect();
    let count = |state: &str| {
        health
            .iter()
            .filter(|h| {
                h.target_health()
                    .and_then(|s| s.state())
                    .is_some_and(|s| s.as_str() == state)
            })
            .count()
    };
    json!({
        "name": g.target_group_name(),
        "protocol": g.protocol().map(|p| p.as_str().to_owned()),
        "port": g.port(),
        "target_type": g.target_type().map(|t| t.as_str().to_owned()),
        "health_check": {
            "enabled": g.health_check_enabled(),
            "protocol": g.health_check_protocol().map(|p| p.as_str().to_owned()),
            "port": g.health_check_port(),
            "path": g.health_check_path(),
            "matcher": g.matcher().and_then(|m| m.http_code()),
            "interval_s": g.health_check_interval_seconds(),
            "timeout_s": g.health_check_timeout_seconds(),
            "healthy_threshold": g.healthy_threshold_count(),
            "unhealthy_threshold": g.unhealthy_threshold_count(),
        },
        "healthy": count("healthy"),
        "unhealthy": count("unhealthy"),
        "targets": targets,
    })
}

/// `arn:aws:elasticloadbalancing:<region>:<account>:targetgroup/<name>/<id>`.
fn target_group_name(arn: &str) -> &str {
    arn.split('/').nth(1).unwrap_or(arn)
}

/// The parts of a load balancer ARN that its metrics and log files use.
struct AlbArn<'a> {
    region: &'a str,
    account: &'a str,
    /// `app/<name>/<id>`, the `LoadBalancer` metric dimension.
    resource_id: &'a str,
}

impl<'a> AlbArn<'a> {
    /// `arn:<partition>:elasticloadbalancing:<region>:<account>:loadbalancer/app/<name>/<id>`.
    fn parse(arn: &'a str) -> Option<Self> {
        let mut parts = arn.splitn(6, ':');
        let (region, account, resource) = (parts.nth(3)?, parts.next()?, parts.next()?);
        Some(Self {
            region,
            account,
            resource_id: resource.strip_prefix("loadbalancer/")?,
        })
    }
}

/// Access logs are stored as
/// `[<prefix>/]AWSLogs/<account>/elasticloadbalancing/<region>/<yyyy>/<mm>/<dd>/
/// <account>_elasticloadbalancing_<region>_<app.name.id>_<yyyymmddThhmmZ>_<ip>_<random>.log.gz`.
fn access_log_source(
    arn: &AlbArn,
    bucket: &str,
    prefix: &str,
    (start, end): (DateTime<Utc>, DateTime<Utc>),
) -> AccessLogSource {
    let root = if prefix.is_empty() {
        format!(
            "AWSLogs/{}/elasticloadbalancing/{}",
            arn.account, arn.region
        )
    } else {
        format!(
            "{prefix}/AWSLogs/{}/elasticloadbalancing/{}",
            arn.account, arn.region
        )
    };
    let file_stem = format!(
        "{}_elasticloadbalancing_{}_{}_",
        arn.account,
        arn.region,
        arn.resource_id.replace('/', ".")
    );
    let last_file_end = end + chrono::Duration::minutes(ACCESS_LOG_INTERVAL_MINUTES);
    let prefixes = days(start, last_file_end)
        .map(|day| format!("{root}/{}/{file_stem}", day.format("%Y/%m/%d")))
        .collect();
    let earliest = start.format("%Y%m%dT%H%MZ").to_string();
    let latest = last_file_end.format("%Y%m%dT%H%MZ").to_string();
    AccessLogSource {
        bucket: bucket.to_owned(),
        label: format!("s3://{bucket}/{root}/.../{file_stem}*"),
        prefixes,
        in_window: Box::new(move |key| {
            key.split_once(&file_stem)
                .and_then(|(_, rest)| rest.get(..earliest.len()))
                .is_some_and(|ended| *ended > *earliest && *ended < *latest)
        }),
        is_error: failed_request,
        fields: Some(ACCESS_LOG_FIELDS),
    }
}

/// A request the load balancer or its target answered with 4xx or 5xx.
fn failed_request(line: &str) -> bool {
    let mut fields = line.split(' ').skip(8);
    let (elb, target) = (fields.next(), fields.next());
    [elb, target]
        .into_iter()
        .flatten()
        .any(|status| status.parse::<u16>().is_ok_and(|s| s >= 400))
}

/// Count metrics, whose `Average`, `Minimum`, and `Maximum` are always 1.
fn summed(name: &str) -> bool {
    const COUNT_SUFFIXES: [&str; 7] = [
        "Count", "Bytes", "LCUs", "Error", "Failure", "Success", "Exceeded",
    ];
    name == "RequestCountPerTarget"
        || (!name.ends_with("HostCount")
            && !name.starts_with("Peak")
            && COUNT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARN: &str = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188";

    #[test]
    fn parses_load_balancer_arn() {
        let arn = AlbArn::parse(ARN).unwrap();
        assert_eq!(arn.region, "eu-central-1");
        assert_eq!(arn.account, "123456789012");
        assert_eq!(arn.resource_id, "app/web/50dc6c495c0c9188");
        assert!(AlbArn::parse("arn:aws:elasticloadbalancing:r:a:targetgroup/x/y").is_none());
    }

    #[test]
    fn access_log_source_lists_each_day_and_filters_by_file_end_time() {
        let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        let source = access_log_source(
            &AlbArn::parse(ARN).unwrap(),
            "logs",
            "lb",
            (at("2026-11-16T23:00:00Z"), at("2026-11-17T01:00:00Z")),
        );
        let stem = "123456789012_elasticloadbalancing_eu-central-1_app.web.50dc6c495c0c9188_";
        let day = "lb/AWSLogs/123456789012/elasticloadbalancing/eu-central-1";
        assert_eq!(
            source.prefixes,
            [
                format!("{day}/2026/11/16/{stem}"),
                format!("{day}/2026/11/17/{stem}")
            ]
        );
        let key = |end: &str| format!("{day}/2026/11/17/{stem}{end}_10.0.0.1_abc.log.gz");
        assert!((source.in_window)(&key("20261117T0005Z")));
        assert!((source.in_window)(&key("20261117T0104Z")));
        assert!(!(source.in_window)(&key("20261117T0105Z")));
        assert!(!(source.in_window)(&key("20261116T2300Z")));
    }

    #[test]
    fn failed_request_checks_both_status_codes() {
        let line = |elb: &str, target: &str| {
            format!(
                "https 2026-11-17T00:00:00Z app/web/1 1.2.3.4:5 10.0.0.1:80 0.001 0.2 0.0 {elb} {target} 10 20 \"GET / HTTP/1.1\""
            )
        };
        assert!(!failed_request(&line("200", "200")));
        assert!(failed_request(&line("502", "-")));
        assert!(failed_request(&line("200", "404")));
        assert!(!failed_request(&line("301", "-")));
    }

    #[test]
    fn counts_are_summed_and_gauges_are_not() {
        for name in [
            "RequestCount",
            "HTTPCode_ELB_5XX_Count",
            "ProcessedBytes",
            "ConsumedLCUs",
            "RequestCountPerTarget",
            "TargetConnectionErrorCount",
        ] {
            assert!(summed(name), "{name}");
        }
        for name in [
            "TargetResponseTime",
            "HealthyHostCount",
            "UnHealthyHostCount",
            "PeakLCUs",
        ] {
            assert!(!summed(name), "{name}");
        }
    }
}

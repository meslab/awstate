//! EC2 Auto Scaling group collection.
//!
//! Auto Scaling groups have no logs of their own; their history is the
//! scaling-activity feed, which is reported as events.

use anyhow::{Context, Result};
use aws_sdk_autoscaling::Client;
use aws_sdk_autoscaling::types::AutoScalingGroup;
use serde_json::json;

use crate::collect::collect_all;
use crate::model::{Ctx, Event, MetricSource, ServiceReport, Spec, iso};

const SERVICE: &str = "asg";
const DIMENSION: &str = "AutoScalingGroupName";

/// Namespaces that publish metrics aggregated per Auto Scaling group: group
/// size metrics (when enabled), EC2 instance metrics, and `CloudWatch` agent
/// metrics (memory, disk) when the agent is configured to aggregate by group.
const NAMESPACES: [&str; 3] = ["AWS/AutoScaling", "AWS/EC2", "CWAgent"];

/// Collects inventory, metrics, and scaling activities for Auto Scaling.
pub async fn collect(ctx: &Ctx, client: &Client) -> ServiceReport {
    let (resources, events) = tokio::join!(
        async {
            let groups = list_groups(client).await.unwrap_or_else(|err| {
                ctx.issues.record("asg inventory", &err);
                Vec::new()
            });
            let specs = groups
                .iter()
                .filter(|g| g.auto_scaling_group_name().is_some_and(|n| ctx.wanted(n)))
                .map(group_spec)
                .collect();
            collect_all(ctx, specs).await
        },
        async {
            if !ctx.events {
                return Vec::new();
            }
            activities(ctx, client).await.unwrap_or_else(|err| {
                ctx.issues.record("asg scaling activities", &err);
                Vec::new()
            })
        }
    );
    ServiceReport { resources, events }
}

async fn list_groups(client: &Client) -> Result<Vec<AutoScalingGroup>> {
    let mut pages = client
        .describe_auto_scaling_groups()
        .into_paginator()
        .send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing Auto Scaling groups")?;
        out.extend(page.auto_scaling_groups.unwrap_or_default());
    }
    Ok(out)
}

fn group_spec(g: &AutoScalingGroup) -> Spec {
    let name = g.auto_scaling_group_name().unwrap_or_default();

    let instances: Vec<_> = g
        .instances()
        .iter()
        .map(|i| {
            json!({
                "id": i.instance_id(),
                "type": i.instance_type(),
                "availability_zone": i.availability_zone(),
                "lifecycle_state": i.lifecycle_state().map(|s| s.as_str().to_owned()),
                "health": i.health_status(),
                "protected_from_scale_in": i.protected_from_scale_in(),
            })
        })
        .collect();

    let suspended: Vec<_> = g
        .suspended_processes()
        .iter()
        .map(|p| {
            json!({
                "process": p.process_name(),
                "reason": p.suspension_reason(),
            })
        })
        .collect();

    let launch_template = g
        .launch_template()
        .or_else(|| {
            g.mixed_instances_policy()
                .and_then(|p| p.launch_template())
                .and_then(|t| t.launch_template_specification())
        })
        .map(|t| {
            json!({
                "name": t.launch_template_name(),
                "version": t.version(),
            })
        });

    let details = json!({
        "status": g.status(),
        "min_size": g.min_size(),
        "max_size": g.max_size(),
        "desired_capacity": g.desired_capacity(),
        "instances": instances,
        "availability_zones": g.availability_zones(),
        "launch_template": launch_template,
        "mixed_instances": g.mixed_instances_policy().is_some(),
        "health_check_type": g.health_check_type(),
        "health_check_grace_period_s": g.health_check_grace_period(),
        "default_cooldown_s": g.default_cooldown(),
        "target_groups": g.target_group_arns(),
        "suspended_processes": suspended,
        "termination_policies": g.termination_policies(),
        "capacity_rebalance": g.capacity_rebalance(),
        "group_metrics_enabled": !g.enabled_metrics().is_empty(),
        "created": g.created_time().map(iso),
    });

    let mut notes = vec![
        "Auto Scaling groups have no logs; scaling activities are listed under events".to_owned(),
    ];
    if g.enabled_metrics().is_empty() {
        notes.push(
            "group metrics collection is disabled, so AWS/AutoScaling size metrics are absent"
                .to_owned(),
        );
    }

    Spec {
        service: SERVICE,
        kind: "group",
        id: name.to_owned(),
        details,
        metric_sources: NAMESPACES
            .into_iter()
            .map(|namespace| MetricSource::by(namespace, DIMENSION, name))
            .collect(),
        log_sources: Vec::new(),
        notes,
    }
}

/// Scaling activities that started inside the window, oldest first.
async fn activities(ctx: &Ctx, client: &Client) -> Result<Vec<Event>> {
    let (start, end) = (ctx.window.aws_start(), ctx.window.aws_end());
    let mut pages = client.describe_scaling_activities().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing scaling activities")?;
        for a in page.activities() {
            let Some(started) = a.start_time() else {
                continue;
            };
            if *started < start || *started > end {
                continue;
            }
            let group = a.auto_scaling_group_name().unwrap_or_default();
            if !ctx.wanted(group) {
                continue;
            }
            let message = [a.description(), a.status_message(), a.cause()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" | ");
            out.push(Event {
                time: Some(iso(started)),
                source_type: Some("auto-scaling-group".to_owned()),
                source: Some(group.to_owned()),
                categories: a
                    .status_code()
                    .map(|s| s.as_str().to_owned())
                    .into_iter()
                    .collect(),
                message: Some(message),
            });
        }
        // Without a group filter the API interleaves groups, so there is no
        // ordering to stop early on; every page is read. Activities are kept
        // for six weeks.
    }
    out.sort_by(|a, b| a.time.cmp(&b.time));
    Ok(out)
}

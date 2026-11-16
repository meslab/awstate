//! Amazon `ElastiCache` collection (node-based clusters, replication
//! groups, and serverless caches).

use anyhow::{Context, Result};
use aws_sdk_elasticache::Client;
use aws_sdk_elasticache::types::{
    CacheCluster, DataStorage, DestinationType, EcpuPerSecond, LogDeliveryConfiguration,
    ReplicationGroup, ServerlessCache,
};
use serde_json::{Value, json};

use crate::collect::collect_all;
use crate::model::{Ctx, Event, LogSource, MetricSource, ServiceReport, Spec, iso};

const SERVICE: &str = "elasticache";
const NAMESPACE: &str = "AWS/ElastiCache";

/// Collects inventory, metrics, logs, and events for `ElastiCache`.
pub async fn collect(ctx: &Ctx, client: &Client) -> ServiceReport {
    let (resources, events) = tokio::join!(
        async { collect_all(ctx, inventory(ctx, client).await).await },
        async {
            if !ctx.events {
                return Vec::new();
            }
            events(ctx, client).await.unwrap_or_else(|err| {
                ctx.issues.record("elasticache events", &err);
                Vec::new()
            })
        }
    );
    ServiceReport { resources, events }
}

async fn inventory(ctx: &Ctx, client: &Client) -> Vec<Spec> {
    let mut specs = Vec::new();

    match list_replication_groups(client).await {
        Ok(groups) => specs.extend(groups.iter().map(replication_group_spec)),
        Err(err) => ctx
            .issues
            .record("elasticache replication groups inventory", &err),
    }
    match list_cache_clusters(client).await {
        Ok(clusters) => specs.extend(clusters.iter().map(cache_cluster_spec)),
        Err(err) => ctx
            .issues
            .record("elasticache cache clusters inventory", &err),
    }
    match list_serverless_caches(client).await {
        Ok(caches) => specs.extend(caches.iter().map(serverless_spec)),
        Err(err) => ctx
            .issues
            .record("elasticache serverless caches inventory", &err),
    }

    specs.retain(|s| !s.id.is_empty() && ctx.wanted(&s.id));
    specs
}

async fn list_cache_clusters(client: &Client) -> Result<Vec<CacheCluster>> {
    let mut pages = client
        .describe_cache_clusters()
        .show_cache_node_info(true)
        .into_paginator()
        .send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing cache clusters")?;
        out.extend(page.cache_clusters.unwrap_or_default());
    }
    Ok(out)
}

async fn list_replication_groups(client: &Client) -> Result<Vec<ReplicationGroup>> {
    let mut pages = client.describe_replication_groups().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing replication groups")?;
        out.extend(page.replication_groups.unwrap_or_default());
    }
    Ok(out)
}

async fn list_serverless_caches(client: &Client) -> Result<Vec<ServerlessCache>> {
    let mut pages = client.describe_serverless_caches().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing serverless caches")?;
        out.extend(page.serverless_caches.unwrap_or_default());
    }
    Ok(out)
}

/// Splits log delivery configs into `CloudWatch` log groups we can read and
/// notes about destinations we cannot (Kinesis Data Firehose).
fn log_destinations(configs: &[LogDeliveryConfiguration]) -> (Vec<String>, Vec<String>, Value) {
    let mut groups = Vec::new();
    let mut notes = Vec::new();
    let mut described = Vec::new();
    for config in configs {
        let log_type = config.log_type().map(|t| t.as_str().to_owned());
        let group = config
            .destination_details()
            .and_then(|d| d.cloud_watch_logs_details())
            .and_then(|d| d.log_group());
        described.push(json!({
            "log_type": log_type,
            "destination_type": config.destination_type().map(DestinationType::as_str),
            "log_group": group,
            "status": config.status().map(|s| s.as_str().to_owned()),
        }));
        match (config.destination_type(), group) {
            (Some(DestinationType::CloudWatchLogs), Some(group)) => {
                if !groups.iter().any(|g| g == group) {
                    groups.push(group.to_owned());
                }
            }
            (Some(other), _) => notes.push(format!(
                "{} logs are delivered to {}, which this tool cannot read",
                log_type.as_deref().unwrap_or("some"),
                other.as_str()
            )),
            (None, _) => {}
        }
    }
    (groups, notes, Value::Array(described))
}

fn cache_cluster_spec(c: &CacheCluster) -> Spec {
    let (mut log_groups, mut notes, log_delivery) =
        log_destinations(c.log_delivery_configurations());
    // Members share their replication group's log destinations; capture
    // those once, on the group.
    if c.replication_group_id().is_some() {
        log_groups.clear();
        notes.clear();
    }

    let cache_nodes: Vec<_> = c
        .cache_nodes()
        .iter()
        .map(|n| {
            json!({
                "id": n.cache_node_id(),
                "status": n.cache_node_status(),
                "availability_zone": n.customer_availability_zone(),
            })
        })
        .collect();

    let details = json!({
        "engine": c.engine(),
        "engine_version": c.engine_version(),
        "node_type": c.cache_node_type(),
        "status": c.cache_cluster_status(),
        "num_nodes": c.num_cache_nodes(),
        "nodes": cache_nodes,
        "replication_group": c.replication_group_id(),
        "availability_zone": c.preferred_availability_zone(),
        "parameter_group": c.cache_parameter_group().map(|g| json!({
            "name": g.cache_parameter_group_name(),
            "apply_status": g.parameter_apply_status(),
        })),
        "snapshot_retention_days": c.snapshot_retention_limit(),
        "maintenance_window": c.preferred_maintenance_window(),
        "auto_minor_version_upgrade": c.auto_minor_version_upgrade(),
        "transit_encryption": c.transit_encryption_enabled(),
        "at_rest_encryption": c.at_rest_encryption_enabled(),
        "log_delivery": log_delivery,
        "created": c.cache_cluster_create_time().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "cache-cluster",
        id: c.cache_cluster_id().unwrap_or_default().to_owned(),
        details,
        metric_sources: vec![MetricSource::by(
            NAMESPACE,
            "CacheClusterId",
            c.cache_cluster_id().unwrap_or_default(),
        )],
        log_sources: log_groups.into_iter().map(LogSource::from).collect(),
        notes,
    }
}

fn replication_group_spec(g: &ReplicationGroup) -> Spec {
    let (log_groups, mut notes, log_delivery) = log_destinations(g.log_delivery_configurations());
    notes.push("metrics are reported per member cache cluster".to_owned());

    let node_groups: Vec<_> = g
        .node_groups()
        .iter()
        .map(|n| {
            let members: Vec<_> = n
                .node_group_members()
                .iter()
                .map(|m| {
                    json!({
                        "cache_cluster": m.cache_cluster_id(),
                        "role": m.current_role(),
                        "availability_zone": m.preferred_availability_zone(),
                    })
                })
                .collect();
            json!({
                "id": n.node_group_id(),
                "status": n.status(),
                "slots": n.slots(),
                "members": members,
            })
        })
        .collect();

    let details = json!({
        "description": g.description(),
        "engine": g.engine(),
        "status": g.status(),
        "node_type": g.cache_node_type(),
        "cluster_mode_enabled": g.cluster_enabled(),
        "multi_az": g.multi_az().map(|m| m.as_str().to_owned()),
        "automatic_failover": g.automatic_failover().map(|a| a.as_str().to_owned()),
        "member_clusters": g.member_clusters(),
        "node_groups": node_groups,
        "snapshot_retention_days": g.snapshot_retention_limit(),
        "transit_encryption": g.transit_encryption_enabled(),
        "at_rest_encryption": g.at_rest_encryption_enabled(),
        "log_delivery": log_delivery,
        "created": g.replication_group_create_time().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "replication-group",
        id: g.replication_group_id().unwrap_or_default().to_owned(),
        details,
        metric_sources: Vec::new(),
        log_sources: log_groups.into_iter().map(LogSource::from).collect(),
        notes,
    }
}

fn serverless_spec(c: &ServerlessCache) -> Spec {
    let details = json!({
        "engine": c.engine(),
        "engine_version": c.full_engine_version(),
        "status": c.status(),
        "description": c.description(),
        "usage_limits": c.cache_usage_limits().map(|l| json!({
            "data_storage_max": l.data_storage().and_then(DataStorage::maximum),
            "data_storage_min": l.data_storage().and_then(DataStorage::minimum),
            "data_storage_unit": l.data_storage().and_then(|d| d.unit()).map(|u| u.as_str().to_owned()),
            "ecpu_per_second_max": l.ecpu_per_second().and_then(EcpuPerSecond::maximum),
            "ecpu_per_second_min": l.ecpu_per_second().and_then(EcpuPerSecond::minimum),
        })),
        "snapshot_retention_days": c.snapshot_retention_limit(),
        "created": c.create_time().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "serverless-cache",
        id: c.serverless_cache_name().unwrap_or_default().to_owned(),
        details,
        // Serverless caches publish under a lowercase `clusterId` dimension.
        metric_sources: vec![MetricSource::by(
            NAMESPACE,
            "clusterId",
            c.serverless_cache_name().unwrap_or_default(),
        )],
        log_sources: Vec::new(),
        notes: Vec::new(),
    }
}

async fn events(ctx: &Ctx, client: &Client) -> Result<Vec<Event>> {
    let mut pages = client
        .describe_events()
        .start_time(ctx.window.aws_start())
        .end_time(ctx.window.aws_end())
        .into_paginator()
        .send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing ElastiCache events")?;
        for e in page.events() {
            if !e.source_identifier().is_none_or(|id| ctx.wanted(id)) {
                continue;
            }
            out.push(Event {
                time: e.date().map(iso),
                source_type: e.source_type().map(|t| t.as_str().to_owned()),
                source: e.source_identifier().map(str::to_owned),
                categories: Vec::new(),
                message: e.message().map(str::to_owned),
            });
        }
    }
    out.sort_by(|a, b| a.time.cmp(&b.time));
    Ok(out)
}

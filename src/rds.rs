//! Amazon RDS / Aurora collection.

use std::collections::HashSet;

use anyhow::{Context, Result};
use aws_sdk_rds::Client;
use aws_sdk_rds::types::{DbCluster, DbInstance};
use futures::{StreamExt, stream};
use serde_json::json;

use crate::collect::{collect_one, write_file};
use crate::model::{
    Ctx, Event, LogCapture, LogSource, MetricSource, Resource, ServiceReport, Spec, iso,
    iso_millis, sanitize,
};

const SERVICE: &str = "rds";
const NAMESPACE: &str = "AWS/RDS";

/// `DescribeDBInstances` also returns these engines, whose metrics live in
/// other namespaces and are out of scope here.
const FOREIGN_ENGINES: [&str; 2] = ["docdb", "neptune"];

/// Collects inventory, metrics, logs, and events for RDS.
pub async fn collect(ctx: &Ctx, client: &Client) -> ServiceReport {
    let (resources, events) = tokio::join!(collect_resources(ctx, client), async {
        if !ctx.events {
            return Vec::new();
        }
        events(ctx, client).await.unwrap_or_else(|err| {
            ctx.issues.record("rds events", &err);
            Vec::new()
        })
    });
    ServiceReport { resources, events }
}

async fn collect_resources(ctx: &Ctx, client: &Client) -> Vec<Resource> {
    let clusters = list_clusters(client).await.unwrap_or_else(|err| {
        ctx.issues.record("rds clusters inventory", &err);
        Vec::new()
    });
    let instances = list_instances(client).await.unwrap_or_else(|err| {
        ctx.issues.record("rds instances inventory", &err);
        Vec::new()
    });

    // Aurora publishes logs per cluster; member instances of these clusters
    // need no separate log capture.
    let clusters_exporting_logs: HashSet<&str> = clusters
        .iter()
        .filter(|c| !c.enabled_cloudwatch_logs_exports().is_empty())
        .filter_map(DbCluster::db_cluster_identifier)
        .collect();

    // Each job is a spec plus whether to fall back to RDS log-file downloads.
    let mut jobs: Vec<(Spec, bool)> = Vec::new();
    for cluster in clusters
        .iter()
        .filter(|c| in_scope(ctx, c.engine(), c.db_cluster_identifier()))
    {
        jobs.push((cluster_spec(cluster), false));
    }
    for instance in instances
        .iter()
        .filter(|i| in_scope(ctx, i.engine(), i.db_instance_identifier()))
    {
        let cluster_exports = instance
            .db_cluster_identifier()
            .is_some_and(|c| clusters_exporting_logs.contains(c));
        let spec = instance_spec(instance);
        let download = spec.log_sources.is_empty() && !cluster_exports;
        jobs.push((spec, download));
    }

    let mut resources: Vec<Resource> = stream::iter(jobs)
        .map(|(spec, download)| async move {
            let rel_dir = spec.rel_dir();
            let mut resource = collect_one(ctx, spec).await;
            if download && ctx.logs_enabled && ctx.max_log_file_bytes > 0 {
                match download_log_files(ctx, client, &resource.id, &rel_dir).await {
                    Ok(captures) => resource.logs.extend(captures),
                    Err(err) => ctx
                        .issues
                        .record(format!("rds/instance/{} log files", resource.id), &err),
                }
            }
            resource
        })
        .buffer_unordered(ctx.concurrency)
        .collect()
        .await;
    resources.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    resources
}

fn in_scope(ctx: &Ctx, engine: Option<&str>, id: Option<&str>) -> bool {
    !engine.is_some_and(|e| FOREIGN_ENGINES.contains(&e)) && id.is_some_and(|id| ctx.wanted(id))
}

async fn list_instances(client: &Client) -> Result<Vec<DbInstance>> {
    let mut pages = client.describe_db_instances().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing DB instances")?;
        out.extend(page.db_instances.unwrap_or_default());
    }
    Ok(out)
}

async fn list_clusters(client: &Client) -> Result<Vec<DbCluster>> {
    let mut pages = client.describe_db_clusters().into_paginator().send();
    let mut out = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("describing DB clusters")?;
        out.extend(page.db_clusters.unwrap_or_default());
    }
    Ok(out)
}

fn instance_spec(i: &DbInstance) -> Spec {
    let id = i.db_instance_identifier().unwrap_or_default().to_owned();
    let exports = i.enabled_cloudwatch_logs_exports();
    let in_cluster = i.db_cluster_identifier().is_some();

    let log_sources = if in_cluster {
        Vec::new()
    } else {
        exports
            .iter()
            .map(|kind| LogSource::from(format!("/aws/rds/instance/{id}/{kind}")))
            .collect()
    };

    let parameter_groups: Vec<_> = i
        .db_parameter_groups()
        .iter()
        .map(|g| {
            json!({
                "name": g.db_parameter_group_name(),
                "apply_status": g.parameter_apply_status(),
            })
        })
        .collect();

    let details = json!({
        "engine": i.engine(),
        "engine_version": i.engine_version(),
        "class": i.db_instance_class(),
        "status": i.db_instance_status(),
        "multi_az": i.multi_az(),
        "availability_zone": i.availability_zone(),
        "cluster": i.db_cluster_identifier(),
        "allocated_storage_gb": i.allocated_storage(),
        "max_allocated_storage_gb": i.max_allocated_storage(),
        "storage_type": i.storage_type(),
        "iops": i.iops(),
        "storage_encrypted": i.storage_encrypted(),
        "replica_of": i.read_replica_source_db_instance_identifier(),
        "replicas": i.read_replica_db_instance_identifiers(),
        "performance_insights": i.performance_insights_enabled(),
        "enhanced_monitoring_interval_s": i.monitoring_interval(),
        "cloudwatch_log_exports": exports,
        "parameter_groups": parameter_groups,
        "has_pending_modifications": i.pending_modified_values().is_some_and(|p| {
            // The API returns an empty struct when nothing is pending.
            p != &aws_sdk_rds::types::PendingModifiedValues::builder().build()
        }),
        "backup_retention_days": i.backup_retention_period(),
        "maintenance_window": i.preferred_maintenance_window(),
        "backup_window": i.preferred_backup_window(),
        "auto_minor_version_upgrade": i.auto_minor_version_upgrade(),
        "created": i.instance_create_time().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "instance",
        id,
        details,
        metric_sources: vec![MetricSource::by(
            NAMESPACE,
            "DBInstanceIdentifier",
            i.db_instance_identifier().unwrap_or_default(),
        )],
        log_sources,
        notes: Vec::new(),
    }
}

fn cluster_spec(c: &DbCluster) -> Spec {
    let id = c.db_cluster_identifier().unwrap_or_default().to_owned();
    let exports = c.enabled_cloudwatch_logs_exports();

    let members: Vec<_> = c
        .db_cluster_members()
        .iter()
        .map(|m| {
            json!({
                "instance": m.db_instance_identifier(),
                "writer": m.is_cluster_writer(),
            })
        })
        .collect();

    let details = json!({
        "engine": c.engine(),
        "engine_version": c.engine_version(),
        "engine_mode": c.engine_mode(),
        "status": c.status(),
        "multi_az": c.multi_az(),
        "members": members,
        "serverless_v2_scaling": c.serverless_v2_scaling_configuration().map(|s| json!({
            "min_capacity": s.min_capacity(),
            "max_capacity": s.max_capacity(),
        })),
        "storage_type": c.storage_type(),
        "storage_encrypted": c.storage_encrypted(),
        "cloudwatch_log_exports": exports,
        "parameter_group": c.db_cluster_parameter_group(),
        "backup_retention_days": c.backup_retention_period(),
        "maintenance_window": c.preferred_maintenance_window(),
        "backup_window": c.preferred_backup_window(),
        "created": c.cluster_create_time().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "cluster",
        log_sources: exports
            .iter()
            .map(|kind| LogSource::from(format!("/aws/rds/cluster/{id}/{kind}")))
            .collect(),
        id,
        details,
        metric_sources: vec![MetricSource::by(
            NAMESPACE,
            "DBClusterIdentifier",
            c.db_cluster_identifier().unwrap_or_default(),
        )],
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
        let page = page.context("describing RDS events")?;
        for e in page.events() {
            if !e.source_identifier().is_none_or(|id| ctx.wanted(id)) {
                continue;
            }
            out.push(Event {
                time: e.date().map(iso),
                source_type: e.source_type().map(|t| t.as_str().to_owned()),
                source: e.source_identifier().map(str::to_owned),
                categories: e.event_categories().to_vec(),
                message: e.message().map(str::to_owned),
            });
        }
    }
    out.sort_by(|a, b| a.time.cmp(&b.time));
    Ok(out)
}

/// Downloads log files written during the window through the RDS API,
/// newest first, until the per-instance byte budget is spent.
///
/// Files are downloaded from their beginning, so they can contain lines
/// from before the window.
async fn download_log_files(
    ctx: &Ctx,
    client: &Client,
    instance: &str,
    rel_dir: &str,
) -> Result<Vec<LogCapture>> {
    let mut pages = client
        .describe_db_log_files()
        .db_instance_identifier(instance)
        .file_last_written(ctx.window.start.timestamp_millis())
        .into_paginator()
        .send();
    let mut files: Vec<(String, i64)> = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("listing log files of {instance}"))?;
        for f in page.describe_db_log_files() {
            if let Some(name) = f.log_file_name() {
                files.push((name.to_owned(), f.last_written().unwrap_or_default()));
            }
        }
    }
    files.sort_by_key(|(_, written)| std::cmp::Reverse(*written));

    let mut budget = ctx.max_log_file_bytes;
    let mut captures = Vec::new();
    for (name, written) in files {
        if budget == 0 {
            captures.push(LogCapture {
                source: format!("rds-log-file:{name} (skipped: byte budget spent)"),
                file: None,
                lines: 0,
                bytes: 0,
                truncated: true,
            });
            continue;
        }

        let (text, truncated) = download_log_file(client, instance, &name, budget)
            .await
            .with_context(|| format!("downloading log file {name} of {instance}"))?;
        budget = budget.saturating_sub(text.len());

        let file = if text.is_empty() {
            None
        } else {
            let rel = format!("{rel_dir}/logs/{}", sanitize(&name));
            write_file(ctx, &rel, text.as_bytes()).await?;
            Some(rel)
        };
        captures.push(LogCapture {
            source: format!("rds-log-file:{name} (last written {})", iso_millis(written)),
            file,
            lines: text.lines().count(),
            bytes: text.len(),
            truncated,
        });
    }
    Ok(captures)
}

/// Downloads one log file up to `budget` bytes; returns the text and whether
/// it was cut short.
async fn download_log_file(
    client: &Client,
    instance: &str,
    name: &str,
    budget: usize,
) -> Result<(String, bool)> {
    let mut text = String::new();
    let mut marker = "0".to_owned();
    loop {
        let portion = client
            .download_db_log_file_portion()
            .db_instance_identifier(instance)
            .log_file_name(name)
            .marker(&marker)
            .send()
            .await?;
        text.push_str(portion.log_file_data().unwrap_or_default());

        let pending = portion.additional_data_pending().unwrap_or(false);
        if text.len() >= budget {
            let mut cut = budget;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            let truncated = pending || cut < text.len();
            text.truncate(cut);
            return Ok((text, truncated));
        }
        match portion.marker() {
            Some(next) if pending && next != marker => next.clone_into(&mut marker),
            _ => return Ok((text, false)),
        }
    }
}

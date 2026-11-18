//! Amazon ECS collection: clusters, services, service events, stopped
//! tasks, and container logs sent to `CloudWatch` Logs.

use anyhow::{Context, Result};
use aws_sdk_ecs::Client;
use aws_sdk_ecs::types::{
    Cluster, ClusterField, DesiredStatus, LogDriver, Service, Task, TaskDefinition,
};
use futures::{StreamExt, stream};
use serde_json::{Value, json};

use crate::collect::collect_all;
use crate::ecr::{ImageChecker, ImageStatus};
use crate::model::{Ctx, Event, LogSource, MetricSource, ServiceReport, Spec, iso};

const SERVICE: &str = "ecs";
const NAMESPACES: [&str; 2] = ["AWS/ECS", "ECS/ContainerInsights"];

/// `DescribeClusters` and `DescribeTasks` accept 100 identifiers per call.
const DESCRIBE_BATCH: usize = 100;
/// `DescribeServices` accepts 10.
const DESCRIBE_SERVICES_BATCH: usize = 10;

/// Collects inventory, metrics, logs, and events for ECS.
pub async fn collect(ctx: &Ctx, client: &Client, images: Option<&ImageChecker>) -> ServiceReport {
    let clusters = list_clusters(client).await.unwrap_or_else(|err| {
        ctx.issues.record("ecs clusters inventory", &err);
        Vec::new()
    });

    let mut specs = Vec::new();
    let mut events = Vec::new();
    for cluster in &clusters {
        let Some(name) = cluster.cluster_name() else {
            continue;
        };
        if ctx.wanted(name) {
            specs.push(cluster_spec(cluster, name));
        }

        match list_services(client, name).await {
            Ok(services) => {
                let wanted: Vec<&Service> = services
                    .iter()
                    .filter(|s| {
                        s.service_name()
                            .is_some_and(|svc| ctx.wanted(&format!("{name}/{svc}")))
                    })
                    .collect();
                if ctx.events {
                    events.extend(wanted.iter().flat_map(|s| service_events(ctx, name, s)));
                }
                let service_specs: Vec<Spec> = stream::iter(wanted)
                    .map(|service| service_spec(ctx, client, images, name, service))
                    .buffer_unordered(ctx.concurrency)
                    .collect()
                    .await;
                specs.extend(service_specs);
            }
            Err(err) => ctx
                .issues
                .record(format!("ecs/cluster/{name} services inventory"), &err),
        }

        if ctx.events {
            match stopped_tasks(ctx, client, name).await {
                Ok(stopped) => events.extend(stopped),
                Err(err) => ctx
                    .issues
                    .record(format!("ecs/cluster/{name} stopped tasks"), &err),
            }
        }
    }

    events.sort_by(|a, b| a.time.cmp(&b.time));
    ServiceReport {
        resources: collect_all(ctx, specs).await,
        events,
    }
}

async fn list_clusters(client: &Client) -> Result<Vec<Cluster>> {
    let mut pages = client.list_clusters().into_paginator().send();
    let mut arns = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.context("listing ECS clusters")?;
        arns.extend(page.cluster_arns.unwrap_or_default());
    }

    let mut out = Vec::new();
    for batch in arns.chunks(DESCRIBE_BATCH) {
        let described = client
            .describe_clusters()
            .set_clusters(Some(batch.to_vec()))
            .include(ClusterField::Settings)
            .include(ClusterField::Statistics)
            .send()
            .await
            .context("describing ECS clusters")?;
        out.extend(described.clusters.unwrap_or_default());
    }
    Ok(out)
}

async fn list_services(client: &Client, cluster: &str) -> Result<Vec<Service>> {
    let mut pages = client
        .list_services()
        .cluster(cluster)
        .into_paginator()
        .send();
    let mut arns = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("listing services of {cluster}"))?;
        arns.extend(page.service_arns.unwrap_or_default());
    }

    let mut out = Vec::new();
    for batch in arns.chunks(DESCRIBE_SERVICES_BATCH) {
        let described = client
            .describe_services()
            .cluster(cluster)
            .set_services(Some(batch.to_vec()))
            .send()
            .await
            .with_context(|| format!("describing services of {cluster}"))?;
        out.extend(described.services.unwrap_or_default());
    }
    Ok(out)
}

fn metric_sources(dimensions: &[(&'static str, &str)]) -> Vec<MetricSource> {
    NAMESPACES
        .into_iter()
        .map(|namespace| {
            MetricSource::exact(
                namespace,
                dimensions
                    .iter()
                    .map(|(name, value)| (*name, (*value).to_owned()))
                    .collect(),
            )
        })
        .collect()
}

fn cluster_spec(c: &Cluster, name: &str) -> Spec {
    let settings: Vec<_> = c
        .settings()
        .iter()
        .map(|s| {
            json!({
                "name": s.name().map(|n| n.as_str().to_owned()),
                "value": s.value(),
            })
        })
        .collect();

    let details = json!({
        "status": c.status(),
        "active_services": c.active_services_count(),
        "running_tasks": c.running_tasks_count(),
        "pending_tasks": c.pending_tasks_count(),
        "container_instances": c.registered_container_instances_count(),
        "capacity_providers": c.capacity_providers(),
        "settings": settings,
    });

    Spec {
        service: SERVICE,
        kind: "cluster",
        id: name.to_owned(),
        details,
        metric_sources: metric_sources(&[("ClusterName", name)]),
        access_log_sources: Vec::new(),
        log_sources: Vec::new(),
        notes: Vec::new(),
    }
}

async fn service_spec(
    ctx: &Ctx,
    client: &Client,
    images: Option<&ImageChecker>,
    cluster: &str,
    s: &Service,
) -> Spec {
    let name = s.service_name().unwrap_or_default();
    let id = format!("{cluster}/{name}");
    let mut notes = Vec::new();

    let task_definition = match s.task_definition() {
        Some(arn) => match describe_task_definition(client, arn).await {
            Ok(definition) => definition,
            Err(err) => {
                ctx.issues
                    .record(format!("ecs/service/{id} task definition"), &err);
                None
            }
        },
        None => None,
    };
    let (mut containers, log_sources) = task_definition
        .as_ref()
        .map_or_default(|d| containers(d, &mut notes));
    check_images(ctx, images, &mut containers, &mut notes).await;

    let deployments: Vec<_> = s
        .deployments()
        .iter()
        .map(|d| {
            json!({
                "status": d.status(),
                "rollout_state": d.rollout_state().map(|r| r.as_str().to_owned()),
                "rollout_reason": d.rollout_state_reason(),
                "task_definition": d.task_definition().map(short_arn),
                "desired": d.desired_count(),
                "running": d.running_count(),
                "pending": d.pending_count(),
                "failed_tasks": d.failed_tasks(),
                "created": d.created_at().map(iso),
                "updated": d.updated_at().map(iso),
            })
        })
        .collect();

    let capacity_providers: Vec<_> = s
        .capacity_provider_strategy()
        .iter()
        .map(|c| {
            json!({
                "provider": c.capacity_provider(),
                "weight": c.weight(),
                "base": c.base(),
            })
        })
        .collect();

    let load_balancers: Vec<_> = s
        .load_balancers()
        .iter()
        .map(|l| {
            json!({
                "target_group": l.target_group_arn().map(short_arn),
                "container": l.container_name(),
                "port": l.container_port(),
            })
        })
        .collect();

    let deployment_config = s.deployment_configuration().map(|c| {
        json!({
            "maximum_percent": c.maximum_percent(),
            "minimum_healthy_percent": c.minimum_healthy_percent(),
            "circuit_breaker": c.deployment_circuit_breaker().map(|b| json!({
                "enabled": b.enable(),
                "rollback": b.rollback(),
            })),
        })
    });

    let details = json!({
        "status": s.status(),
        "desired": s.desired_count(),
        "running": s.running_count(),
        "pending": s.pending_count(),
        "launch_type": s.launch_type().map(|l| l.as_str().to_owned()),
        "capacity_providers": capacity_providers,
        "platform_version": s.platform_version(),
        "scheduling_strategy": s.scheduling_strategy().map(|x| x.as_str().to_owned()),
        "task_definition": s.task_definition().map(short_arn),
        "task_cpu": task_definition.as_ref().and_then(|d| d.cpu()),
        "task_memory": task_definition.as_ref().and_then(|d| d.memory()),
        "containers": containers,
        "deployments": deployments,
        "deployment_config": deployment_config,
        "load_balancers": load_balancers,
        "health_check_grace_period_s": s.health_check_grace_period_seconds(),
        "created": s.created_at().map(iso),
    });

    Spec {
        service: SERVICE,
        kind: "service",
        metric_sources: metric_sources(&[("ClusterName", cluster), ("ServiceName", name)]),
        id,
        details,
        access_log_sources: Vec::new(),
        log_sources,
        notes,
    }
}

/// Adds `image_status` to each container and a note for every image the
/// service could not pull when it next starts a task.
async fn check_images(
    ctx: &Ctx,
    images: Option<&ImageChecker>,
    containers: &mut [Value],
    notes: &mut Vec<String>,
) {
    let Some(images) = images else {
        return;
    };
    for container in containers {
        let Some(image) = container["image"].as_str().map(str::to_owned) else {
            continue;
        };
        let status = images.check(ctx, &image).await;
        if status == ImageStatus::Missing {
            notes.push(format!(
                "container {} image {image} no longer exists in ECR; new tasks cannot start",
                container["name"].as_str().unwrap_or_default()
            ));
        }
        container["image_status"] = json!(status);
    }
}

async fn describe_task_definition(client: &Client, arn: &str) -> Result<Option<TaskDefinition>> {
    let described = client
        .describe_task_definition()
        .task_definition(arn)
        .send()
        .await
        .with_context(|| format!("describing task definition {arn}"))?;
    Ok(described.task_definition)
}

/// Describes a task definition's containers and finds the `CloudWatch` log
/// streams they write to.
fn containers(
    definition: &TaskDefinition,
    notes: &mut Vec<String>,
) -> (Vec<Value>, Vec<LogSource>) {
    let mut described = Vec::new();
    let mut sources: Vec<LogSource> = Vec::new();
    for c in definition.container_definitions() {
        let name = c.name().unwrap_or_default();
        let log_config = c.log_configuration();
        let driver = log_config.map(|l| l.log_driver().as_str().to_owned());
        described.push(json!({
            "name": name,
            "image": c.image(),
            "cpu": c.cpu(),
            "memory": c.memory(),
            "memory_reservation": c.memory_reservation(),
            "essential": c.essential(),
            "log_driver": driver,
        }));

        let Some(log_config) = log_config else {
            notes.push(format!("container {name} has no log configuration"));
            continue;
        };
        if *log_config.log_driver() != LogDriver::Awslogs {
            notes.push(format!(
                "container {name} logs through {}, which this tool cannot read",
                log_config.log_driver().as_str()
            ));
            continue;
        }
        let options = log_config.options();
        let Some(group) = options.and_then(|o| o.get("awslogs-group")) else {
            continue;
        };
        // awslogs streams are named `<prefix>/<container>/<task id>`.
        let source = LogSource {
            group: group.clone(),
            stream_prefix: options
                .and_then(|o| o.get("awslogs-stream-prefix"))
                .map(|prefix| format!("{prefix}/{name}/")),
            us_east_1: false,
        };
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    (described, sources)
}

/// Service events (deployments, task placement failures, health check
/// failures) inside the window. ECS keeps only the latest 100 per service.
fn service_events(ctx: &Ctx, cluster: &str, s: &Service) -> Vec<Event> {
    let (start, end) = (ctx.window.aws_start(), ctx.window.aws_end());
    let source = format!("{cluster}/{}", s.service_name().unwrap_or_default());
    s.events()
        .iter()
        .filter(|e| e.created_at().is_some_and(|t| *t >= start && *t <= end))
        .map(|e| Event {
            time: e.created_at().map(iso),
            source_type: Some("ecs-service".to_owned()),
            source: Some(source.clone()),
            categories: Vec::new(),
            message: e.message().map(str::to_owned),
        })
        .collect()
}

/// Tasks that stopped inside the window, with why. ECS only retains
/// stopped tasks for about an hour, so this covers the window's tail.
async fn stopped_tasks(ctx: &Ctx, client: &Client, cluster: &str) -> Result<Vec<Event>> {
    let mut pages = client
        .list_tasks()
        .cluster(cluster)
        .desired_status(DesiredStatus::Stopped)
        .into_paginator()
        .send();
    let mut arns = Vec::new();
    while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("listing stopped tasks of {cluster}"))?;
        arns.extend(page.task_arns.unwrap_or_default());
    }

    let (start, end) = (ctx.window.aws_start(), ctx.window.aws_end());
    let mut out = Vec::new();
    for batch in arns.chunks(DESCRIBE_BATCH) {
        let described = client
            .describe_tasks()
            .cluster(cluster)
            .set_tasks(Some(batch.to_vec()))
            .send()
            .await
            .with_context(|| format!("describing stopped tasks of {cluster}"))?;
        for task in described.tasks() {
            let Some(stopped) = task.stopped_at() else {
                continue;
            };
            // `group` is `service:<name>` for service tasks.
            let group = task.group().unwrap_or_default();
            let owner = group.strip_prefix("service:").unwrap_or(group);
            let source = format!("{cluster}/{owner}");
            if *stopped < start || *stopped > end || !ctx.wanted(&source) {
                continue;
            }
            out.push(Event {
                time: Some(iso(stopped)),
                source_type: Some("ecs-task-stopped".to_owned()),
                source: Some(source),
                categories: task
                    .stop_code()
                    .map(|c| c.as_str().to_owned())
                    .into_iter()
                    .collect(),
                message: Some(stop_message(task)),
            });
        }
    }
    Ok(out)
}

fn stop_message(task: &Task) -> String {
    let mut parts = vec![
        task.task_arn().map_or_default(short_arn).to_owned(),
        task.stopped_reason()
            .unwrap_or("no reason given")
            .to_owned(),
    ];
    for c in task.containers() {
        let name = c.name().unwrap_or_default();
        match (c.exit_code(), c.reason()) {
            (Some(code), Some(reason)) => parts.push(format!("{name}: exit {code} ({reason})")),
            (Some(code), None) if code != 0 => parts.push(format!("{name}: exit {code}")),
            (None, Some(reason)) => parts.push(format!("{name}: {reason}")),
            _ => {}
        }
    }
    parts.join(" | ")
}

/// The last path segment of an ARN (`family:revision`, a task id, ...).
fn short_arn(arn: &str) -> &str {
    arn.rsplit_once('/').map_or(arn, |(_, tail)| tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_arn_keeps_last_segment() {
        assert_eq!(
            short_arn("arn:aws:ecs:eu-central-1:123456789012:task-definition/web:42"),
            "web:42"
        );
        assert_eq!(short_arn("web:42"), "web:42");
    }

    #[test]
    fn metric_sources_are_exact_per_namespace() {
        let sources = metric_sources(&[("ClusterName", "c"), ("ServiceName", "s")]);
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|s| s.exact && s.dimensions.len() == 2));
    }
}

//! Rule-based checks over a finished collection, so that a daily or weekly
//! run says what needs attention instead of leaving it to be spotted in
//! hundreds of metric rows.
//!
//! Each check reads only what is already in the snapshot: resource details,
//! metric summaries, and events. Thresholds are deliberately conservative;
//! a finding should be worth a person's time.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::cli::Severity;
use crate::model::{Event, Issue, MetricSummary, Resource, ServiceReport};

/// Sustained CPU above this (p95 of per-period averages, percent) is flagged.
const CPU_P95_PERCENT: f64 = 80.0;
/// Free storage below these fractions of allocated storage is flagged.
const STORAGE_WARN_FRACTION: f64 = 0.10;
const STORAGE_CRITICAL_FRACTION: f64 = 0.05;
/// Swap used most of the time (p95, bytes) beyond this suggests the
/// instance class is short on memory.
const SWAP_P95_BYTES: f64 = 200e6;
/// Memory used by an `ElastiCache` node beyond this (max, percent).
const CACHE_MEMORY_PERCENT: f64 = 90.0;
/// RDS event categories that mean something went wrong.
const RDS_TROUBLE_CATEGORIES: [&str; 4] = ["failover", "failure", "low storage", "recovery"];

/// One thing in the snapshot that needs attention.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub service: String,
    /// The resource identifier, as in `manifest.json`.
    pub resource: String,
    /// Stable name of the check, for filtering and suppressing.
    pub check: &'static str,
    pub message: String,
}

/// Runs every check, returning findings most severe first.
pub fn evaluate(services: &[(&str, ServiceReport)], issues: &[Issue]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, report) in services {
        let mut push = |severity, resource: &str, check, message: String| {
            out.push(Finding {
                severity,
                service: (*name).to_owned(),
                resource: resource.to_owned(),
                check,
                message,
            });
        };
        for r in &report.resources {
            common(r, &mut push);
            match (*name, r.kind) {
                ("ecs", "service") => ecs_service(r, &report.events, &mut push),
                ("rds", _) => rds(r, &mut push),
                ("elasticache", _) => elasticache(r, &mut push),
                ("asg", _) => asg(r, &report.events, &mut push),
                _ => {}
            }
        }
        match *name {
            "ecs" => ecs_stopped_tasks(&report.events, &mut push),
            "rds" => rds_events(&report.events, &mut push),
            _ => {}
        }
    }
    if !issues.is_empty() {
        out.push(Finding {
            severity: Severity::Info,
            service: String::new(),
            resource: String::new(),
            check: "collection-incomplete",
            message: format!(
                "{} part(s) could not be collected; checks on them may be missing",
                issues.len()
            ),
        });
    }
    out.sort_by(|a, b| {
        (b.severity, &a.service, &a.resource, a.check).cmp(&(
            a.severity,
            &b.service,
            &b.resource,
            b.check,
        ))
    });
    out
}

/// Receives one finding: severity, resource id, check name, message.
type Push<'a> = dyn FnMut(Severity, &str, &'static str, String) + 'a;

/// Checks that apply to any resource.
fn common(r: &Resource, push: &mut Push) {
    if let Some(cpu) = metric(r, "CPUUtilization").or_else(|| metric(r, "EngineCPUUtilization"))
        && cpu.p95 >= CPU_P95_PERCENT
    {
        push(
            Severity::Warning,
            &r.id,
            "cpu-high",
            format!(
                "CPU p95 {:.0}% (avg {:.0}%, max {:.0}% at {})",
                cpu.p95, cpu.avg, cpu.max, cpu.max_at
            ),
        );
    }
}

fn ecs_service(r: &Resource, events: &[Event], push: &mut Push) {
    let d = &r.details;
    for c in array(&d["containers"]) {
        let name = c["name"].as_str().unwrap_or_default();
        let image = c["image"].as_str().unwrap_or_default();
        if c["image_status"] == "missing" {
            push(
                Severity::Critical,
                &r.id,
                "image-missing",
                format!(
                    "container {name} image {image} no longer exists in ECR; \
                     the service cannot start new tasks"
                ),
            );
        }
        if mutable_tag(image) {
            push(
                Severity::Info,
                &r.id,
                "mutable-image-tag",
                format!("container {name} runs {image}; a redeploy may change what runs"),
            );
        }
    }

    if let (Some(desired), Some(running)) = (d["desired"].as_i64(), d["running"].as_i64())
        && running < desired
    {
        let severity = if running == 0 {
            Severity::Critical
        } else {
            Severity::Warning
        };
        push(
            severity,
            &r.id,
            "tasks-below-desired",
            format!("{running} of {desired} desired tasks running at collection time"),
        );
    }

    let failures: Vec<&Event> = events
        .iter()
        .filter(|e| e.source.as_deref() == Some(&r.id))
        .filter(|e| {
            e.message.as_deref().is_some_and(|m| {
                m.contains("unable to consistently start tasks")
                    || m.contains("was unable to place a task")
            })
        })
        .collect();
    if let (Some(first), Some(last)) = (failures.first(), failures.last()) {
        let (severity, recovery) = recovery(events, &r.id, last);
        push(
            severity,
            &r.id,
            "task-start-failures",
            format!(
                "{recovery}{} task start or placement failures between {} and {}; latest: {}",
                failures.len(),
                first.time.as_deref().unwrap_or("?"),
                last.time.as_deref().unwrap_or("?"),
                last.message.as_deref().unwrap_or_default()
            ),
        );
    }

    for dep in array(&d["deployments"]) {
        let failed = dep["failed_tasks"].as_i64().unwrap_or(0);
        let task_definition = dep["task_definition"].as_str().unwrap_or("?");
        if dep["rollout_state"] == "FAILED" {
            push(
                Severity::Critical,
                &r.id,
                "deployment-failed",
                format!(
                    "deployment of {task_definition} failed: {}",
                    dep["rollout_reason"].as_str().unwrap_or("no reason given")
                ),
            );
        } else if failed > 0 {
            push(
                Severity::Warning,
                &r.id,
                "deployment-failed-tasks",
                format!("deployment of {task_definition} has {failed} failed task(s)"),
            );
        }
    }

    if d["deployment_config"]["circuit_breaker"]["enabled"] == false {
        push(
            Severity::Info,
            &r.id,
            "circuit-breaker-disabled",
            "deployment circuit breaker is off; a broken deployment retries forever \
             instead of rolling back"
                .to_owned(),
        );
    }
}

/// Stopped tasks that did not stop on purpose, per service. ECS keeps
/// stopped tasks for about an hour, so these describe the window's tail.
fn ecs_stopped_tasks(events: &[Event], push: &mut Push) {
    let mut by_source: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for e in events {
        let unplanned = e
            .categories
            .iter()
            .any(|c| c != "ServiceSchedulerInitiated" && c != "UserInitiated");
        if e.source_type.as_deref() == Some("ecs-task-stopped") && unplanned {
            by_source
                .entry(e.source.as_deref().unwrap_or_default())
                .or_default()
                .push(e);
        }
    }
    for (source, stopped) in by_source {
        let Some(latest) = stopped.last() else {
            continue;
        };
        let (severity, recovery) = recovery(events, source, latest);
        push(
            severity,
            source,
            "tasks-stopped",
            format!(
                "{recovery}{} task(s) stopped recently ({}); latest: {}",
                stopped.len(),
                latest.categories.join(", "),
                latest.message.as_deref().unwrap_or_default()
            ),
        );
    }
}

/// Severity and message prefix for a service problem whose latest
/// occurrence is `last`: a warning, unless the service reached a steady state
/// afterwards, in which case it is history worth knowing but not acting on.
fn recovery(events: &[Event], service: &str, last: &Event) -> (Severity, String) {
    // Event times share one RFC 3339 UTC format, so they order as strings.
    let steady = events
        .iter()
        .filter(|e| e.source.as_deref() == Some(service))
        .filter(|e| {
            e.message
                .as_deref()
                .is_some_and(|m| m.contains("has reached a steady state"))
        })
        .filter_map(|e| e.time.as_deref())
        .filter(|t| last.time.as_deref().is_some_and(|l| *t > l))
        .max();
    match steady {
        Some(t) => (
            Severity::Info,
            format!("recovered (steady state at {t}) after "),
        ),
        None => (Severity::Warning, String::new()),
    }
}

fn rds(r: &Resource, push: &mut Push) {
    let d = &r.details;
    if let Some(status) = d["status"].as_str()
        && status != "available"
    {
        push(
            Severity::Warning,
            &r.id,
            "status",
            format!("status is {status}"),
        );
    }
    if d["backup_retention_days"].as_i64() == Some(0) {
        push(
            Severity::Warning,
            &r.id,
            "backups-disabled",
            "automated backups are off (retention 0 days); there is no point-in-time recovery"
                .to_owned(),
        );
    }
    if let Some(since) = metric(r, "DatabaseConnections").and_then(|m| m.zero_since.as_deref()) {
        push(
            Severity::Warning,
            &r.id,
            "connections-dropped",
            format!("no client connections since {since}, though there were earlier"),
        );
    }
    if let (Some(gib), Some(free)) = (
        d["allocated_storage_gb"].as_f64(),
        metric(r, "FreeStorageSpace"),
    ) && gib > 0.0
    {
        let fraction = free.min / (gib * 1024.0 * 1024.0 * 1024.0);
        if fraction < STORAGE_WARN_FRACTION {
            let severity = if fraction < STORAGE_CRITICAL_FRACTION {
                Severity::Critical
            } else {
                Severity::Warning
            };
            push(
                severity,
                &r.id,
                "storage-low",
                format!(
                    "free storage fell to {:.1}% of {gib} GiB (now {:.1} GB free)",
                    fraction * 100.0,
                    free.last / 1e9
                ),
            );
        }
    }
    if let Some(credits) = metric(r, "CPUCreditBalance")
        && credits.min <= 0.0
    {
        push(
            Severity::Warning,
            &r.id,
            "cpu-credits-exhausted",
            format!(
                "CPU credit balance reached 0; the instance was throttled to baseline \
                 (latest balance {:.0})",
                credits.last
            ),
        );
    }
    if let Some(swap) = metric(r, "SwapUsage")
        && swap.p95 >= SWAP_P95_BYTES
    {
        push(
            Severity::Info,
            &r.id,
            "swap-sustained",
            format!(
                "swap usage p95 {:.0} MB; the instance class may be short on memory",
                swap.p95 / 1e6
            ),
        );
    }
}

fn rds_events(events: &[Event], push: &mut Push) {
    for e in events {
        if let Some(category) = e
            .categories
            .iter()
            .find(|c| RDS_TROUBLE_CATEGORIES.contains(&c.as_str()))
        {
            push(
                Severity::Warning,
                e.source.as_deref().unwrap_or_default(),
                "rds-event",
                format!(
                    "{category} at {}: {}",
                    e.time.as_deref().unwrap_or("?"),
                    e.message.as_deref().unwrap_or_default()
                ),
            );
        }
    }
}

fn elasticache(r: &Resource, push: &mut Push) {
    if let Some(status) = r.details["status"].as_str()
        && status != "available"
    {
        push(
            Severity::Warning,
            &r.id,
            "status",
            format!("status is {status}"),
        );
    }
    if let Some(memory) = metric(r, "DatabaseMemoryUsagePercentage")
        && memory.max >= CACHE_MEMORY_PERCENT
    {
        push(
            Severity::Warning,
            &r.id,
            "memory-high",
            format!(
                "memory usage reached {:.0}% at {}",
                memory.max, memory.max_at
            ),
        );
    }
    if let Some(evictions) = metric(r, "Evictions")
        && evictions.max > 0.0
    {
        push(
            Severity::Info,
            &r.id,
            "evictions",
            format!(
                "keys were evicted (up to {:.0} per period, peak at {})",
                evictions.max, evictions.max_at
            ),
        );
    }
}

fn asg(r: &Resource, events: &[Event], push: &mut Push) {
    let d = &r.details;
    let instances = array(&d["instances"]);
    let unhealthy: Vec<&str> = instances
        .iter()
        .filter(|i| i["health"].as_str().is_some_and(|h| h != "Healthy"))
        .filter_map(|i| i["id"].as_str())
        .collect();
    if !unhealthy.is_empty() {
        push(
            Severity::Warning,
            &r.id,
            "instances-unhealthy",
            format!("unhealthy instances: {}", unhealthy.join(", ")),
        );
    }
    let in_service = instances
        .iter()
        .filter(|i| i["lifecycle_state"] == "InService")
        .count();
    if let Some(desired) = d["desired_capacity"].as_u64()
        && (in_service as u64) < desired
    {
        push(
            Severity::Warning,
            &r.id,
            "capacity-below-desired",
            format!("{in_service} of {desired} desired instances in service at collection time"),
        );
    }
    if let Some(checks) = metric(r, "StatusCheckFailed")
        && checks.max > 0.0
    {
        push(
            Severity::Warning,
            &r.id,
            "status-check-failed",
            format!(
                "an instance failed EC2 status checks (at {})",
                checks.max_at
            ),
        );
    }

    let own: Vec<&Event> = events
        .iter()
        .filter(|e| e.source.as_deref() == Some(&r.id))
        .collect();
    let failed: Vec<&&Event> = own
        .iter()
        .filter(|e| {
            e.categories
                .iter()
                .any(|c| c == "Failed" || c == "Cancelled")
        })
        .collect();
    if let Some(latest) = failed.last() {
        push(
            Severity::Warning,
            &r.id,
            "scaling-failed",
            format!(
                "{} scaling activities failed; latest at {}: {}",
                failed.len(),
                latest.time.as_deref().unwrap_or("?"),
                latest.message.as_deref().unwrap_or_default()
            ),
        );
    }
    let interruptions = own
        .iter()
        .filter(|e| {
            e.message
                .as_deref()
                .is_some_and(|m| m.contains("Spot Instance interruption"))
        })
        .count();
    if interruptions > 0 {
        push(
            Severity::Info,
            &r.id,
            "spot-interruptions",
            format!("{interruptions} instance(s) replaced after Spot interruption notices"),
        );
    }
}

/// The resource's own metric by name: the one with the fewest extra
/// dimensions, so `DBLoad` beats `DBLoad` split by insights mode.
fn metric<'a>(r: &'a Resource, name: &str) -> Option<&'a MetricSummary> {
    r.metrics
        .iter()
        .filter(|m| m.name == name)
        .min_by_key(|m| m.dimensions.len())
        .map(|m| &m.summary)
}

fn array(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// Tags that a registry push can move: `latest`, or no tag at all. Digests
/// and other tags are taken as pinned.
fn mutable_tag(image: &str) -> bool {
    if image.contains('@') {
        return false;
    }
    let tail = image.rsplit('/').next().unwrap_or(image);
    tail.rsplit_once(':').is_none_or(|(_, tag)| tag == "latest")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::MetricHead;

    fn summary(avg: f64, min: f64, max: f64, p95: f64) -> MetricSummary {
        MetricSummary {
            datapoints: 10,
            avg,
            min,
            max,
            max_at: "t".to_owned(),
            p95,
            first: avg,
            last: avg,
            zero_since: None,
        }
    }

    fn resource(service: &'static str, kind: &'static str, id: &str, details: Value) -> Resource {
        Resource {
            service,
            kind,
            id: id.to_owned(),
            details,
            metrics_file: None,
            metrics: Vec::new(),
            logs: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn with_metric(mut r: Resource, name: &str, s: MetricSummary) -> Resource {
        r.metrics.push(MetricHead {
            namespace: "AWS/X".to_owned(),
            name: name.to_owned(),
            dimensions: BTreeMap::new(),
            summary: s,
        });
        r
    }

    fn event(source: &str, categories: &[&str], message: &str) -> Event {
        Event {
            time: Some("t".to_owned()),
            source_type: None,
            source: Some(source.to_owned()),
            categories: categories.iter().map(|c| (*c).to_owned()).collect(),
            message: Some(message.to_owned()),
        }
    }

    fn checks(
        service: &'static str,
        resources: Vec<Resource>,
        events: Vec<Event>,
    ) -> Vec<&'static str> {
        let report = ServiceReport { resources, events };
        evaluate(&[(service, report)], &[])
            .into_iter()
            .map(|f| f.check)
            .collect()
    }

    #[test]
    fn broken_ecs_service_is_critical_and_sorted_first() {
        let r = resource(
            "ecs",
            "service",
            "c/app",
            json!({
                "desired": 1,
                "running": 0,
                "containers": [{"name": "app", "image": "x/app@sha256:1", "image_status": "missing"}],
                "deployments": [],
                "deployment_config": {"circuit_breaker": {"enabled": false}},
            }),
        );
        let events = vec![
            event("c/app", &[], "(service app) was unable to place a task."),
            event(
                "c/other",
                &[],
                "(service other) was unable to place a task.",
            ),
        ];
        let report = ServiceReport {
            resources: vec![r],
            events,
        };
        let findings = evaluate(&[("ecs", report)], &[]);
        let got: Vec<_> = findings.iter().map(|f| (f.severity, f.check)).collect();
        assert_eq!(
            got,
            [
                (Severity::Critical, "image-missing"),
                (Severity::Critical, "tasks-below-desired"),
                (Severity::Warning, "task-start-failures"),
                (Severity::Info, "circuit-breaker-disabled"),
            ]
        );
        assert!(findings[2].message.starts_with("1 task start"));
    }

    #[test]
    fn ecs_failures_followed_by_steady_state_are_demoted_to_info() {
        let at = |time: &str, source_type: &str, categories: &[&str], message: &str| Event {
            time: Some(time.to_owned()),
            source_type: Some(source_type.to_owned()),
            source: Some("c/app".to_owned()),
            categories: categories.iter().map(|c| (*c).to_owned()).collect(),
            message: Some(message.to_owned()),
        };
        let evaluate_with_steady_at = |steady: &str| {
            let r = resource(
                "ecs",
                "service",
                "c/app",
                json!({"desired": 1, "running": 1, "containers": [], "deployments": []}),
            );
            let events = vec![
                at(
                    steady,
                    "ecs-service",
                    &[],
                    "(service app) has reached a steady state.",
                ),
                at(
                    "2026-11-17T19:00:00Z",
                    "ecs-service",
                    &[],
                    "(service app) was unable to place a task.",
                ),
                at(
                    "2026-11-17T20:30:00Z",
                    "ecs-task-stopped",
                    &["TaskFailedToStart"],
                    "x | Task failed to start",
                ),
            ];
            let report = ServiceReport {
                resources: vec![r],
                events,
            };
            evaluate(&[("ecs", report)], &[])
                .into_iter()
                .map(|f| (f.check, f.severity, f.message.starts_with("recovered")))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            evaluate_with_steady_at("2026-11-17T20:39:04Z"),
            [
                ("task-start-failures", Severity::Info, true),
                ("tasks-stopped", Severity::Info, true),
            ]
        );
        assert_eq!(
            evaluate_with_steady_at("2026-11-17T18:00:00Z"),
            [
                ("task-start-failures", Severity::Warning, false),
                ("tasks-stopped", Severity::Warning, false),
            ]
        );
    }

    #[test]
    fn rds_checks_storage_backups_and_dropped_connections() {
        let mut connections = summary(5.0, 0.0, 30.0, 25.0);
        connections.zero_since = Some("2026-11-14T14:00:00Z".to_owned());
        let r = resource(
            "rds",
            "instance",
            "db",
            json!({"status": "available", "backup_retention_days": 0, "allocated_storage_gb": 20}),
        );
        let r = with_metric(r, "DatabaseConnections", connections);
        let r = with_metric(r, "FreeStorageSpace", summary(1.5e9, 0.9e9, 2e9, 1.9e9));
        assert_eq!(
            checks("rds", vec![r], Vec::new()),
            ["storage-low", "backups-disabled", "connections-dropped"]
        );
    }

    #[test]
    fn healthy_resources_produce_nothing() {
        let r = resource(
            "rds",
            "instance",
            "db",
            json!({"status": "available", "backup_retention_days": 7, "allocated_storage_gb": 20}),
        );
        let r = with_metric(r, "CPUUtilization", summary(10.0, 1.0, 95.0, 30.0));
        let r = with_metric(r, "FreeStorageSpace", summary(15e9, 14e9, 16e9, 15e9));
        assert_eq!(checks("rds", vec![r], Vec::new()), [] as [&str; 0]);
    }

    #[test]
    fn asg_counts_spot_interruptions_and_failed_activities() {
        let r = resource(
            "asg",
            "group",
            "g",
            json!({"desired_capacity": 1, "instances": [
                {"id": "i-1", "health": "Healthy", "lifecycle_state": "InService"}
            ]}),
        );
        let events = vec![
            event(
                "g",
                &["Successful"],
                "Terminating | in response to an EC2 Spot Instance interruption notice.",
            ),
            event(
                "g",
                &["Failed"],
                "Launching a new EC2 instance. Status Reason: capacity",
            ),
        ];
        assert_eq!(
            checks("asg", vec![r], events),
            ["scaling-failed", "spot-interruptions"]
        );
    }

    #[test]
    fn mutable_tags() {
        assert!(mutable_tag("public.ecr.aws/datadog/agent:latest"));
        assert!(mutable_tag("nginx"));
        assert!(mutable_tag("registry:5000/app"));
        assert!(!mutable_tag("registry:5000/app:1.2"));
        assert!(!mutable_tag("repo/app@sha256:ab"));
    }
}

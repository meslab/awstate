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
/// Share of requests answered with 5xx at or beyond which a load balancer
/// finding is a warning rather than info.
const HTTP_5XX_WARN_FRACTION: f64 = 0.01;
/// `CloudFront` 5xx error rate (p95 of per-period averages, percent) that
/// is flagged as sustained, and the peak that is flagged as a spike.
const CDN_5XX_P95_PERCENT: f64 = 1.0;
const CDN_5XX_PEAK_PERCENT: f64 = 5.0;
/// `CloudFront` 4xx error rate (p95, percent) worth knowing about.
const CDN_4XX_P95_PERCENT: f64 = 10.0;
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
                ("alb", _) => alb(r, &mut push),
                ("cloudfront", _) => cloudfront(r, &mut push),
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
        .filter(|e| !scale_in_completed_after_protection(&own, e))
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

/// ECS managed termination protection cancels a scale-in until the instance
/// is drained, then unprotects it and the scale-in goes through; only a
/// cancellation that no termination follows means capacity is stuck.
fn scale_in_completed_after_protection(group_events: &[&Event], cancelled: &Event) -> bool {
    let blocked_by_protection = cancelled.categories.iter().any(|c| c == "Cancelled")
        && cancelled
            .message
            .as_deref()
            .is_some_and(|m| m.contains("protected from scale-in"));
    let Some(cancelled_at) = cancelled.time.as_deref() else {
        return false;
    };
    blocked_by_protection
        && group_events.iter().any(|e| {
            e.categories.iter().any(|c| c == "Successful")
                && e.message
                    .as_deref()
                    .is_some_and(|m| m.starts_with("Terminating"))
                && e.time.as_deref().is_some_and(|t| t > cancelled_at)
        })
}

fn alb(r: &Resource, push: &mut Push) {
    let d = &r.details;
    if let Some(state) = d["state"].as_str()
        && state != "active"
    {
        let reason = d["state_reason"].as_str().unwrap_or_default();
        push(
            Severity::Warning,
            &r.id,
            "status",
            format!("state is {state} {reason}").trim_end().to_owned(),
        );
    }
    alb_target_groups(r, push);
    alb_errors(r, push);
}

fn alb_target_groups(r: &Resource, push: &mut Push) {
    let d = &r.details;
    let forwarded_to: Vec<&str> = array(&d["listeners"])
        .iter()
        .flat_map(|l| array(&l["default_actions"]))
        .filter_map(|a| a["target_group"].as_str())
        .collect();
    for tg in array(&d["target_groups"]) {
        let name = tg["name"].as_str().unwrap_or("?");
        let targets = array(&tg["targets"]);
        let healthy = tg["healthy"].as_u64().unwrap_or(0);
        let unhealthy: Vec<&Value> = targets
            .iter()
            .filter(|t| t["state"] == "unhealthy")
            .collect();
        if let Some(first) = unhealthy.first() {
            let severity = if healthy == 0 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            push(
                severity,
                &r.id,
                "targets-unhealthy",
                format!(
                    "target group {name}: {} unhealthy, {healthy} healthy at collection time;                      e.g. {} {}",
                    unhealthy.len(),
                    first["id"].as_str().unwrap_or("?"),
                    first["description"].as_str().unwrap_or_default()
                ),
            );
        } else if targets.is_empty() && forwarded_to.contains(&name) {
            push(
                Severity::Warning,
                &r.id,
                "target-group-empty",
                format!("listener default target group {name} has no registered targets"),
            );
        }
    }
}

/// 5xx responses and connection failures, from the window's metrics.
fn alb_errors(r: &Resource, push: &mut Push) {
    let requests = metric(r, "RequestCount").and_then(|m| m.total);
    for (name, check, what) in [
        ("HTTPCode_ELB_5XX_Count", "elb-5xx", "load balancer"),
        ("HTTPCode_Target_5XX_Count", "target-5xx", "target"),
    ] {
        let Some(errors) = metric(r, name) else {
            continue;
        };
        let total = errors.total.unwrap_or(0.0);
        if total <= 0.0 {
            continue;
        }
        let share = requests.filter(|r| *r > 0.0).map(|r| total / r);
        let severity = if share.is_none_or(|s| s >= HTTP_5XX_WARN_FRACTION) {
            Severity::Warning
        } else {
            Severity::Info
        };
        let of_requests = share.map_or_else(String::new, |s| {
            format!(
                " ({:.2}% of {:.0} requests)",
                s * 100.0,
                requests.unwrap_or(0.0)
            )
        });
        push(
            severity,
            &r.id,
            check,
            format!(
                "{total:.0} {what} 5xx responses{of_requests}; peak {:.0} per period at {}",
                errors.max, errors.max_at
            ),
        );
    }

    for (name, check, what) in [
        (
            "RejectedConnectionCount",
            "connections-rejected",
            "connections rejected because the load balancer reached its connection limit",
        ),
        (
            "TargetConnectionErrorCount",
            "target-connection-errors",
            "failed connections to targets",
        ),
    ] {
        if let Some(m) = metric(r, name)
            && m.total.is_some_and(|t| t > 0.0)
        {
            push(
                Severity::Warning,
                &r.id,
                check,
                format!(
                    "{:.0} {what}; peak {:.0} per period at {}",
                    m.total.unwrap_or(0.0),
                    m.max,
                    m.max_at
                ),
            );
        }
    }
}

fn cloudfront(r: &Resource, push: &mut Push) {
    let d = &r.details;
    if d["enabled"] == false {
        push(
            Severity::Info,
            &r.id,
            "disabled",
            "distribution is disabled".to_owned(),
        );
    }
    if let Some(status) = d["status"].as_str()
        && status != "Deployed"
    {
        push(
            Severity::Info,
            &r.id,
            "status",
            format!("status is {status}; a configuration change is still propagating"),
        );
    }
    if let Some(rate) = metric(r, "5xxErrorRate") {
        if rate.p95 >= CDN_5XX_P95_PERCENT {
            push(
                Severity::Warning,
                &r.id,
                "error-rate-5xx",
                format!(
                    "5xx error rate p95 {:.1}% (avg {:.2}%, max {:.1}% at {})",
                    rate.p95, rate.avg, rate.max, rate.max_at
                ),
            );
        } else if rate.max >= CDN_5XX_PEAK_PERCENT {
            push(
                Severity::Info,
                &r.id,
                "error-rate-5xx",
                format!(
                    "5xx error rate spiked to {:.1}% at {}",
                    rate.max, rate.max_at
                ),
            );
        }
    }
    if let Some(rate) = metric(r, "4xxErrorRate")
        && rate.p95 >= CDN_4XX_P95_PERCENT
    {
        push(
            Severity::Info,
            &r.id,
            "error-rate-4xx",
            format!(
                "4xx error rate p95 {:.1}% (max {:.1}% at {})",
                rate.p95, rate.max, rate.max_at
            ),
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
            total: None,
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
            statistic: None,
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
    fn asg_ignores_scale_in_protection_that_a_termination_resolves() {
        let at = |time: &str, categories: &[&str], message: &str| Event {
            time: Some(time.to_owned()),
            ..event("g", categories, message)
        };
        let blocked = "Could not scale to desired capacity because all remaining \
                       instances are protected from scale-in.";
        let evaluate_with_events = |events: Vec<Event>| {
            let r = resource(
                "asg",
                "group",
                "g",
                json!({"desired_capacity": 0, "instances": []}),
            );
            checks("asg", vec![r], events)
        };

        assert_eq!(
            evaluate_with_events(vec![
                at("2026-11-17T20:57:19Z", &["Cancelled"], blocked),
                at(
                    "2026-11-17T20:57:29Z",
                    &["Successful"],
                    "Terminating EC2 instance: i-1"
                ),
            ]),
            [] as [&str; 0]
        );
        assert_eq!(
            evaluate_with_events(vec![
                at(
                    "2026-11-17T20:51:34Z",
                    &["Successful"],
                    "Terminating EC2 instance: i-1"
                ),
                at("2026-11-17T20:57:19Z", &["Cancelled"], blocked),
            ]),
            ["scaling-failed"]
        );
    }

    #[test]
    fn alb_flags_unhealthy_targets_and_5xx_share() {
        let r = resource(
            "alb",
            "load-balancer",
            "web",
            json!({
                "state": "active",
                "listeners": [{"default_actions": [{"target_group": "empty"}]}],
                "target_groups": [
                    {"name": "api", "healthy": 0, "targets": [
                        {"id": "10.0.0.1", "state": "unhealthy", "description": "Health checks failed"}
                    ]},
                    {"name": "empty", "healthy": 0, "targets": []},
                    {"name": "unused", "healthy": 0, "targets": []},
                ],
            }),
        );
        let total = |t: f64| {
            let mut s = summary(1.0, 0.0, 5.0, 2.0);
            s.total = Some(t);
            s
        };
        let r = with_metric(r, "RequestCount", total(10_000.0));
        let r = with_metric(r, "HTTPCode_ELB_5XX_Count", total(5.0));
        let r = with_metric(r, "HTTPCode_Target_5XX_Count", total(500.0));
        let r = with_metric(r, "RejectedConnectionCount", total(0.0));
        let findings = evaluate(
            &[(
                "alb",
                ServiceReport {
                    resources: vec![r],
                    events: Vec::new(),
                },
            )],
            &[],
        );
        let got: Vec<_> = findings.iter().map(|f| (f.severity, f.check)).collect();
        assert_eq!(
            got,
            [
                (Severity::Critical, "targets-unhealthy"),
                (Severity::Warning, "target-5xx"),
                (Severity::Warning, "target-group-empty"),
                (Severity::Info, "elb-5xx"),
            ]
        );
        assert!(
            findings[1]
                .message
                .starts_with("500 target 5xx responses (5.00% of 10000")
        );
    }

    #[test]
    fn cloudfront_flags_sustained_5xx_and_propagation() {
        let r = resource(
            "cloudfront",
            "distribution",
            "E2ABC",
            json!({"enabled": true, "status": "InProgress"}),
        );
        let r = with_metric(r, "5xxErrorRate", summary(0.8, 0.0, 12.0, 2.5));
        let r = with_metric(r, "4xxErrorRate", summary(1.0, 0.0, 3.0, 2.0));
        assert_eq!(
            checks("cloudfront", vec![r], Vec::new()),
            ["error-rate-5xx", "status"]
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

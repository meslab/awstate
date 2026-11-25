# awstate

Snapshot the recent state of AWS RDS/Aurora, ElastiCache, EC2 Auto Scaling,
ECS, Application Load Balancers, and CloudFront into a directory laid out for
analysis by a person or an AI model: inventory, CloudWatch metrics, logs,
service events, CloudTrail configuration changes, and rule-based findings.

```sh
awstate --profile prod --region eu-west-1 --last 6h --format json
```

## Install

```sh
make install            # release build, stripped, copied to ~/.local/bin
make install PREFIX=/usr/local/bin
```

Requires a recent stable Rust toolchain (edition 2024).

## Usage

```sh
# Last 24h, every service, default output directory ./awstate-<UTC timestamp>
awstate --profile prod

# An incident window, only RDS and ECS, only resources matching "checkout"
awstate --start 2026-11-15T08:00:00Z --end 2026-11-15T11:00:00Z \
  --services rds,ecs --filter checkout -o incident-1115

# Error lines only, no metrics
awstate --last 2h --skip metrics --log-filter-pattern '?ERROR ?FATAL ?deadlock'

# Scheduled run: exit 2 when anything at warning or above is found
awstate --last 24h --fail-on warning --format json > run.json
```

`awstate --help` lists every option. The most useful ones:

| option | default | purpose |
|---|---|---|
| `--last` / `--start`, `--end` | `24h` | time window (RFC 3339 for explicit bounds) |
| `--services` | all | `rds,elasticache,asg,ecs,alb,cloudfront` |
| `--skip` | none | `metrics,logs,events` |
| `--filter` | none | substrings a resource identifier must contain |
| `-o, --output` | `./awstate-<ts>` | snapshot directory |
| `--metric-period` | 300s (≤48h), 3600s | CloudWatch period; multiple of 60 |
| `--max-log-events` | 5000 | events per log group / lines per access log |
| `--max-access-log-bytes` | 64 MiB | S3 access log budget per LB or distribution |
| `--access-log-lines` | `errors` | `errors` (4xx/5xx/unanswered) or `all` |
| `--fail-on` | none | exit 2 at or above `info`/`warning`/`critical` |
| `--format` | `text` | stdout run report: `text` or `json` |

Credentials come from the standard AWS chain (`--profile`, `AWS_PROFILE`,
SSO, environment, instance role). The run fails fast if they cannot be
loaded; for SSO, run `aws sso login` first. CloudFront metrics, logs, and
CloudTrail events are read from us-east-1 regardless of `--region`.

## Output

The command prints a run report to stdout; progress logging goes to stderr,
so `--format json` output can be piped straight into `jq` or an agent.

```
snapshot:   awstate-20261120T101500Z
window:     2026-11-19T10:15:00Z to 2026-11-20T10:15:00Z UTC, region eu-west-1, metric period 300s
read first: awstate-20261120T101500Z/summary.md
findings:   awstate-20261120T101500Z/findings.json
manifest:   awstate-20261120T101500Z/manifest.json

services:
  rds     2 resources     14 events
  ecs     5 resources    310 events

findings: 1 critical, 2 warning, 4 info
  critical  rds  db-1  storage-low: ...
  warning   ecs  main/api  tasks-stopped: ...

collection issues: 1 (data for these is incomplete)
  rds/instance/db-1 logs: AccessDenied ...
```

The JSON form has the same content: `snapshot_dir`, `read_first`,
`findings_file`, `manifest_file`, `region`, `window`,
`metric_period_seconds`, `services`, `finding_counts`, `findings` (critical
and warning only, at most 50), `findings_omitted`, and `collection_issues`.

The snapshot directory:

```
summary.md                        start here: findings, per-resource metric tables, grouped events
findings.json                     every finding, most severe first
manifest.json                     window, resources, details, metric summaries, file paths, issues
<service>/events.json             service events and CloudTrail changes
<service>/<kind>/<id>/metrics.json  full time series per metric
<service>/<kind>/<id>/logs/*.log    CloudWatch Logs, RDS log files, S3 access logs
```

All paths inside the snapshot are relative to its root. In `metrics.json`
each series has `columns` (`time, avg, min, max`, or `time, sum, min, max`
for count-like metrics fetched as sums) and one `rows` entry per period.
Metrics are discovered with `ListMetrics`, so every metric a resource
publishes is included, not a fixed list.

Snapshots can contain database and access logs; `/awstate-*/` is
git-ignored.

## Findings

Conservative rule-based checks over the collected data, meant to point at
where to look rather than replace analysis. Each finding has a `severity`
(`info`, `warning`, `critical`), `service`, `resource`, a stable `check`
name, and a `message`. Examples:

- any resource: `cpu-high`
- RDS: `storage-low`, `swap-sustained`, `cpu-credits-exhausted`,
  `connections-dropped`, `backups-disabled`, `rds-event`
- ElastiCache: `memory-high`, `evictions`
- Auto Scaling: `instances-unhealthy`, `capacity-below-desired`,
  `status-check-failed`, `scaling-failed`, `spot-interruptions`
- ECS: `tasks-below-desired`, `task-start-failures`, `tasks-stopped`,
  `deployment-failed`, `circuit-breaker-disabled`, `image-missing`,
  `mutable-image-tag`
- ALB: `targets-unhealthy`, `target-group-empty`, `connections-rejected`,
  `target-connection-errors`, `elb-5xx`, `target-5xx`
- CloudFront: `error-rate-5xx`, `error-rate-4xx`
- `collection-incomplete` when some data could not be collected

Thresholds are constants at the top of `src/findings.rs`.

## IAM

`iam-policy.json` is a read-only policy covering everything the tool calls:
CloudWatch metrics and logs, RDS, ElastiCache, Auto Scaling, ECS, ECR,
ELB, CloudFront, CloudTrail `LookupEvents`, and `s3:GetObject`/`ListBucket`
for access logs (plus `GetBucketLocation`). Missing permissions are not fatal; the affected parts are
listed as collection issues.

## Development

```sh
make format lint test
```

## License

[MIT](LICENSE)

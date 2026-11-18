//! Configuration changes recorded by `CloudTrail`, for services that have
//! no event feed of their own (load balancers, `CloudFront`).
//!
//! `CloudTrail` event history keeps 90 days of management events at no
//! cost, but `LookupEvents` filters on one attribute only and is limited to
//! two requests a second. Events are looked up by service and read-only
//! calls (monitoring tools polling `Describe*`) dropped client-side.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use aws_sdk_cloudtrail::Client;
use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};
use serde_json::Value;

use crate::model::{Ctx, Event, iso};

/// Pages of 50 events read per service before giving up on older ones.
const MAX_PAGES: usize = 60;

/// Request parameters longer than this are cut in event messages.
const MAX_PARAMETERS_CHARS: usize = 600;

/// A substring that identifies a resource in a `CloudTrail` record (an ARN
/// fragment, a distribution id) and the collected resource it belongs to.
pub struct Owner {
    pub token: String,
    pub resource: String,
}

/// Write events from `event_source` (e.g. `elasticloadbalancing.amazonaws.com`)
/// inside the window that mention one of `owners`, oldest first.
pub async fn changes(
    ctx: &Ctx,
    client: &Client,
    event_source: &str,
    source_type: &str,
    owners: &[Owner],
) -> Result<Vec<Event>> {
    if owners.is_empty() {
        return Ok(Vec::new());
    }
    let attribute = LookupAttribute::builder()
        .attribute_key(LookupAttributeKey::EventSource)
        .attribute_value(event_source)
        .build()
        .context("building CloudTrail lookup")?;
    let mut pages = client
        .lookup_events()
        .lookup_attributes(attribute)
        .start_time(ctx.window.aws_start())
        .end_time(ctx.window.aws_end())
        .into_paginator()
        .send();

    let mut out = Vec::new();
    let mut read = 0;
    while let Some(page) = pages.next().await {
        let page =
            page.with_context(|| format!("looking up CloudTrail events of {event_source}"))?;
        for e in page.events() {
            if e.read_only() == Some("true") {
                continue;
            }
            let record = e.cloud_trail_event().unwrap_or_default();
            let Some(owner) = owners.iter().find(|o| record.contains(o.token.as_str())) else {
                continue;
            };
            let record: Value = serde_json::from_str(record).unwrap_or_default();
            let mut categories: Vec<String> =
                e.event_name().map(str::to_owned).into_iter().collect();
            if let Some(code) = record["errorCode"].as_str() {
                categories.push(format!("error:{code}"));
            }
            out.push(Event {
                time: e.event_time().map(iso),
                source_type: Some(source_type.to_owned()),
                source: Some(owner.resource.clone()),
                categories,
                message: Some(describe(e.event_name(), e.username(), &record)),
            });
        }
        read += 1;
        if read >= MAX_PAGES {
            ctx.issues.record(
                format!("cloudtrail {event_source}"),
                &anyhow::anyhow!(
                    "stopped after {MAX_PAGES} pages of events; earlier changes in the window are missing"
                ),
            );
            break;
        }
    }
    out.sort_by(|a, b| a.time.cmp(&b.time));
    Ok(out)
}

/// `<event> by <user>: <parameters> | <error>`.
fn describe(event_name: Option<&str>, username: Option<&str>, record: &Value) -> String {
    let mut message = format!(
        "{} by {}",
        event_name.unwrap_or("?"),
        username
            .or_else(|| record["userIdentity"]["arn"].as_str())
            .unwrap_or("?")
    );
    let parameters = &record["requestParameters"];
    if !parameters.is_null() {
        let mut text = parameters.to_string();
        if let Some((cut, _)) = text.char_indices().nth(MAX_PARAMETERS_CHARS) {
            text.truncate(cut);
            text.push_str("...");
        }
        let _ = write!(message, ": {text}");
    }
    if let Some(error) = record["errorMessage"]
        .as_str()
        .or(record["errorCode"].as_str())
    {
        let _ = write!(message, " | {error}");
    }
    message
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn describe_includes_parameters_and_error() {
        let record = json!({
            "requestParameters": {"targetGroupArn": "tg"},
            "errorCode": "AccessDenied",
            "errorMessage": "not allowed",
        });
        assert_eq!(
            describe(Some("RegisterTargets"), Some("deployer"), &record),
            r#"RegisterTargets by deployer: {"targetGroupArn":"tg"} | not allowed"#
        );
        assert_eq!(describe(None, None, &json!({})), "? by ?");
    }
}

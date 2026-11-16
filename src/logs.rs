//! `CloudWatch` Logs capture.

use std::fmt::Write as _;

use anyhow::{Context, Result};

use crate::collect::write_file;

use crate::model::{Ctx, LogCapture, iso_millis, sanitize};

/// Pulls the window's events from `group` into `<rel_dir>/logs/<group>.log`,
/// one `timestamp [stream] message` line per event, earliest first.
pub async fn capture_group(ctx: &Ctx, group: &str, rel_dir: &str) -> Result<LogCapture> {
    let mut pages = ctx
        .logs
        .filter_log_events()
        .log_group_name(group)
        .start_time(ctx.window.start.timestamp_millis())
        .end_time(ctx.window.end.timestamp_millis())
        .set_filter_pattern(ctx.log_filter_pattern.clone())
        .into_paginator()
        .send();

    let mut text = String::new();
    let mut lines = 0usize;
    let mut truncated = false;
    'pages: while let Some(page) = pages.next().await {
        let page = page.with_context(|| format!("reading log group {group}"))?;
        for event in page.events() {
            if lines >= ctx.max_log_events {
                truncated = true;
                break 'pages;
            }
            let time = event.timestamp().map_or_default(iso_millis);
            let stream = event.log_stream_name().unwrap_or("-");
            let message = event.message().unwrap_or_default().trim_end();
            // Writing to a String cannot fail.
            let _ = writeln!(text, "{time} [{stream}] {message}");
            lines += 1;
        }
    }

    let source = format!("cloudwatch-logs:{group}");
    let file = write_log(ctx, rel_dir, group, &text).await?;
    Ok(LogCapture {
        source,
        file,
        lines,
        bytes: text.len(),
        truncated,
    })
}

/// Writes captured log text under the resource's `logs/` directory and
/// returns the path relative to the output root. Empty captures write nothing.
pub async fn write_log(ctx: &Ctx, rel_dir: &str, name: &str, text: &str) -> Result<Option<String>> {
    if text.is_empty() {
        return Ok(None);
    }
    let rel = format!("{rel_dir}/logs/{}.log", sanitize(name));
    write_file(ctx, &rel, text.as_bytes()).await?;
    Ok(Some(rel))
}

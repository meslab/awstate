//! Checks that the ECR images ECS task definitions point at still exist.
//!
//! A running task keeps working after its image is deleted (by a lifecycle
//! policy, say), but the next task the service starts cannot pull it. That
//! failure only surfaces when a host is replaced or the service scales, so
//! it is worth flagging before it happens.

use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_ecr::Client;
use aws_sdk_ecr::types::ImageIdentifier;
use serde::Serialize;

use crate::model::Ctx;

/// Whether an image reference resolves in ECR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageStatus {
    Present,
    /// The tag or digest is gone, or the repository itself is.
    Missing,
    /// Missing from a pull-through cache repository, which fetches it from
    /// upstream on the next pull.
    NotCached,
    /// Not an ECR image in this region, or the lookup failed.
    Unchecked,
}

/// An image URI split into the parts `DescribeImages` takes.
#[derive(Debug, PartialEq, Eq)]
struct EcrImage<'a> {
    registry: &'a str,
    region: &'a str,
    repository: &'a str,
    reference: Reference<'a>,
}

#[derive(Debug, PartialEq, Eq)]
enum Reference<'a> {
    Digest(&'a str),
    Tag(&'a str),
}

/// Looks up images once per run, however many services share them.
pub struct ImageChecker {
    client: Client,
    region: String,
    /// Held across lookups so concurrent services sharing an image wait for
    /// one lookup instead of each making (and failing) their own.
    state: futures::lock::Mutex<State>,
}

#[derive(Default)]
struct State {
    images: HashMap<String, ImageStatus>,
    /// Pull-through cache repository prefixes per registry, fetched only
    /// when an image in that registry turns out to be missing.
    pull_through: HashMap<String, Vec<String>>,
}

impl ImageChecker {
    pub fn new(client: Client, region: &str) -> Self {
        Self {
            client,
            region: region.to_owned(),
            state: futures::lock::Mutex::default(),
        }
    }

    /// Resolves `image`, recording lookup failures as collection issues.
    pub async fn check(&self, ctx: &Ctx, image: &str) -> ImageStatus {
        let Some(parsed) = parse_image(image).filter(|i| i.region == self.region) else {
            return ImageStatus::Unchecked;
        };
        let mut state = self.state.lock().await;
        if let Some(status) = state.images.get(image) {
            return *status;
        }
        let status = match self.describe(&parsed).await {
            Ok(true) => ImageStatus::Present,
            Ok(false) => {
                if !state.pull_through.contains_key(parsed.registry) {
                    let prefixes = self
                        .pull_through_prefixes(parsed.registry)
                        .await
                        .unwrap_or_else(|err| {
                            ctx.issues.record(
                                format!("ecr pull-through cache rules of {}", parsed.registry),
                                &err,
                            );
                            Vec::new()
                        });
                    state
                        .pull_through
                        .insert(parsed.registry.to_owned(), prefixes);
                }
                if is_pull_through(&state.pull_through[parsed.registry], parsed.repository) {
                    ImageStatus::NotCached
                } else {
                    ImageStatus::Missing
                }
            }
            Err(err) => {
                ctx.issues.record(format!("ecr image {image}"), &err);
                ImageStatus::Unchecked
            }
        };
        state.images.insert(image.to_owned(), status);
        status
    }

    /// Whether the image exists; `Err` only when the answer is unknown.
    async fn describe(&self, image: &EcrImage<'_>) -> Result<bool> {
        let id = match image.reference {
            Reference::Digest(d) => ImageIdentifier::builder().image_digest(d),
            Reference::Tag(t) => ImageIdentifier::builder().image_tag(t),
        }
        .build();
        let result = self
            .client
            .describe_images()
            .registry_id(image.registry)
            .repository_name(image.repository)
            .image_ids(id)
            .send()
            .await;
        match result {
            Ok(out) => Ok(!out.image_details().is_empty()),
            Err(err)
                if err.as_service_error().is_some_and(|e| {
                    e.is_image_not_found_exception() || e.is_repository_not_found_exception()
                }) =>
            {
                Ok(false)
            }
            Err(err) => Err(err).context("describing image"),
        }
    }

    async fn pull_through_prefixes(&self, registry: &str) -> Result<Vec<String>> {
        let mut pages = self
            .client
            .describe_pull_through_cache_rules()
            .registry_id(registry)
            .into_paginator()
            .send();
        let mut out = Vec::new();
        while let Some(page) = pages.next().await {
            let page = page.context("describing pull-through cache rules")?;
            out.extend(
                page.pull_through_cache_rules()
                    .iter()
                    .filter_map(|r| r.ecr_repository_prefix().map(str::to_owned)),
            );
        }
        Ok(out)
    }
}

fn is_pull_through(prefixes: &[String], repository: &str) -> bool {
    prefixes.iter().any(|p| {
        repository
            .strip_prefix(p.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Parses `<account>.dkr.ecr.<region>.amazonaws.com[.cn]/<repo>[:tag|@digest]`.
fn parse_image(image: &str) -> Option<EcrImage<'_>> {
    let (host, path) = image.split_once('/')?;
    let (registry, rest) = host.split_once(".dkr.ecr.")?;
    let region = rest
        .strip_suffix(".amazonaws.com")
        .or_else(|| rest.strip_suffix(".amazonaws.com.cn"))?;
    if registry.len() != 12 || !registry.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (repository, reference) = if let Some((repo, digest)) = path.split_once('@') {
        (repo, Reference::Digest(digest))
    } else {
        // A colon after the last slash separates the tag.
        let tail_start = path.rfind('/').map_or(0, |i| i + 1);
        match path[tail_start..].rfind(':') {
            Some(i) => (
                &path[..tail_start + i],
                Reference::Tag(&path[tail_start + i + 1..]),
            ),
            None => (path, Reference::Tag("latest")),
        }
    };
    Some(EcrImage {
        registry,
        region,
        repository,
        reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_digest_tag_and_implicit_latest() {
        let i = parse_image("123456789012.dkr.ecr.eu-central-1.amazonaws.com/team/app@sha256:ab")
            .unwrap();
        assert_eq!(
            i,
            EcrImage {
                registry: "123456789012",
                region: "eu-central-1",
                repository: "team/app",
                reference: Reference::Digest("sha256:ab"),
            }
        );

        let i = parse_image("123456789012.dkr.ecr.eu-central-1.amazonaws.com/hub/fa/app:1.70.0")
            .unwrap();
        assert_eq!(i.repository, "hub/fa/app");
        assert_eq!(i.reference, Reference::Tag("1.70.0"));

        let i = parse_image("123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app").unwrap();
        assert_eq!(i.region, "cn-north-1");
        assert_eq!(i.reference, Reference::Tag("latest"));
    }

    #[test]
    fn pull_through_matches_whole_prefix_segments() {
        let prefixes = ["docker-hub".to_owned()];
        assert!(is_pull_through(&prefixes, "docker-hub/fusionauth/app"));
        assert!(!is_pull_through(&prefixes, "docker-hubble/app"));
        assert!(!is_pull_through(&prefixes, "docker-hub"));
    }

    #[test]
    fn ignores_non_ecr_images() {
        assert!(parse_image("public.ecr.aws/datadog/agent:latest").is_none());
        assert!(parse_image("nginx:1.27").is_none());
        assert!(parse_image("registry.example.com:5000/app:1").is_none());
    }
}

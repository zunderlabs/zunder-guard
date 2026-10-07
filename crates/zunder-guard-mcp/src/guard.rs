// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The HTTP connection to Guard, and nothing else: plain HTTP to a loopback
//! address, no redirects, no proxies, bounded answers.
//!
//! This server never talks to Hyperliquid directly. Its only peer is the
//! Guard named by [`GuardUrl`], which must be on this machine: Guard itself
//! listens on loopback addresses only, and a URL elsewhere (the venue's own
//! API among them) is refused before anything is sent.

use std::{io::Read, time::Duration};

use reqwest::{Url, blocking::Client, redirect::Policy};
use serde_json::Value;

use crate::contract::{EVENTS_PATH, EXCHANGE_PATH, INFO_PATH, KILL_PATH, STATUS_PATH};

/// Guard's default address.
pub const DEFAULT_GUARD_URL: &str = "http://127.0.0.1:8547";
/// Largest answer read from Guard: 8 MiB (a large account's open orders).
pub const MAX_ANSWER: u64 = 8 << 20;
const TIMEOUT: Duration = Duration::from_secs(15);

/// A checked Guard address: `http://` with `127.0.0.1`, `localhost` or
/// `[::1]`, an optional port, and no path, query, fragment or user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardUrl(Url);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("the Guard URL cannot be parsed")]
    Unparsable,
    #[error(
        "the Guard URL must be http:// on 127.0.0.1, localhost or [::1]: this server talks only to a Guard on this machine"
    )]
    NotLoopback,
    #[error("the Guard URL must be only scheme, host and port (no path, query, fragment or user)")]
    Extra,
}

impl GuardUrl {
    pub fn parse(text: &str) -> Result<Self, UrlError> {
        let url = Url::parse(text).map_err(|_| UrlError::Unparsable)?;
        if url.scheme() != "http" {
            return Err(UrlError::NotLoopback);
        }
        // The URL parser normalises IP addresses (`127.1` is `127.0.0.1`)
        // and lower-cases names, so these three are exactly loopback.
        if !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) {
            return Err(UrlError::NotLoopback);
        }
        if !(url.path().is_empty() || url.path() == "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(UrlError::Extra);
        }
        Ok(Self(url))
    }

    fn join(&self, path: &str) -> Result<Url, GuardError> {
        self.0.join(path).map_err(|_| GuardError::NotSent)
    }
}

impl std::fmt::Display for GuardUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str().trim_end_matches('/'))
    }
}

/// Why a request to Guard failed. No variant carries text from the
/// connection, so nothing from outside reaches the agent through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The connection failed: nothing reached Guard.
    #[error("Guard does not answer at the configured address; is zunder-guard running?")]
    NotSent,
    /// The request may have reached Guard (a timeout, a broken answer).
    #[error("the request may have reached Guard, but no answer came back")]
    OutcomeUnknown,
    #[error("Guard answered with HTTP status {0}")]
    Http(u16),
    #[error("Guard's answer is not JSON")]
    NotJson,
    #[error("Guard's answer is too large")]
    TooLarge,
}

/// The connection to Guard.
#[derive(Debug, Clone)]
pub struct GuardClient {
    url: GuardUrl,
    http: Client,
}

impl GuardClient {
    pub fn new(url: GuardUrl) -> Result<Self, GuardError> {
        let http = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| GuardError::NotSent)?;
        Ok(Self { url, http })
    }

    pub fn url(&self) -> &GuardUrl {
        &self.url
    }

    pub fn status(&self) -> Result<Value, GuardError> {
        self.get(STATUS_PATH)
    }

    pub fn events(&self, since: u64) -> Result<Value, GuardError> {
        self.get(&format!("{EVENTS_PATH}?since={since}"))
    }

    /// One `/info` request in Hyperliquid's format.
    pub fn info(&self, request: &Value) -> Result<Value, GuardError> {
        let body = serde_json::to_vec(request).map_err(|_| GuardError::NotSent)?;
        self.post(INFO_PATH, body)
    }

    /// One signed `/exchange` request (built by `sign::signed_request`).
    pub fn exchange(&self, body: Vec<u8>) -> Result<Value, GuardError> {
        self.post(EXCHANGE_PATH, body)
    }

    /// Guard's signed kill request (built by `sign::signed_kill_request`):
    /// pulls the kill switch, never releases it.
    pub fn kill(&self, body: Vec<u8>) -> Result<Value, GuardError> {
        self.post(KILL_PATH, body)
    }

    fn get(&self, path: &str) -> Result<Value, GuardError> {
        let response = self
            .http
            .get(self.url.join(path)?)
            .send()
            .map_err(classify)?;
        read(response)
    }

    fn post(&self, path: &str, body: Vec<u8>) -> Result<Value, GuardError> {
        let response = self
            .http
            .post(self.url.join(path)?)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(classify)?;
        read(response)
    }
}

fn classify(error: reqwest::Error) -> GuardError {
    // Only a failed connection or a request that could not be built proves
    // that nothing reached Guard; anything else may have.
    if error.is_connect() || error.is_builder() {
        GuardError::NotSent
    } else {
        GuardError::OutcomeUnknown
    }
}

fn read(response: reqwest::blocking::Response) -> Result<Value, GuardError> {
    let status = response.status();
    let mut body = Vec::new();
    response
        .take(MAX_ANSWER + 1)
        .read_to_end(&mut body)
        .map_err(|_| GuardError::OutcomeUnknown)?;
    if body.len() as u64 > MAX_ANSWER {
        return Err(GuardError::TooLarge);
    }
    if !status.is_success() {
        return Err(GuardError::Http(status.as_u16()));
    }
    serde_json::from_slice(&body).map_err(|_| GuardError::NotJson)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_http_is_accepted() {
        for good in [
            "http://127.0.0.1:8547",
            "http://127.0.0.1:8547/",
            "http://localhost:9000",
            "http://[::1]:8547",
        ] {
            assert!(GuardUrl::parse(good).is_ok(), "{good}");
        }
        for (bad, error) in [
            ("https://api.hyperliquid.xyz", UrlError::NotLoopback),
            ("http://api.hyperliquid-testnet.xyz", UrlError::NotLoopback),
            ("http://10.0.0.5:8547", UrlError::NotLoopback),
            ("http://0.0.0.0:8547", UrlError::NotLoopback),
            ("http://127.0.0.2:8547", UrlError::NotLoopback),
            ("http://localhost.evil.com:8547", UrlError::NotLoopback),
            ("https://127.0.0.1:8547", UrlError::NotLoopback),
            ("http://127.0.0.1:8547/exchange", UrlError::Extra),
            ("http://user:pw@127.0.0.1:8547", UrlError::Extra),
            ("http://127.0.0.1:8547/?x=1", UrlError::Extra),
            ("not a url", UrlError::Unparsable),
        ] {
            assert_eq!(GuardUrl::parse(bad).unwrap_err(), error, "{bad}");
        }
        assert_eq!(
            GuardUrl::parse("http://127.0.0.1:8547/")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:8547"
        );
    }
}

// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! How requests reach the venue.
//!
//! [`Transport`] is sealed: the only implementations are [`HttpTransport`],
//! which goes to the REST URL of the [`VenueNetwork`] it was built for and
//! nowhere else, and [`ScriptedTransport`], which never touches the
//! network. No code outside this crate can point the executor anywhere
//! else.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use thiserror::Error;

use super::{Network, network::VenueNetwork};
use crate::error::ExecError;

/// The two REST endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// Read-only queries.
    Info,
    /// Signed actions: orders and cancels.
    Exchange,
}

impl Endpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Endpoint::Info => "/info",
            Endpoint::Exchange => "/exchange",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The request never left this machine. Nothing happened.
    #[error("not sent: {0}")]
    NotSent(String),
    /// The request may have reached the venue, but no usable answer came
    /// back.
    #[error("no answer: {0}")]
    NoAnswer(String),
    /// The venue answered with an HTTP error status.
    #[error("HTTP {status}: {body}")]
    Status { status: u16, body: String },
}

mod sealed {
    pub trait Sealed {}
}

/// Sends a JSON body to an endpoint and returns the response body.
pub trait Transport: sealed::Sealed + Send + Sync {
    /// The network the requests go to; `None` for a transport that never
    /// leaves this machine. The executor refuses a transport for another
    /// network than the one it signs for.
    fn network(&self) -> Option<Network>;

    fn post(
        &self,
        endpoint: Endpoint,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, TransportError>> + Send;
}

/// HTTPS to the Hyperliquid API of one network.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    network: Network,
    base_url: &'static str,
}

/// Longest the venue may take to answer before the request counts as
/// unanswered.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Most of an error body kept for the error message.
const ERROR_BODY_LIMIT: usize = 500;

impl HttpTransport {
    pub fn new(network: VenueNetwork) -> Result<Self, ExecError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // A redirect could carry a signed request to another host.
            // Hyperliquid's API does not redirect.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|error| ExecError::Config(format!("cannot build the HTTP client: {error}")))?;
        Ok(Self {
            client,
            network: network.network(),
            base_url: network.rest_url(),
        })
    }

    pub fn base_url(&self) -> &'static str {
        self.base_url
    }
}

impl sealed::Sealed for HttpTransport {}

impl Transport for HttpTransport {
    fn network(&self) -> Option<Network> {
        Some(self.network)
    }

    async fn post(&self, endpoint: Endpoint, body: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let url = format!("{}{}", self.base_url, endpoint.path());
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| {
                // Only a failure to connect proves the request never left.
                if error.is_connect() || error.is_builder() {
                    TransportError::NotSent(error.to_string())
                } else {
                    TransportError::NoAnswer(error.to_string())
                }
            })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| TransportError::NoAnswer(error.to_string()))?;
        if !status.is_success() {
            let shown = &bytes[..bytes.len().min(ERROR_BODY_LIMIT)];
            return Err(TransportError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(shown).into_owned(),
            });
        }
        Ok(bytes.to_vec())
    }
}

/// A transport for tests that never touches the network. Each request gets
/// the next scripted reply, which must be for the same endpoint, and every
/// request is recorded. Clones share the script.
#[derive(Debug, Clone, Default)]
pub struct ScriptedTransport {
    script: Arc<Mutex<Script>>,
}

#[derive(Debug, Default)]
struct Script {
    replies: VecDeque<(Endpoint, Result<String, TransportError>)>,
    sent: Vec<(Endpoint, serde_json::Value)>,
}

impl ScriptedTransport {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answer the next request, which must go to `endpoint`, with `json`.
    pub fn reply(&self, endpoint: Endpoint, json: impl Into<String>) {
        self.lock().replies.push_back((endpoint, Ok(json.into())));
    }

    /// Fail the next request, which must go to `endpoint`.
    pub fn fail(&self, endpoint: Endpoint, error: TransportError) {
        self.lock().replies.push_back((endpoint, Err(error)));
    }

    /// Every request so far, with its body parsed as JSON.
    pub fn sent(&self) -> Vec<(Endpoint, serde_json::Value)> {
        self.lock().sent.clone()
    }

    /// Replies not used yet.
    pub fn pending(&self) -> usize {
        self.lock().replies.len()
    }
}

impl sealed::Sealed for ScriptedTransport {}

impl Transport for ScriptedTransport {
    fn network(&self) -> Option<Network> {
        None
    }

    async fn post(&self, endpoint: Endpoint, body: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let mut script = self.lock();
        let parsed = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        script.sent.push((endpoint, parsed));
        match script.replies.pop_front() {
            None => Err(TransportError::NotSent(format!(
                "no scripted reply left for a request to {}",
                endpoint.path()
            ))),
            Some((expected, _)) if expected != endpoint => Err(TransportError::NotSent(format!(
                "the script expected a request to {}, got one to {}",
                expected.path(),
                endpoint.path()
            ))),
            Some((_, reply)) => reply.map(String::into_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperliquid::{address::Address, network::MainnetConsent};

    #[test]
    fn http_transport_goes_to_the_chosen_network_only() {
        let transport = HttpTransport::new(VenueNetwork::testnet()).unwrap();
        assert_eq!(transport.base_url(), "https://api.hyperliquid-testnet.xyz");
        assert_eq!(transport.network(), Some(Network::Testnet));

        let account = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
        let consent =
            MainnetConsent::confirm(Address::from_hex(account).unwrap(), Some(account)).unwrap();
        let transport = HttpTransport::new(VenueNetwork::mainnet(consent)).unwrap();
        assert_eq!(transport.base_url(), "https://api.hyperliquid.xyz");
        assert_eq!(transport.network(), Some(Network::Mainnet));
        assert_eq!(ScriptedTransport::new().network(), None);
    }

    #[tokio::test]
    async fn scripted_replies_are_used_in_order_and_requests_recorded() {
        let transport = ScriptedTransport::new();
        transport.reply(Endpoint::Info, r#"{"ok":1}"#);
        transport.fail(
            Endpoint::Exchange,
            TransportError::NoAnswer("timeout".into()),
        );

        let reply = transport
            .post(Endpoint::Info, br#"{"type":"meta"}"#.to_vec())
            .await
            .unwrap();
        assert_eq!(reply, br#"{"ok":1}"#);
        assert_eq!(
            transport.post(Endpoint::Exchange, b"{}".to_vec()).await,
            Err(TransportError::NoAnswer("timeout".into()))
        );
        // Nothing scripted is left: refused, not invented.
        assert!(matches!(
            transport.post(Endpoint::Info, b"{}".to_vec()).await,
            Err(TransportError::NotSent(_))
        ));
        let sent = transport.sent();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0].1, serde_json::json!({"type": "meta"}));
    }

    #[tokio::test]
    async fn a_reply_for_the_wrong_endpoint_is_refused() {
        let transport = ScriptedTransport::new();
        transport.reply(Endpoint::Info, "{}");
        assert!(matches!(
            transport.post(Endpoint::Exchange, b"{}".to_vec()).await,
            Err(TransportError::NotSent(message)) if message.contains("expected a request to /info")
        ));
    }
}

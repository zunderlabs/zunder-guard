// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Where Guard's requests go: Hyperliquid's `info` endpoint for reading,
//! and its `exchange` endpoint for sending, which only a sending Guard has.
//!
//! - [`InfoClient`] reads: HTTPS to the network's REST URL, `/info` only,
//!   no redirects. Paper mode uses nothing else, so a paper Guard has no
//!   way to send an order at all.
//! - Sending goes through `zunder-venue`'s [`HttpTransport`], which is built
//!   from a [`VenueNetwork`]: testnet for the asking, mainnet only with a
//!   person's [`zunder_venue::hyperliquid::MainnetConsent`].

use std::{future::Future, time::Duration};

use serde_json::Value;
use thiserror::Error;
use zunder_guard_core::sign::SigningNetwork;
use zunder_venue::hyperliquid::{
    Endpoint, HttpTransport, Network, Transport, TransportError, VenueNetwork,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamError {
    /// Nothing left this machine.
    #[error("not sent: {0}")]
    NotSent(String),
    /// It may have reached the venue; no usable answer came back.
    #[error("no answer: {0}")]
    NoAnswer(String),
    #[error("HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("the answer is not JSON: {0}")]
    NotJson(String),
    #[error("this Guard does not send (paper mode)")]
    Paper,
}

impl From<TransportError> for UpstreamError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::NotSent(text) => UpstreamError::NotSent(text),
            TransportError::NoAnswer(text) => UpstreamError::NoAnswer(text),
            TransportError::Status { status, body } => UpstreamError::Status { status, body },
        }
    }
}

/// The venue, as Guard sees it.
pub trait Upstream: Send + Sync + 'static {
    /// POST a JSON body to `/info`.
    fn info(&self, body: &Value) -> impl Future<Output = Result<Value, UpstreamError>> + Send;

    /// POST a signed request to `/exchange`. [`UpstreamError::Paper`] for a
    /// Guard that does not send.
    fn exchange(&self, body: Vec<u8>) -> impl Future<Output = Result<Value, UpstreamError>> + Send;

    /// The WebSocket URL market-data subscriptions are passed through to;
    /// `None` when there is none (tests).
    fn ws_url(&self) -> Option<String>;

    /// The network `exchange` sends to, whose phantom agent Guard must sign
    /// with; `None` for a Guard that does not send.
    fn sends_to(&self) -> Option<SigningNetwork>;
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ERROR_BODY_LIMIT: usize = 500;

/// Reads `/info` of one network, and nothing else.
#[derive(Debug, Clone)]
pub struct InfoClient {
    client: reqwest::Client,
    url: String,
}

impl InfoClient {
    pub fn new(network: Network) -> Result<Self, UpstreamError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|error| UpstreamError::NotSent(error.to_string()))?;
        Ok(Self {
            client,
            url: format!("{}/info", network.rest_url()),
        })
    }

    pub async fn post(&self, body: &Value) -> Result<Value, UpstreamError> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(body)
                    .map_err(|error| UpstreamError::NotSent(error.to_string()))?,
            )
            .send()
            .await
            .map_err(|error| {
                if error.is_connect() || error.is_builder() {
                    UpstreamError::NotSent(error.to_string())
                } else {
                    UpstreamError::NoAnswer(error.to_string())
                }
            })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| UpstreamError::NoAnswer(error.to_string()))?;
        if !status.is_success() {
            let shown = &bytes[..bytes.len().min(ERROR_BODY_LIMIT)];
            return Err(UpstreamError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(shown).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|error| UpstreamError::NotJson(error.to_string()))
    }
}

/// Hyperliquid itself: reads through [`InfoClient`], sends (when built
/// with a [`VenueNetwork`]) through `zunder-venue`'s [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct Hyperliquid {
    info: InfoClient,
    exchange: Option<HttpTransport>,
    network: Network,
}

impl Hyperliquid {
    /// A Guard that only reads: paper mode.
    pub fn paper(network: Network) -> Result<Self, UpstreamError> {
        Ok(Self {
            info: InfoClient::new(network)?,
            exchange: None,
            network,
        })
    }

    /// A Guard that sends on `venue`'s network.
    pub fn sending(venue: VenueNetwork) -> Result<Self, UpstreamError> {
        let exchange =
            HttpTransport::new(venue).map_err(|error| UpstreamError::NotSent(error.to_string()))?;
        Ok(Self {
            info: InfoClient::new(venue.network())?,
            exchange: Some(exchange),
            network: venue.network(),
        })
    }
}

impl Upstream for Hyperliquid {
    async fn info(&self, body: &Value) -> Result<Value, UpstreamError> {
        self.info.post(body).await
    }

    async fn exchange(&self, body: Vec<u8>) -> Result<Value, UpstreamError> {
        let Some(transport) = &self.exchange else {
            return Err(UpstreamError::Paper);
        };
        let bytes = transport.post(Endpoint::Exchange, body).await?;
        serde_json::from_slice(&bytes).map_err(|error| UpstreamError::NotJson(error.to_string()))
    }

    fn ws_url(&self) -> Option<String> {
        Some(self.network.ws_url().to_owned())
    }

    fn sends_to(&self) -> Option<SigningNetwork> {
        self.exchange.as_ref().map(|_| {
            if self.network.is_live() {
                SigningNetwork::Mainnet
            } else {
                SigningNetwork::Testnet
            }
        })
    }
}

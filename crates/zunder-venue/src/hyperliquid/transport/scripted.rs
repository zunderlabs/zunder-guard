// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A transport for tests: scripted replies, recorded requests, no network.
//! Compiled only for tests (feature `test-hooks`, which only
//! dev-dependencies enable); a release build has no transport but
//! [`HttpTransport`](super::HttpTransport).

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use zunder_hl_protocol::Network;

use super::{Endpoint, Transport, TransportError, sealed};

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

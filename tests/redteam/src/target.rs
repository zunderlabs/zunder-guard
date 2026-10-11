// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The thing under attack, and how its reply is read.
//!
//! A [`Target`] is either a running Guard (over HTTP and WebSocket) or the
//! in-process [`crate::mock::NaiveMock`]. Every probe comes back as a
//! [`Reply`], which [`Verdict::of`] turns into a verdict the catalogue can
//! judge. Both Guard's real replies and the plain Hyperliquid error shapes
//! are understood, so the same case reads correctly against paper mode (a
//! `would …` reply), testnet (a forwarded `ok`) and the mock.

use std::fmt;

use serde_json::Value;

/// A reply from a target, or a transport-level result.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A JSON reply from the endpoint.
    Json(Value),
    /// A non-2xx HTTP status (for example 413 on an oversized body).
    HttpStatus(u16),
    /// Nothing usable came back, but the connection worked (timeout, reset).
    NoAnswer(String),
    /// The target could not be reached at all.
    Unreachable(String),
}

/// What a target did with a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forwarded or would forward at the requested size: the attack got
    /// through.
    Allowed,
    /// Resized down before forwarding: not through at full size.
    Resized,
    /// Vetoed by Guard with a code.
    Vetoed,
    /// Rejected by the venue or Guard with a plain error (bad signature,
    /// nonce reused, unreachable, bad request).
    Rejected,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Verdict::Allowed => "allowed",
            Verdict::Resized => "resized",
            Verdict::Vetoed => "vetoed",
            Verdict::Rejected => "rejected",
        };
        f.write_str(text)
    }
}

/// The verdict and (when Guard gave one) the refusal code read from a reply.
#[derive(Debug, Clone)]
pub struct Read {
    pub verdict: Verdict,
    pub code: Option<String>,
    pub detail: String,
}

impl Read {
    pub fn of(reply: &Reply) -> Self {
        match reply {
            Reply::HttpStatus(status) => Read {
                verdict: Verdict::Rejected,
                code: Some(format!("http_{status}")),
                detail: format!("HTTP {status}"),
            },
            Reply::NoAnswer(text) => Read {
                verdict: Verdict::Rejected,
                code: Some("no_answer".to_owned()),
                detail: format!("no answer: {text}"),
            },
            Reply::Unreachable(text) => Read {
                verdict: Verdict::Rejected,
                code: Some("unreachable".to_owned()),
                detail: format!("unreachable: {text}"),
            },
            Reply::Json(value) => Self::of_json(value),
        }
    }

    fn of_json(value: &Value) -> Self {
        // A WebSocket post wraps the exchange reply; unwrap it if present.
        if let Some(inner) = value.pointer("/data/response/payload") {
            return Self::of_json(inner);
        }
        let status = value.get("status").and_then(Value::as_str);
        if status == Some("ok") {
            // Guard puts its verdict beside the venue's reply, with the
            // entry's asked and forwarded size: only a forwarded size below
            // the asked one counts as cut (a resize that only attached a
            // stop is a full-size forward).
            let code = value.get("code").and_then(Value::as_str).map(str::to_owned);
            let size = |key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse::<f64>().ok())
            };
            let verdict = match (size("requested_size"), size("size")) {
                (Some(asked), Some(sent)) if sent < asked => Verdict::Resized,
                _ => Verdict::Allowed,
            };
            return Read {
                verdict,
                code,
                detail: "status ok (forwarded)".to_owned(),
            };
        }
        let response = value
            .get("response")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Guard's veto: "Zunder Guard veto [code]: text".
        if let Some(code) = between(&response, "Zunder Guard veto [", "]") {
            return Read {
                verdict: Verdict::Vetoed,
                code: Some(code),
                detail: response,
            };
        }
        // Guard paper mode: "Zunder Guard paper mode: would {verdict} [code]: …".
        if response.contains("Zunder Guard paper mode") {
            let code = between(&response, "[", "]");
            let size = |key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse::<f64>().ok())
            };
            let verdict = if response.contains("would veto") {
                Verdict::Vetoed
            } else {
                // With the sizes: cut only when the size would be below the
                // asked one (a resize that only attaches a stop is full
                // size); without them, by the label.
                match (size("requested_size"), size("size")) {
                    (Some(asked), Some(sent)) if sent < asked => Verdict::Resized,
                    (Some(_), Some(_)) => Verdict::Allowed,
                    _ if response.contains("would resize") => Verdict::Resized,
                    _ => Verdict::Allowed,
                }
            };
            return Read {
                verdict,
                code,
                detail: response,
            };
        }
        // A plain Hyperliquid or transport error.
        Read {
            verdict: Verdict::Rejected,
            code: None,
            detail: if response.is_empty() {
                value.to_string()
            } else {
                response
            },
        }
    }
}

fn between(text: &str, open: &str, close: &str) -> Option<String> {
    let start = text.find(open)? + open.len();
    let rest = text.get(start..)?;
    let end = rest.find(close)?;
    Some(rest.get(..end)?.to_owned())
}

/// A target the suite can attack.
pub trait Target {
    /// POST a body to `/exchange`.
    fn exchange(&mut self, body: &[u8]) -> Reply;
    /// POST a body to `/info`.
    fn info(&mut self, body: &[u8]) -> Reply;
    /// Send a WebSocket `post` frame and read its answer. The default
    /// routes the inner payload through `/exchange`, which is what Guard's
    /// WebSocket path does; the HTTP target overrides it with a real socket.
    fn ws_action(&mut self, frame: &str) -> Reply {
        let payload = serde_json::from_str::<Value>(frame)
            .ok()
            .and_then(|value| value.pointer("/request/payload").cloned())
            .unwrap_or(Value::Null);
        match serde_json::to_vec(&payload) {
            Ok(body) => self.exchange(&body),
            Err(error) => Reply::NoAnswer(error.to_string()),
        }
    }
    /// A raw POST to an arbitrary path, for guessed control endpoints. The
    /// default (the mock) has no such endpoints.
    fn raw_post(&mut self, _path: &str, _body: &[u8]) -> Reply {
        Reply::HttpStatus(404)
    }
    /// A request whose body never completes. Only meaningful over a real
    /// socket; the default is a no-op the runner reads as "not applicable".
    fn slowloris(&mut self) -> Reply {
        Reply::NoAnswer("slowloris: not applicable to an in-process target".to_owned())
    }
    /// Is the target still answering its status endpoint? Used after the
    /// robustness probes to prove it did not crash.
    fn healthy(&mut self) -> bool;
    /// The account's open orders as the venue reports them
    /// (`frontendOpenOrders`), for the cases that check what rests
    /// afterwards. `None` where the target cannot tell (the mock).
    fn open_orders(&mut self) -> Option<Vec<Value>> {
        None
    }
    /// A human label for the report.
    fn label(&self) -> String;
}

/// A running Guard reached over HTTP and WebSocket.
pub struct HttpTarget {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpTarget {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            client,
        })
    }

    fn post(&self, path: &str, body: &[u8]) -> Reply {
        let result = self
            .client
            .post(format!("{}{path}", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send();
        match result {
            Ok(response) => {
                let status = response.status();
                let text = response.text().unwrap_or_default();
                if !status.is_success() {
                    return Reply::HttpStatus(status.as_u16());
                }
                match serde_json::from_str::<Value>(&text) {
                    Ok(value) => Reply::Json(value),
                    Err(error) => Reply::NoAnswer(format!("not JSON: {error}")),
                }
            }
            Err(error) => {
                if error.is_timeout() {
                    Reply::NoAnswer(error.to_string())
                } else {
                    Reply::Unreachable(error.to_string())
                }
            }
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Guard's `/guard/status`, for the target profile (mode, allowlist).
    pub fn status(&self) -> Option<Value> {
        let text = self
            .client
            .get(format!("{}/guard/status", self.base))
            .send()
            .ok()?
            .text()
            .ok()?;
        serde_json::from_str(&text).ok()
    }

    /// The HIP-3 dex this Guard manages, found through its public interface
    /// only: the first dex in `/guard/status` `dexes` besides the main dex;
    /// its `meta` and mids through `/info` (a live market with a mid, and a
    /// halted one if any); and from `perpDexs` a dex the status does not
    /// list. `None` when Guard manages no HIP-3 dex (or says nothing of
    /// dexes: an older Guard).
    pub fn discover_hip3(&self) -> Option<crate::catalogue::Hip3Target> {
        let status = self.status()?;
        let managed: Vec<(u64, String)> = status
            .get("dexes")?
            .as_array()?
            .iter()
            .filter_map(|dex| Some((dex["index"].as_u64()?, dex["name"].as_str()?.to_owned())))
            .collect();
        let (dex, name) = managed.iter().find(|(index, _)| *index > 0)?.clone();
        let info = |body: Value| match self.post("/info", body.to_string().as_bytes()) {
            Reply::Json(value) => Some(value),
            _ => None,
        };
        let meta = info(serde_json::json!({"type": "meta", "dex": name}))?;
        let mids = info(serde_json::json!({"type": "allMids", "dex": name}))?;
        let universe = meta.get("universe")?.as_array()?;
        let delisted = |asset: &Value| asset["isDelisted"].as_bool() == Some(true);
        // Only a market the rules allow, so that the oversize case meets the
        // size rules and not the market list: from the `zr1_` code in the
        // status (base64url JSON, `markets`).
        let markets: Vec<String> = status
            .get("rules")
            .and_then(Value::as_str)
            .and_then(|code| code.strip_prefix("zr1_"))
            .and_then(|body| {
                use base64::Engine as _;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(body)
                    .ok()
            })
            .and_then(|json| serde_json::from_slice::<Value>(&json).ok())
            .and_then(|rules| {
                rules["markets"].as_array().map(|markets| {
                    markets
                        .iter()
                        .filter_map(|market| market.as_str().map(str::to_owned))
                        .collect()
                })
            })
            .unwrap_or_default();
        let allowed = |coin: &str| {
            markets
                .iter()
                .any(|market| market == coin || *market == format!("{name}:*"))
        };
        let (index, mid) = universe.iter().enumerate().find_map(|(index, asset)| {
            let coin = asset["name"].as_str()?;
            let mid = mids.get(coin)?.as_str()?;
            (!delisted(asset) && allowed(coin)).then(|| (index as u64, mid.to_owned()))
        })?;
        let halted = universe
            .iter()
            .position(delisted)
            .map(|index| crate::catalogue::Hip3Target::id(dex, index as u64));
        // A dex the status does not list: from perpDexs, or one past it.
        let listed = info(serde_json::json!({"type": "perpDexs"}))
            .and_then(|dexes| dexes.as_array().map(Vec::len))
            .unwrap_or(0) as u64;
        let other_dex = (1..listed.max(2) + 1)
            .find(|index| !managed.iter().any(|(managed, _)| managed == index))
            .unwrap_or(listed + 1);
        Some(crate::catalogue::Hip3Target {
            dex,
            name,
            index,
            asset: crate::catalogue::Hip3Target::id(dex, index),
            mid,
            other_dex,
            halted,
        })
    }

    fn slowloris_raw(&self) -> Reply {
        use std::io::Write;
        use std::net::TcpStream;
        let host = self
            .base
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let addr = if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:80")
        };
        match TcpStream::connect(&addr) {
            Ok(mut stream) => {
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                // Announce a large body, then send almost none of it and leave.
                let header = format!(
                    "POST /exchange HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n{{"
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(500));
                Reply::NoAnswer("slowloris: partial request sent and abandoned".to_owned())
            }
            Err(error) => Reply::Unreachable(error.to_string()),
        }
    }
}

impl Target for HttpTarget {
    fn open_orders(&mut self) -> Option<Vec<Value>> {
        let account = self.status()?.get("account")?.as_str()?.to_owned();
        let body =
            serde_json::to_vec(&serde_json::json!({"type": "frontendOpenOrders", "user": account}))
                .ok()?;
        match self.post("/info", &body) {
            Reply::Json(Value::Array(orders)) => Some(orders),
            _ => None,
        }
    }

    fn exchange(&mut self, body: &[u8]) -> Reply {
        self.post("/exchange", body)
    }

    fn info(&mut self, body: &[u8]) -> Reply {
        self.post("/info", body)
    }

    fn ws_action(&mut self, frame: &str) -> Reply {
        // Guard's WebSocket is loopback and plain (ws://). The workspace's
        // tungstenite has no `connect` feature, so do the TCP + handshake by
        // hand.
        use std::net::TcpStream;
        use tungstenite::Message;
        use tungstenite::client::IntoClientRequest;

        let host = self
            .base
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let addr = if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:80")
        };
        let ws_url = format!(
            "{}/ws",
            self.base
                .replacen("http://", "ws://", 1)
                .replacen("https://", "wss://", 1)
        );
        let request = match ws_url.as_str().into_client_request() {
            Ok(request) => request,
            Err(error) => return Reply::Unreachable(error.to_string()),
        };
        let tcp = match TcpStream::connect(&addr) {
            Ok(tcp) => tcp,
            Err(error) => return Reply::Unreachable(error.to_string()),
        };
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let mut socket = match tungstenite::client(request, tcp) {
            Ok((socket, _)) => socket,
            Err(error) => return Reply::NoAnswer(format!("handshake: {error}")),
        };
        if let Err(error) = socket.send(Message::text(frame.to_owned())) {
            return Reply::NoAnswer(error.to_string());
        }
        match socket.read() {
            Ok(Message::Text(text)) => serde_json::from_str::<Value>(text.as_str())
                .map(Reply::Json)
                .unwrap_or_else(|error| Reply::NoAnswer(error.to_string())),
            Ok(_) => Reply::NoAnswer("non-text WebSocket frame".to_owned()),
            Err(error) => Reply::NoAnswer(error.to_string()),
        }
    }

    fn raw_post(&mut self, path: &str, body: &[u8]) -> Reply {
        self.post(path, body)
    }

    fn slowloris(&mut self) -> Reply {
        self.slowloris_raw()
    }

    fn healthy(&mut self) -> bool {
        self.client
            .get(format!("{}/guard/status", self.base))
            .send()
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }

    fn label(&self) -> String {
        format!("running Guard at {}", self.base)
    }
}

// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's HTTP and WebSocket front: Hyperliquid's API on a loopback
//! address.
//!
//! - `POST /info`: passed through to the venue (a short cache for `meta`
//!   and the like).
//! - `POST /exchange`: through Guard ([`Guard::exchange`]).
//! - `GET /ws` (WebSocket, at most [`MAX_SOCKETS`] clients, messages up to
//!   1 MiB): subscriptions pass through to the venue's WebSocket; `info`
//!   posts are answered through Guard's passthrough (its cache and budget);
//!   `post` requests of type `action` go through Guard and are answered on
//!   the socket as the venue would.
//! - `GET /guard/status` and `GET /guard/events?since=N`: read-only, for
//!   the browser monitor (`docs/guard.md`, "Local status and events").
//! - `POST /guard/preview` (`{"action": {...}}`, unsigned): what Guard would
//!   decide now; read-only, nothing journaled or sent.
//! - `GET /healthz`: 200 while Guard serves (`zunder-guard health`).
//!
//! Requests whose `Host` is not a loopback name (beyond loopback: not a
//! private name, see `private_host`), or that carry an `Origin` that is
//! not loopback, are refused: a web page can neither read the status
//! through DNS rebinding nor send to Guard from another site. Bodies over
//! 1 MiB are refused.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{
        CONNECTION, CONTENT_TYPE, HOST, ORIGIN, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    WebSocketStream, connect_async,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{
    guard::{Clock, Guard},
    upstream::Upstream,
};

/// Largest request body accepted, and largest WebSocket message and frame.
pub const MAX_BODY: usize = 1 << 20;
/// How long Guard waits to reach the venue's WebSocket for a client.
const VENUE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// A WebSocket client that sends nothing for this long is closed (a ping
/// counts), so idle clients cannot hold every slot.
const SOCKET_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Aborts its tasks when dropped.
struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// How long a request body may take to arrive.
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Most WebSocket clients served at once.
pub const MAX_SOCKETS: usize = 8;

/// The WebSocket clients now connected.
static SOCKETS: AtomicUsize = AtomicUsize::new(0);

/// Counts one connected WebSocket client while it lives.
struct SocketSlot;

impl SocketSlot {
    fn take() -> Option<Self> {
        SOCKETS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |open| {
                (open < MAX_SOCKETS).then_some(open + 1)
            })
            .ok()
            .map(|_| SocketSlot)
    }
}

impl Drop for SocketSlot {
    fn drop(&mut self) {
        SOCKETS.fetch_sub(1, Ordering::SeqCst);
    }
}

type Reply = Response<Full<Bytes>>;

fn json_reply(status: StatusCode, value: &Value) -> Reply {
    let mut response = Response::new(Full::new(Bytes::from(value.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

fn error_reply(status: StatusCode, text: &str) -> Reply {
    json_reply(status, &json!({"error": text}))
}

/// Whether the `Host` header names this machine.
fn loopback_host(request: &Request<Incoming>) -> bool {
    let Some(host) = request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
    else {
        // HTTP/1.0 clients may send none: they reached a loopback socket.
        return true;
    };
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    matches!(name, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// Who may pull the kill switch over HTTP: this machine always (an IPv4
/// loopback reached over dual-stack included); when Guard listens beyond
/// loopback (in a container, behind a published port), also peers on a
/// private network. The client signature is what admits a kill, as for
/// `/exchange`; this check only narrows who can try (behind Docker's
/// proxy every remote peer looks like the private bridge gateway).
fn kill_peer_allowed(peer: SocketAddr, strict_host: bool) -> bool {
    let ip = peer.ip().to_canonical();
    if ip.is_loopback() {
        return true;
    }
    if strict_host {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            // fc00::/7 (unique local) and fe80::/10 (link local).
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Whether the `Host` header names no public DNS name, for a Guard that
/// listens beyond loopback (a container's private network): an IP
/// address, `localhost`, a single-label name (a container or service
/// name) or a name under `.internal` or `.local`. A page that rebinds a
/// public name to Guard's address sends that public name, and is refused.
fn private_host(request: &Request<Incoming>) -> bool {
    let Some(host) = request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
    else {
        return true;
    };
    private_host_name(host)
}

fn private_host_name(host: &str) -> bool {
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !name.ends_with(':') => {
            name
        }
        _ => host,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.starts_with('[') && name.ends_with(']') {
        return name[1..name.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .is_ok();
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    valid
        && (!name.contains('.')
            || name.ends_with(".internal")
            || name.ends_with(".local")
            || name == "localhost"
            || name.ends_with(".localhost"))
}

/// Whether the `Origin` header, if any, is this machine's. Browsers send
/// one on every cross-site request and WebSocket; bots mostly send none,
/// and some (Python's websocket-client) send the loopback URL they connect
/// to. A page on another site is refused before it reaches Guard.
fn loopback_origin(request: &Request<Incoming>) -> bool {
    let Some(origin) = request.headers().get(ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    let name = match rest.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => rest,
    };
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

/// Serve on `listener` until the task is dropped.
/// `strict_host`: refuse requests whose `Host` is not a loopback name
/// (when Guard listens on loopback only); a Guard that was told to listen
/// on another address (a container's private network) checks `Origin`
/// only.
pub async fn serve<U: Upstream, C: Clock>(
    guard: Arc<Guard<U, C>>,
    listener: TcpListener,
    strict_host: bool,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            // Out of file descriptors, say: do not spin.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let guard = guard.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let guard = guard.clone();
                async move { Ok::<_, Infallible>(route(guard, request, strict_host, peer).await) }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
                .ok();
        });
    }
}

/// Bind `addr` (a loopback address) and serve.
pub async fn bind<U: Upstream, C: Clock>(
    guard: Arc<Guard<U, C>>,
    addr: SocketAddr,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let strict_host = bound.ip().is_loopback();
    Ok((bound, tokio::spawn(serve(guard, listener, strict_host))))
}

async fn body_json(request: Request<Incoming>) -> Result<Value, Reply> {
    // A body that dribbles in is cut off: a slow client cannot hold a
    // request open (and Guard's attention) for long.
    let collected = tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(request.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| {
        error_reply(
            StatusCode::REQUEST_TIMEOUT,
            "the body did not arrive in time",
        )
    })?;
    let bytes = collected
        .map_err(|_| {
            error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the body is too large or broken",
            )
        })?
        .to_bytes();
    serde_json::from_slice(&bytes)
        .map_err(|_| error_reply(StatusCode::UNPROCESSABLE_ENTITY, "the body is not JSON"))
}

async fn route<U: Upstream, C: Clock>(
    guard: Arc<Guard<U, C>>,
    request: Request<Incoming>,
    strict_host: bool,
    peer: SocketAddr,
) -> Reply {
    if request.uri().path() == "/healthz" && request.method() == Method::GET {
        // Up while it recovers after a restart (protection runs; bots'
        // requests wait).
        let status = if guard.recovering() {
            "recovering"
        } else {
            "ok"
        };
        return json_reply(StatusCode::OK, &json!({"status": status}));
    }
    let host_ok = if strict_host {
        loopback_host(&request)
    } else {
        private_host(&request)
    };
    if !host_ok || !loopback_origin(&request) {
        return error_reply(
            StatusCode::FORBIDDEN,
            "Guard answers loopback hosts and origins only",
        );
    }
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    match (request.method().clone(), path.as_str()) {
        (Method::POST, "/info") => match body_json(request).await {
            Ok(body) => match guard.info(&body).await {
                Ok(value) => json_reply(StatusCode::OK, &value),
                Err(error) => error_reply(StatusCode::BAD_GATEWAY, &error.to_string()),
            },
            Err(reply) => reply,
        },
        (Method::POST, "/exchange") => match body_json(request).await {
            Ok(body) => json_reply(StatusCode::OK, &guard.exchange(body, "http").await),
            Err(reply) => reply,
        },
        (Method::POST, "/guard/preview") => match body_json(request).await {
            Ok(body) => json_reply(StatusCode::OK, &guard.preview(body).await),
            Err(reply) => reply,
        },
        (Method::GET, "/guard/status") => json_reply(StatusCode::OK, &guard.status().await),
        // The kill switch from a bot or agent: only from this machine, only
        // signed by a client key, and it can only pull.
        (Method::POST, "/guard/kill") if !kill_peer_allowed(peer, strict_host) => error_reply(
            StatusCode::FORBIDDEN,
            "the kill endpoint answers this machine (or, in a container, its private network) only",
        ),
        (Method::POST, "/guard/kill") => match body_json(request).await {
            Ok(body) => json_reply(StatusCode::OK, &guard.kill(&body).await),
            Err(reply) => reply,
        },
        (Method::GET, "/guard/decision") => {
            let param = |name: &str| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
                    .map(str::to_owned)
            };
            let nonce = param("nonce").and_then(|nonce| nonce.parse::<u64>().ok());
            let client = param("client");
            let client_ok = client.as_ref().is_none_or(|client| {
                client.len() == 42
                    && client.starts_with("0x")
                    && client[2..].bytes().all(|b| b.is_ascii_hexdigit())
            });
            match nonce {
                Some(nonce) if client_ok => match guard.decision(nonce, client.as_deref()).await {
                    Some(found) => json_reply(StatusCode::OK, &found),
                    None => error_reply(StatusCode::NOT_FOUND, "no decision with that nonce"),
                },
                _ => error_reply(
                    StatusCode::BAD_REQUEST,
                    "pass ?nonce=N and, recommended, &client=0x followed by 40 hex digits",
                ),
            }
        }
        (Method::GET, "/guard/events") => {
            let since = query
                .split('&')
                .find_map(|pair| pair.strip_prefix("since="))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            json_reply(StatusCode::OK, &guard.events(since).await)
        }
        (Method::GET, "/ws") => upgrade(guard, request),
        _ => error_reply(
            StatusCode::NOT_FOUND,
            "Guard serves /info, /exchange, /ws and /guard/*",
        ),
    }
}

fn upgrade<U: Upstream, C: Clock>(
    guard: Arc<Guard<U, C>>,
    mut request: Request<Incoming>,
) -> Reply {
    let is_upgrade = request
        .headers()
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let Some(key) = request.headers().get(SEC_WEBSOCKET_KEY).cloned() else {
        return error_reply(StatusCode::BAD_REQUEST, "a WebSocket upgrade is expected");
    };
    if !is_upgrade {
        return error_reply(StatusCode::BAD_REQUEST, "a WebSocket upgrade is expected");
    }
    let Some(slot) = SocketSlot::take() else {
        return error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "Guard serves at most 8 WebSocket clients at once",
        );
    };
    let accept = derive_accept_key(key.as_bytes());
    let upgrading = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let _slot = slot;
        if let Ok(upgraded) = upgrading.await {
            let config = WebSocketConfig::default()
                .max_message_size(Some(MAX_BODY))
                .max_frame_size(Some(MAX_BODY));
            let socket = WebSocketStream::from_raw_socket(
                TokioIo::new(upgraded),
                Role::Server,
                Some(config),
            )
            .await;
            websocket(guard, socket).await;
        }
    });
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(
        UPGRADE,
        hyper::header::HeaderValue::from_static("websocket"),
    );
    headers.insert(
        CONNECTION,
        hyper::header::HeaderValue::from_static("Upgrade"),
    );
    if let Ok(accept) = hyper::header::HeaderValue::from_str(&accept) {
        headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
    }
    response
}

/// One client's WebSocket: action posts through Guard, everything else to
/// and from the venue's WebSocket.
async fn websocket<U: Upstream, C: Clock, S>(guard: Arc<Guard<U, C>>, socket: WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut to_client, mut from_client) = socket.split();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Message>(256);
    // The venue's socket, if there is one (given up on after a few
    // seconds: a stalled venue must not hold the client's slot).
    let mut venue_tx = None;
    let mut tasks = Vec::new();
    let connected = match guard.upstream().ws_url() {
        Some(url) => tokio::time::timeout(VENUE_CONNECT_TIMEOUT, connect_async(url.as_str()))
            .await
            .ok()
            .and_then(Result::ok),
        None => None,
    };
    if let Some((venue, _)) = connected {
        let (mut sink, mut stream) = venue.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(256);
        venue_tx = Some(tx);
        tasks.push(tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
        }));
        let out = out_tx.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(Ok(message)) = stream.next().await {
                if out.send(message).await.is_err() {
                    break;
                }
            }
        }));
    }
    tasks.push(tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if to_client.send(message).await.is_err() {
                break;
            }
        }
    }));
    // The client loop ends on close, on error, or after a quiet stretch;
    // the venue's tasks end with it.
    let _ends_tasks = AbortOnDrop(tasks);
    while let Ok(Some(Ok(message))) =
        tokio::time::timeout(SOCKET_IDLE_TIMEOUT, from_client.next()).await
    {
        let text = match &message {
            Message::Text(text) => text.as_str().to_owned(),
            Message::Close(_) => break,
            _ => continue,
        };
        let parsed: Option<Value> = serde_json::from_str(&text).ok();
        let action_post = parsed.as_ref().filter(|value| {
            value.get("method").and_then(Value::as_str) == Some("post")
                && value.pointer("/request/type").and_then(Value::as_str) == Some("action")
        });
        if let Some(post) = action_post {
            let id = post.get("id").cloned().unwrap_or(Value::Null);
            let payload = post
                .pointer("/request/payload")
                .cloned()
                .unwrap_or(Value::Null);
            let reply = guard.exchange(payload, "ws").await;
            let answer = json!({
                "channel": "post",
                "data": {"id": id, "response": {"type": "action", "payload": reply}},
            });
            if out_tx
                .send(Message::text(answer.to_string()))
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        // Only market data and reads pass through to the venue's socket.
        let method = parsed
            .as_ref()
            .and_then(|value| value.get("method"))
            .and_then(Value::as_str);
        let info_or_data = match method {
            Some("subscribe" | "unsubscribe" | "ping") => true,
            Some("post") => {
                parsed
                    .as_ref()
                    .and_then(|value| value.pointer("/request/type"))
                    .and_then(Value::as_str)
                    == Some("info")
            }
            _ => false,
        };
        if !info_or_data {
            let answer = json!({"channel": "error", "data": "Guard passes subscribe, unsubscribe, ping and info posts to the venue, and judges action posts; nothing else"});
            if out_tx
                .send(Message::text(answer.to_string()))
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        // Info posts are answered through Guard's own passthrough, so they
        // share its cache and its budget with the venue.
        let info_post = parsed.as_ref().filter(|value| {
            value.get("method").and_then(Value::as_str) == Some("post")
                && value.pointer("/request/type").and_then(Value::as_str) == Some("info")
        });
        if let Some(post) = info_post {
            let payload = post
                .pointer("/request/payload")
                .cloned()
                .unwrap_or(Value::Null);
            let answer = match guard.info(&payload).await {
                Ok(response) => {
                    json!({"channel": "post", "data": {"id": post.get("id"), "response": {"type": "info", "payload": {"type": "info", "data": response}}}})
                }
                Err(error) => {
                    json!({"channel": "post", "data": {"id": post.get("id"), "response": {"type": "error", "payload": error.to_string()}}})
                }
            };
            if out_tx
                .send(Message::text(answer.to_string()))
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        match &venue_tx {
            Some(venue) => {
                if venue.send(Message::text(text)).await.is_err() {
                    break;
                }
            }
            None => {
                let answer = json!({"channel": "error", "data": "Guard has no connection to the venue's WebSocket"});
                if out_tx
                    .send(Message::text(answer.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{kill_peer_allowed, private_host_name};

    #[test]
    fn the_kill_endpoint_answers_this_machine_or_a_private_network() {
        let peer = |text: &str| text.parse::<std::net::SocketAddr>().unwrap();
        // Loopback, also as an IPv4-mapped address on a dual-stack socket.
        for loopback in ["127.0.0.1:5000", "[::1]:5000", "[::ffff:127.0.0.1]:5000"] {
            assert!(kill_peer_allowed(peer(loopback), true), "{loopback}");
            assert!(kill_peer_allowed(peer(loopback), false), "{loopback}");
        }
        // A Docker bridge gateway: only when Guard listens beyond loopback.
        assert!(!kill_peer_allowed(peer("172.17.0.1:5000"), true));
        assert!(kill_peer_allowed(peer("172.17.0.1:5000"), false));
        assert!(kill_peer_allowed(peer("[fd00::7]:5000"), false));
        // The public internet: never.
        for public in ["8.8.8.8:5000", "[2001:db8::1]:5000"] {
            assert!(!kill_peer_allowed(peer(public), false), "{public}");
        }
    }

    #[test]
    fn beyond_loopback_only_private_host_names_pass() {
        for host in [
            "127.0.0.1:8547",
            "10.0.0.7:8547",
            "[::1]:8547",
            "[fd00::7]",
            "localhost:8547",
            "guard:8547",
            "zunder-guard",
            "guard.railway.internal:8547",
            "guard.local",
        ] {
            assert!(private_host_name(host), "{host}");
        }
        for host in [
            "evil.example.com",
            "evil.example.com:8547",
            "rebind.attacker.net:8547",
            "",
            "a b",
        ] {
            assert!(!private_host_name(host), "{host}");
        }
    }
}

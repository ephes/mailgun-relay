//! HTTP surface (PLAN.md 2.2, 2.9): the 413 layer, the route table with
//! Starlette's matching, and the 404/405/307 fallbacks.
//!
//! Routing works on the percent-decoded path, as Starlette does, so one
//! dispatcher replaces axum's raw-path router.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::serve::IncomingStream;
use regex::Regex;
use tokio::net::TcpListener;

use crate::pipeline::{self, Relay};
use crate::pystr::py_strip;

pub struct AppState {
    pub relay: Arc<Relay>,
}

/// Both ends of the TCP connection (uvicorn's `client` and `server`): the
/// peer decides whether proxy headers are trusted, the local address is the
/// redirect netloc when the request has no usable `Host` header.
#[derive(Debug, Clone, Copy)]
pub struct Connection {
    pub remote: SocketAddr,
    pub local: Option<SocketAddr>,
}

impl Connected<IncomingStream<'_, TcpListener>> for Connection {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Connection {
            remote: *stream.remote_addr(),
            local: stream.io().local_addr().ok(),
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .fallback(dispatch)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            body_limit,
        ))
        .with_state(state)
}

fn json(status: StatusCode, body: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// Reject a declared `Content-Length` above `MAX_BODY_BYTES` on every path,
/// before routing and auth (`relay:app.py` `BodySizeLimitMiddleware`).
async fn body_limit(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    if let Some(value) = request.headers().get(header::CONTENT_LENGTH) {
        let declared = value
            .to_str()
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        let max = state.relay.settings.max_body_bytes;
        let too_large = declared.is_none_or(|n| i128::from(n) > i128::from(max));
        if too_large {
            return json(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"message":"Payload Too Large"}"#,
            );
        }
    }
    next.run(request).await
}

#[derive(Debug, Clone, PartialEq)]
enum Route {
    Health,
    /// `/v3/{domain}/messages` with the decoded path segment.
    Messages(String),
}

impl Route {
    fn allowed(&self) -> &'static [Method] {
        match self {
            // FastAPI does not add HEAD to a GET route.
            Route::Health => &[Method::GET],
            Route::Messages(_) => &[Method::POST],
        }
    }
}

/// Starlette matches `^<pattern>$` with Python's `re`, where `$` also
/// matches before one final newline; `{domain}` is `[^/]+`.
fn match_route(path: &str) -> Option<Route> {
    let path = path.strip_suffix('\n').unwrap_or(path);
    if path == "/health" {
        return Some(Route::Health);
    }
    let domain = path.strip_prefix("/v3/")?.strip_suffix("/messages")?;
    (!domain.is_empty() && !domain.contains('/')).then(|| Route::Messages(domain.to_owned()))
}

async fn dispatch(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let path = percent_decode(request.uri().path());
    match match_route(&path) {
        Some(route) if route.allowed().contains(request.method()) => match route {
            Route::Health => json(StatusCode::OK, r#"{"status":"ok"}"#),
            Route::Messages(domain) => {
                let (parts, body) = request.into_parts();
                pipeline::post_messages(Arc::clone(&state.relay), domain, parts.headers, body).await
            }
        },
        Some(route) => {
            let allow = route
                .allowed()
                .iter()
                .map(Method::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let mut response = json(
                StatusCode::METHOD_NOT_ALLOWED,
                r#"{"detail":"Method Not Allowed"}"#,
            );
            if let Ok(value) = HeaderValue::from_str(&allow) {
                response.headers_mut().insert(header::ALLOW, value);
            }
            response
        }
        None => {
            // Starlette `redirect_slashes`: any method, any route.
            let stripped = path.trim_end_matches('/');
            if path != "/" && path.len() != stripped.len() && match_route(stripped).is_some() {
                redirect(&request, stripped)
            } else {
                json(StatusCode::NOT_FOUND, r#"{"detail":"Not Found"}"#)
            }
        }
    }
}

/// `RedirectResponse(str(URL(scope=redirect_scope)))`: scheme (uvicorn's
/// proxy headers from 127.0.0.1), netloc from a well-formed `Host` header or
/// the connection's local address, the decoded path, the raw query, then
/// `quote`.
fn redirect(request: &Request, path: &str) -> Response {
    let connection = request
        .extensions()
        .get::<ConnectInfo<Connection>>()
        .map(|info| info.0);
    let mut scheme = "http".to_owned();
    let forwarded: Vec<&HeaderValue> = request
        .headers()
        .get_all("x-forwarded-proto")
        .iter()
        .collect();
    if connection.is_some_and(|c| c.remote.ip() == Ipv4Addr::LOCALHOST)
        && let [value] = forwarded.as_slice()
    {
        let value: String = value.as_bytes().iter().map(|&b| char::from(b)).collect();
        let value = py_strip(&value);
        if ["http", "https", "ws", "wss"].contains(&value) {
            scheme = value.to_owned();
        }
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| HOST_RE.is_match(h));
    let netloc = match (host, connection.and_then(|c| c.local)) {
        (Some(host), _) => Some(host.to_owned()),
        (None, Some(local)) => {
            let default_port = if matches!(scheme.as_str(), "https" | "wss") {
                443
            } else {
                80
            };
            let (ip, port) = (local.ip(), local.port());
            Some(if port == default_port {
                ip.to_string()
            } else {
                format!("{ip}:{port}")
            })
        }
        (None, None) => None,
    };
    let mut url = match netloc {
        Some(netloc) => format!("{scheme}://{netloc}{path}"),
        None => path.to_owned(),
    };
    if let Some(query) = request.uri().query().filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    if let Ok(value) = HeaderValue::from_str(&quote(&url)) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// Starlette's `_HOST_RE` (case-insensitive); `URL(scope=...)` ignores other
/// `Host` values.
static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-zA-Z0-9.-]+|\[[a-fA-F0-9]*:[a-fA-F0-9.:]+\])(?::[0-9]+)?$").unwrap()
});

/// `urllib.parse.unquote` (UTF-8, errors replaced), as uvicorn decodes paths.
fn percent_decode(path: &str) -> String {
    let hex = |b: Option<&u8>| b.and_then(|&b| char::from(b).to_digit(16));
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(high), Some(low)) => {
                out.push((high << 4 | low) as u8);
                i += 3;
            }
            (byte, _, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `urllib.parse.quote(url, safe=":/%#?=@[]!$&'()*+,;")` (RedirectResponse).
fn quote(url: &str) -> String {
    const SAFE: &[u8] = b":/%#?=@[]!$&'()*+,;_.-~";
    let mut out = String::with_capacity(url.len());
    for &b in url.as_bytes() {
        if b.is_ascii_alphanumeric() || SAFE.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use tower::ServiceExt;

    use super::*;

    async fn call(
        request: axum::http::Request<Body>,
    ) -> (StatusCode, Vec<(String, String)>, String) {
        let settings = crate::config::Settings {
            max_body_bytes: 100,
            ..crate::config::Settings::from_env([]).unwrap()
        };
        let state = Arc::new(AppState {
            relay: pipeline::tests::relay(settings).0,
        });
        let response = router(state).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
            .collect();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn request(method: &str, uri: &str) -> axum::http::request::Builder {
        axum::http::Request::builder().method(method).uri(uri)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn health_and_fallbacks() {
        let (status, headers, body) =
            call(request("GET", "/health").body(Body::empty()).unwrap()).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, r#"{"status":"ok"}"#)
        );
        assert_eq!(header(&headers, "content-type"), Some("application/json"));

        for method in ["HEAD", "POST", "DELETE"] {
            let (status, headers, body) =
                call(request(method, "/health").body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(header(&headers, "allow"), Some("GET"));
            if method != "HEAD" {
                assert_eq!(body, r#"{"detail":"Method Not Allowed"}"#);
            }
        }
        for path in [
            "/",
            "/healthz",
            "/v3/mg.example/messages.mime",
            "/v3//messages",
            "/HEALTH",
        ] {
            let (status, _, body) = call(request("GET", path).body(Body::empty()).unwrap()).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::NOT_FOUND, r#"{"detail":"Not Found"}"#),
                "{path}"
            );
        }
        // Starlette routes on the decoded path; `$` also matches before "\n".
        for path in ["/%68ealth", "/health%0A"] {
            let (status, _, _) = call(request("GET", path).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn trailing_slash_redirects() {
        let cases = [
            (
                "/health/",
                "mailgun.example",
                None,
                "http://mailgun.example/health",
            ),
            (
                "/health//?a=b%20c",
                "h:8085",
                None,
                "http://h:8085/health?a=b%20c",
            ),
            ("/health/", "bad host", None, "http://10.1.2.3:8085/health"),
            ("/health/", "h", Some("https"), "https://h/health"),
            ("/health/", "h", Some(" wss "), "wss://h/health"),
            ("/health/", "h", Some("ftp"), "http://h/health"),
        ];
        for (path, host, proto, location) in cases {
            for peer in ["127.0.0.1:5000", "10.0.0.1:5000"] {
                let mut builder = request("POST", path).header("host", host);
                if let Some(proto) = proto {
                    builder = builder.header("x-forwarded-proto", proto);
                }
                let mut req = builder.body(Body::empty()).unwrap();
                let peer: SocketAddr = peer.parse().unwrap();
                let local = Some("10.1.2.3:8085".parse().unwrap());
                req.extensions_mut().insert(ConnectInfo(Connection {
                    remote: peer,
                    local,
                }));
                let (status, headers, body) = call(req).await;
                let expected = if peer.ip().is_loopback() {
                    location.to_owned()
                } else {
                    location
                        .replacen("https:", "http:", 1)
                        .replacen("wss:", "http:", 1)
                };
                assert_eq!(status, StatusCode::TEMPORARY_REDIRECT, "{path}");
                assert_eq!(
                    header(&headers, "location"),
                    Some(expected.as_str()),
                    "{path} {peer}"
                );
                assert_eq!(body, "");
            }
        }
        let (status, _, _) = call(request("GET", "/x/").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Without connection information (no `server` in the scope) Starlette
        // redirects to the path alone.
        let req = request("GET", "/health/?q=1").body(Body::empty()).unwrap();
        let (_, headers, _) = call(req).await;
        assert_eq!(header(&headers, "location"), Some("/health?q=1"));
    }

    #[tokio::test]
    async fn declared_length_over_the_limit_is_413_everywhere() {
        for path in ["/health", "/nowhere", "/health/"] {
            for (length, expected) in [("100", None), ("101", Some(StatusCode::PAYLOAD_TOO_LARGE))]
            {
                let req = request("GET", path)
                    .header("content-length", length)
                    .body(Body::from("x".repeat(length.parse().unwrap())))
                    .unwrap();
                let (status, _, body) = call(req).await;
                if let Some(expected) = expected {
                    assert_eq!(
                        (status, body.as_str()),
                        (expected, r#"{"message":"Payload Too Large"}"#),
                        "{path}"
                    );
                } else {
                    assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
                }
            }
        }
    }

    #[test]
    fn host_header_validation() {
        for ok in [
            "mailgun.example",
            "a.b:8085",
            "[::1]:80",
            "[fe80::1]",
            "LOCALHOST",
        ] {
            assert!(HOST_RE.is_match(ok), "{ok}");
        }
        for bad in [
            "",
            "a b",
            "a:",
            "a:b",
            "[::1",
            "ü.de",
            "a.b:80:80",
            "[x::1]",
        ] {
            assert!(!HOST_RE.is_match(bad), "{bad}");
        }
    }

    #[test]
    fn decoding_and_quoting() {
        assert_eq!(
            percent_decode("/v3/a%20b/%2Fx%zz%c3%a4%ff"),
            "/v3/a b//x%zzä\u{fffd}"
        );
        assert_eq!(
            quote("http://h/a b/ä?x=1&y=<"),
            "http://h/a%20b/%C3%A4?x=1&y=%3C"
        );
        assert_eq!(match_route("/health\n"), Some(Route::Health));
        assert_eq!(match_route("/health\n\n"), None);
    }
}

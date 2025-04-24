use crate::Result;
use crate::context::SecureRpcContext;
use crate::error::Error;
use axum::{
    Router,
    body::Body,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, Method, Request, StatusCode, Uri,
        header::{CONNECTION, UPGRADE},
    },
    response::{IntoResponse, Response},
    routing::{any, get},
};
use futures::{sink::SinkExt, stream::StreamExt};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::upgrade::Upgraded;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetRequestHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{Span, debug, error, info, warn};

/// Starts the main RPC gateway server.
pub async fn start_rpc_gateway(ctx: Arc<SecureRpcContext>) -> Result<()> {
    let listen_addr = ctx.config().rpc.listen_addr;
    let proxy_url = ctx.config().rpc.proxy_to_url.clone();
    let max_body_size = ctx.config().rpc.max_body_size_bytes;
    let request_timeout = Duration::from_secs(ctx.config().rpc.request_timeout_secs);

    info!(%listen_addr, %proxy_url, "Starting RPC gateway");

    let http_client = Client::builder(TokioExecutor::new()).build_http();

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    let app_state = RpcGatewayState {
        ctx,
        http_client,
        proxy_url,
    };

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    axum::serve(
        listener,
        Router::new()
            .route("/", any(rpc_handler))
            .route("/*path", any(rpc_handler))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO)),
            )
            .layer(cors)
            .layer(tower::limit::RequestBodyLimitLayer::new(max_body_size))
            .layer(tower::timeout::TimeoutLayer::new(request_timeout))
            .with_state(app_state)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[derive(Clone)]
struct RpcGatewayState {
    ctx: Arc<SecureRpcContext>,
    http_client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    proxy_url: url::Url,
}

/// Main handler for both HTTP and WebSocket upgrade requests.
async fn rpc_handler(
    State(state): State<RpcGatewayState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: Option<WebSocketUpgrade>,
    headers: HeaderMap,
    req: Request<Body>,
) -> Result<Response, Error> {
    debug!(client_ip = %addr.ip(), method = %req.method(), uri = %req.uri(), "Received request");

    // --- Firewall Check ---
    if !state.ctx.firewall.is_allowed(&addr.ip()).await {
        warn!(client_ip = %addr.ip(), "Blocked request due to firewall rules");
        return Ok((StatusCode::FORBIDDEN, "Access Denied").into_response());
    }
    // Potential future check: Use headers.get("Authorization") to extract a token,
    // look up the associated account, and call ctx.firewall.is_account_allowed(&account).await

    // --- WebSocket Handling ---
    if let Some(ws) = ws {
        // Check if it's a WebSocket upgrade request
        if headers.contains_key(UPGRADE) && headers.contains_key(CONNECTION) {
            // TODO CHECK header value properly
            debug!(client_ip = %addr.ip(), "Handling WebSocket upgrade request");
            return Ok(ws.on_upgrade(move |socket| {
                handle_websocket(socket, state.ctx, state.proxy_url.clone(), addr)
            }));
        }
    }

    // --- HTTP Proxy Handling ---
    debug!(client_ip = %addr.ip(), "Proxying HTTP request");
    proxy_http_request(state, req).await
}

/// Proxies a standard HTTP request to the backend RPC node.
async fn proxy_http_request(state: RpcGatewayState, req: Request<Body>) -> Result<Response, Error> {
    let (mut parts, body) = req.into_parts();

    // Construct the target URI
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let target_uri_str = format!(
        "{}{}",
        state.proxy_url.as_str().trim_end_matches('/'),
        path_and_query
    );

    let target_uri = match target_uri_str.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            error!(error = %e, uri = %target_uri_str, "Failed to parse target URI");
            return Ok((StatusCode::BAD_REQUEST, "Invalid target URI").into_response());
        }
    };

    parts.uri = target_uri;
    // Clear host header to avoid mismatches
    parts.headers.remove(hyper::header::HOST);

    let body_bytes = match body.collect().await {
        //.map_err(Error::HyperError)? {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!(error = %e, "Failed to read request body");
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read request body",
            )
                .into_response());
        }
    };

    let proxy_req = Request::from_parts(parts, Full::new(body_bytes)); //.map_err(Error::HttpError)?;

    match state.http_client.request(proxy_req).await {
        Ok(resp) => Ok(resp.map(|b| b.map_err(|e| Error::HyperUtilError(e)).boxed())), // Adjusted error mapping
        Err(e) => {
            error!(error = %e, "Failed to proxy request");
            Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Proxy error: {}", e),
            )
                .into_response())
        }
    }
}

/// Handles a WebSocket connection, proxying messages between client and backend.
async fn handle_websocket(
    mut client_socket: WebSocket,
    ctx: Arc<SecureRpcContext>,
    proxy_url: url::Url,
    client_addr: SocketAddr,
) {
    let host = proxy_url.host_str().unwrap_or("localhost");
    let port = proxy_url.port_or_known_default().unwrap_or(80); // Default WS port
    let target_addr = format!("{}:{}", host, port);

    debug!(%client_addr, %target_addr, "Attempting to establish backend WebSocket connection");

    let upstream_connection = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!(error = %e, %target_addr, "Failed to connect to backend WebSocket server");
            let _ = client_socket
                .send(Message::Close(Some({
                    axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::ERROR,
                        reason: "Backend connection failed".into(),
                    }
                })))
                .await;
            return;
        }
    };

    let ws_scheme = if proxy_url.scheme() == "https" || proxy_url.scheme() == "wss" {
        "wss"
    } else {
        "ws"
    };
    let ws_url = format!("{}://{}{}", ws_scheme, host, proxy_url.path());

    let (mut backend_socket_tx, mut backend_socket_rx) =
        match tokio_tungstenite::client_async(&ws_url, upstream_connection).await {
            Ok((stream, _response)) => {
                debug!(%client_addr, %target_addr, "Backend WebSocket connection established");
                stream.split()
            }
            Err(e) => {
                error!(error = %e, %ws_url, "WebSocket handshake with backend failed");
                let _ = client_socket
                    .send(Message::Close(Some({
                        axum::extract::ws::CloseFrame {
                            code: axum::extract::ws::close_code::ERROR,
                            reason: "Backend handshake failed".into(),
                        }
                    })))
                    .await;
                return;
            }
        };

    // Forward messages from client to backend
    let client_to_backend = async {
        while let Some(msg) = client_socket.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Text(text))
                        .await
                        .is_err()
                    {
                        warn!(%client_addr, "Failed sending Text message to backend, connection likely closed");
                        break;
                    }
                }
                Ok(Message::Binary(bin)) => {
                    if backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Binary(bin))
                        .await
                        .is_err()
                    {
                        warn!(%client_addr, "Failed sending Binary message to backend, connection likely closed");
                        break;
                    }
                }
                Ok(Message::Ping(ping)) => {
                    if backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Ping(ping))
                        .await
                        .is_err()
                    {
                        warn!(%client_addr, "Failed sending Ping message to backend, connection likely closed");
                        break;
                    }
                }
                Ok(Message::Pong(pong)) => {
                    if backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Pong(pong))
                        .await
                        .is_err()
                    {
                        warn!(%client_addr, "Failed sending Pong message to backend, connection likely closed");
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    debug!(%client_addr, "Client closed WebSocket connection gracefully");
                    let _ = backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                    break;
                }
                Err(e) => {
                    warn!(%client_addr, error = %e, "Error receiving message from client");
                    let _ = backend_socket_tx
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                    break;
                }
            }
        }
        debug!(%client_addr, "Client-to-Backend WebSocket forwarding task finished");
    };

    // Forward messages from backend to client
    let backend_to_client = async {
        while let Some(msg) = backend_socket_rx.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    if client_socket.send(Message::Text(text)).await.is_err() {
                        warn!(%client_addr, "Failed sending Text message to client, connection likely closed");
                        break;
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Binary(bin)) => {
                    if client_socket.send(Message::Binary(bin)).await.is_err() {
                        warn!(%client_addr, "Failed sending Binary message to client, connection likely closed");
                        break;
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Ping(ping)) => {
                    if client_socket.send(Message::Ping(ping)).await.is_err() {
                        warn!(%client_addr, "Failed sending Ping message to client, connection likely closed");
                        break;
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Pong(pong)) => {
                    if client_socket.send(Message::Pong(pong)).await.is_err() {
                        warn!(%client_addr, "Failed sending Pong message to client, connection likely closed");
                        break;
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(close)) => {
                    debug!(%client_addr, "Backend closed WebSocket connection gracefully");
                    let _ = client_socket
                        .send(Message::Close(close.map(|cf| {
                            axum::extract::ws::CloseFrame {
                                code: cf.code.into(),
                                reason: cf.reason,
                            }
                        })))
                        .await;
                    break;
                }
                Ok(tokio_tungstenite::tungstenite::Message::Frame(_)) => {
                    // Raw frames usually indicate lower-level control, ignore for basic proxying
                    debug!(%client_addr, "Ignoring raw WebSocket frame from backend");
                }
                Err(e) => {
                    warn!(%client_addr, error = %e, "Error receiving message from backend");
                    let _ = client_socket
                        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                            code: axum::extract::ws::close_code::ERROR,
                            reason: "Backend error".into(),
                        })))
                        .await;
                    break;
                }
            }
        }
        debug!(%client_addr, "Backend-to-Client WebSocket forwarding task finished");
    };

    // Run both forwarding tasks concurrently
    tokio::select! {
        _ = client_to_backend => { info!(%client_addr, "Client WebSocket connection closed."); }
        _ = backend_to_client => { info!(%client_addr, "Backend WebSocket connection closed."); }
    }
}

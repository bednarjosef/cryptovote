//! HTTP front of the issuer: enrollment with the (mock) eID backend, the
//! registry files, and publication to nodes.

use crate::{Issuer, parse_commitment};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cv_client::light::NodeClient;
use cv_core::crypto::field::fr_to_bytes;
use cv_core::registry::encode_leaves;
use cv_core::wire::{EnrollRequest, EnrollResponse};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct IssuerServer {
    pub issuer: Mutex<Issuer>,
    pub nodes: Vec<String>,
    pub state_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct StatusJson {
    public_key: String,
    epoch: u64,
    leaf_count: u64,
    root: String,
}

pub fn router(state: Arc<IssuerServer>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/enroll", post(enroll))
        .route("/v1/registry", get(registry))
        .route("/v1/publish", post(publish))
        .with_state(state)
}

async fn status(State(st): State<Arc<IssuerServer>>) -> Json<StatusJson> {
    let i = st.issuer.lock().unwrap();
    Json(StatusJson {
        public_key: hex::encode(i.public_key()),
        epoch: i.epoch(),
        leaf_count: i.leaf_count(),
        root: hex::encode(fr_to_bytes(&i.tree().root())),
    })
}

async fn enroll(State(st): State<Arc<IssuerServer>>, Json(req): Json<EnrollRequest>) -> Response {
    let commitment = match parse_commitment(&req.commitment) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let resp = {
        let mut i = st.issuer.lock().unwrap();
        // TRUST: Issuer decides who is one eligible person (whitepaper §2).
        match i.enroll(&req.eid, commitment) {
            Ok((index, replaced)) => {
                if let Some(p) = &st.state_path {
                    let _ = i.save(p);
                }
                EnrollResponse {
                    index,
                    epoch: i.epoch(),
                    root: hex::encode(fr_to_bytes(&i.tree().root())),
                    replaced,
                }
            }
            Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
        }
    };
    publish_all(&st).await;
    Json(resp).into_response()
}

async fn registry(State(st): State<Arc<IssuerServer>>) -> Response {
    let i = st.issuer.lock().unwrap();
    let mut body = i.snapshot().encode();
    body.extend_from_slice(&encode_leaves(i.leaves()));
    ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response()
}

async fn publish(State(st): State<Arc<IssuerServer>>) -> StatusCode {
    publish_all(&st).await;
    StatusCode::OK
}

/// Push the current snapshot and leaves to every configured node.
pub async fn publish_all(st: &IssuerServer) {
    let (snapshot, leaves) = {
        let i = st.issuer.lock().unwrap();
        (i.snapshot(), i.leaves().to_vec())
    };
    for n in &st.nodes {
        if let Err(e) = NodeClient::new(n.clone())
            .post_registry(&snapshot, &leaves)
            .await
        {
            tracing::warn!(node = %n, "registry publication failed: {e}");
        }
    }
}

pub struct IssuerHandle {
    pub addr: SocketAddr,
    pub state: Arc<IssuerServer>,
    task: tokio::task::JoinHandle<()>,
}

impl IssuerHandle {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(self) {
        self.task.abort();
    }
}

pub async fn start(
    issuer: Issuer,
    listen: SocketAddr,
    nodes: Vec<String>,
    state_path: Option<PathBuf>,
) -> anyhow::Result<IssuerHandle> {
    let state = Arc::new(IssuerServer {
        issuer: Mutex::new(issuer),
        nodes,
        state_path,
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let app = router(state.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(IssuerHandle { addr, state, task })
}

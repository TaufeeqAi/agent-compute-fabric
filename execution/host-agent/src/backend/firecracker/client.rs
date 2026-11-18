//! Minimal HTTP/1.1-over-UDS client for Firecracker's API (hyper 1.x).
//!
//! One short-lived connection per request keeps failure semantics simple: there is no pooled
//! connection whose half-dead state could be mistaken for the VMM's.

use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{net::UnixStream, time::timeout};

use super::models::FcError;
use crate::{
    error::{AcfError, FailureClass},
    guest::UdsTarget,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcCallError {
    /// Could not connect: the request never reached the VMM. **No side effect.**
    Connect(String),
    /// Connected, but the exchange failed or timed out: the request may have been applied.
    Exchange(String),
    /// Firecracker answered with an error status. A definite, explained rejection.
    Status { status: u16, fault: String },
}

impl FcCallError {
    /// Convert for the caller. `mutating` says whether the endpoint changes VMM state; an
    /// ambiguous exchange failure on a mutating endpoint must be reconciled, not retried blindly.
    pub fn into_acf(self, what: &str, mutating: bool) -> AcfError {
        match self {
            Self::Connect(m) => AcfError::new(FailureClass::DependencyUnavailable, format!("{what}: cannot reach the VMM API: {m}")),
            Self::Exchange(m) => {
                let e = AcfError::new(FailureClass::Timeout, format!("{what}: API exchange failed: {m}"));
                if mutating { e.with_possible_side_effect() } else { e }
            }
            Self::Status { status, fault } => {
                let class = if status == 400 { FailureClass::IncompatibleRuntime } else { FailureClass::DependencyUnavailable };
                // A rejected request did not apply, except that a rejected *snapshot/load* may have
                // consumed the process; callers that care (restore) treat load failures as Possible.
                AcfError::new(class, format!("{what}: Firecracker returned {status}: {fault}"))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FcClient {
    target: UdsTarget,
    call_timeout: Duration,
}

impl FcClient {
    pub fn new(target: UdsTarget, call_timeout: Duration) -> Self {
        Self { target, call_timeout }
    }

    async fn raw(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), FcCallError> {
        let stream = timeout(self.call_timeout, UnixStream::connect(self.target.resolve()))
            .await
            .map_err(|_| FcCallError::Connect("connect timed out".into()))?
            .map_err(|e| FcCallError::Connect(e.to_string()))?;
        let exchange = async {
            let (mut sender, conn) = http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut b = Request::builder().method(method).uri(path).header("Host", "localhost").header("Accept", "application/json");
            let payload = match body {
                Some(v) => {
                    b = b.header("Content-Type", "application/json");
                    Bytes::from(v)
                }
                None => Bytes::new(),
            };
            let req = b.body(Full::new(payload)).map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let collected = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES).collect().await.map_err(|e| e.to_string())?;
            driver.abort();
            Ok::<_, String>((status, collected.to_bytes().to_vec()))
        };
        timeout(self.call_timeout, exchange).await.map_err(|_| FcCallError::Exchange("timed out".into()))?.map_err(FcCallError::Exchange)
    }

    async fn send<B: Serialize>(&self, method: Method, path: &str, body: Option<&B>) -> Result<Vec<u8>, FcCallError> {
        let payload = match body {
            Some(b) => Some(serde_json::to_vec(b).map_err(|e| FcCallError::Exchange(format!("cannot encode request: {e}")))?),
            None => None,
        };
        let (status, bytes) = self.raw(method, path, payload).await?;
        if (200..300).contains(&status) {
            Ok(bytes)
        } else {
            let fault = serde_json::from_slice::<FcError>(&bytes)
                .map(|e| e.fault_message)
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).chars().take(300).collect());
            Err(FcCallError::Status { status, fault })
        }
    }

    pub async fn put<B: Serialize>(&self, path: &str, body: &B) -> Result<(), FcCallError> {
        self.send(Method::PUT, path, Some(body)).await.map(|_| ())
    }

    pub async fn patch<B: Serialize>(&self, path: &str, body: &B) -> Result<(), FcCallError> {
        self.send(Method::PATCH, path, Some(body)).await.map(|_| ())
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, FcCallError> {
        let bytes = self.send::<()>(Method::GET, path, None).await?;
        serde_json::from_slice(&bytes).map_err(|e| FcCallError::Exchange(format!("undecodable response from {path}: {e}")))
    }
}

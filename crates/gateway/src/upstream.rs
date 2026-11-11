use async_trait::async_trait;
use std::sync::Mutex;

use crate::ApiError;

pub struct Outbound {
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub header_name: String,
    pub header_value: String,
}

pub struct Inbound {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait Upstream: Send + Sync {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError>;
}

/// Test double that records the injected header and returns a fixed body.
pub struct RecordingUpstream {
    pub last_header: Mutex<Option<(String, String)>>,
}

impl RecordingUpstream {
    pub fn new() -> Self {
        Self {
            last_header: Mutex::new(None),
        }
    }

    pub fn last_value(&self) -> Option<String> {
        self.last_header
            .lock()
            .expect("upstream lock")
            .as_ref()
            .map(|(_, value)| value.clone())
    }
}

impl Default for RecordingUpstream {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Upstream for RecordingUpstream {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError> {
        *self.last_header.lock().expect("upstream lock") =
            Some((request.header_name, request.header_value));
        Ok(Inbound {
            status: 200,
            body: b"upstream-ok".to_vec(),
        })
    }
}

/// Used by the dev binary. Inject returns 502 until a real upstream is configured.
pub struct UnconfiguredUpstream;

#[async_trait]
impl Upstream for UnconfiguredUpstream {
    async fn forward(&self, _request: Outbound) -> Result<Inbound, ApiError> {
        Err(ApiError::UpstreamFailed)
    }
}

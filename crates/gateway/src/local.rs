//! Local channel for env and header delivery.
//!
//! The socket directory is mode `0700` and the socket is mode `0600`.
//! A connection is accepted only when the peer uid matches this process.
//! The public TCP listener never sets `local_channel`. The socket speaks
//! the same HTTP routes as the public listener.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::service::Gateway;

pub fn peer_uid_allowed(peer_uid: u32, self_uid: u32) -> bool {
    peer_uid == self_uid
}

pub fn socket_path(directory: &Path) -> PathBuf {
    directory.join("credentials.sock")
}

/// Bind `directory/credentials.sock` and serve the local router.
pub async fn serve_local(gateway: Arc<Gateway>, directory: PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(&directory)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let path = socket_path(&directory);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let app = crate::http::router_local(gateway);
    axum::serve(SameUserListener { inner: listener }, app).await
}

fn peer_ok(stream: &UnixStream) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    let self_uid = nix::unistd::Uid::current().as_raw();
    peer_uid_allowed(cred.uid(), self_uid)
}

struct SameUserListener {
    inner: UnixListener,
}

impl axum::serve::Listener for SameUserListener {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) if peer_ok(&stream) => return (stream, addr),
                Ok(_) => continue,
                Err(err) => {
                    tracing::error!(error = %err, "local channel accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::{peer_uid_allowed, serve_local, socket_path};
    use crate::b64::b64std_encode;
    use crate::service::{generate_dpop, Clock, Gateway};
    use crate::store::MemoryStore;
    use crate::RecordingUpstream;
    use credentials_crypto::{DevPolicy, MemoryRootKeys};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    #[test]
    fn only_the_same_uid_is_accepted() {
        assert!(peer_uid_allowed(1000, 1000));
        assert!(!peer_uid_allowed(1000, 0));
    }

    async fn http(path: &std::path::Path, request: &str) -> String {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn status_of(response: &str) -> u16 {
        response.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    fn json_body(response: &str) -> serde_json::Value {
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        serde_json::from_str(body.trim()).unwrap()
    }

    #[tokio::test]
    async fn same_user_socket_returns_env_object() {
        let dir = std::env::temp_dir().join(format!("credentials-local-{}", uuid::Uuid::now_v7()));
        let gateway = Arc::new(
            Gateway::new(
                Arc::new(MemoryStore::new()),
                Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
                Arc::new(RecordingUpstream::new()),
                Arc::new(Clock),
            )
            .unwrap(),
        );
        let serving = Arc::clone(&gateway);
        let directory = dir.clone();
        tokio::spawn(async move {
            serve_local(serving, directory).await.unwrap();
        });
        let sock = socket_path(&dir);
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(sock_mode, 0o600);

        let created = json_body(
            &http(
                &sock,
                "POST /v1/workspaces HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await,
        );
        let credential = created["credential"].as_str().unwrap();
        let value = b64std_encode(b"sk-socket");
        let secret_body = serde_json::json!({
            "name": "prod/openai/api_key",
            "value": value,
            "policy": {
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
                "env_name": "OPENAI_API_KEY",
                "hosts": ["api.openai.com"],
                "allow_proxy": false,
                "allow_header": true,
                "allow_env": true
            }
        });
        let secret_bytes = serde_json::to_vec(&secret_body).unwrap();
        let stored = http(
            &sock,
            &format!(
                "POST /v1/secrets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                secret_bytes.len(),
                String::from_utf8(secret_bytes).unwrap()
            ),
        )
        .await;
        assert_eq!(status_of(&stored), 200);

        let dpop = generate_dpop().unwrap();
        let agent_body = serde_json::json!({"display_name": "runner"});
        let agent_bytes = serde_json::to_vec(&agent_body).unwrap();
        let agent = json_body(
            &http(
                &sock,
                &format!(
                    "POST /v1/agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    agent_bytes.len(),
                    String::from_utf8(agent_bytes).unwrap()
                ),
            )
            .await,
        );
        let session_body = serde_json::json!({
            "agent_id": agent["id"],
            "scopes": ["secret:inject:prod/openai/api_key"],
            "ttl_seconds": 60,
            "dpop_public_b64": dpop.public_b64(),
        });
        let session_bytes = serde_json::to_vec(&session_body).unwrap();
        let session = json_body(
            &http(
                &sock,
                &format!(
                    "POST /v1/agent-sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    session_bytes.len(),
                    String::from_utf8(session_bytes).unwrap()
                ),
            )
            .await,
        );
        let token = session["token"].as_str().unwrap();
        let htu = "http://localhost/v1/inject";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let proof = dpop.proof("POST", htu, token, now, "socket-env");
        let inject_body = serde_json::json!({
            "secret": "prod/openai/api_key",
            "delivery": "env"
        });
        let inject_bytes = serde_json::to_vec(&inject_body).unwrap();
        let injected = http(
            &sock,
            &format!(
                "POST /v1/inject HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nDPoP: {proof}\r\nx-dpop-htu: {htu}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                inject_bytes.len(),
                String::from_utf8(inject_bytes).unwrap()
            ),
        )
        .await;
        assert_eq!(status_of(&injected), 200, "{injected}");
        let payload = json_body(&injected);
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            payload["body"].as_str().unwrap(),
        )
        .unwrap();
        let object: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(object["env_name"], "OPENAI_API_KEY");
        assert_eq!(object["value"], "sk-socket");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

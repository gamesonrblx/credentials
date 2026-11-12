//! The real upstream client is HTTPS only, does not follow redirects, and
//! sets the secret header once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use credentials_gateway::{HttpUpstream, Outbound, Upstream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn http_is_rejected_before_a_connection() {
    let upstream = HttpUpstream::new().unwrap();
    let err = upstream
        .forward(outbound(
            "http://api.openai.com/v1",
            "Authorization",
            "Bearer secret",
        ))
        .await;
    let Err(err) = err else {
        panic!("http was accepted");
    };
    assert_eq!(err.code(), "upstream_failed");
}

#[tokio::test]
async fn https_overwrites_the_header_and_does_not_follow_redirects() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
    let addr = serve(hits.clone(), seen.clone()).await;
    let upstream = HttpUpstream::new_insecure().unwrap();
    let ok = upstream
        .forward(outbound(
            &format!("https://{addr}/ok"),
            "Authorization",
            "Bearer sk-live",
        ))
        .await
        .unwrap();
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body, b"ok");
    let header = seen.lock().await.clone();
    assert_eq!(header.matches("authorization:").count(), 1);
    assert!(header
        .to_ascii_lowercase()
        .contains("authorization: bearer sk-live"));
    assert!(!header.to_ascii_lowercase().contains("bearer old"));

    let redirected = upstream
        .forward(outbound(
            &format!("https://{addr}/redir"),
            "Authorization",
            "Bearer sk-live",
        ))
        .await
        .unwrap();
    assert_eq!(redirected.status, 302);
    assert_eq!(redirected.body, b"stay");
    assert_eq!(hits.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn trace_is_refused_before_a_connection() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
    let addr = serve(hits.clone(), seen).await;
    let upstream = HttpUpstream::new_insecure().unwrap();
    let mut request = outbound(&format!("https://{addr}/ok"), "Authorization", "Bearer x");
    request.method = "TRACE".into();
    let Err(err) = upstream.forward(request).await else {
        panic!("TRACE was sent");
    };
    assert_eq!(err.code(), "forbidden");
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn content_type_is_sent_and_header_injection_is_refused() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
    let addr = serve(hits.clone(), seen.clone()).await;
    let upstream = HttpUpstream::new_insecure().unwrap();
    let mut request = outbound(&format!("https://{addr}/ok"), "Authorization", "Bearer x");
    request.content_type = Some("application/json".into());
    upstream.forward(request).await.unwrap();
    assert!(seen
        .lock()
        .await
        .to_ascii_lowercase()
        .contains("content-type: application/json"));

    let mut request = outbound(&format!("https://{addr}/ok"), "Authorization", "Bearer x");
    request.content_type = Some("text/plain\r\nX-Evil: 1".into());
    assert!(upstream.forward(request).await.is_err());
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn oversized_responses_are_cut_off() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
    let addr = serve(hits.clone(), seen).await;
    let upstream = HttpUpstream::new_insecure().unwrap();
    for path in ["/big-declared", "/big-streamed"] {
        let Err(err) = upstream
            .forward(outbound(
                &format!("https://{addr}{path}"),
                "Authorization",
                "Bearer x",
            ))
            .await
        else {
            panic!("{path} was buffered");
        };
        assert_eq!(err.code(), "upstream_failed");
    }
}

#[tokio::test]
async fn real_client_refuses_loopback_by_name_and_by_literal() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
    let addr = serve(hits.clone(), seen).await;
    let upstream = HttpUpstream::new().unwrap();
    for url in [
        format!("https://localhost:{}/ok", addr.port()),
        format!("https://{addr}/ok"),
    ] {
        let Err(err) = upstream
            .forward(outbound(&url, "Authorization", "Bearer x"))
            .await
        else {
            panic!("{url} was reached");
        };
        assert_eq!(err.code(), "upstream_failed");
    }
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

fn outbound(url: &str, name: &str, value: &str) -> Outbound {
    Outbound {
        method: "POST".into(),
        url: url.into(),
        body: Vec::new(),
        header_name: name.into(),
        header_value: value.into(),
        content_type: None,
    }
}

async fn serve(
    hits: Arc<AtomicUsize>,
    seen: Arc<tokio::sync::Mutex<String>>,
) -> std::net::SocketAddr {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let hits = hits.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let Ok(n) = tls.read(&mut buf).await else {
                    return;
                };
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                hits.fetch_add(1, Ordering::Relaxed);
                *seen.lock().await = text.clone();
                if text.contains("/big-declared") || text.contains("/big-streamed") {
                    let head = if text.contains("/big-declared") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 9437184\r\nConnection: close\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
                    };
                    if tls.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let chunk = vec![b'x'; 64 * 1024];
                    for _ in 0..144 {
                        if tls.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                    let _ = tls.shutdown().await;
                    return;
                }
                let body = if text.contains("GET /redir") || text.contains("POST /redir") {
                    "HTTP/1.1 302 Found\r\nLocation: https://evil.example/steal\r\nContent-Length: 4\r\nConnection: close\r\n\r\nstay"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                let _ = tls.write_all(body.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

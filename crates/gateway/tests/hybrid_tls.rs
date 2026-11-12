//! Spec test 16: a client that offers X25519MLKEM768 negotiates group 4588.

use std::sync::Arc;

use credentials_gateway::{group_code, hybrid_provider, is_hybrid, server_config, HYBRID_GROUP};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn client_offering_hybrid_negotiates_group_4588() {
    let (addr, root) = listen(true).await;
    let group = handshake(addr, &root, true).await;
    assert_eq!(group_code(group), HYBRID_GROUP);
    assert_eq!(HYBRID_GROUP, 0x11ec);
    assert!(is_hybrid(group));
}

#[tokio::test]
async fn classical_client_is_rejected_when_hybrid_is_required() {
    let (addr, root) = listen(true).await;
    let err = handshake_result(addr, &root, false).await;
    assert!(err.is_err());
}

async fn listen(require_hybrid: bool) -> (std::net::SocketAddr, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = server_config(cert.clone(), key, require_hybrid).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut buf = [0u8; 16];
        let _ = tls.read(&mut buf).await;
        let _ = tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    });
    (addr, cert)
}

async fn handshake(
    addr: std::net::SocketAddr,
    root: &CertificateDer<'static>,
    offer_hybrid: bool,
) -> rustls::NamedGroup {
    let tls = handshake_result(addr, root, offer_hybrid).await.unwrap();
    tls.get_ref()
        .1
        .negotiated_key_exchange_group()
        .unwrap()
        .name()
}

async fn handshake_result(
    addr: std::net::SocketAddr,
    root: &CertificateDer<'static>,
    offer_hybrid: bool,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).map_err(|err| err.to_string())?;
    let provider = Arc::new(if offer_hybrid {
        hybrid_provider(false)
    } else {
        let mut provider = hybrid_provider(false);
        provider.kx_groups.retain(|group| !is_hybrid(group.name()));
        provider
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| err.to_string())?;
    let name = ServerName::try_from("localhost").unwrap();
    connector
        .connect(name, stream)
        .await
        .map_err(|err| err.to_string())
}

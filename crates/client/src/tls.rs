//! TLS 1.3 client. The first key-exchange group is `X25519MLKEM768` (4588).

use std::sync::Arc;

use rustls::client::ClientConfig;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::RootCertStore;

pub const HYBRID_GROUP: u16 = 4588;

pub fn hybrid_config(require_hybrid: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if require_hybrid {
        vec![kx_group::X25519MLKEM768]
    } else {
        vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
        ]
    };
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

pub fn hybrid_http(require_hybrid: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(hybrid_config(require_hybrid))
        .build()
        .expect("http client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_group_is_4588() {
        let config = hybrid_config(true);
        let group = config.crypto_provider().kx_groups.first().unwrap().name();
        assert_eq!(u16::from(group), HYBRID_GROUP);
    }
}

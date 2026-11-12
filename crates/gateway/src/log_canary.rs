//! Spec item 14: a known canary must not reach the log sink.

use std::sync::{Mutex, Once};

use tracing::field::Visit;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

use crate::service::{Clock, Gateway};
use crate::store::MemoryStore;
use crate::DeliveryPolicy;
use crate::RecordingUpstream;
use credentials_crypto::{DevPolicy, MemoryRootKeys};

static START: Once = Once::new();
static SINK: Mutex<String> = Mutex::new(String::new());

struct Capture;

struct Fields(String);

impl Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl<S> Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let line = format!(
            "{} {}{}\n",
            event.metadata().target(),
            event.metadata().name(),
            fields.0
        );
        SINK.lock().expect("log sink").push_str(&line);
    }
}

fn install() {
    START.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(Capture);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

#[derive(Clone, Default)]
struct Buffer(std::sync::Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The formatter `main` installs drops sensitive field values.
#[test]
fn production_formatter_redacts_sensitive_fields() {
    let canary = "canary-0b5f3e19a7c4";
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .fmt_fields(crate::redact::redacting_fields())
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            value = canary,
            authorization = %canary,
            Token = ?canary,
            secret_name = "prod/openai/api_key",
            "inject attempted"
        );
        let span = tracing::info_span!("request", dpop = canary);
        let _entered = span.enter();
        tracing::warn!(password = canary, "inside span");
    });
    let text = String::from_utf8(buffer.0.lock().expect("log buffer").clone()).unwrap();
    assert!(
        !text.contains(canary),
        "canary reached the formatter: {text}"
    );
    assert!(text.contains("value=[redacted]"), "{text}");
    assert!(text.contains("authorization=[redacted]"), "{text}");
    assert!(text.contains("Token=[redacted]"), "{text}");
    assert!(text.contains("prod/openai/api_key"), "{text}");
    assert!(text.contains("inject attempted"), "{text}");
}

#[tokio::test]
async fn canary_stays_out_of_the_log_sink() {
    install();
    SINK.lock().expect("log sink").clear();
    let canary = "canary-7c1e0b9a4d22";
    let gateway = Gateway::new(
        std::sync::Arc::new(MemoryStore::new()),
        std::sync::Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        std::sync::Arc::new(RecordingUpstream::new()),
        std::sync::Arc::new(Clock),
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            canary.as_bytes(),
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: None,
                hosts: vec!["api.openai.com".into()],
                allow_proxy: true,
                allow_header: false,
                allow_env: false,
            },
        )
        .await
        .unwrap();
    let rejected = gateway
        .inject(crate::InjectRequest {
            token: canary.into(),
            dpop: canary.into(),
            secret: "prod/openai/api_key".into(),
            delivery: crate::Delivery::Proxy,
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            body: Vec::new(),
            htm: "POST".into(),
            htu: "https://credentials.local/v1/inject".into(),
            local_channel: false,
            content_type: None,
        })
        .await;
    assert!(rejected.is_err());
    let sink = SINK.lock().expect("log sink").clone();
    assert!(
        !sink.contains(canary),
        "canary reached the log sink: {sink}"
    );
}

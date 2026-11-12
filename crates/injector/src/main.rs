//! Customer-run injector CLI. The secret value is never printed.
//!
//! `deliver` verifies a signed grant and performs its delivery.
//! `import-dotenv` seals a `.env` file into `POST /v1/e2e-secrets` bodies.

use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credentials_crypto::E2E_ENCAPSULATION_KEY_LEN;
use credentials_injector::{
    deliver, grant_from_inject_response, import_dotenv, submission_json, verify_grant, Delivered,
    ReqwestTransport, SubmissionPolicy,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "usage:
  credentials-injector deliver --key <decapsulation-key-file> --control-plane-key <file>
      --grant <file> [--body <file>] --out <file>
  credentials-injector import-dotenv --env-file <file> --encapsulation-key <file>
      --workspace-id <uuid> --workspace-key-id <uuid> [--prefix <prefix>]
      [--host <host>]... [--header-name <name>] [--header-format <format>]
      [--no-proxy] [--allow-header] [--allow-env] --out <file>";

/// Flags that take no value.
const SWITCHES: &[&str] = &["--no-proxy", "--allow-header", "--allow-env"];

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let parsed = match Args::parse(args) {
        Ok(parsed) => parsed,
        Err(()) => return usage(),
    };
    let result = match command.as_deref() {
        Some("deliver") => run_deliver(parsed).await,
        Some("import-dotenv") => run_import(parsed),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage) => usage(),
        Err(Failure::Message(message)) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage,
    Message(String),
}

fn failed(what: &str, err: impl Display) -> Failure {
    Failure::Message(format!("{what} failed: {err}"))
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// Hand-rolled `--name value` parsing.
struct Args {
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Args {
    fn parse(mut raw: impl Iterator<Item = String>) -> Result<Self, ()> {
        let mut values = Vec::new();
        let mut switches = Vec::new();
        while let Some(arg) = raw.next() {
            if SWITCHES.contains(&arg.as_str()) {
                switches.push(arg);
            } else if arg.starts_with("--") {
                let value = raw.next().ok_or(())?;
                values.push((arg, value));
            } else {
                return Err(());
            }
        }
        Ok(Self { values, switches })
    }

    fn all(&mut self, key: &str) -> Vec<String> {
        let (taken, rest): (Vec<_>, Vec<_>) =
            self.values.drain(..).partition(|(name, _)| name == key);
        self.values = rest;
        taken.into_iter().map(|(_, value)| value).collect()
    }

    fn optional(&mut self, key: &str) -> Result<Option<String>, Failure> {
        let mut found = self.all(key);
        if found.len() > 1 {
            return Err(Failure::Usage);
        }
        Ok(found.pop())
    }

    fn required(&mut self, key: &str) -> Result<String, Failure> {
        self.optional(key)?.ok_or(Failure::Usage)
    }

    fn switch(&mut self, key: &str) -> bool {
        let before = self.switches.len();
        self.switches.retain(|name| name != key);
        before != self.switches.len()
    }

    /// Unknown flags are a usage error.
    fn finish(self) -> Result<(), Failure> {
        if self.values.is_empty() && self.switches.is_empty() {
            Ok(())
        } else {
            Err(Failure::Usage)
        }
    }
}

async fn run_deliver(mut args: Args) -> Result<(), Failure> {
    let key_path = args.required("--key")?;
    let control_plane_path = args.required("--control-plane-key")?;
    let grant_path = args.required("--grant")?;
    let body_path = args.optional("--body")?;
    let out_path = args.required("--out")?;
    args.finish()?;

    let control_plane_key = read_control_plane_key(&control_plane_path)?;
    let grant = std::fs::read(&grant_path).map_err(|err| failed("reading the grant", err))?;
    let grant =
        grant_from_inject_response(&grant).map_err(|err| failed("reading the grant", err))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failed("reading the clock", "time is before 1970"))?
        .as_secs();
    let verified = verify_grant(&control_plane_key, &grant, now)
        .map_err(|err| failed("verifying the grant", err))?;
    let body = match body_path {
        Some(path) => std::fs::read(&path).map_err(|err| failed("reading the body", err))?,
        None => Vec::new(),
    };
    let key = read_decapsulation_key(&key_path)?;
    let transport = ReqwestTransport::new().map_err(|err| failed("building the client", err))?;

    // Create the output first so a refused path does not cost an upstream call.
    let mut out = create_private(&out_path).map_err(|err| failed("creating the output", err))?;
    let delivered = match deliver(&verified, &key, &body, &transport).await {
        Ok(delivered) => delivered,
        Err(err) => {
            drop(out);
            let _ = std::fs::remove_file(&out_path);
            return Err(failed("delivery", err));
        }
    };
    drop(key);
    let (written, summary) = match &delivered {
        Delivered::Proxy(response) => (out.write_all(&response.body), response.status.to_string()),
        Delivered::Header(handoff) => {
            (out.write_all(handoff.to_json().as_bytes()), "header".into())
        }
        Delivered::Env(handoff) => (out.write_all(handoff.to_json().as_bytes()), "env".into()),
    };
    written
        .and_then(|()| out.sync_all())
        .map_err(|err| failed("writing the output", err))?;
    println!("{summary}");
    Ok(())
}

/// Raw 32-byte decapsulation key. The file contents are wiped after use.
fn read_decapsulation_key(path: &str) -> Result<Zeroizing<[u8; 32]>, Failure> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|err| failed("reading the key", err))?);
    if bytes.len() != 32 {
        return Err(failed("reading the key", "the key file must hold 32 bytes"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Standard base64 of the 32-byte Ed25519 key from `GET /v1/keys`.
fn read_control_plane_key(path: &str) -> Result<[u8; 32], Failure> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| failed("reading the control-plane key", err))?;
    STANDARD
        .decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            failed(
                "reading the control-plane key",
                "expected base64 of 32 bytes",
            )
        })
}

fn run_import(mut args: Args) -> Result<(), Failure> {
    let env_path = args.required("--env-file")?;
    let key_path = args.required("--encapsulation-key")?;
    let workspace_id = parse_uuid(&args.required("--workspace-id")?)?;
    let workspace_key_id = parse_uuid(&args.required("--workspace-key-id")?)?;
    let prefix = args.optional("--prefix")?;
    let hosts = args.all("--host");
    let header_name = args.optional("--header-name")?;
    let header_format = args.optional("--header-format")?;
    let no_proxy = args.switch("--no-proxy");
    let allow_header = args.switch("--allow-header");
    let allow_env = args.switch("--allow-env");
    let out_path = args.required("--out")?;
    args.finish()?;

    let allow_proxy = !no_proxy;
    let wants_header = allow_proxy || allow_header;
    let policy = SubmissionPolicy {
        hosts,
        header_name: header_name.or_else(|| wants_header.then(|| "Authorization".to_owned())),
        header_format: header_format.or_else(|| wants_header.then(|| "Bearer {value}".to_owned())),
        allow_proxy,
        allow_header,
        allow_env,
    };
    policy
        .validate()
        .map_err(|err| failed("checking the policy", err))?;

    let encapsulation_key = read_encapsulation_key(&key_path)?;
    let source = Zeroizing::new(
        std::fs::read_to_string(&env_path).map_err(|err| failed("reading the .env file", err))?,
    );
    let imported = import_dotenv(
        &source,
        prefix.as_deref(),
        &encapsulation_key,
        workspace_id,
        workspace_key_id,
    )
    .map_err(|err| failed("importing", err))?;
    drop(source);

    let mut submissions = Vec::with_capacity(imported.len());
    for item in &imported {
        submissions.push(submission_json(item, &policy).map_err(|err| failed("importing", err))?);
    }
    let text = serde_json::to_vec_pretty(&submissions)
        .map_err(|err| failed("encoding the output", err))?;
    let mut out = create_private(&out_path).map_err(|err| failed("creating the output", err))?;
    out.write_all(&text)
        .and_then(|()| out.sync_all())
        .map_err(|err| failed("writing the output", err))?;
    for item in &imported {
        println!("{} -> {}", item.env_name, item.name);
    }
    Ok(())
}

/// Raw encapsulation key bytes, or standard base64 as `GET /v1/workspace-keys` returns it.
fn read_encapsulation_key(path: &str) -> Result<Vec<u8>, Failure> {
    let bytes = std::fs::read(path).map_err(|err| failed("reading the encapsulation key", err))?;
    if bytes.len() == E2E_ENCAPSULATION_KEY_LEN {
        return Ok(bytes);
    }
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| STANDARD.decode(text.trim()).ok())
        .filter(|key| key.len() == E2E_ENCAPSULATION_KEY_LEN)
        .ok_or_else(|| {
            failed(
                "reading the encapsulation key",
                "expected the raw key or its base64",
            )
        })
}

fn parse_uuid(text: &str) -> Result<Uuid, Failure> {
    Uuid::parse_str(text).map_err(|_| Failure::Usage)
}

/// A new file the caller alone can read. On Unix the mode is 0600. On Windows
/// the file inherits the ACL of its directory, so pick a private directory.
fn create_private(path: &str) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

//! Write one opened secret to a file. The value is not printed.

use std::io::Write;

fn main() {
    let mut args = std::env::args().skip(1);
    let key_path = args.next();
    let grant_path = args.next();
    let out_path = args.next();
    let Some(key_path) = key_path else { usage() };
    let Some(grant_path) = grant_path else {
        usage()
    };
    let Some(out_path) = out_path else { usage() };
    let key_bytes = std::fs::read(&key_path).unwrap_or_else(|_| fail("key file"));
    if key_bytes.len() != 32 {
        fail("key file");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let grant = std::fs::read(&grant_path).unwrap_or_else(|_| fail("grant file"));
    let opened = credentials_injector::open_grant(&key, &grant).unwrap_or_else(|_| fail("open"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&out_path).unwrap_or_else(|_| fail("output"));
    file.write_all(&opened).unwrap_or_else(|_| fail("output"));
}

fn usage() -> ! {
    eprintln!("usage: credentials-injector <decapsulation-key-file> <grant-file> <output-file>");
    std::process::exit(2);
}

fn fail(what: &str) -> ! {
    eprintln!("{what} failed");
    std::process::exit(1);
}

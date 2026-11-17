//! The real `envy serve` (HTTP and SQLite) driven over the network by the client library.
//! Built only with `--features server` on Linux.
#![cfg(all(feature = "server", target_os = "linux"))]

use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Output},
    thread,
    time::Duration,
};

use chrono::DateTime;
use dot_envy::{
    backends::{BackendStore, FileBackends},
    identity,
    remote::{
        client::{Enrolment, RemoteVault, enrol},
        transport::{HttpTransport, Transport},
    },
    schema::Secret,
    vault::{Change, MemoryVault, SecretVault},
};
use tempfile::TempDir;

const ENVY: &str = env!("CARGO_BIN_EXE_envy");

struct Server {
    child: Child,
    url: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn envy(args: &[&str]) -> Output {
    Command::new(ENVY)
        .args(args)
        .env("ENVY_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap()
}

/// `envy serve --init`, returning the root token it wrote.
fn init(data: &Path) -> String {
    let token_file = data.with_extension("token");
    let out = envy(&[
        "serve",
        "--data",
        data.to_str().unwrap(),
        "--init",
        "--init-output",
        token_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_to_string(token_file)
        .unwrap()
        .trim()
        .to_string()
}

/// Starts `envy serve` on a free port. Another process may take the port between choosing
/// it and the server binding it, so a server that exits early is started again elsewhere.
fn start(data: &Path) -> Server {
    for _ in 0..5 {
        let port = free_port();
        let child = Command::new(ENVY)
            .args(["serve", "--data", data.to_str().unwrap(), "--listen"])
            .arg(format!("127.0.0.1:{port}"))
            .spawn()
            .unwrap();
        // From here on, `Drop` stops the process whatever happens.
        let mut server = Server {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };
        for _ in 0..100 {
            if ureq::get(format!("{}/v1/health", server.url))
                .call()
                .is_ok()
            {
                return server;
            }
            if server.child.try_wait().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    panic!("the server did not start");
}

fn connect(url: &str) -> anyhow::Result<Box<dyn Transport>> {
    Ok(Box::new(HttpTransport::new(url)?))
}

fn change() -> Change {
    Change {
        at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        keep: 5,
    }
}

#[test]
fn values_round_trip_over_http_and_survive_a_restart() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("server");
    let root = init(&data);
    let server = start(&data);

    let transport = HttpTransport::new(&server.url).unwrap();
    let admin = enrol(&transport, Enrolment::RootToken(root.clone()), "admin").unwrap();
    let identities = MemoryVault::new();
    identity::save(&identities, &server.url, &admin).unwrap();
    let choices = FileBackends::new(Some(dir.path().join("client")));
    choices.set_remote_url("proj", Some(&server.url)).unwrap();

    let vault = RemoteVault::new(
        &choices,
        None,
        &identities,
        None,
        Some(dir.path().join("client")),
        Box::new(connect),
    );
    vault.create_project("proj", &[1; 32]).unwrap();
    vault
        .set("proj", "dev", "TOKEN", &Secret::new("over-http"), change())
        .unwrap();

    let again = enrol(&transport, Enrolment::RootToken(root), "intruder");
    assert!(
        again
            .unwrap_err()
            .to_string()
            .contains("root token is not valid"),
        "the root token works once"
    );

    drop(server);
    let server = start(&data);
    choices.set_remote_url("proj", Some(&server.url)).unwrap();
    // The port, and so the URL, changed: the identity is stored for the new one.
    let same = identity::Identity::parse(admin.export().expose_secret()).unwrap();
    identity::save(&identities, &server.url, &same).unwrap();
    let vault = RemoteVault::new(
        &choices,
        None,
        &identities,
        None,
        Some(dir.path().join("client")),
        Box::new(connect),
    );
    assert_eq!(
        vault
            .get("proj", "dev", "TOKEN")
            .unwrap()
            .unwrap()
            .expose_secret(),
        "over-http"
    );
}

#[test]
fn without_tls_only_loopback_addresses_are_served() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("server");
    init(&data);
    let out = envy(&[
        "serve",
        "--data",
        data.to_str().unwrap(),
        "--listen",
        "0.0.0.0:0",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("only listens on a loopback address"),
        "{stderr}"
    );
}

#[test]
fn init_refuses_a_folder_that_already_holds_a_server() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("server");
    init(&data);
    let out = envy(&["serve", "--data", data.to_str().unwrap(), "--init"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already holds an Envy server"));
}

#[test]
fn oversized_requests_are_refused() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("server");
    init(&data);
    let server = start(&data);
    let body = vec![b' '; 5 * 1024 * 1024];
    let response = ureq::post(format!("{}/v1/rpc", server.url))
        .config()
        .http_status_as_error(false)
        .build()
        .send(&body[..])
        .unwrap();
    assert_eq!(response.status().as_u16(), 413);
}

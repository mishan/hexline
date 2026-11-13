//! The driver against a real hxd: the binary HXD_BIN names, started on a
//! config and an accounts directory of the test's own. Run with
//! `cargo test -p hxng-client --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hxng_client::driver::{connect, Client, Error, Start, Update, Updates};
use hxng_client::{LoginParams, Output};
use serde_json::{json, Value};
use tokio::process::{Child, Command};
use tokio::time::timeout;

struct Server {
    /// Held so the server is killed with the test, before its directory
    /// goes.
    _proc: Child,
    _dir: TempDir,
    url: String,
}

/// A directory removed when the test is done.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn account(name: &str) -> String {
    format!(
        "name = \"{name}\"\npassword = \"pw-{name}\"\n[access]\nread_chat = true\nsend_chat = true\nsend_msgs = true\n"
    )
}

impl Server {
    async fn start(accounts: &[&str]) -> Server {
        let bin = std::env::var("HXD_BIN").expect(
            "HXD_BIN must name an hxd binary for the live tests (`make test-live` sets it)",
        );
        let root =
            std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
        let dir = PathBuf::from(root).join(format!(
            "hexline-live-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(dir.join("accounts")).unwrap();
        for a in accounts {
            std::fs::write(dir.join("accounts").join(format!("{a}.toml")), account(a)).unwrap();
        }
        let (legacy, ng) = (free_port(), free_port());
        let name = format!("hexline-live-{ng}");
        std::fs::write(
            dir.join("hxd-ng.toml"),
            format!(
                "[server]\nbind = \"127.0.0.1:{legacy}\"\nname = \"{name}\"\n\
                 [paths]\naccounts = \"accounts\"\n\
                 [ng]\nbind = \"127.0.0.1:{ng}\"\n\
                 [limits]\nng_requests = 0\nreconnect_seconds = 0\n"
            ),
        )
        .unwrap();
        let proc = Command::new(&bin)
            .arg("--config")
            .arg(dir.join("hxd-ng.toml"))
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("hxd.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("{bin}: {e}"));
        let server = Server {
            _proc: proc,
            _dir: TempDir(dir),
            url: format!("ws://127.0.0.1:{ng}/ng"),
        };
        for _ in 0..200 {
            if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", ng)).await {
                drop(s);
                return server;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("hxd did not listen on {ng}");
    }
}

fn login(name: &str) -> Start {
    Start::Login(LoginParams {
        login: Some(name.into()),
        password: Some(format!("pw-{name}")),
        ..LoginParams::default()
    })
}

/// The next event called `ev`, skipping the rest.
async fn next(updates: &mut Updates, ev: &str) -> Value {
    timeout(Duration::from_secs(5), async {
        loop {
            match updates.recv().await.expect("updates ended") {
                Update::Event { ev: e, data, .. } if e == ev => return data,
                Update::Closed { lost, error } => panic!("closed: {lost:?} {error:?}"),
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {ev}"))
}

async fn chat(client: &Client, text: &str) {
    let reply = client
        .request("chat", json!({ "text": text }))
        .await
        .unwrap();
    assert!(reply.is_ok(), "{reply:?}");
}

#[tokio::test]
async fn a_password_login_chats_and_hears_others() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, answer, mut heard) = connect(&server.url, &login("alice"), None).await.unwrap();
    let Output::LoggedIn(ok) = answer else {
        panic!("{answer:?}")
    };
    assert!(ok.detach.is_some(), "an account with a password may detach");
    let (bob, _, _bob_heard) = connect(&server.url, &login("bob"), None).await.unwrap();
    next(&mut heard, "user_joined").await;
    chat(&bob, "hi alice").await;
    assert_eq!(next(&mut heard, "chat").await["text"], "hi alice");
    chat(&alice, "hi bob").await;
}

#[tokio::test]
async fn a_dropped_connection_resumes_and_replays_what_it_missed() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, _, mut heard) = connect(&server.url, &login("alice"), None).await.unwrap();
    let (bob, _, mut bob_heard) = connect(&server.url, &login("bob"), None).await.unwrap();
    next(&mut heard, "user_joined").await;
    drop(alice);
    let resumable = loop {
        match heard.recv().await.unwrap() {
            Update::Closed { lost, .. } => break lost.resumable.expect("resumable"),
            _ => continue,
        }
    };
    // Detached on the server, not just closed here: a line sent before
    // then would go to the dead socket, and the resume would be a resync.
    timeout(Duration::from_secs(5), async {
        while next(&mut bob_heard, "user_changed").await["user"]["status"] != "detached" {}
    })
    .await
    .expect("alice shown detached");
    chat(&bob, "while you were out").await;
    let (_alice, answer, mut heard) = connect(&server.url, &Start::Resume(resumable), None)
        .await
        .unwrap();
    assert!(
        matches!(
            answer,
            Output::Resumed {
                must_sync: false,
                ..
            }
        ),
        "{answer:?}"
    );
    assert_eq!(next(&mut heard, "chat").await["text"], "while you were out");
}

#[tokio::test]
async fn a_wrong_password_is_refused() {
    let server = Server::start(&["alice"]).await;
    let start = Start::Login(LoginParams {
        login: Some("alice".into()),
        password: Some("nope".into()),
        ..LoginParams::default()
    });
    match connect(&server.url, &start, None).await {
        Err(Error::Refused(r)) => {
            assert_eq!(r.error.code, "login_failed");
            assert!(r.resumable.is_none());
        }
        other => panic!("{:?}", other.map(|(_, o, _)| o)),
    }
}

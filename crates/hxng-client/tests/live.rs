//! The driver against a real hxd: the binary HXD_BIN names, started on a
//! config and an accounts directory of the test's own. Run with
//! `cargo test -p hxng-client --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::time::Duration;

use hxng_client::driver::{connect, Client, Error, Start, Update, Updates};
use hxng_client::testing::Server;
use hxng_client::{LoginParams, Output};
use serde_json::{json, Value};
use tokio::time::timeout;

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

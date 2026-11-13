//! The core as the app drives it, against a real hxd (HXD_BIN). Run with
//! `cargo test -p hexline-core --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hexline_core::{CoreError, CoreUpdate, ServerConnection, Status, UpdateSink};
use hxng_client::testing::Server;

#[derive(Default)]
struct Sink(Mutex<Vec<Vec<CoreUpdate>>>);

impl UpdateSink for Sink {
    fn deliver(&self, updates: Vec<CoreUpdate>) {
        self.0.lock().unwrap().push(updates);
    }
}

impl Sink {
    /// Waits for an update `wanted` picks out.
    async fn heard(&self, what: &str, wanted: impl Fn(&CoreUpdate) -> bool) {
        for _ in 0..100 {
            if self.0.lock().unwrap().iter().flatten().any(&wanted) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("never heard {what}");
    }
}

fn said(text: &'static str) -> impl Fn(&CoreUpdate) -> bool {
    move |u| matches!(u, CoreUpdate::Chat { line } if line.text == text)
}

fn pw(name: &str) -> Option<String> {
    Some(format!("pw-{name}"))
}

#[tokio::test]
async fn the_app_logs_in_chats_and_is_handed_what_others_say() {
    let server = Server::start(&["alice", "bob"]).await;
    let alice_sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(server.url.clone(), alice_sink.clone());
    let info = alice
        .login(Some("alice".into()), pw("alice"))
        .await
        .unwrap();
    assert!(info.can_resume);
    alice_sink
        .heard("her own row first", |u| {
            matches!(u, CoreUpdate::Roster { self_uid, users, .. }
                if users.iter().any(|x| x.uid == *self_uid && x.nick == "alice"))
        })
        .await;
    assert!(matches!(
        alice_sink.0.lock().unwrap()[0][..],
        [CoreUpdate::Roster { .. }]
    ));
    let bob = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    bob.login(Some("bob".into()), pw("bob")).await.unwrap();
    alice_sink
        .heard(
            "bob joining",
            |u| matches!(u, CoreUpdate::UserJoined { user } if user.nick == "bob"),
        )
        .await;
    bob.chat("hello from bob".into()).await.unwrap();
    alice_sink.heard("bob's line", said("hello from bob")).await;

    alice.disconnect().await;
    let closed = alice_sink.0.lock().unwrap().iter().flatten().any(|u| {
        matches!(
            u,
            CoreUpdate::Closed {
                can_resume: true,
                replaced: false
            }
        )
    });
    assert!(
        closed,
        "the last update was handed over before disconnect returned"
    );
    assert!(matches!(
        alice.chat("gone".into()).await,
        Err(CoreError::Closed)
    ));

    alice
        .login(Some("alice".into()), pw("alice"))
        .await
        .unwrap();
    assert!(matches!(
        alice.login(Some("alice".into()), pw("alice")).await,
        Err(CoreError::Busy)
    ));
    bob.chat("welcome back".into()).await.unwrap();
    alice_sink
        .heard("bob's welcome", said("welcome back"))
        .await;
}

/// A sink that throws, as a Kotlin one might.
struct Throws;

impl UpdateSink for Throws {
    fn deliver(&self, _: Vec<CoreUpdate>) {
        panic!("the app threw");
    }
}

#[tokio::test]
async fn an_app_that_throws_is_taken_for_one_no_longer_listening() {
    let server = Server::start(&["alice", "bob"]).await;
    let bob_sink = Arc::new(Sink::default());
    let bob = ServerConnection::new(server.url.clone(), bob_sink.clone());
    bob.login(Some("bob".into()), pw("bob")).await.unwrap();
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Throws));
    alice
        .login(Some("alice".into()), pw("alice"))
        .await
        .unwrap();
    bob.chat("anyone?".into()).await.unwrap();
    bob_sink
        .heard("alice detached", |u| {
            matches!(u, CoreUpdate::UserChanged { user } if user.nick == "alice" && user.status == Status::Detached)
        })
        .await;
}

#[tokio::test]
async fn a_wrong_password_comes_back_as_its_code() {
    let server = Server::start(&["alice"]).await;
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    match alice.login(Some("alice".into()), Some("nope".into())).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "login_failed"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn history_pages_back_from_the_newest() {
    let server = Server::start(&["alice"]).await;
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    alice
        .login(Some("alice".into()), pw("alice"))
        .await
        .unwrap();
    for n in 0..5 {
        alice.chat(format!("line {n}")).await.unwrap();
    }
    let newest = alice.history(None, None, 2).await.unwrap();
    let texts: Vec<_> = newest.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!((texts, newest.has_more), (vec!["line 3", "line 4"], true));
    let before = alice.history(newest.lines[0].id, None, 10).await.unwrap();
    let texts: Vec<_> = before.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        (texts, before.has_more),
        (vec!["line 0", "line 1", "line 2"], false)
    );
}

#[tokio::test]
async fn history_catches_up_forward_from_a_line() {
    let server = Server::start(&["alice"]).await;
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    alice
        .login(Some("alice".into()), pw("alice"))
        .await
        .unwrap();
    for n in 0..4 {
        alice.chat(format!("line {n}")).await.unwrap();
    }
    let all = alice.history(None, None, 10).await.unwrap();
    let after = alice.history(None, all.lines[0].id, 2).await.unwrap();
    let texts: Vec<_> = after.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!((texts, after.has_more), (vec!["line 1", "line 2"], true));
}

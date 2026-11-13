//! The core as the app drives it, against a real hxd (HXD_BIN). Run with
//! `cargo test -p hexline-core --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hexline_core::{CoreError, CoreUpdate, ServerConnection, UpdateSink};
use hxng_client::testing::Server;

#[derive(Default)]
struct Sink(Mutex<Vec<Vec<CoreUpdate>>>);

impl UpdateSink for Sink {
    fn deliver(&self, updates: Vec<CoreUpdate>) {
        self.0.lock().unwrap().push(updates);
    }
}

impl Sink {
    /// Waits for an event called `ev` whose data contains `needle`.
    async fn heard(&self, ev: &str, needle: &str) {
        for _ in 0..100 {
            let found = self.0.lock().unwrap().iter().flatten().any(|u| {
                matches!(u, CoreUpdate::Event { ev: e, data, .. } if e == ev && data.contains(needle))
            });
            if found {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no {ev} with {needle}");
    }
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
    let bob = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    bob.login(Some("bob".into()), pw("bob")).await.unwrap();
    bob.chat("hello from bob".into()).await.unwrap();
    alice_sink.heard("chat", "hello from bob").await;

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
    alice_sink.heard("chat", "welcome back").await;
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
    bob_sink.heard("user_changed", "detached").await;
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

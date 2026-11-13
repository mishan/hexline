//! The core as the app drives it, against a real hxd (HXD_BIN). Run with
//! `cargo test -p hexline-core --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hexline_core::{CoreError, CoreUpdate, DeviceIdentity, ServerConnection, Status, UpdateSink};
use hxng_client::testing::{device, Proxy, Server};
use serde_json::Value;

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
        self.heard_within(5, what, wanted).await;
    }

    async fn heard_within(&self, secs: u64, what: &str, wanted: impl Fn(&CoreUpdate) -> bool) {
        for _ in 0..secs * 20 {
            if self.0.lock().unwrap().iter().flatten().any(&wanted) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("never heard {what}: {:?}", self.all());
    }

    fn all(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|u| format!("{u:?}"))
            .collect()
    }

    /// Where the first update `wanted` picks out falls, among all of them.
    fn at(&self, wanted: impl Fn(&CoreUpdate) -> bool) -> Option<usize> {
        self.0.lock().unwrap().iter().flatten().position(wanted)
    }

    fn positions(&self, wanted: impl Fn(&CoreUpdate) -> bool) -> Vec<usize> {
        let told = self.0.lock().unwrap();
        told.iter()
            .flatten()
            .enumerate()
            .filter(|(_, u)| wanted(u))
            .map(|(i, _)| i)
            .collect()
    }

    fn count(&self, wanted: impl Fn(&CoreUpdate) -> bool) -> usize {
        self.positions(wanted).len()
    }
}

/// One field of what `saved()` gave, which the app keeps as bytes.
fn saved_field(saved: &[u8], key: &str) -> Value {
    serde_json::from_slice::<Value>(saved).unwrap()[key].clone()
}

fn roster(u: &CoreUpdate) -> bool {
    matches!(u, CoreUpdate::Roster { .. })
}

fn reconnecting(u: &CoreUpdate) -> bool {
    matches!(u, CoreUpdate::Reconnecting { .. })
}

fn status_of(nick: &'static str, status: Status) -> impl Fn(&CoreUpdate) -> bool {
    move |u| matches!(u, CoreUpdate::UserChanged { user } if user.nick == nick && user.status == status)
}

/// A connection logged in as `name`, and what it is told.
async fn logged_in(url: &str, name: &str) -> (Arc<ServerConnection>, Arc<Sink>) {
    let sink = Arc::new(Sink::default());
    let conn = ServerConnection::new(url.to_owned(), sink.clone());
    conn.login(Some(name.into()), pw(name), None).await.unwrap();
    sink.heard("the roster", roster).await;
    (conn, sink)
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
        .login(Some("alice".into()), pw("alice"), None)
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
    let bob_sink = Arc::new(Sink::default());
    let bob = ServerConnection::new(server.url.clone(), bob_sink.clone());
    bob.login(Some("bob".into()), pw("bob"), None)
        .await
        .unwrap();
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
                can_resume: false,
                replaced: false
            }
        )
    });
    assert!(
        closed,
        "the last update, the session logged out, was handed over before disconnect returned: {:?}",
        alice_sink.all()
    );
    assert!(alice.saved().is_none());
    bob_sink
        .heard("alice leaving, not away", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    assert!(matches!(
        alice.chat("gone".into()).await,
        Err(CoreError::Closed)
    ));

    alice
        .login(Some("alice".into()), pw("alice"), None)
        .await
        .unwrap();
    assert!(matches!(
        alice.login(Some("alice".into()), pw("alice"), None).await,
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
    bob.login(Some("bob".into()), pw("bob"), None)
        .await
        .unwrap();
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Throws));
    alice
        .login(Some("alice".into()), pw("alice"), None)
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
    match alice
        .login(Some("alice".into()), Some("nope".into()), None)
        .await
    {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "login_failed"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn history_pages_back_from_the_newest() {
    let server = Server::start(&["alice"]).await;
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    alice
        .login(Some("alice".into()), pw("alice"), None)
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
        .login(Some("alice".into()), pw("alice"), None)
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

#[tokio::test]
async fn a_lost_link_is_resumed_and_what_was_missed_replayed() {
    let server = Server::start(&["alice", "bob"]).await;
    let proxy = Proxy::to(&server).await;
    let (alice, sink) = logged_in(&proxy.url, "alice").await;
    let (bob, bob_sink) = logged_in(&server.url, "bob").await;
    proxy.refuse(true);
    proxy.sever();
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
    bob.chat("while you were out".into()).await.unwrap();
    sink.heard("a try", reconnecting).await;
    proxy.refuse(false);
    alice.network_changed();
    sink.heard("the replay", said("while you were out")).await;
    let back = sink
        .at(|u| matches!(u, CoreUpdate::Reconnected { gap: false }))
        .unwrap();
    assert!(
        back < sink.at(said("while you were out")).unwrap(),
        "{:?}",
        sink.all()
    );
    assert_eq!(
        sink.count(roster),
        1,
        "a replay needs no roster: {:?}",
        sink.all()
    );
    alice.chat("back again".into()).await.unwrap();
    bob_sink.heard("alice's line", said("back again")).await;
}

#[tokio::test]
async fn a_session_that_expired_while_the_link_was_down_is_logged_in_again() {
    let server = Server::with_grace(&["alice", "bob"], 1).await;
    let proxy = Proxy::to(&server).await;
    let (alice, sink) = logged_in(&proxy.url, "alice").await;
    let first = saved_field(&alice.saved().unwrap(), "session");
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    proxy.refuse(true);
    proxy.sever();
    bob_sink
        .heard_within(30, "alice's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    proxy.refuse(false);
    alice.network_changed();
    sink.heard("back", |u| {
        matches!(u, CoreUpdate::Reconnected { gap: true })
    })
    .await;
    let back = sink
        .at(|u| matches!(u, CoreUpdate::Reconnected { .. }))
        .unwrap();
    let rosters = sink.positions(roster);
    assert_eq!(rosters.len(), 2, "{:?}", sink.all());
    assert!(rosters[1] > back);
    assert_ne!(saved_field(&alice.saved().unwrap(), "session"), first);
    alice.chat("new session".into()).await.unwrap();
    bob_sink.heard("alice's line", said("new session")).await;
}

#[tokio::test]
async fn ending_while_reconnecting_stops_for_good_and_leaving_logs_out() {
    for leave in [false, true] {
        let server = Server::start(&["alice", "bob"]).await;
        let proxy = Proxy::to(&server).await;
        let (alice, sink) = logged_in(&proxy.url, "alice").await;
        let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
        proxy.refuse(true);
        proxy.sever();
        sink.heard("a try", reconnecting).await;
        // Inside the backoff's first second: the core is not trying.
        proxy.refuse(false);
        if leave {
            alice.disconnect().await;
        } else {
            alice.hang_up(false);
            sink.heard("the end", |u| matches!(u, CoreUpdate::Closed { .. }))
                .await;
        }
        let told = sink.all();
        let want = format!("Closed {{ can_resume: {}", !leave);
        assert!(told.last().unwrap().starts_with(&want), "{leave}: {told:?}");
        alice.network_changed();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(sink.all(), told, "nothing after the last update");
        assert_eq!(alice.saved().is_some(), !leave);
        if leave {
            bob_sink
                .heard("alice gone, not away", |u| {
                    matches!(u, CoreUpdate::UserParted { .. })
                })
                .await;
        }
    }
}

#[tokio::test]
async fn a_server_that_drops_each_link_is_tried_less_and_less_often() {
    let server = Server::start(&["alice"]).await;
    let proxy = Proxy::to(&server).await;
    let (_alice, sink) = logged_in(&proxy.url, "alice").await;
    proxy.cut_each_after(Duration::from_millis(300));
    proxy.sever();
    tokio::time::sleep(Duration::from_secs(7)).await;
    // Backing off 1, 2, 4 s: three losses in seven seconds, not six.
    let tries = sink.count(reconnecting);
    assert!((2..=4).contains(&tries), "{tries}: {:?}", sink.all());
}

#[tokio::test]
async fn saved_bytes_that_do_not_read_are_not_made_a_guest() {
    let conn = ServerConnection::new("ws://127.0.0.1:9/ng".into(), Arc::new(Sink::default()));
    match conn.login(None, None, Some(b"{\"v\":2}".to_vec())).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "session_expired"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn in_the_background_the_link_goes_and_comes_back_at_the_front() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, sink) = logged_in(&server.url, "alice").await;
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    alice.set_background_linger(100);
    alice.set_foreground(false);
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        sink.count(reconnecting),
        0,
        "no try while behind: {:?}",
        sink.all()
    );
    alice.set_foreground(true);
    sink.heard("back", |u| {
        matches!(u, CoreUpdate::Reconnected { gap: false })
    })
    .await;
    bob_sink
        .heard("alice back", status_of("alice", Status::Active))
        .await;
}

#[tokio::test]
async fn a_saved_session_resumes_after_a_restart_with_a_roster() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, sink) = logged_in(&server.url, "alice").await;
    let (bob, bob_sink) = logged_in(&server.url, "bob").await;
    bob.chat("before".into()).await.unwrap();
    sink.heard("before", said("before")).await;
    let saved = alice.saved().unwrap();
    alice.hang_up(false);
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
    bob.chat("while gone".into()).await.unwrap();

    let sink = Arc::new(Sink::default());
    let again = ServerConnection::new(server.url.clone(), sink.clone());
    let info = again
        .login(Some("alice".into()), pw("alice"), Some(saved.clone()))
        .await
        .unwrap();
    assert!(info.server_name.starts_with("hexline-live-"), "{info:?}");
    sink.heard("the replay", said("while gone")).await;
    let roster_at = sink.at(roster).unwrap();
    assert!(roster_at > sink.at(said("while gone")).unwrap());
    assert!(matches!(
        &sink.0.lock().unwrap().iter().flatten().nth(roster_at),
        Some(CoreUpdate::Roster { self_uid, .. }) if *self_uid == saved_field(&saved, "self_uid")
    ));
    assert_eq!(sink.at(said("before")), None, "{:?}", sink.all());
    assert_eq!(
        saved_field(&again.saved().unwrap(), "session"),
        saved_field(&saved, "session")
    );
}

#[tokio::test]
async fn a_session_taken_by_another_device_is_not_taken_back() {
    let server = Server::start(&["alice"]).await;
    let (alice, sink) = logged_in(&server.url, "alice").await;
    let saved = alice.saved().unwrap();
    let other = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    other
        .login(Some("alice".into()), pw("alice"), Some(saved))
        .await
        .unwrap();
    sink.heard("replaced", |u| {
        matches!(u, CoreUpdate::Closed { replaced: true, .. })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(sink.count(reconnecting), 0, "{:?}", sink.all());
    assert!(alice.saved().is_none());
}

/// A sink that takes its time over the last update, as an app busy with
/// its screen might: the connection is not over until it returns.
struct SlowToClose(Arc<Sink>);

impl UpdateSink for SlowToClose {
    fn deliver(&self, updates: Vec<CoreUpdate>) {
        if updates
            .iter()
            .any(|u| matches!(u, CoreUpdate::Closed { .. }))
        {
            std::thread::sleep(Duration::from_millis(500));
        }
        self.0.deliver(updates);
    }
}

#[tokio::test]
async fn a_login_after_a_hang_up_starts_once_the_last_one_has_ended() {
    let server = Server::start(&["alice", "bob"]).await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(server.url.clone(), Arc::new(SlowToClose(sink.clone())));
    alice
        .login(Some("alice".into()), pw("alice"), None)
        .await
        .unwrap();
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    alice.hang_up(false);
    let mut tries = 0;
    while let Err(e) = alice.login(Some("alice".into()), pw("alice"), None).await {
        assert!(matches!(e, CoreError::Busy), "{e:?}");
        tries += 1;
        assert!(tries < 100, "still busy");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for _ in 0..100 {
        if sink.count(roster) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let closed = sink.positions(|u| matches!(u, CoreUpdate::Closed { .. }));
    let rosters = sink.positions(roster);
    assert_eq!(closed.len(), 1, "{:?}", sink.all());
    assert!(closed[0] < rosters[1], "{:?}", sink.all());
    alice.chat("still here".into()).await.unwrap();
    bob_sink.heard("alice's line", said("still here")).await;
}

#[tokio::test]
async fn an_app_in_the_background_while_logging_in_lets_the_link_go() {
    let server = Server::start(&["alice", "bob"]).await;
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(server.url.clone(), sink.clone());
    alice.set_background_linger(100);
    alice.set_foreground(false);
    alice
        .login(Some("alice".into()), pw("alice"), None)
        .await
        .unwrap();
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
}

#[tokio::test]
async fn an_accounts_lapsed_session_is_not_made_a_guest_without_its_password() {
    let server = Server::with_grace(&["alice", "bob"], 1).await;
    let (alice, _) = logged_in(&server.url, "alice").await;
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    let saved = alice.saved().unwrap();
    alice.hang_up(false);
    bob_sink
        .heard_within(30, "alice's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    let again = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    match again.login(None, None, Some(saved)).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "session_expired"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_resume_the_server_cannot_replay_is_synced_with_a_roster() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, _) = logged_in(&server.url, "alice").await;
    let (bob, bob_sink) = logged_in(&server.url, "bob").await;
    let mut saved: Value = serde_json::from_slice(&alice.saved().unwrap()).unwrap();
    alice.hang_up(false);
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
    // A seq the session never reached: the server cannot replay after it.
    saved["last_seq"] = Value::from(saved["last_seq"].as_u64().unwrap() + 1000);
    let sink = Arc::new(Sink::default());
    let again = ServerConnection::new(server.url.clone(), sink.clone());
    again
        .login(
            Some("alice".into()),
            pw("alice"),
            Some(saved.to_string().into_bytes()),
        )
        .await
        .unwrap();
    sink.heard("a roster", roster).await;
    assert!(matches!(
        &sink.0.lock().unwrap().iter().flatten().find(|u| roster(u)),
        Some(CoreUpdate::Roster { self_uid, .. }) if *self_uid == saved["self_uid"]
    ));
    bob.chat("after the sync".into()).await.unwrap();
    sink.heard("a line after it", said("after the sync")).await;
    let resynced: Value = serde_json::from_slice(&again.saved().unwrap()).unwrap();
    assert!(resynced["last_seq"].as_u64() < saved["last_seq"].as_u64());
}

/// A new identity's device, as the app hands it over, with the identity's
/// fingerprint.
fn identity(name: &str) -> (DeviceIdentity, String) {
    let (id, d) = device(name);
    let fingerprint = hl_identity::Fingerprint::of(&id.public()).to_string();
    (
        DeviceIdentity {
            device_seed: d.key.seed().to_vec(),
            cert: d.cert,
            card: d.card,
        },
        fingerprint,
    )
}

#[tokio::test]
async fn an_identity_logs_in_and_after_its_session_lapses_proves_its_device_again() {
    let server = Server::with_identity(&["bob"], 1).await;
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(proxy.url.clone(), sink.clone());
    let (device, fingerprint) = identity("Alice");
    let info = alice.login_identity(device, true, None).await.unwrap();
    assert!(info.can_resume, "{info:?}");
    assert_eq!(info.fingerprint.as_deref(), Some(fingerprint.as_str()));
    sink.heard("her roster", roster).await;
    let first = saved_field(&alice.saved().unwrap(), "session");
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;

    proxy.refuse(true);
    proxy.sever();
    bob_sink
        .heard_within(30, "alice's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    proxy.refuse(false);
    alice.network_changed();
    sink.heard("back", |u| {
        matches!(u, CoreUpdate::Reconnected { gap: true })
    })
    .await;
    assert_ne!(saved_field(&alice.saved().unwrap(), "session"), first);
    assert_eq!(
        saved_field(&alice.saved().unwrap(), "guest"),
        Value::Bool(false)
    );
    // A new session: bob sees alice part and join again.
    let parted = bob_sink
        .at(|u| matches!(u, CoreUpdate::UserParted { .. }))
        .unwrap();
    bob_sink
        .heard(
            "alice back",
            |u| matches!(u, CoreUpdate::UserJoined { user } if user.nick == "Alice"),
        )
        .await;
    assert!(bob_sink
        .positions(|u| matches!(u, CoreUpdate::UserJoined { .. }))
        .iter()
        .any(|&i| i > parted));
}

#[tokio::test]
async fn a_device_seed_that_is_not_one_is_refused_before_anything_is_sent() {
    let alice = ServerConnection::new("ws://127.0.0.1:9/ng".into(), Arc::new(Sink::default()));
    let (mut device, _) = identity("Alice");
    device.device_seed.pop();
    assert!(matches!(
        alice.login_identity(device, true, None).await,
        Err(CoreError::Protocol { .. })
    ));
}

#[tokio::test]
async fn a_session_the_server_did_not_make_the_identitys_is_refused() {
    // A server with a guest account, which an upgrade that lost its token
    // is let in to.
    let server = Server::with_identity(&["guest"], 300).await;
    let proxy = Proxy::to(&server).await;
    proxy.strip_authorization();
    let alice = ServerConnection::new(proxy.url.clone(), Arc::new(Sink::default()));
    let (device, _) = identity("Alice");
    match alice.login_identity(device, true, None).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "identity_not_honored"),
        other => panic!("{other:?}"),
    }
}

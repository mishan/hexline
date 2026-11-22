//! The core as the app drives it, against a real hxd (HXD_BIN). Run with
//! `cargo test -p hexline-core --features live-tests --test live`.

#![cfg(feature = "live-tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hexline_core::{
    ClassicLogin, CoreError, CoreUpdate, DeviceIdentity, ServerConnection, Status, UpdateSink,
};
use hxng_client::testing::{back_up, device, Proxy, Server};
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

/// What resumes `conn`'s session, once the core has it to give.
async fn saved_soon(conn: &ServerConnection) -> Vec<u8> {
    for _ in 0..100 {
        if let Some(saved) = conn.saved() {
            return saved;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no session to save");
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
    // Severed only once alice has what was sent her: an event lost in
    // flight is one the server cannot replay, and answers with a resync.
    sink.heard("bob joining", |u| {
        matches!(u, CoreUpdate::UserJoined { .. })
    })
    .await;
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
        .at(|u| matches!(u, CoreUpdate::Reconnected { gap: false, .. }))
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

fn session_kept(u: &CoreUpdate) -> bool {
    matches!(u, CoreUpdate::SessionKept)
}

/// Waits until `sink` has been told its session is kept `times` times.
async fn kept_times(sink: &Sink, times: usize) {
    for _ in 0..300 {
        if sink.count(session_kept) >= times {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "told the session kept fewer than {times} times: {:?}",
        sink.all()
    );
}

#[tokio::test]
async fn a_links_session_is_told_kept_once_there_is_one_to_save_on_a_quiet_link() {
    let server = Server::start(&["alice"]).await;
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(proxy.url.clone(), sink.clone());
    alice
        .login(Some("alice".into()), pw("alice"), None)
        .await
        .unwrap();
    kept_times(&sink, 1).await;
    assert!(sink.at(roster) < sink.at(session_kept), "{:?}", sink.all());
    let saved = alice.saved().expect("a session once told it is kept");

    // The link lost and taken back, with nobody there to say anything.
    proxy.sever();
    kept_times(&sink, 2).await;
    let back = sink
        .at(|u| matches!(u, CoreUpdate::Reconnected { .. }))
        .unwrap();
    assert!(back < sink.positions(session_kept)[1], "{:?}", sink.all());
    assert!(alice.saved().is_some());

    // And a session taken up again by a new connection, as after a restart.
    alice.hang_up(false);
    let again_sink = Arc::new(Sink::default());
    let again = ServerConnection::new(server.url.clone(), again_sink.clone());
    let info = again
        .login(Some("alice".into()), pw("alice"), Some(saved))
        .await
        .unwrap();
    assert!(info.resumed, "{info:?}");
    kept_times(&again_sink, 1).await;
    assert!(again.saved().is_some());
}

/// Waits until `sink` has been told its session is kept after `after`.
async fn kept_after(sink: &Sink, after: usize) {
    for _ in 0..300 {
        if sink.positions(session_kept).iter().any(|&k| k > after) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "never told the session kept after {after}: {:?}",
        sink.all()
    );
}

#[tokio::test]
async fn a_session_is_told_kept_as_the_app_goes_and_after_each_line_behind() {
    let server = Server::start(&["alice", "bob"]).await;
    let (alice, sink) = logged_in(&server.url, "alice").await;
    let (bob, bob_sink) = logged_in(&server.url, "bob").await;
    kept_times(&sink, 1).await;

    // In front, lines move the cursor but ask for no write each.
    for n in 0..3 {
        bob.chat(format!("in front {n}")).await.unwrap();
    }
    sink.heard("the last in front", said("in front 2")).await;
    alice.set_background_linger(60_000);
    alice.set_foreground(false);
    // Told as it goes, once the cursor covers what it was handed in front.
    kept_after(&sink, sink.at(said("in front 2")).unwrap()).await;
    assert_eq!(sink.count(session_kept), 2, "{:?}", sink.all());

    // Behind, each line is told, so what is kept covers it however soon
    // the process is stopped.
    bob.chat("behind".into()).await.unwrap();
    sink.heard("behind", said("behind")).await;
    kept_after(&sink, sink.at(said("behind")).unwrap()).await;
    let saved = alice.saved().unwrap();
    alice.hang_up(false);
    bob_sink
        .heard("alice detached", status_of("alice", Status::Detached))
        .await;
    bob.chat("while gone".into()).await.unwrap();

    // Replayed, before the roster a new connection is given: a cursor short
    // of "behind" is synced instead, and nothing is replayed.
    let again_sink = Arc::new(Sink::default());
    let again = ServerConnection::new(server.url.clone(), again_sink.clone());
    let info = again
        .login(Some("alice".into()), pw("alice"), Some(saved))
        .await
        .unwrap();
    assert!(info.resumed, "{info:?}");
    again_sink.heard("the replay", said("while gone")).await;
    let roster_at = again_sink.at(roster).unwrap();
    assert!(
        roster_at > again_sink.at(said("while gone")).unwrap(),
        "{:?}",
        again_sink.all()
    );
    assert_eq!(
        again_sink.at(said("behind")),
        None,
        "{:?}",
        again_sink.all()
    );
}

#[tokio::test]
async fn a_session_that_expired_while_the_link_was_down_is_logged_in_again() {
    let server = Server::with_grace(&["alice", "bob"], 1).await;
    let proxy = Proxy::to(&server).await;
    let (alice, sink) = logged_in(&proxy.url, "alice").await;
    let first = saved_field(&saved_soon(&alice).await, "session");
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
        matches!(u, CoreUpdate::Reconnected { gap: true, .. })
    })
    .await;
    let back = sink
        .at(|u| matches!(u, CoreUpdate::Reconnected { .. }))
        .unwrap();
    let rosters = sink.positions(roster);
    assert_eq!(rosters.len(), 2, "{:?}", sink.all());
    assert!(rosters[1] > back);
    assert_ne!(saved_field(&saved_soon(&alice).await, "session"), first);
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
        matches!(u, CoreUpdate::Reconnected { gap: false, .. })
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
    alice.hang_up(false);
    // The cursor moves just after each batch is delivered, and a resume
    // from short of the last is synced rather than replayed: it is final
    // once the link is.
    sink.heard("hung up", |u| matches!(u, CoreUpdate::Closed { .. }))
        .await;
    let saved = saved_soon(&alice).await;
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
    assert!(info.resumed, "{info:?}");
    sink.heard("the replay", said("while gone")).await;
    let roster_at = sink.at(roster).unwrap();
    assert!(roster_at > sink.at(said("while gone")).unwrap());
    assert!(matches!(
        &sink.0.lock().unwrap().iter().flatten().nth(roster_at),
        Some(CoreUpdate::Roster { self_uid, .. }) if *self_uid == saved_field(&saved, "self_uid")
    ));
    assert_eq!(sink.at(said("before")), None, "{:?}", sink.all());
    assert_eq!(
        saved_field(&saved_soon(&again).await, "session"),
        saved_field(&saved, "session")
    );
}

#[tokio::test]
async fn a_session_taken_by_another_device_is_not_taken_back() {
    let server = Server::start(&["alice"]).await;
    let (alice, sink) = logged_in(&server.url, "alice").await;
    let saved = saved_soon(&alice).await;
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
    let saved = saved_soon(&alice).await;
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
    let mut saved: Value = serde_json::from_slice(&saved_soon(&alice).await).unwrap();
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
    let resynced: Value = serde_json::from_slice(&saved_soon(&again).await).unwrap();
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
            rotation: None,
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
    let info = alice
        .login_identity(device, true, None, None)
        .await
        .unwrap();
    assert!(info.can_resume, "{info:?}");
    assert_eq!(info.fingerprint.as_deref(), Some(fingerprint.as_str()));
    sink.heard("her roster", roster).await;
    let first = saved_field(&saved_soon(&alice).await, "session");
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
    // The fresh login's account of the identity, told with it.
    sink.heard("back", |u| {
        matches!(u, CoreUpdate::Reconnected { gap: true, info: Some(i) }
            if i.fingerprint.as_deref() == Some(fingerprint.as_str()))
    })
    .await;
    assert_ne!(saved_field(&saved_soon(&alice).await, "session"), first);
    assert_eq!(
        saved_field(&saved_soon(&alice).await, "guest"),
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
        alice.login_identity(device, true, None, None).await,
        Err(CoreError::Protocol { .. })
    ));
}

#[tokio::test]
async fn a_certificate_outside_its_time_is_refused_before_anything_is_sent() {
    use hl_identity::{Card, DeviceCert, DeviceKey, IdentityKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Past its end, and not begun: a phone whose clock is behind.
    for (issued, lifetime, want) in [
        (now - 2000, 1000, "cert_expired"),
        (now + 3600, 86_400, "cert_not_yet_valid"),
    ] {
        let id = IdentityKey::generate();
        let key = DeviceKey::generate();
        let cert = DeviceCert::for_keys(&id, key.public(), key.public_enc(), issued, lifetime)
            .unwrap()
            .sign(&id);
        let card = Card::new(&id, "Alice", now).sign(&id, Vec::new()).unwrap();
        // Nothing listens here: a login that reached for the network would
        // be refused as unreachable instead.
        let alice = ServerConnection::new("ws://127.0.0.1:9/ng".into(), Arc::new(Sink::default()));
        let device = DeviceIdentity {
            device_seed: key.seed().to_vec(),
            cert,
            card,
            rotation: None,
        };
        let refused = alice.login_identity(device, true, None, None).await;
        assert!(
            matches!(&refused, Err(CoreError::Refused { code, .. }) if code == want),
            "{want}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_saved_session_is_not_resumed_with_a_certificate_past_its_time() {
    use hl_identity::{DeviceCert, DeviceKey};
    let server = Server::with_identity(&[], 300).await;
    let (id, d) = device("Alice");
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: d.key.seed().to_vec(),
        cert: d.cert.clone(),
        card: d.card.clone(),
        rotation: None,
    };
    alice
        .login_identity(device, true, None, None)
        .await
        .unwrap();
    let saved = saved_soon(&alice).await;
    alice.hang_up(false);

    // The same identity's device, its certificate since past its time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = DeviceKey::generate();
    let lapsed = DeviceCert::for_keys(&id, key.public(), key.public_enc(), now - 2000, 1000)
        .unwrap()
        .sign(&id);
    // Nothing listens here: a resume that reached for the network would be
    // refused as unreachable instead.
    let again = ServerConnection::new("ws://127.0.0.1:9/ng".into(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: key.seed().to_vec(),
        cert: lapsed,
        card: d.card.clone(),
        rotation: None,
    };
    let refused = again.login_identity(device, true, None, Some(saved)).await;
    assert!(
        matches!(&refused, Err(CoreError::Refused { code, .. }) if code == "cert_expired"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_device_revoked_while_its_link_was_down_is_refused_and_not_tried_again() {
    let server = Server::with_identity(&["bob"], 300).await;
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(proxy.url.clone(), sink.clone());
    let (_id, d) = device("Alice");
    let device_fp = hl_identity::Fingerprint::of(&d.key.public()).to_string();
    let again = || DeviceIdentity {
        device_seed: d.key.seed().to_vec(),
        cert: d.cert.clone(),
        card: d.card.clone(),
        rotation: None,
    };
    alice
        .login_identity(again(), true, None, None)
        .await
        .unwrap();
    sink.heard("her roster", roster).await;
    let (_bob, bob_sink) = logged_in(&server.url, "bob").await;
    bob_sink
        .heard(
            "alice",
            |u| matches!(u, CoreUpdate::Roster { users, .. } if users.iter().any(|u| u.nick == "Alice")),
        )
        .await;

    proxy.refuse(true);
    proxy.sever();
    server.revoke_device(&device_fp);
    // Her session, waiting to be resumed, ends with the revocation.
    bob_sink
        .heard_within(10, "alice's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    proxy.refuse(false);
    alice.network_changed();
    sink.heard_within(
        10,
        "the refusal",
        |u| matches!(u, CoreUpdate::Refused { code, .. } if code == "revoked"),
    )
    .await;
    sink.heard("the end", |u| matches!(u, CoreUpdate::Closed { .. }))
        .await;
    let closed = sink.at(|u| matches!(u, CoreUpdate::Closed { .. })).unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        sink.positions(reconnecting).iter().all(|&i| i < closed),
        "tried again after the refusal: {:?}",
        sink.all()
    );

    let fresh = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let refused = fresh.login_identity(again(), true, None, None).await;
    assert!(
        matches!(&refused, Err(CoreError::Refused { code, .. }) if code == "revoked"),
        "{refused:?}"
    );
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
    match alice.login_identity(device, true, None, None).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "identity_not_honored"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_identity_the_server_makes_a_guest_of_is_still_its_own_session() {
    let server = Server::with_guest_identity(&["guest"]).await;
    let alice = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let (device, fingerprint) = identity("Alice");
    let info = alice
        .login_identity(device, true, None, None)
        .await
        .unwrap();
    assert_eq!(info.fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert!(info.outcome.is_some(), "{info:?}");
}

#[tokio::test]
async fn an_identity_given_an_accounts_password_is_linked_to_it_and_lands_on_it_after() {
    let server = Server::with_identity(&["bob"], 300).await;
    let (_, d) = device("Bob");
    let bobs = || DeviceIdentity {
        device_seed: d.key.seed().to_vec(),
        cert: d.cert.clone(),
        card: d.card.clone(),
        rotation: None,
    };
    let link = |password: &str| ClassicLogin {
        login: "bob".into(),
        password: password.into(),
    };
    let bob = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    match bob
        .login_identity(bobs(), true, Some(link("pw-wrong")), None)
        .await
    {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "login_failed"),
        other => panic!("{other:?}"),
    }
    let info = bob
        .login_identity(bobs(), true, Some(link("pw-bob")), None)
        .await
        .unwrap();
    assert_eq!(info.outcome.as_deref(), Some("linked"), "{info:?}");
    bob.disconnect().await;

    // Asked to make an account, and landing on bob's by the link instead.
    let again = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let info = again
        .login_identity(bobs(), true, None, None)
        .await
        .unwrap();
    assert_eq!(info.outcome.as_deref(), Some("linked"), "{info:?}");
}

#[tokio::test]
async fn a_linked_identity_logs_in_again_after_a_lapse_without_the_password() {
    let server = Server::with_identity(&["bob", "alice"], 1).await;
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let bob = ServerConnection::new(proxy.url.clone(), sink.clone());
    let (device, _) = identity("Bob");
    let link = ClassicLogin {
        login: "bob".into(),
        password: "pw-bob".into(),
    };
    bob.login_identity(device, true, Some(link), None)
        .await
        .unwrap();
    sink.heard("his roster", roster).await;
    // The password sent again would be refused now.
    let file = server.account_file("bob");
    let account = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, account.replace("pw-bob", "pw-changed")).unwrap();

    let (_alice, alice_sink) = logged_in(&server.url, "alice").await;
    proxy.refuse(true);
    proxy.sever();
    // The session gone, so only a login brings him back.
    alice_sink
        .heard_within(30, "bob's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    proxy.refuse(false);
    bob.network_changed();
    sink.heard_within(30, "back on his account", |u| {
        matches!(u, CoreUpdate::Reconnected { gap: true, info: Some(i) }
            if i.outcome.as_deref() == Some("linked"))
    })
    .await;
}

/// `account`'s file, made to take no link but one an operator makes: an
/// identity that names it lands as a guest, so the server needs a guest.
fn not_self_linkable(server: &Server, account: &str) {
    let file = server.account_file(account);
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str("[identity]\nallow_self_link = false\n");
    std::fs::write(&file, text).unwrap();
}

#[tokio::test]
async fn a_link_the_server_could_not_make_leaves_no_account_made_after_a_lapse() {
    let server = Server::with_identity(&["bob", "alice", "guest"], 1).await;
    not_self_linkable(&server, "bob");
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let bob = ServerConnection::new(proxy.url.clone(), sink.clone());
    let (device, _) = identity("Bob");
    let link = ClassicLogin {
        login: "bob".into(),
        password: "pw-bob".into(),
    };
    let info = bob
        .login_identity(device, true, Some(link), None)
        .await
        .unwrap();
    assert_eq!(info.outcome.as_deref(), Some("classic_pending_link"));
    sink.heard("his roster", roster).await;

    let (_alice, alice_sink) = logged_in(&server.url, "alice").await;
    proxy.refuse(true);
    proxy.sever();
    alice_sink
        .heard_within(30, "bob's session ending", |u| {
            matches!(u, CoreUpdate::UserParted { .. })
        })
        .await;
    proxy.refuse(false);
    bob.network_changed();
    sink.heard_within(30, "back, still a guest", |u| {
        matches!(u, CoreUpdate::Reconnected { info: Some(i), .. }
            if i.outcome.as_deref() == Some("guest"))
    })
    .await;
}

#[tokio::test]
async fn an_upgrade_refused_after_a_link_is_proved_again_without_the_password() {
    let server = Server::with_identity(&["bob", "guest"], 300).await;
    not_self_linkable(&server, "bob");
    let proxy = Proxy::to(&server).await;
    proxy.refuse_upgrades(1);
    let bob = ServerConnection::new(proxy.url.clone(), Arc::new(Sink::default()));
    let (device, _) = identity("Bob");
    let link = ClassicLogin {
        login: "bob".into(),
        password: "pw-bob".into(),
    };
    let info = bob
        .login_identity(device, true, Some(link), None)
        .await
        .unwrap();
    assert_eq!(proxy.upgrades_refused(), 1);
    // The first auth's answer, not the guest the second one was made.
    assert_eq!(info.outcome.as_deref(), Some("classic_pending_link"));
    let heard = proxy.heard();
    let sent = heard.windows(6).filter(|w| w == b"pw-bob").count();
    assert_eq!(sent, 1, "{}", String::from_utf8_lossy(&heard));
}

#[tokio::test]
async fn a_server_that_takes_no_identity_sign_in_says_so() {
    let server = Server::start(&["bob"]).await;
    let bob = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let (device, _) = identity("Bob");
    match bob.login_identity(device, true, None, None).await {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "no_identity_sign_in"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_identitys_session_resumes_as_itself_and_another_identitys_is_not_resumed() {
    let server = Server::with_identity(&[], 300).await;
    let proxy = Proxy::to(&server).await;
    let sink = Arc::new(Sink::default());
    let alice = ServerConnection::new(proxy.url.clone(), sink.clone());
    let (device, fingerprint) = identity("Alice");
    alice
        .login_identity(device, true, None, None)
        .await
        .unwrap();
    sink.heard("her roster", roster).await;
    proxy.sever();
    sink.heard("back", |u| {
        matches!(
            u,
            CoreUpdate::Reconnected {
                gap: false,
                info: None
            }
        )
    })
    .await;
    let saved = saved_soon(&alice).await;
    assert_eq!(saved_field(&saved, "fingerprint"), Value::from(fingerprint));
    alice.hang_up(false);

    // Bob's device with Alice's saved session: a login of his own.
    let bob = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let (device, bobs) = identity("Bob");
    let info = bob
        .login_identity(device, true, None, Some(saved.clone()))
        .await
        .unwrap();
    assert_eq!(info.fingerprint.as_deref(), Some(bobs.as_str()));
    assert!(!info.resumed, "{info:?}");
    assert_ne!(
        saved_field(&saved_soon(&bob).await, "session"),
        saved_field(&saved, "session")
    );
}

#[tokio::test]
async fn an_identity_kept_at_a_registrar_is_restored_to_a_device_that_logs_in() {
    use hexline_core::{cert_for_device, restore_identity, SecretKind};
    use hl_identity::envelope::Secret;
    use hl_identity::RecoveryCode;
    let server = Server::with_registrar(&[]).await;
    let alice = back_up(&server, "alice", &Secret::Passphrase("correct horse")).await;
    let code = RecoveryCode::generate();
    let bob = back_up(&server, "bob", &Secret::RecoveryCode(&code)).await;

    for (handle, kind, secret, id) in [
        (
            "alice",
            SecretKind::Passphrase,
            "correct horse".to_string(),
            &alice,
        ),
        (
            "bob",
            SecretKind::RecoveryCode,
            code.display().to_string(),
            &bob,
        ),
    ] {
        let restored = restore_identity(
            server.http.clone(),
            handle.into(),
            kind,
            secret,
            "Pixel".into(),
        )
        .await
        .unwrap();
        let fingerprint = hl_identity::Fingerprint::of(&id.public()).to_string();
        assert_eq!(restored.fingerprint, fingerprint);
        assert!(restored.new_card, "the registrar keeps no card for it");
        assert!(restored.attested, "the card carries a fresh attestation");
        let info = cert_for_device(
            restored.cert.clone(),
            restored.card.clone(),
            restored.seed.clone(),
        )
        .unwrap();
        assert_eq!(info.fingerprint, fingerprint);
        assert!(info.can_login && info.can_manage && !info.can_vouch);
        assert_eq!(info.name.as_deref(), Some("Pixel"));

        let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
        let device = DeviceIdentity {
            device_seed: restored.seed,
            cert: restored.cert,
            card: restored.card,
            rotation: None,
        };
        let login = conn.login_identity(device, true, None, None).await.unwrap();
        assert_eq!(login.fingerprint, Some(fingerprint));
    }
}

#[tokio::test]
async fn a_wrong_secret_and_a_handle_with_no_envelope_are_answered_alike() {
    use hexline_core::{restore_identity, SecretKind};
    use hl_identity::envelope::Secret;
    let server = Server::with_registrar(&[]).await;
    back_up(&server, "alice", &Secret::Passphrase("correct horse")).await;
    for (handle, secret) in [("alice", "wrong horse"), ("nobody", "correct horse")] {
        match restore_identity(
            server.http.clone(),
            handle.into(),
            SecretKind::Passphrase,
            secret.into(),
            "Pixel".into(),
        )
        .await
        {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "not_found", "{handle}"),
            other => panic!("{handle}: {:?}", other.map(|r| r.fingerprint)),
        }
    }
}

#[tokio::test]
async fn what_would_be_refused_anyway_is_refused_before_the_registrar_is_asked() {
    use hexline_core::{restore_identity, SecretKind};
    // Nothing listens here: a refusal that asked it would be a connect error.
    let nowhere = "http://127.0.0.1:9".to_string();
    for (kind, secret, name, want) in [
        (SecretKind::Passphrase, "  ", "Pixel", "bad_passphrase"),
        (
            SecretKind::RecoveryCode,
            "not a code",
            "Pixel",
            "bad_recovery_code",
        ),
        (
            SecretKind::Passphrase,
            "correct horse",
            " Pixel",
            "bad_device_name",
        ),
    ] {
        match restore_identity(
            nowhere.clone(),
            "alice".into(),
            kind,
            secret.into(),
            name.into(),
        )
        .await
        {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, want),
            other => panic!("{want}: {:?}", other.map(|r| r.fingerprint)),
        }
    }
    match restore_identity(
        "http://192.0.2.1".into(),
        "alice".into(),
        SecretKind::Passphrase,
        "x".into(),
        "Pixel".into(),
    )
    .await
    {
        Err(CoreError::Refused { code, .. }) => assert_eq!(code, "bad_registrar"),
        other => panic!("{:?}", other.map(|r| r.fingerprint)),
    }
}

#[tokio::test]
async fn a_restored_device_is_vouched_for_where_unattested_identities_are_guests() {
    use hexline_core::{restore_identity, SecretKind};
    use hl_identity::envelope::Secret;
    let server = Server::with_registrar_vouching(&[]).await;
    back_up(&server, "alice", &Secret::Passphrase("correct horse")).await;
    let restored = restore_identity(
        server.http.clone(),
        "alice".into(),
        SecretKind::Passphrase,
        "correct horse".into(),
        "Pixel".into(),
    )
    .await
    .unwrap();
    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: restored.seed,
        cert: restored.cert,
        card: restored.card,
        rotation: None,
    };
    let info = conn.login_identity(device, true, None, None).await.unwrap();
    assert_eq!(info.outcome.as_deref(), Some("created"), "{info:?}");
}

/// What enrolling a device asks: refused with this code.
/// What a phone holding an identity set up at `registrar` keeps of it,
/// before any device epoch is learned.
fn kept(registrar: &str) -> hexline_core::HolderKept {
    hexline_core::HolderKept {
        registrar: Some(registrar.to_owned()),
        epoch: 0,
        devices: Vec::new(),
    }
}

fn refused_as(e: &CoreError) -> &str {
    match e {
        CoreError::Refused { code, .. } => code,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn a_device_a_holder_certifies_by_its_code_logs_in_as_the_identity() {
    use hexline_core::{cert_for_device, Enrollee};
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let typed = session.code.to_lowercase().replace('-', " ");
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(typed),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    // What the holder's prompt shows is what the phone shows.
    assert_eq!(
        hl_identity::Fingerprint::of(&asked.request.device).short(),
        phone.device_fingerprint()
    );
    assert_eq!(asked.request.name.as_deref(), Some("Hexline"));
    holder.approve(&session, &asked, 90).await;
    let enrolled = asking.await.unwrap().unwrap();
    let fingerprint = hl_identity::Fingerprint::of(&holder.id.public());
    assert_eq!(enrolled.fingerprint, fingerprint.to_string());
    assert_eq!(enrolled.short, fingerprint.short());
    assert_eq!(enrolled.name, "Alice");
    let info = cert_for_device(enrolled.cert.clone(), enrolled.card.clone(), phone.seed()).unwrap();
    assert!(info.can_login && info.can_message && !info.can_manage);

    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: phone.seed(),
        cert: enrolled.cert,
        card: enrolled.card,
        rotation: None,
    };
    let login = conn.login_identity(device, true, None, None).await.unwrap();
    assert_eq!(login.fingerprint, Some(fingerprint.to_string()));
}

#[tokio::test]
async fn a_holders_no_and_a_wrong_code_are_told_apart() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    holder.deny(&session, &asked, "not_mine").await;
    match asking.await.unwrap().unwrap_err() {
        CoreError::Refused { code, detail, .. } => {
            assert_eq!((code.as_str(), detail.as_str()), ("denied", "not_mine"))
        }
        other => panic!("{other:?}"),
    }
    // Its one request spent, the code admits no other.
    let again = Enrollee::new()
        .enroll(
            server.url.clone(),
            Some(session.code.clone()),
            "Hexline".into(),
        )
        .await
        .unwrap_err();
    assert_eq!(refused_as(&again), "unknown_code");
    let typo = Enrollee::new()
        .enroll(server.url.clone(), Some("K7PM".into()), "Hexline".into())
        .await
        .unwrap_err();
    assert_eq!(refused_as(&typo), "bad_code");
}

#[tokio::test]
async fn an_answer_for_another_device_is_refused() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    let other = hl_identity::DeviceKey::generate();
    // Its own encryption key beside another's signing key, and the reverse.
    holder
        .answer_with(
            &session,
            &asked,
            other.public(),
            asked.request.device_enc,
            90,
        )
        .await;
    assert_eq!(
        refused_as(&asking.await.unwrap().unwrap_err()),
        "wrong_device"
    );

    let session = holder.open().await;
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    holder
        .answer_with(
            &session,
            &asked,
            asked.request.device,
            other.public_enc(),
            90,
        )
        .await;
    assert_eq!(
        refused_as(&asking.await.unwrap().unwrap_err()),
        "wrong_device"
    );
}

#[tokio::test]
async fn a_wait_for_a_holder_stops_when_canceled() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    holder.asked(&session).await;
    phone.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(5), asking)
        .await
        .expect("a canceled wait ends at once")
        .unwrap();
    assert_eq!(refused_as(&ended.unwrap_err()), "canceled");
}

#[tokio::test]
async fn a_device_is_renewed_by_its_holder_standing_by_and_without_one_needs_a_code() {
    use hexline_core::{cert_for_device, Enrollee};
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    holder.approve(&session, &asked, 1).await;
    let first = asking.await.unwrap().unwrap();

    // Nobody standing by: the renewal is to be asked for with a code.
    let renewing = Enrollee::renewing(phone.seed(), first.cert.clone()).unwrap();
    let none = renewing
        .clone()
        .enroll(server.url.clone(), None, "Hexline".into())
        .await
        .unwrap_err();
    assert_eq!(refused_as(&none), "no_holder");

    let standing = holder.stand_by().await;
    let asking = tokio::spawn(
        renewing
            .clone()
            .enroll(server.url.clone(), None, "Hexline".into()),
    );
    let asked = holder.asked(&standing).await;
    let prev =
        hl_identity::DeviceCert::parse(asked.request.prev.as_deref().expect("its certificate"))
            .unwrap();
    assert_eq!(asked.request.device, prev.device);
    assert_eq!(asked.request.caps, prev.caps, "no more than it has");
    holder.approve(&standing, &asked, 90).await;
    let renewed = asking.await.unwrap().unwrap();
    assert_eq!(renewed.fingerprint, first.fingerprint);
    let was = cert_for_device(first.cert, first.card, phone.seed()).unwrap();
    let now = cert_for_device(renewed.cert, renewed.card, renewing.seed()).unwrap();
    assert_eq!(now.device, was.device, "the same device");
    assert!(now.expires > was.expires);
}

#[tokio::test]
async fn a_renewal_answered_by_another_identity_is_refused() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let alice = Holder::new(&server, "Alice");
    let session = alice.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = alice.asked(&session).await;
    alice.approve(&session, &asked, 1).await;
    let first = asking.await.unwrap().unwrap();

    // By a code another identity's holder shows.
    let mallory = Holder::new(&server, "Mallory");
    let session = mallory.open().await;
    let renewing = Enrollee::renewing(phone.seed(), first.cert).unwrap();
    let asking = tokio::spawn(renewing.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = mallory.asked(&session).await;
    mallory.approve(&session, &asked, 90).await;
    assert_eq!(
        refused_as(&asking.await.unwrap().unwrap_err()),
        "wrong_identity"
    );
}

#[tokio::test]
async fn a_server_with_no_mailbox_says_so() {
    use hexline_core::Enrollee;
    let server = Server::start(&[]).await;
    let none = Enrollee::new()
        .enroll(
            server.url.clone(),
            Some("K7PM-4XWE".into()),
            "Hexline".into(),
        )
        .await
        .unwrap_err();
    assert_eq!(refused_as(&none), "no_mailbox");
}

#[tokio::test]
async fn a_new_device_for_an_identity_on_the_phone_is_kept_only_from_that_identity() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let alice = Holder::new(&server, "Alice");
    let session = alice.open().await;
    let lapsed = Enrollee::new();
    let asking = tokio::spawn(lapsed.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = alice.asked(&session).await;
    alice.approve(&session, &asked, 1).await;
    let kept = asking.await.unwrap().unwrap();

    // The device that takes its place, by a code, from either holder.
    let mallory = Holder::new(&server, "Mallory");
    for (holder, want) in [(&mallory, Some("wrong_identity")), (&alice, None)] {
        let session = holder.open().await;
        let phone = Enrollee::new();
        phone.expect_identity(kept.fingerprint.clone()).unwrap();
        let asking = tokio::spawn(phone.clone().enroll(
            server.url.clone(),
            Some(session.code.clone()),
            "Hexline".into(),
        ));
        let asked = holder.asked(&session).await;
        holder.approve(&session, &asked, 90).await;
        let got = asking.await.unwrap();
        assert_eq!(got.as_ref().err().map(refused_as), want, "{got:?}");
    }
}

#[tokio::test]
async fn an_enrollment_canceled_before_it_asks_spends_no_code() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let left = Enrollee::new();
    left.cancel();
    let ended = left
        .enroll(
            server.url.clone(),
            Some(session.code.clone()),
            "Hexline".into(),
        )
        .await
        .unwrap_err();
    assert_eq!(refused_as(&ended), "canceled");
    // The code admits one request, and that is still to come.
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    holder.approve(&session, &asked, 90).await;
    asking.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_poll_the_link_drops_is_asked_again_under_the_same_request() {
    use hexline_core::Enrollee;
    use hxng_client::testing::Holder;
    let server = Server::with_identity(&[], 1).await;
    let proxy = Proxy::to(&server).await;
    let holder = Holder::new(&server, "Alice");
    let session = holder.open().await;
    let phone = Enrollee::new();
    let asking = tokio::spawn(phone.clone().enroll(
        proxy.url.clone(),
        Some(session.code.clone()),
        "Hexline".into(),
    ));
    let asked = holder.asked(&session).await;
    for _ in 0..100 {
        if phone.may_have_asked() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(phone.may_have_asked(), "its request sent");
    // Into its long poll by now, which is cut off while the holder answers.
    tokio::time::sleep(Duration::from_millis(200)).await;
    proxy.sever();
    holder.approve(&session, &asked, 90).await;
    let enrolled = tokio::time::timeout(Duration::from_secs(20), asking)
        .await
        .expect("answered")
        .unwrap()
        .unwrap();
    assert_eq!(
        enrolled.fingerprint,
        hl_identity::Fingerprint::of(&holder.id.public()).to_string()
    );
    assert!(enrolled.info.can_login && !enrolled.info.can_vouch);
}

/// A holder set up with both codes typed back, its device minted and held.
fn confirmed_setup() -> (
    Arc<hexline_core::HolderSetup>,
    String,
    hexline_core::HolderMinted,
) {
    let setup = hexline_core::HolderSetup::new("Carol".into()).unwrap();
    assert!(setup.confirm_successor(setup.successor_code().unwrap()));
    let recovery = String::from_utf8(setup.recovery_code().unwrap()).unwrap();
    assert!(setup.confirm_recovery(recovery.clone().into_bytes()));
    let minted = setup.mint("Pixel".into()).unwrap();
    setup.held().unwrap();
    (setup, recovery, minted)
}

/// The fingerprint `code` restores `handle` to, on a device whose card
/// the registrar keeps, attested for it: as a phone with nothing but the
/// code finds it.
async fn restored_by(server: &Server, handle: &str, code: &str) -> Result<String, CoreError> {
    use hexline_core::{restore_identity, SecretKind};
    let restored = restore_identity(
        server.http.clone(),
        handle.into(),
        SecretKind::RecoveryCode,
        code.into(),
        "Tablet".into(),
    )
    .await?;
    assert!(!restored.new_card, "the registrar keeps the card");
    assert!(restored.attested, "and attests it again");
    Ok(restored.fingerprint)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_holder_made_on_the_phone_logs_in_attested_and_is_restored_by_its_recovery_code() {
    use hexline_core::{holder_mint, restore_identity_to_hold, SecretKind};
    let server = Server::with_registrar_vouching(&[]).await;
    let (setup, recovery, minted) = confirmed_setup();
    let (fingerprint, seed) = (setup.fingerprint(), setup.identity_seed().unwrap());
    let committed = setup
        .clone()
        .commit(server.http.clone(), "carol".into(), None)
        .await
        .unwrap();
    let card = hl_identity::Card::parse(&committed.card).unwrap();
    assert_eq!(
        card.successor,
        hl_identity::Card::parse(&setup.card()).unwrap().successor
    );
    assert!(
        card.successor.is_some(),
        "the commitment kept on the attested card"
    );
    assert_eq!(
        refused_as(&setup.identity_seed().unwrap_err()),
        "committed",
        "nothing kept once committed"
    );

    // Restored by a phone that has seen nothing but the code.
    let paper = recovery.to_lowercase().replace('-', " ");
    assert_eq!(
        restored_by(&server, "carol", &paper).await.unwrap(),
        fingerprint
    );
    let held = restore_identity_to_hold(
        server.http.clone(),
        "carol".into(),
        SecretKind::RecoveryCode,
        recovery,
        "Tablet".into(),
    )
    .await
    .unwrap();
    assert_eq!(held.identity_seed, seed);
    assert_eq!(
        hl_identity::Card::parse(&held.device.card)
            .unwrap()
            .successor,
        card.successor,
        "the commitment kept from the registrar's card"
    );
    holder_mint(held.identity_seed, held.device.card, "Tablet".into(), 0).unwrap();

    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: minted.device_seed,
        cert: minted.cert,
        card: committed.card,
        rotation: None,
    };
    let login = conn.login_identity(device, true, None, None).await.unwrap();
    assert_eq!(login.fingerprint, Some(fingerprint));
    assert_eq!(
        login.outcome.as_deref(),
        Some("created"),
        "attested: {login:?}"
    );
}

/// `id`'s registration of `handle` at `server`'s registrar, committing to
/// `successor`: later than any request a commit just signed.
async fn registered(
    server: &Server,
    id: &hl_identity::IdentityKey,
    handle: &str,
    successor: Option<[u8; 32]>,
) -> Result<Value, CoreError> {
    use base64::Engine;
    let request = hl_identity::RegisterRequest {
        identity: id.public(),
        registrar: "127.0.0.1".into(),
        handle: handle.into(),
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2,
        successor,
        proof: None,
    }
    .sign(id)
    .unwrap();
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    Ok(hxng_client::auth::post(
        &http,
        &format!("{}/registrar/register", server.http),
        Some(serde_json::json!({
            "request": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request)
        })),
    )
    .await?)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_registrar_holds_the_successor_a_setup_commits_to() {
    let server = Server::with_registrar(&[]).await;
    let (setup, ..) = confirmed_setup();
    let seed: [u8; 32] = setup.identity_seed().unwrap().try_into().unwrap();
    setup
        .commit(server.http.clone(), "gina".into(), None)
        .await
        .unwrap();
    let id = hl_identity::IdentityKey::from_seed(&seed);
    let e = registered(&server, &id, "gina", Some([9; 32]))
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "successor_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handle_taken_leaves_the_codes_to_commit_another() {
    let server = Server::with_registrar(&[]).await;
    let (first, ..) = confirmed_setup();
    first
        .commit(server.http.clone(), "dave".into(), None)
        .await
        .unwrap();
    let (second, recovery, _) = confirmed_setup();
    let taken = second
        .clone()
        .commit(server.http.clone(), "dave".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&taken), "handle_taken");
    let fingerprint = second.fingerprint();
    second
        .commit(server.http.clone(), "dave2".into(), None)
        .await
        .unwrap();
    assert_eq!(
        restored_by(&server, "dave2", &recovery).await.unwrap(),
        fingerprint
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_setup_registered_and_cut_short_is_committed_again_as_its_handle_alone() {
    let server = Server::with_registrar_invites(&["let-me-in"]).await;
    let (setup, recovery, _) = confirmed_setup();
    setup.fail_after_registering();
    let e = setup
        .clone()
        .commit(
            server.http.clone(),
            "hana".into(),
            Some(" let-me-in ".into()),
        )
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "registered_not_backed_up");
    let other = setup
        .clone()
        .commit(server.http.clone(), "hana2".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&other), "registered_as");
    // The invite is spent: asked again, the handle is not registered again.
    let fingerprint = setup.fingerprint();
    setup
        .commit(server.http.clone(), "hana".into(), None)
        .await
        .unwrap();
    assert_eq!(
        restored_by(&server, "hana", &recovery).await.unwrap(),
        fingerprint
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_setup_the_process_ended_in_is_committed_again_and_only_its_new_recovery_code_restores() {
    use hexline_core::HolderSetup;
    let server = Server::with_registrar(&[]).await;
    let (setup, first_code, minted) = confirmed_setup();
    // What the phone kept before the commit, as a process that ended
    // after it committed would find it.
    let (seed, card) = (setup.identity_seed().unwrap(), setup.card());
    setup
        .commit(server.http.clone(), "erin".into(), None)
        .await
        .unwrap();
    let resumed = HolderSetup::resume(
        seed,
        card,
        server.http.clone(),
        "erin".into(),
        minted.device_seed,
        minted.cert,
    )
    .unwrap();
    assert_eq!(resumed.successor_code(), None);
    let code = String::from_utf8(resumed.recovery_code().unwrap()).unwrap();
    assert!(resumed.confirm_recovery(code.clone().into_bytes()));
    let elsewhere = resumed
        .clone()
        .commit(server.http.clone(), "erin2".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&elsewhere), "registered_as");
    // In the second the process before signed in, as a restart may be.
    resumed
        .clone()
        .commit(server.http.clone(), "erin".into(), None)
        .await
        .unwrap();
    assert_eq!(
        restored_by(&server, "erin", &code).await.unwrap(),
        resumed.fingerprint()
    );
    assert_eq!(
        refused_as(&restored_by(&server, "erin", &first_code).await.unwrap_err()),
        "not_found"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registrar_that_wants_an_invite_registers_only_with_one() {
    let server = Server::with_registrar_invites(&["let-me-in"]).await;
    let (setup, ..) = confirmed_setup();
    for (invite, want) in [(None, "proof_required"), (Some("wrong"), "proof_invalid")] {
        let e = setup
            .clone()
            .commit(server.http.clone(), "frank".into(), invite.map(Into::into))
            .await
            .unwrap_err();
        assert_eq!(refused_as(&e), want, "{invite:?}");
    }
    setup
        .commit(
            server.http.clone(),
            "frank".into(),
            Some("let-me-in".into()),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_commit_asks_nothing_before_both_codes_are_typed_back_and_the_seed_is_held() {
    let setup = hexline_core::HolderSetup::new("Carol".into()).unwrap();
    // Nothing listens here: a commit that asked it would be a connect error.
    let nowhere = || "http://127.0.0.1:9".to_string();
    let e = setup
        .clone()
        .commit(nowhere(), "carol".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "unconfirmed");
    assert!(setup.confirm_successor(setup.successor_code().unwrap()));
    assert!(setup.confirm_recovery(setup.recovery_code().unwrap()));
    setup.mint("Pixel".into()).unwrap();
    let e = setup
        .clone()
        .commit(nowhere(), "carol".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "unheld");
    // A device minted again is not the one the app kept, until it says so.
    setup.held().unwrap();
    setup.mint("Pixel".into()).unwrap();
    let e = setup
        .commit(nowhere(), "carol".into(), None)
        .await
        .unwrap_err();
    assert_eq!(
        refused_as(&e),
        "unheld",
        "a device minted after it was held"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_commit_while_another_is_under_way_is_refused_and_the_first_goes_through() {
    let server = Server::with_registrar(&[]).await;
    let (setup, recovery, _) = confirmed_setup();
    let (registered, release) = setup.hold_after_registering();
    let first = tokio::spawn(
        setup
            .clone()
            .commit(server.http.clone(), "joan".into(), None),
    );
    registered.await.unwrap();
    for handle in ["joan", "joan2"] {
        let e = setup
            .clone()
            .commit(server.http.clone(), handle.into(), None)
            .await
            .unwrap_err();
        assert_eq!(refused_as(&e), "busy", "{handle}");
    }
    release.send(()).unwrap();
    first.await.unwrap().unwrap();
    assert_eq!(
        restored_by(&server, "joan", &recovery).await.unwrap(),
        setup.fingerprint()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_is_not_minted_or_held_while_a_commit_is_under_way() {
    let server = Server::with_registrar(&[]).await;
    let (setup, recovery, _) = confirmed_setup();
    let (registered, release) = setup.hold_after_registering();
    let first = tokio::spawn(
        setup
            .clone()
            .commit(server.http.clone(), "kim0".into(), None),
    );
    registered.await.unwrap();
    match setup.mint("Tablet".into()) {
        Err(e) => assert_eq!(refused_as(&e), "busy"),
        Ok(_) => panic!("minted while a commit was under way"),
    }
    assert_eq!(refused_as(&setup.held().unwrap_err()), "busy");
    release.send(()).unwrap();
    first.await.unwrap().unwrap();
    assert_eq!(
        restored_by(&server, "kim0", &recovery).await.unwrap(),
        setup.fingerprint()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registrar_is_checked_for_a_holder_before_any_code_is_shown() {
    use hexline_core::check_holder_registrar;
    let server = Server::with_registrar(&[]).await;
    check_holder_registrar(server.http.clone()).await.unwrap();
    let plain = Server::start(&[]).await;
    let e = check_holder_registrar(plain.http.clone())
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "not_a_registrar");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_setup_whose_handle_is_anothers_takes_another() {
    use hexline_core::HolderSetup;
    let server = Server::with_registrar(&[]).await;
    let (theirs, ..) = confirmed_setup();
    theirs
        .commit(server.http.clone(), "ivy".into(), None)
        .await
        .unwrap();
    let (setup, _, minted) = confirmed_setup();
    let resumed = HolderSetup::resume(
        setup.identity_seed().unwrap(),
        setup.card(),
        server.http.clone(),
        "ivy".into(),
        minted.device_seed,
        minted.cert,
    )
    .unwrap();
    let code = resumed.recovery_code().unwrap();
    assert!(resumed.confirm_recovery(code.clone()));
    let taken = resumed
        .clone()
        .commit(server.http.clone(), "ivy".into(), None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&taken), "handle_taken");
    resumed
        .clone()
        .commit(server.http.clone(), "ivy2".into(), None)
        .await
        .unwrap();
    let code = String::from_utf8(code).unwrap();
    assert_eq!(
        restored_by(&server, "ivy2", &code).await.unwrap(),
        resumed.fingerprint()
    );
}

/// A held identity committed at `server`'s registrar as `handle`: its seed,
/// its device and its card.
async fn held(server: &Server, handle: &str) -> (Vec<u8>, hexline_core::HolderMinted, Vec<u8>) {
    let (setup, _, minted) = confirmed_setup();
    let seed = setup.identity_seed().unwrap();
    let committed = setup
        .commit(server.http.clone(), handle.into(), None)
        .await
        .unwrap();
    (seed, minted, committed.card)
}

async fn restored_with(
    server: &Server,
    handle: &str,
    kind: hexline_core::SecretKind,
    secret: &str,
) -> Result<String, CoreError> {
    hexline_core::restore_identity(
        server.http.clone(),
        handle.into(),
        kind,
        secret.into(),
        "Tablet".into(),
    )
    .await
    .map(|r| r.fingerprint)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passphrase_backup_is_put_changed_and_removed() {
    use hexline_core::{backup_delete, backup_passphrase, SecretKind::Passphrase};
    let server = Server::with_registrar(&[]).await;
    let (seed, ..) = held(&server, "liam").await;
    let fingerprint = hl_identity::IdentityKey::from_seed(&seed.clone().try_into().unwrap())
        .fingerprint()
        .to_string();
    for short in ["  ", "nine char"] {
        let e = backup_passphrase(seed.clone(), server.http.clone(), short.into())
            .await
            .unwrap_err();
        assert_eq!(refused_as(&e), "bad_passphrase", "{short:?}");
    }
    backup_passphrase(seed.clone(), server.http.clone(), "correct horse".into())
        .await
        .unwrap();
    assert_eq!(
        restored_with(&server, "liam", Passphrase, "correct horse")
            .await
            .unwrap(),
        fingerprint
    );
    backup_passphrase(seed.clone(), server.http.clone(), "battery staple".into())
        .await
        .unwrap();
    assert_eq!(
        refused_as(
            &restored_with(&server, "liam", Passphrase, "correct horse")
                .await
                .unwrap_err()
        ),
        "not_found"
    );
    assert_eq!(
        restored_with(&server, "liam", Passphrase, "battery staple")
            .await
            .unwrap(),
        fingerprint
    );
    backup_delete(seed.clone(), server.http.clone(), Passphrase)
        .await
        .unwrap();
    assert_eq!(
        refused_as(
            &restored_with(&server, "liam", Passphrase, "battery staple")
                .await
                .unwrap_err()
        ),
        "not_found"
    );
    backup_delete(seed, server.http.clone(), Passphrase)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_recovery_code_replaces_the_one_before_once_typed_back() {
    use hexline_core::{RecoveryCodeSetup, SecretKind::RecoveryCode};
    let server = Server::with_registrar(&[]).await;
    let (setup, first, _) = confirmed_setup();
    let seed = setup.identity_seed().unwrap();
    setup
        .commit(server.http.clone(), "mia".into(), None)
        .await
        .unwrap();
    let new = RecoveryCodeSetup::new();
    let code = String::from_utf8(new.code().unwrap()).unwrap();
    assert_eq!(
        refused_as(
            &new.clone()
                .put(seed.clone(), server.http.clone())
                .await
                .unwrap_err()
        ),
        "unconfirmed"
    );
    assert!(!new.confirm(first.clone().into_bytes()));
    assert!(new.confirm(code.to_lowercase().into_bytes()));
    assert_eq!(new.code(), None, "shown no more once typed back");
    new.clone()
        .put(seed.clone(), server.http.clone())
        .await
        .unwrap();
    assert!(restored_with(&server, "mia", RecoveryCode, &code)
        .await
        .is_ok());
    assert_eq!(
        refused_as(
            &restored_with(&server, "mia", RecoveryCode, &first)
                .await
                .unwrap_err()
        ),
        "not_found"
    );
    assert_eq!(
        refused_as(&new.put(seed, server.http.clone()).await.unwrap_err()),
        "committed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_holders_renewed_certificate_logs_its_device_in() {
    use hexline_core::holder_renew;
    let server = Server::with_registrar_vouching(&[]).await;
    let (seed, minted, card) = held(&server, "noah").await;
    let cert = holder_renew(
        seed,
        card.clone(),
        minted.device_seed.clone(),
        minted.cert.clone(),
        0,
    )
    .unwrap();
    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: minted.device_seed,
        cert,
        card,
        rotation: None,
    };
    assert!(conn
        .login_identity(device, true, None, None)
        .await
        .unwrap()
        .fingerprint
        .is_some());
}

/// `work` polled once, as far as it goes before it first waits.
async fn begun<F: std::future::Future>(work: &mut std::pin::Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(work.as_mut().poll(cx).is_pending(), "done at once");
        std::task::Poll::Ready(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backup_begun_after_another_supersedes_it_before_it_signs() {
    use hexline_core::{backup_passphrase, SecretKind::Passphrase};
    let server = Server::with_registrar(&[]).await;
    let (seed, ..) = held(&server, "una").await;
    // The first held before it reserves its time until the second has begun.
    let (arrive, arrived) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    hexline_core::before_reserving(&seed, move || {
        arrive.send(()).unwrap();
        released.recv().unwrap();
    });
    let first = tokio::spawn(backup_passphrase(
        seed.clone(),
        server.http.clone(),
        "first passphrase".into(),
    ));
    tokio::task::spawn_blocking(move || arrived.recv().unwrap())
        .await
        .unwrap();
    let second = backup_passphrase(seed, server.http.clone(), "second passphrase".into());
    tokio::pin!(second);
    begun(&mut second).await;
    release.send(()).unwrap();
    second.await.unwrap();
    assert_eq!(refused_as(&first.await.unwrap().unwrap_err()), "superseded");
    assert!(
        restored_with(&server, "una", Passphrase, "second passphrase")
            .await
            .is_ok()
    );
    assert_eq!(
        refused_as(
            &restored_with(&server, "una", Passphrase, "first passphrase")
                .await
                .unwrap_err()
        ),
        "not_found"
    );
}

/// A held identity's session at `server`'s mailbox, for `phone` to ask by
/// its code, and the request it is sent.
async fn asked_by(
    server: &Server,
    card: &[u8],
    phone: &Arc<hexline_core::Enrollee>,
) -> (
    Arc<hexline_core::HolderSession>,
    hexline_core::HolderRequest,
    tokio::task::JoinHandle<Result<hexline_core::Enrolled, CoreError>>,
) {
    let session =
        hexline_core::open_holder_session(server.http.clone(), card.to_vec(), kept(&server.http))
            .await
            .unwrap();
    assert_eq!(
        session.host(),
        server.http.trim_start_matches("http://"),
        "with its port"
    );
    let typed = session.code().to_lowercase().replace('-', " ");
    let mut asking = tokio::spawn(phone.clone().enroll(
        server.url.clone(),
        Some(typed),
        "Tablet".into(),
    ));
    let asked = match within(async {
        tokio::select! {
            asked = session.clone().next_request() => asked,
            done = &mut asking => panic!("the enrollee ended before it asked: {:?}", done.unwrap().err()),
        }
    })
    .await
    {
        Ok(asked) => asked,
        Err(e) => panic!("{e:?}"),
    };
    (session, asked, asking)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_holding_its_identity_enrolls_another_device_by_its_code() {
    use hexline_core::{cert_for_device, Enrollee};
    let server = Server::with_registrar(&[]).await;
    let (seed, _, card) = held(&server, "pat").await;
    let phone = Enrollee::new();
    let (session, asked, asking) = asked_by(&server, &card, &phone).await;
    assert!(session.qr().is_none(), "no web client here to scan for");
    assert_eq!(
        asked.fingerprint,
        phone.device_fingerprint(),
        "the prompt shows what the device shows"
    );
    assert_eq!(asked.name.as_deref(), Some("Tablet"));
    assert!(!asked.scanned && !asked.renewal);
    // The code admits nobody else meanwhile.
    let again =
        within(Enrollee::new().enroll(server.url.clone(), Some(session.code()), "Tablet".into()))
            .await
            .unwrap_err();
    assert_eq!(refused_as(&again), "unknown_code");
    assert_eq!(
        within(session.clone().next_request()).await.unwrap(),
        asked,
        "asked again, it is asked as it was shown"
    );
    let certified = approved(&session, &seed, false, asked.device.clone())
        .await
        .unwrap();
    assert!(!certified.can_manage);
    let enrolled = asking.await.unwrap().unwrap();
    let info = cert_for_device(enrolled.cert.clone(), enrolled.card.clone(), phone.seed()).unwrap();
    assert!(info.can_login && info.can_message && !info.can_manage && !info.can_vouch);
    assert_eq!(info.expires, certified.expires);
    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let device = DeviceIdentity {
        device_seed: phone.seed(),
        cert: enrolled.cert,
        card: enrolled.card,
        rotation: None,
    };
    assert!(conn
        .login_identity(device, true, None, None)
        .await
        .unwrap()
        .fingerprint
        .is_some());
    assert_eq!(
        refused_as(&within(session.next_request()).await.unwrap_err()),
        "used",
        "a code admits one request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_the_holder_says_no_to_is_told_why() {
    use hexline_core::Enrollee;
    let server = Server::with_registrar(&[]).await;
    let (_, _, card) = held(&server, "quin").await;
    let phone = Enrollee::new();
    let (session, _, asking) = asked_by(&server, &card, &phone).await;
    session.deny("not mine".into()).await.unwrap();
    match asking.await.unwrap() {
        Err(CoreError::Refused { code, detail, .. }) => {
            assert_eq!(code, "denied");
            assert!(detail.contains("not mine"), "{detail}");
        }
        other => panic!("{:?}", other.map(|e| e.fingerprint)),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_shown_past_its_time_ends_the_wait_and_admits_nobody() {
    use hexline_core::Enrollee;
    let server = Server::with_registrar(&[]).await;
    let (_, _, card) = held(&server, "sol").await;
    let session = hexline_core::open_holder_session(server.http.clone(), card, kept(&server.http))
        .await
        .unwrap();
    session.run_out();
    assert_eq!(
        refused_as(&within(session.clone().next_request()).await.unwrap_err()),
        "expired"
    );
    let late =
        within(Enrollee::new().enroll(server.url.clone(), Some(session.code()), "Tablet".into()))
            .await
            .unwrap_err();
    assert_eq!(
        refused_as(&late),
        "unknown_code",
        "the session was given back"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_this_phone_certified_is_revoked_and_its_login_refused() {
    use hexline_core::RevokeReason;
    use hexline_core::{revoke_device, Enrollee};
    let server = Server::with_registrar_fresh_records().await;
    let (seed, minted, card) = held(&server, "ruth").await;
    let own = cert_info_device(&minted.cert, &card, &minted.device_seed);
    let phone = Enrollee::new();
    let (session, asked, asking) = asked_by(&server, &card, &phone).await;
    let certified = approved(&session, &seed, false, asked.device)
        .await
        .unwrap();
    let enrolled = asking.await.unwrap().unwrap();
    let device = || DeviceIdentity {
        device_seed: phone.seed(),
        cert: enrolled.cert.clone(),
        card: enrolled.card.clone(),
        rotation: None,
    };
    // Admitted before the revocation, its records fetched and held.
    let before = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    assert!(before
        .login_identity(device(), true, None, None)
        .await
        .unwrap()
        .fingerprint
        .is_some());
    let e = revoke_device(
        seed.clone(),
        server.http.clone(),
        own.clone(),
        RevokeReason::Retired,
        0,
        own.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(refused_as(&e), "own_device");
    revoke_device(
        seed,
        server.http.clone(),
        certified.device,
        RevokeReason::Lost,
        certified.expires,
        own,
    )
    .await
    .unwrap();
    // Past the records the server holds, which it fetched at that login.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let conn = ServerConnection::new(server.url.clone(), Arc::new(Sink::default()));
    let e = conn
        .login_identity(device(), true, None, None)
        .await
        .unwrap_err();
    assert_eq!(refused_as(&e), "revoked");
}

/// `wait`, held to a few seconds: what it waits for is due at once, and a
/// mailbox would otherwise hold it to its session's ten minutes.
async fn within<T>(wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("an answer without waiting out the mailbox")
}

/// `session`'s request certified and the certificate sent, as the app does.
async fn approved(
    session: &Arc<hexline_core::HolderSession>,
    seed: &[u8],
    manage: bool,
    device: Vec<u8>,
) -> Result<hexline_core::Certified, CoreError> {
    let certified = session
        .clone()
        .certify(seed.to_vec(), manage, device)
        .await?;
    session.clone().deliver().await?;
    Ok(certified)
}

fn cert_info_device(cert: &[u8], card: &[u8], seed: &[u8]) -> Vec<u8> {
    hexline_core::cert_for_device(cert.to_vec(), card.to_vec(), seed.to_vec())
        .unwrap()
        .device
}

/// `request`, as an enrollee sends it, posted to `server`'s mailbox by
/// `code`; the secret it collects its answer by.
async fn post_request(server: &Server, code: &str, request: &[u8]) -> String {
    use base64::Engine;
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    let posted = hxng_client::auth::post(
        &http,
        &format!("{}/identity/enroll/requests", server.http),
        Some(serde_json::json!({
            "request": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request),
            "code": code,
        })),
    )
    .await
    .unwrap();
    posted["request"].as_str().unwrap().to_owned()
}

/// The certificate the holder answered the request `secret` with, as the
/// enrollee collects it.
async fn answered_with(server: &Server, secret: &str) -> hl_identity::DeviceCert {
    use base64::Engine;
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    let (status, body) = hxng_client::auth::get(
        &http,
        &format!("{}/identity/enroll/requests/{secret}", server.http),
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bundle = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body["bundle"].as_str().unwrap())
        .unwrap();
    hl_identity::DeviceCert::parse(&hl_identity::Bundle::parse(&bundle).unwrap().cert).unwrap()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A session opened for `card`, sent the request `made` makes of a new
/// device, and what the holder is asked or told.
async fn sent(
    server: &Server,
    card: &[u8],
    made: impl FnOnce(&hl_identity::DeviceKey) -> Vec<u8>,
) -> (
    Arc<hexline_core::HolderSession>,
    Result<hexline_core::HolderRequest, CoreError>,
) {
    let session =
        hexline_core::open_holder_session(server.http.clone(), card.to_vec(), kept(&server.http))
            .await
            .unwrap();
    let device = hl_identity::DeviceKey::generate();
    post_request(server, &session.code(), &made(&device)).await;
    let asked = within(session.clone().next_request()).await;
    (session, asked)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_no_device_would_make_is_said_no_to_unasked() {
    use hl_identity::{enroll::pair_tag, EnrollRequest};
    type Made = Box<dyn FnOnce(&hl_identity::DeviceKey) -> Vec<u8>>;
    let cases: Vec<(&str, Made)> = vec![
        (
            "unreadable_request",
            Box::new(|_| b"not a request".to_vec()),
        ),
        (
            "stale_request",
            Box::new(|d| EnrollRequest::new(d, unix_now() - 1_000).sign(d)),
        ),
        (
            "unreadable_request",
            Box::new(|d| {
                let mut r = EnrollRequest::new(d, unix_now());
                r.days = Some(0);
                r.sign(d)
            }),
        ),
        (
            "no_login_request",
            Box::new(|d| {
                let mut r = EnrollRequest::new(d, unix_now());
                r.caps = Some(hl_identity::caps::MESSAGE);
                r.sign(d)
            }),
        ),
        // A pairing on a session that drew no QR code to pair by.
        (
            "unpaired_request",
            Box::new(|d| {
                let mut r = EnrollRequest::new(d, unix_now());
                r.pair = Some(pair_tag(&[9; 16], &d.public()));
                r.sign(d)
            }),
        ),
    ];
    for (code, made) in cases {
        // A server each, as the sessions they leave open count against the address.
        let server = Server::with_registrar(&[]).await;
        let (_, _, card) = held(&server, "tao").await;
        let (session, asked) = sent(&server, &card, made).await;
        assert_eq!(refused_as(&asked.unwrap_err()), code);
        assert_eq!(
            refused_as(&within(session.next_request()).await.unwrap_err()),
            "used",
            "{code}: the code spent on it"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_gets_the_days_it_asked_for_and_a_renewal_only_in_its_time() {
    use hl_identity::{DeviceCert, EnrollRequest, IdentityKey};
    let server = Server::with_registrar(&[]).await;
    let (seed, _, card) = held(&server, "uma").await;
    let session =
        hexline_core::open_holder_session(server.http.clone(), card.clone(), kept(&server.http))
            .await
            .unwrap();
    let device = hl_identity::DeviceKey::generate();
    let mut request = EnrollRequest::new(&device, unix_now());
    request.days = Some(7);
    let secret = post_request(&server, &session.code(), &request.sign(&device)).await;
    let asked = within(session.clone().next_request()).await.unwrap();
    assert_eq!((asked.asks_days, asked.gets_secs), (Some(7), 7 * 86_400));
    assert!(!asked.renewal && asked.may_manage);
    let certified = approved(&session, &seed, false, asked.device)
        .await
        .unwrap();
    let cert = answered_with(&server, &secret).await;
    assert_eq!(
        cert.expires - cert.issued,
        7 * 86_400,
        "the lifetime signed"
    );
    assert_eq!(cert.expires, certified.expires);

    let id = IdentityKey::from_seed(seed.as_slice().try_into().unwrap());
    for (issued, renewal) in [
        (unix_now() - 86_400, true),
        (unix_now() - 40 * 86_400, false),
    ] {
        let (_, asked) = sent(&server, &card, |d| {
            let mut r = EnrollRequest::new(d, unix_now());
            r.prev = Some(
                DeviceCert::for_device(&id, d, issued, 30 * 86_400)
                    .unwrap()
                    .sign(&id),
            );
            r.sign(d)
        })
        .await;
        let asked = asked.unwrap();
        assert_eq!(asked.renewal, renewal, "issued {issued}");
        assert_eq!(asked.gets_secs / 86_400, if renewal { 30 } else { 90 });
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_asked_about_past_its_session_is_answered_no_more() {
    use hexline_core::Enrollee;
    let server = Server::with_registrar(&[]).await;
    let (seed, _, card) = held(&server, "xia").await;
    let phone = Enrollee::new();
    let (session, asked, _asking) = asked_by(&server, &card, &phone).await;
    session.run_out();
    within(session.clone().answer_ends()).await;
    assert_eq!(
        refused_as(
            &session
                .clone()
                .certify(seed, false, asked.device)
                .await
                .unwrap_err()
        ),
        "expired"
    );
    assert_eq!(
        refused_as(&within(session.clone().next_request()).await.unwrap_err()),
        "expired"
    );
    assert_eq!(
        refused_as(&session.deny("no".into()).await.unwrap_err()),
        "expired"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_short_renewal_the_holder_approves_is_one_its_device_takes() {
    use hexline_core::Enrollee;
    use hl_identity::{caps, DeviceCert, DeviceKey, IdentityKey};
    let server = Server::with_registrar(&[]).await;
    let (seed, _, card) = held(&server, "yan").await;
    let id = IdentityKey::from_seed(seed.as_slice().try_into().unwrap());
    let device = DeviceKey::generate();
    let mut prev = DeviceCert::for_device(&id, &device, unix_now() - 60, 960).unwrap();
    prev.caps = Some(caps::LOGIN | caps::MESSAGE);
    let phone = Enrollee::renewing(device.seed().to_vec(), prev.sign(&id)).unwrap();
    let (session, asked, asking) = asked_by(&server, &card, &phone).await;
    assert!(asked.renewal);
    assert_eq!(asked.gets_secs, 960, "no longer than it had");
    approved(&session, &seed, false, asked.device)
        .await
        .unwrap();
    within(asking).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_answered_once_for_the_device_asked_about() {
    use hl_identity::EnrollRequest;
    let server = Server::with_registrar(&[]).await;
    let (seed, _, card) = held(&server, "val").await;
    let new = |d: &hl_identity::DeviceKey| EnrollRequest::new(d, unix_now()).sign(d);
    let (session, asked) = sent(&server, &card, new).await;
    let asked = asked.unwrap();
    assert_eq!(
        refused_as(
            &session
                .clone()
                .certify(seed.clone(), false, vec![7; 32])
                .await
                .unwrap_err()
        ),
        "not_asked"
    );
    assert_eq!(
        refused_as(&session.clone().deliver().await.unwrap_err()),
        "nothing_certified"
    );
    let (one, two) = tokio::join!(
        session
            .clone()
            .certify(seed.clone(), false, asked.device.clone()),
        session
            .clone()
            .certify(seed.clone(), false, asked.device.clone()),
    );
    assert!(one.is_ok() != two.is_ok(), "minted once");
    let again = one.err().or(two.err()).unwrap();
    assert_eq!(refused_as(&again), "used");
    assert_eq!(
        refused_as(&session.clone().deny("no".into()).await.unwrap_err()),
        "used",
        "no no after a certificate"
    );
    assert_eq!(
        within(session.clone().next_request()).await.unwrap(),
        asked,
        "asked again, it is what was certified"
    );
    session.clone().deliver().await.unwrap();
    assert_eq!(
        refused_as(&session.clone().deliver().await.unwrap_err()),
        "used",
        "sent once"
    );

    let (session, asked) = sent(&server, &card, new).await;
    let asked = asked.unwrap();
    session.clone().deny("no".into()).await.unwrap();
    assert_eq!(
        refused_as(
            &approved(&session, &seed, false, asked.device)
                .await
                .unwrap_err()
        ),
        "used",
        "no approval after a no"
    );

    // Canceled, it answers nothing, whatever the mailbox would take.
    let (session, asked) = sent(&server, &card, new).await;
    let asked = asked.unwrap();
    session.clone().cancel();
    assert_eq!(
        refused_as(
            &session
                .clone()
                .certify(seed.clone(), false, asked.device.clone())
                .await
                .unwrap_err()
        ),
        "canceled"
    );
    assert_eq!(
        refused_as(&session.deny("no".into()).await.unwrap_err()),
        "canceled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_canceled_before_its_wait_ends_that_wait_at_once() {
    let server = Server::with_registrar(&[]).await;
    let (_, _, card) = held(&server, "wes").await;
    let session =
        hexline_core::open_holder_session(server.http.clone(), card.clone(), kept(&server.http))
            .await
            .unwrap();
    assert_eq!(
        session.identity(),
        hl_identity::Fingerprint::of(&hl_identity::Card::parse(&card).unwrap().identity).short(),
        "the identity shown beside the code"
    );
    session.clone().cancel();
    assert_eq!(
        refused_as(&within(session.next_request()).await.unwrap_err()),
        "canceled"
    );
}

/// A request as a web client that scanned `url` makes, posted to the
/// mailbox; with `pair` false, its pairing made under another secret.
async fn scanned(server: &Server, url: &str, pair: bool) {
    use hl_identity::{enroll::pair_tag, DeviceKey, EnrollRequest};
    let fragment = url.split_once('#').unwrap().1;
    let field = |k: &str| {
        fragment
            .split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .unwrap()
            .to_owned()
    };
    use base64::Engine;
    let secret: [u8; 16] = if pair {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(field("pair"))
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        [9; 16]
    };
    let device = DeviceKey::generate();
    let mut request = EnrollRequest::new(
        &device,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    request.name = Some("Browser".into());
    request.pair = Some(pair_tag(&secret, &device.public()));
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    hxng_client::auth::post(
        &http,
        &format!("{}/identity/enroll/requests", server.http),
        Some(serde_json::json!({
            "request": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.sign(&device)),
            "code": field("enroll"),
        })),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_scanned_the_holders_qr_code_is_taken_by_its_pairing() {
    let server = Server::with_registrar_and_web(true).await;
    let (seed, _, card) = held(&server, "sam").await;
    let session =
        hexline_core::open_holder_session(server.http.clone(), card.clone(), kept(&server.http))
            .await
            .unwrap();
    let qr = session
        .qr()
        .expect("a web client on the server's own origin");
    assert!(qr.size >= 21 && qr.modules.len() == (qr.size * qr.size) as usize);
    let url = session.qr_url().unwrap();
    assert!(
        url.starts_with(&format!("{}/app/#enroll=", server.http)),
        "{url}"
    );
    scanned(&server, &url, true).await;
    let asked = within(session.clone().next_request()).await.unwrap();
    assert!(asked.scanned);
    assert_eq!(asked.name.as_deref(), Some("Browser"));
    assert!(asked.may_manage, "asking nothing, it is left to the holder");
    let certified = approved(&session, &seed, true, asked.device).await.unwrap();
    assert!(certified.can_manage, "managing, when the holder says so");

    let forged = hexline_core::open_holder_session(server.http.clone(), card, kept(&server.http))
        .await
        .unwrap();
    scanned(&server, &forged.qr_url().unwrap(), false).await;
    assert_eq!(
        refused_as(&within(forged.next_request()).await.unwrap_err()),
        "unpaired_request",
        "a pairing that does not hold is denied unasked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_web_client_on_another_origin_gets_no_qr_code() {
    let server = Server::with_registrar_and_web(false).await;
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    let (_, discovery) =
        hxng_client::auth::get(&http, &format!("{}/.well-known/hotline", server.http))
            .await
            .unwrap();
    let discovery: serde_json::Value = serde_json::from_slice(&discovery).unwrap();
    assert_eq!(
        discovery["identity"]["web"], "https://web.example/app/",
        "a web client advertised, on another origin"
    );
    let (_, _, card) = held(&server, "sid").await;
    let session = hexline_core::open_holder_session(server.http.clone(), card, kept(&server.http))
        .await
        .unwrap();
    assert!(session.qr().is_none(), "a code typed, never one scanned");
}

/// A holder committed as `handle` at `server`'s registrar: its seed, its
/// attested card, and the successor code that card commits to.
async fn committed_holder(server: &Server, handle: &str) -> (Vec<u8>, Vec<u8>, String) {
    let setup = hexline_core::HolderSetup::new("Ivy".into()).unwrap();
    let s1 = String::from_utf8(setup.successor_code().unwrap()).unwrap();
    assert!(setup.confirm_successor(s1.clone().into_bytes()));
    assert!(setup.confirm_recovery(setup.recovery_code().unwrap()));
    setup.mint("Pixel".into()).unwrap();
    setup.held().unwrap();
    let seed = setup.identity_seed().unwrap();
    let committed = setup
        .commit(server.http.clone(), handle.into(), None)
        .await
        .unwrap();
    (seed, committed.card, s1)
}

/// That holder's rotation to the successor `s1` names, signed: the record,
/// and the commitment the successor's card carries.
fn signed_rotation(seed: &[u8], card: &[u8], s1: &str) -> (Vec<u8>, [u8; 32]) {
    let r = hexline_core::RotationSetup::new(card.to_vec(), s1.as_bytes().to_vec()).unwrap();
    assert!(r.confirm_next_successor(r.next_successor_code().unwrap()));
    assert!(r.confirm_recovery(r.recovery_code().unwrap()));
    r.mint("Pixel".into()).unwrap();
    let record = r.sign(seed.to_vec()).unwrap();
    let card1 = hl_identity::Card::parse(&r.successor_card().unwrap()).unwrap();
    (record, card1.successor.unwrap())
}

/// What `server`'s registrar's lookup answers for `handle`.
async fn looked_up(server: &Server, handle: &str) -> Value {
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    let url = format!("{}/registrar/lookup/{handle}", server.http);
    let (status, body) = hxng_client::auth::get(&http, &url).await.unwrap();
    assert_eq!(status, 200, "{handle}");
    serde_json::from_slice(&body).unwrap()
}

/// `record` posted to `http`'s registrar: its answer, or what came instead.
async fn posted(
    http: String,
    record: Vec<u8>,
) -> Result<hexline_core::Posted, hexline_core::PostOutcome> {
    match hexline_core::post_rotation(http, record).await {
        hexline_core::PostOutcome::Answered { answer } => Ok(answer),
        unanswered => Err(unanswered),
    }
}

fn fingerprint_of(commitment: [u8; 32]) -> String {
    hl_identity::Fingerprint(commitment).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_publishes_and_the_successor_holds_the_commitment_it_names() {
    use hexline_core::Posted;
    let server = Server::with_registrar(&[]).await;
    let (seed, card, s1) = committed_holder(&server, "ivy").await;
    let (record, next) = signed_rotation(&seed, &card, &s1);
    for post in ["first", "again"] {
        assert_eq!(
            posted(server.http.clone(), record.clone()).await.unwrap(),
            Posted::Published,
            "{post}"
        );
    }
    let found = looked_up(&server, "ivy").await;
    let k1 = hl_identity::SuccessorCode::parse(&s1).unwrap().key();
    assert_eq!(found["fingerprint"], k1.fingerprint().to_string());
    assert_eq!(found["successor"], fingerprint_of(next));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successor_holding_another_commitment_refuses_the_rotation_for_good() {
    use hexline_core::Posted;
    let server = Server::with_registrar(&[]).await;
    let (seed, card, s1) = committed_holder(&server, "june").await;
    let k1 = hl_identity::SuccessorCode::parse(&s1).unwrap().key();
    registered(&server, &k1, "june2", Some([9; 32]))
        .await
        .unwrap();
    let (record, _) = signed_rotation(&seed, &card, &s1);
    for post in ["first", "again"] {
        assert_eq!(
            posted(server.http.clone(), record.clone()).await.unwrap(),
            Posted::Refused {
                code: "successor_mismatch".into()
            },
            "{post}"
        );
    }
    let k0 = hl_identity::IdentityKey::from_seed(&seed.try_into().unwrap());
    assert_eq!(
        looked_up(&server, "june").await["fingerprint"],
        k0.fingerprint().to_string(),
        "the identity stays where it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_rotation_is_pending_until_published_and_another_waits_behind_it() {
    use hexline_core::Posted;
    // Held for a day, so nothing here outlasts the hold but its publication.
    let server = Server::with_registrar_delay(86_400).await;
    let (seed, card, s1) = committed_holder(&server, "kai").await;
    let (first, next) = signed_rotation(&seed, &card, &s1);
    // Another phone holding the same successor code, with a code of its own after.
    let (second, _) = signed_rotation(&seed, &card, &s1);
    let post = |record: &Vec<u8>| posted(server.http.clone(), record.clone());
    let Posted::Pending { until } = post(&first).await.unwrap() else {
        panic!("not held");
    };
    assert_eq!(post(&first).await.unwrap(), Posted::Pending { until });
    assert_eq!(
        post(&second).await.unwrap(),
        Posted::PendingElsewhere { until: Some(until) }
    );
    let k0 = hl_identity::IdentityKey::from_seed(&seed.try_into().unwrap());
    assert_eq!(
        looked_up(&server, "kai").await["fingerprint"],
        k0.fingerprint().to_string(),
        "nothing moved while it waits"
    );

    let k1 = hl_identity::SuccessorCode::parse(&s1).unwrap().key();
    server.publish(&k0.fingerprint().to_string(), &k1.fingerprint().to_string());
    assert_eq!(post(&first).await.unwrap(), Posted::Published);
    assert_eq!(
        post(&second).await.unwrap(),
        Posted::Superseded {
            next: Some(fingerprint_of(next))
        },
        "rotated to the same successor, under the first's commitment"
    );
    assert_eq!(
        looked_up(&server, "kai").await["successor"],
        fingerprint_of(next)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_published_first_with_another_commitment_supersedes_this_one() {
    use hexline_core::Posted;
    let server = Server::with_registrar(&[]).await;
    let (seed, card, s1) = committed_holder(&server, "lena").await;
    let (theirs, their_next) = signed_rotation(&seed, &card, &s1);
    let (mine, _) = signed_rotation(&seed, &card, &s1);
    let post = |record: &Vec<u8>| posted(server.http.clone(), record.clone());
    assert_eq!(post(&theirs).await.unwrap(), Posted::Published);
    assert_eq!(
        post(&mine).await.unwrap(),
        Posted::Superseded {
            next: Some(fingerprint_of(their_next))
        }
    );
    assert_eq!(
        post(&theirs).await.unwrap(),
        Posted::Published,
        "theirs again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_of_a_revoked_or_unregistered_identity_is_refused_for_good() {
    use hexline_core::Posted;
    let server = Server::with_registrar(&[]).await;
    let (seed, card, s1) = committed_holder(&server, "max").await;
    let k0 = hl_identity::IdentityKey::from_seed(&seed.clone().try_into().unwrap());
    let revocation = hl_identity::IdentityRevocation {
        identity: k0.public(),
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        reason: None,
    }
    .sign(&k0)
    .unwrap();
    use base64::Engine;
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    hxng_client::auth::post(
        &http,
        &format!("{}/registrar/records", server.http),
        Some(serde_json::json!({
            "record": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(revocation)
        })),
    )
    .await
    .unwrap();
    let (record, _) = signed_rotation(&seed, &card, &s1);
    assert_eq!(
        posted(server.http.clone(), record).await.unwrap(),
        Posted::Refused {
            code: "revoked".into()
        }
    );

    // An identity the registrar never registered.
    let stranger = hl_identity::IdentityKey::generate();
    let s1 = hl_identity::SuccessorCode::generate();
    let mut card = hl_identity::Card::new(&stranger, "Ned", 1);
    card.successor = Some(s1.commitment());
    let card = card.sign(&stranger, Vec::new()).unwrap();
    let (record, _) = signed_rotation(stranger.seed().as_ref(), &card, &s1.display());
    assert_eq!(
        posted(server.http.clone(), record).await.unwrap(),
        Posted::Refused {
            code: "not_registered".into()
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frozen_identitys_rotation_publishes_when_posted_again_once_lifted() {
    use hexline_core::Posted;
    let server = Server::with_registrar(&[]).await;
    let (seed, card, s1) = committed_holder(&server, "nora").await;
    let k0 = hl_identity::IdentityKey::from_seed(&seed.clone().try_into().unwrap());
    let (record, _) = signed_rotation(&seed, &card, &s1);
    server.freeze(&k0.fingerprint().to_string(), false);
    let post = || posted(server.http.clone(), record.clone());
    assert_eq!(post().await.unwrap(), Posted::Frozen);
    server.freeze(&k0.fingerprint().to_string(), true);
    assert_eq!(post().await.unwrap(), Posted::Published);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_rotated_first_to_another_key_is_rotated_away() {
    use base64::Engine;
    use hexline_core::Posted;
    use hl_identity::{Card, IdentityKey, Rotation, SuccessorCode};
    let server = Server::with_registrar(&[]).await;
    // Registered with no commitment, so the registrar takes a rotation to
    // any key the old one acknowledges with it.
    let k0 = IdentityKey::generate();
    registered(&server, &k0, "olga", None).await.unwrap();
    let theirs = IdentityKey::generate();
    let taken = Rotation {
        identity: k0.public(),
        successor: theirs.public(),
        time: 1,
        next: None,
    }
    .sign(&k0, &theirs)
    .unwrap();
    let http = hxng_client::auth::http_client(&server.http, None).unwrap();
    hxng_client::auth::post(
        &http,
        &format!("{}/registrar/records", server.http),
        Some(serde_json::json!({
            "record": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(taken)
        })),
    )
    .await
    .unwrap();

    // This phone's card commits to a successor of its own.
    let s1 = SuccessorCode::generate();
    let mut card = Card::new(&k0, "Olga", 1);
    card.successor = Some(s1.commitment());
    let card = card.sign(&k0, Vec::new()).unwrap();
    let (record, _) = signed_rotation(k0.seed().as_ref(), &card, &s1.display());
    assert_eq!(
        posted(server.http.clone(), record).await.unwrap(),
        Posted::RotatedAway {
            successor: theirs.fingerprint().to_string()
        }
    );
}

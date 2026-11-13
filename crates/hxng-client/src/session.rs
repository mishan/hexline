//! One connection's view of a session (hotline-ng.md §2, §3, §5, §6).

use std::collections::VecDeque;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::frame::{self, ErrorReply, Incoming};
use crate::handshake::{LoginOk, LoginParams, Resumable, ResumeOk, SyncOk, Token};
use crate::{ProtocolError, StateError};

/// What a frame from the server meant.
#[derive(Debug, Clone)]
pub enum Output {
    LoggedIn(Box<LoginOk>),
    /// The session is attached again; `ok.replay` buffered events follow.
    /// `must_sync`: a resync was under way when the last connection went,
    /// and the gap it was for is still unfilled — send [`Session::sync`].
    Resumed {
        ok: ResumeOk,
        must_sync: bool,
    },
    /// The session is attached, but its gap cannot be replayed: send
    /// [`Session::sync`]. Events may arrive before its reply; keep them.
    ResyncRequired,
    Synced(SyncOk),
    /// The handshake failed, and the server closes the connection.
    Refused(ErrorReply),
    Reply {
        id: u64,
        result: Result<Value, ErrorReply>,
    },
    /// An event, in sequence. One whose `ev` the client does not know is
    /// still one to count and pass over (§3).
    Event {
        seq: u64,
        ev: String,
        data: Value,
    },
}

/// What is left when the connection goes.
#[derive(Debug)]
pub struct Lost {
    /// Requests that will now never be answered (§5): failed.
    pub failed: Vec<u64>,
    /// What resumes the session on a new connection, if it may detach
    /// and is not over.
    pub resumable: Option<Resumable>,
    /// Another connection resumed the session (close code 1008,
    /// `replaced`). It is that one's now: resuming it again would take it
    /// back, and the two would trade it for ever.
    pub replaced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Handshake,
    Live,
    /// Refused: the server is closing the connection.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Login,
    Resume,
    Sync,
    Logout,
    Request,
}

#[derive(Debug)]
pub struct Session {
    phase: Phase,
    next_id: u64,
    pending: VecDeque<(u64, Pending)>,
    /// The highest seq received. `None` after `resync_required` until an
    /// event or `sync` says where the sequence is.
    last_seq: Option<u64>,
    /// Between `resync_required` and `sync`'s reply, across connections.
    resyncing: bool,
    attached: Option<(String, Token)>,
    /// Kicked, or logged out: nothing to resume.
    over: bool,
}

impl Default for Session {
    fn default() -> Self {
        Session::new()
    }
}

impl Session {
    /// A connection that will log in.
    pub fn new() -> Session {
        Session {
            phase: Phase::Fresh,
            next_id: 0,
            pending: VecDeque::new(),
            last_seq: Some(0),
            resyncing: false,
            attached: None,
            over: false,
        }
    }

    /// A connection that will resume `r`.
    pub fn resuming(r: Resumable) -> Session {
        Session {
            last_seq: Some(r.last_seq),
            resyncing: r.needs_sync,
            attached: Some((r.session, r.token)),
            ..Session::new()
        }
    }

    /// The frame carries the password, and [`Session::resume`]'s the token,
    /// so both are wiped once sent.
    pub fn login(&mut self, params: &LoginParams) -> Result<Zeroizing<String>, StateError> {
        self.begin(Pending::Login, "login", json!(params))
    }

    pub fn resume(&mut self) -> Result<Zeroizing<String>, StateError> {
        let Some((session, token)) = &self.attached else {
            return Err(StateError::NothingToResume);
        };
        let params = json!({
            "session": session,
            "token": token.expose(),
            "last_seq": self.last_seq.unwrap_or(0),
        });
        self.begin(Pending::Resume, "resume", params)
    }

    fn begin(
        &mut self,
        kind: Pending,
        req: &str,
        params: Value,
    ) -> Result<Zeroizing<String>, StateError> {
        if self.phase != Phase::Fresh {
            return Err(StateError::AlreadyStarted);
        }
        self.phase = Phase::Handshake;
        Ok(Zeroizing::new(self.send(kind, req, params).1))
    }

    /// A failure comes back as an [`Output::Reply`] to the id returned.
    pub fn sync(&mut self) -> Result<(u64, String), StateError> {
        self.live()?;
        Ok(self.send(Pending::Sync, "sync", json!({})))
    }

    /// Any request but the handshake's and `sync`, which have their own.
    pub fn request(&mut self, req: &str, params: Value) -> Result<(u64, String), StateError> {
        if matches!(req, "login" | "resume" | "sync") {
            return Err(StateError::Reserved);
        }
        self.live()?;
        let kind = if req == "logout" {
            Pending::Logout
        } else {
            Pending::Request
        };
        Ok(self.send(kind, req, params))
    }

    fn live(&self) -> Result<(), StateError> {
        if self.phase == Phase::Live {
            Ok(())
        } else {
            Err(StateError::NotLive)
        }
    }

    fn send(&mut self, kind: Pending, req: &str, params: Value) -> (u64, String) {
        let id = self.next_id;
        self.next_id += 1;
        self.pending.push_back((id, kind));
        (id, frame::request(id, req, params))
    }

    pub fn receive(&mut self, text: &str) -> Result<Output, ProtocolError> {
        if self.phase == Phase::Closed {
            return Err(ProtocolError::Handshake("a frame after the refusal"));
        }
        match frame::parse(text)? {
            Incoming::Reply { id, result } => self.reply(id, result),
            Incoming::Event { seq, ev, data } => {
                if self.phase != Phase::Live {
                    return Err(ProtocolError::Handshake(
                        "an event before the handshake's reply",
                    ));
                }
                if let Some(last) = self.last_seq {
                    let expected = last.checked_add(1).ok_or(ProtocolError::Malformed("seq"))?;
                    if seq != expected {
                        return Err(ProtocolError::SeqGap { expected, got: seq });
                    }
                }
                self.last_seq = Some(seq);
                self.over |= ev == "kicked";
                Ok(Output::Event { seq, ev, data })
            }
        }
    }

    fn reply(
        &mut self,
        id: u64,
        result: Result<Value, ErrorReply>,
    ) -> Result<Output, ProtocolError> {
        let kind = match self.pending.front() {
            Some(&(due, kind)) if due == id => kind,
            _ => return Err(ProtocolError::UnexpectedReply(id)),
        };
        self.pending.pop_front();
        match (kind, result) {
            (Pending::Login, Ok(v)) => {
                let ok: LoginOk = decode("login reply", v)?;
                self.phase = Phase::Live;
                self.last_seq = Some(ok.seq);
                self.attached = ok.detach.map(|_| (ok.session.clone(), ok.token.clone()));
                Ok(Output::LoggedIn(Box::new(ok)))
            }
            (Pending::Resume, Ok(v)) => {
                let ok = decode("resume reply", v)?;
                self.phase = Phase::Live;
                Ok(Output::Resumed {
                    ok,
                    must_sync: self.resyncing,
                })
            }
            (Pending::Resume, Err(e)) if e.code == "resync_required" => {
                self.phase = Phase::Live;
                self.last_seq = None;
                self.resyncing = true;
                Ok(Output::ResyncRequired)
            }
            (Pending::Login | Pending::Resume, Err(e)) => {
                self.phase = Phase::Closed;
                // A resume refused for now — too many connections, too
                // often — leaves the session as it was, to resume later
                // (§6.2); only these mean it is gone.
                if matches!(e.code.as_str(), "session_expired" | "bad_request") {
                    self.attached = None;
                }
                Ok(Output::Refused(e))
            }
            (Pending::Sync, Ok(v)) => {
                let ok: SyncOk = decode("sync reply", v)?;
                // Events already in hand carry seqs at or below sync's (§6.3);
                // one above it is one the server promised not to have sent.
                if self.last_seq.is_some_and(|last| last > ok.seq) {
                    return Err(ProtocolError::Handshake(
                        "sync's seq behind events received",
                    ));
                }
                self.last_seq = Some(ok.seq);
                self.resyncing = false;
                Ok(Output::Synced(ok))
            }
            (Pending::Logout, Ok(v)) => {
                self.over = true;
                Ok(Output::Reply { id, result: Ok(v) })
            }
            (Pending::Sync | Pending::Logout | Pending::Request, result) => {
                Ok(Output::Reply { id, result })
            }
        }
    }

    /// What resumes the session, as it stands now: to persist, or for
    /// [`Session::resuming`] on the next connection.
    pub fn resumable(&self) -> Option<Resumable> {
        if self.over {
            return None;
        }
        let (session, token) = self.attached.clone()?;
        Some(Resumable {
            session,
            token,
            last_seq: self.last_seq.unwrap_or(0),
            needs_sync: self.resyncing,
        })
    }

    /// The connection is gone, closed with `code` (1006 when it simply
    /// dropped) and `reason`.
    pub fn closed(self, code: u16, reason: &str) -> Lost {
        let replaced = code == 1008 && reason == "replaced";
        let resumable = self.resumable().filter(|_| !replaced);
        Lost {
            failed: self
                .pending
                .into_iter()
                .filter(|(_, kind)| !matches!(kind, Pending::Login | Pending::Resume))
                .map(|(id, _)| id)
                .collect(),
            resumable,
            replaced,
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    what: &'static str,
    v: Value,
) -> Result<T, ProtocolError> {
    serde_json::from_value(v).map_err(|_| ProtocolError::Malformed(what))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn login_ok(id: u64, detach: Value) -> String {
        json!({ "reply": id, "ok": {
            "session": "s_1", "token": "secret", "self": { "uid": 3 },
            "server": { "name": "Test", "subject": "" },
            "users": [{ "uid": 3 }], "detach": detach, "caps": ["history"], "seq": 0,
            "history": { "max": 50 },
        }})
        .to_string()
    }

    fn event(seq: u64) -> String {
        json!({ "seq": seq, "ev": "chat", "data": {} }).to_string()
    }

    fn logged_in() -> Session {
        let mut s = Session::new();
        s.login(&LoginParams::default()).unwrap();
        s.receive(&login_ok(0, json!({ "grace": 300 }))).unwrap();
        s
    }

    fn resync(s: &mut Session) {
        let mut r = Session::resuming(s.resumable().unwrap());
        r.resume().unwrap();
        let e = json!({ "reply": 0, "error": { "code": "resync_required", "text": "" } });
        assert!(matches!(
            r.receive(&e.to_string()).unwrap(),
            Output::ResyncRequired
        ));
        *s = r;
    }

    #[test]
    fn a_login_attaches_and_events_follow_in_sequence() {
        let mut s = Session::new();
        let sent: Value = serde_json::from_str(&s.login(&LoginParams::default()).unwrap()).unwrap();
        assert_eq!(sent, json!({ "id": 0, "req": "login", "params": {} }));
        let Output::LoggedIn(ok) = s.receive(&login_ok(0, json!({ "grace": 300 }))).unwrap() else {
            panic!("not logged in")
        };
        assert_eq!(ok.blocks["history"], json!({ "max": 50 }));
        assert_eq!(format!("{:?}", ok.token), "Token(..)");
        let params = LoginParams {
            password: Some("hunter2".into()),
            ..LoginParams::default()
        };
        assert!(!format!("{params:?}").contains("hunter2"));
        for seq in 1..=3 {
            assert!(matches!(s.receive(&event(seq)), Ok(Output::Event { .. })));
        }
        assert_eq!(
            s.receive(&event(5)).unwrap_err(),
            ProtocolError::SeqGap {
                expected: 4,
                got: 5
            }
        );
        assert_eq!(s.resumable().unwrap().last_seq, 3);
    }

    #[test]
    fn a_session_that_may_not_detach_is_never_resumed() {
        let mut s = Session::new();
        s.login(&LoginParams::default()).unwrap();
        s.receive(&login_ok(0, Value::Null)).unwrap();
        assert!(s.resumable().is_none());
        assert!(s.closed(1006, "").resumable.is_none());
    }

    #[test]
    fn the_handshake_comes_first_and_once() {
        let mut s = Session::new();
        assert_eq!(
            s.request("chat", json!({})).unwrap_err(),
            StateError::NotLive
        );
        assert_eq!(s.resume().unwrap_err(), StateError::NothingToResume);
        s.login(&LoginParams::default()).unwrap();
        assert_eq!(
            s.login(&LoginParams::default()).unwrap_err(),
            StateError::AlreadyStarted
        );
        assert_eq!(
            s.receive(&event(1)).unwrap_err(),
            ProtocolError::Handshake("an event before the handshake's reply")
        );
        s.receive(&login_ok(0, Value::Null)).unwrap();
        for req in ["login", "resume", "sync"] {
            assert_eq!(s.request(req, json!({})).unwrap_err(), StateError::Reserved);
        }
    }

    #[test]
    fn replies_come_in_the_order_requests_went() {
        let mut s = logged_in();
        let (a, _) = s.request("chat", json!({})).unwrap();
        let (b, _) = s.request("chat", json!({})).unwrap();
        let reply = |id: u64| json!({ "reply": id, "ok": {} }).to_string();
        assert_eq!(
            s.receive(&reply(b)).unwrap_err(),
            ProtocolError::UnexpectedReply(b)
        );
        assert!(matches!(s.receive(&reply(a)), Ok(Output::Reply { id, .. }) if id == a));
        assert!(matches!(s.receive(&reply(b)), Ok(Output::Reply { id, .. }) if id == b));
        assert_eq!(
            s.receive(&reply(b)).unwrap_err(),
            ProtocolError::UnexpectedReply(b)
        );
    }

    #[test]
    fn a_lost_connection_fails_what_was_outstanding() {
        let mut s = logged_in();
        s.receive(&event(1)).unwrap();
        let (a, _) = s.request("chat", json!({})).unwrap();
        let lost = s.closed(1006, "");
        assert_eq!(lost.failed, vec![a]);
        let r = lost.resumable.unwrap();
        assert_eq!(
            (r.session.as_str(), r.token.expose(), r.last_seq),
            ("s_1", "secret", 1)
        );
    }

    #[test]
    fn a_resume_continues_the_sequence_where_it_stood() {
        let mut s = logged_in();
        s.receive(&event(1)).unwrap();
        let mut r = Session::resuming(s.resumable().unwrap());
        let sent: Value = serde_json::from_str(&r.resume().unwrap()).unwrap();
        assert_eq!(
            sent["params"],
            json!({ "session": "s_1", "token": "secret", "last_seq": 1 })
        );
        let ok = json!({ "reply": 0, "ok": { "replay": 1, "self": { "uid": 3 } } });
        assert!(matches!(
            r.receive(&ok.to_string()),
            Ok(Output::Resumed {
                ok: ResumeOk { replay: 1, .. },
                must_sync: false
            })
        ));
        assert!(r.receive(&event(2)).is_ok());
    }

    #[test]
    fn a_refused_handshake_leaves_nothing_to_resume() {
        let mut r = Session::resuming(logged_in().resumable().unwrap());
        r.resume().unwrap();
        let e = json!({ "reply": 0, "error": { "code": "session_expired", "text": "" } });
        assert!(
            matches!(r.receive(&e.to_string()), Ok(Output::Refused(ErrorReply { code, .. })) if code == "session_expired")
        );
        assert!(r.resumable().is_none());
        assert!(r.receive(&event(1)).is_err());
    }

    #[test]
    fn a_resync_keeps_events_in_hand_and_continues_from_sync() {
        let mut s = logged_in();
        resync(&mut s);
        assert!(s.receive(&event(40)).is_ok());
        assert!(s.receive(&event(41)).is_ok());
        let (sync_id, _) = s.sync().unwrap();
        let ok = json!({ "reply": sync_id, "ok": {
            "server": { "name": "Test", "subject": "" }, "users": [], "seq": 45 } });
        assert!(matches!(
            s.receive(&ok.to_string()),
            Ok(Output::Synced(SyncOk { seq: 45, .. }))
        ));
        assert_eq!(
            s.receive(&event(45)).unwrap_err(),
            ProtocolError::SeqGap {
                expected: 46,
                got: 45
            }
        );
        assert!(s.receive(&event(46)).is_ok());
    }

    #[test]
    fn sync_may_not_place_the_sequence_behind_events_received() {
        let mut s = logged_in();
        resync(&mut s);
        s.receive(&event(50)).unwrap();
        let (sync_id, _) = s.sync().unwrap();
        let ok = json!({ "reply": sync_id, "ok": {
            "server": { "name": "Test", "subject": "" }, "users": [], "seq": 45 } });
        assert_eq!(
            s.receive(&ok.to_string()).unwrap_err(),
            ProtocolError::Handshake("sync's seq behind events received")
        );
    }

    #[test]
    fn a_resume_refused_for_now_keeps_the_session_and_one_refused_for_good_does_not() {
        for (code, kept) in [
            ("session_expired", false),
            ("bad_request", false),
            ("too_many_connections", true),
            ("rate_limited", true),
            ("server_error", true),
            ("a_code_from_later", true),
        ] {
            let mut r = Session::resuming(logged_in().resumable().unwrap());
            r.resume().unwrap();
            let e = json!({ "reply": 0, "error": { "code": code, "text": "" } });
            assert!(
                matches!(r.receive(&e.to_string()), Ok(Output::Refused(_))),
                "{code}"
            );
            assert_eq!(r.closed(1000, "").resumable.is_some(), kept, "{code}");
        }
    }

    #[test]
    fn a_resync_cut_short_is_finished_on_the_next_connection() {
        let mut s = logged_in();
        resync(&mut s);
        s.receive(&event(40)).unwrap();
        let r = s.closed(1006, "").resumable.unwrap();
        assert!(r.needs_sync);
        let mut next = Session::resuming(r);
        next.resume().unwrap();
        let ok = json!({ "reply": 0, "ok": { "replay": 0, "self": { "uid": 3 } } });
        assert!(matches!(
            next.receive(&ok.to_string()),
            Ok(Output::Resumed {
                must_sync: true,
                ..
            })
        ));
        let (id, _) = next.sync().unwrap();
        let ok = json!({ "reply": id, "ok": {
            "server": { "name": "Test", "subject": "" }, "users": [], "seq": 44 } });
        next.receive(&ok.to_string()).unwrap();
        assert!(!next.resumable().unwrap().needs_sync);
    }

    #[test]
    fn a_session_kicked_logged_out_or_taken_over_is_not_resumed() {
        let mut kicked = logged_in();
        kicked
            .receive(&json!({ "seq": 1, "ev": "kicked" }).to_string())
            .unwrap();
        assert!(kicked.closed(1000, "kicked").resumable.is_none());

        let mut out = logged_in();
        let (id, _) = out.request("logout", json!({})).unwrap();
        out.receive(&json!({ "reply": id, "ok": {} }).to_string())
            .unwrap();
        assert!(out.closed(1000, "logout").resumable.is_none());

        let lost = logged_in().closed(1008, "replaced");
        assert!(lost.replaced && lost.resumable.is_none());
        assert!(logged_in().closed(1006, "").resumable.is_some());
    }

    #[test]
    fn a_sequence_at_its_end_is_refused_not_wrapped() {
        let mut s = Session::resuming(Resumable {
            last_seq: u64::MAX,
            ..logged_in().resumable().unwrap()
        });
        s.resume().unwrap();
        let ok = json!({ "reply": 0, "ok": { "replay": 0, "self": {} } });
        s.receive(&ok.to_string()).unwrap();
        assert_eq!(
            s.receive(&event(0)).unwrap_err(),
            ProtocolError::Malformed("seq")
        );
    }

    proptest! {
        #[test]
        fn a_contiguous_sequence_is_accepted_and_a_gap_found_where_it_is(
            names in prop::collection::vec("[a-z_]{1,12}", 1..40),
            gap_at in any::<prop::sample::Index>(),
            skip in 2u64..5,
        ) {
            let mut s = logged_in();
            let at = gap_at.index(names.len());
            for (i, ev) in names.iter().enumerate() {
                let i = i as u64;
                let seq = if i as usize >= at { i + skip } else { i + 1 };
                let got = s.receive(&json!({ "seq": seq, "ev": ev }).to_string());
                if i as usize == at {
                    prop_assert_eq!(got.unwrap_err(), ProtocolError::SeqGap { expected: i + 1, got: seq });
                    break;
                }
                prop_assert!(got.is_ok());
            }
        }

        #[test]
        fn no_frame_makes_a_session_panic(text in ".{0,200}") {
            let _ = logged_in().receive(&text);
            let mut s = Session::new();
            s.login(&LoginParams::default()).unwrap();
            let _ = s.receive(&text);
        }
    }
}

//! The client side of the Hotline-ng wire (hxd-ng's `docs/hotline-ng.md`),
//! with no I/O of its own: text frames in, text frames and what they mean
//! out. A [`Session`] holds what the protocol asks a client to keep — the
//! handshake's state, requests awaiting replies, and the event sequence —
//! and refuses a frame that breaks it, so that a gap or a misplaced reply
//! is found where it happens rather than as a roster that drifted.

mod frame;
mod handshake;
mod session;

use std::fmt;

pub use frame::{parse, request, ErrorReply, Incoming};
pub use handshake::{Detach, LoginOk, LoginParams, Resumable, ResumeOk, ServerInfo, SyncOk, Token};
pub use session::{Lost, Output, Session};

/// A frame the protocol does not allow. The connection carrying it is
/// lost: the client resumes or logs in again on a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    NotJson,
    Malformed(&'static str),
    /// An event out of sequence (§3): every seq is the last one plus one.
    SeqGap {
        expected: u64,
        got: u64,
    },
    /// A reply to no request, or out of the order they were sent (§5).
    UnexpectedReply(u64),
    /// Something the handshake (§6) does not allow at this point.
    Handshake(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::NotJson => f.write_str("frame is not JSON"),
            ProtocolError::Malformed(what) => write!(f, "malformed frame: {what}"),
            ProtocolError::SeqGap { expected, got } => {
                write!(f, "event seq {got} where {expected} was due")
            }
            ProtocolError::UnexpectedReply(id) => write!(f, "reply to {id}, which was not due"),
            ProtocolError::Handshake(what) => write!(f, "handshake: {what}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A request this session cannot make in the state it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Before the handshake, or after the connection was refused.
    NotLive,
    /// `login` and `resume` begin a connection; a second is not sent.
    AlreadyStarted,
    /// `resume` without a session to resume.
    NothingToResume,
    /// `login`, `resume` and `sync` have methods of their own.
    Reserved,
}

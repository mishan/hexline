//! What `login`, `resume` and `sync` send and answer (hotline-ng.md §6).
//! Rosters and user objects stay JSON here; they are typed where they are
//! used.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// A session's bearer token: kept where a password would be, never
/// logged (§6.1), so its `Debug` says nothing of it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Token(#[serde(deserialize_with = "zeroizing")] Zeroizing<String>);

fn zeroizing<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

impl Token {
    pub fn new(token: String) -> Token {
        Token(Zeroizing::new(token))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

/// `login`'s params. The flags ask for families a server lists in `caps`
/// only to a login that asked (§4).
#[derive(Clone, Default, Serialize)]
pub struct LoginParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub replies: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reactions: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub emoji: bool,
}

impl fmt::Debug for LoginParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginParams")
            .field("login", &self.login)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .field("nick", &self.nick)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub subject: String,
    #[serde(default)]
    pub agreement: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Detach {
    /// Seconds the session survives a lost connection.
    pub grace: u64,
}

/// `login`'s `ok`.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginOk {
    pub session: String,
    pub token: Token,
    #[serde(rename = "self")]
    pub self_user: Value,
    pub server: ServerInfo,
    pub users: Vec<Value>,
    /// `None`: this session never detaches, and is never resumed.
    pub detach: Option<Detach>,
    pub caps: Vec<String>,
    pub seq: u64,
    /// Each capability's login block, by its name.
    #[serde(flatten)]
    pub blocks: Map<String, Value>,
}

/// `resume`'s `ok`: `replay` events follow it, in seq order.
#[derive(Debug, Clone, Deserialize)]
pub struct ResumeOk {
    pub replay: u64,
    #[serde(rename = "self")]
    pub self_user: Value,
}

/// `sync`'s `ok`: the roster whole, and the seq to continue from.
#[derive(Debug, Clone, Deserialize)]
pub struct SyncOk {
    pub server: ServerInfo,
    pub users: Vec<Value>,
    pub seq: u64,
    #[serde(flatten)]
    pub blocks: Map<String, Value>,
}

/// What a client keeps to resume a session on a new connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resumable {
    pub session: String,
    pub token: Token,
    /// The highest seq received; the store a client keeps it in must be
    /// written with what those events carried, or a resume skips them.
    pub last_seq: u64,
    /// A resync was not finished: the next connection syncs, whatever its
    /// resume replays.
    pub needs_sync: bool,
}

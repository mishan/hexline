//! What the app shows of a server, typed from the wire's JSON
//! (hotline-ng.md §7.4). A field the wire omits or sends wrong reads as
//! its absence rather than failing the event: a newer server's user is
//! still a user.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Status {
    Active,
    Idle,
    /// Its connection is gone and it may come back (§2).
    Detached,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct User {
    pub uid: u16,
    pub nick: String,
    pub icon: u32,
    pub admin: bool,
    pub status: Status,
    /// The server's own account (system-account.md).
    pub system: bool,
}

impl User {
    pub(crate) fn from_json(v: &Value) -> Option<User> {
        Some(User {
            uid: u16::try_from(v.get("uid")?.as_u64()?).ok()?,
            nick: v.get("nick")?.as_str()?.to_owned(),
            icon: v
                .get("icon")
                .and_then(Value::as_u64)
                .and_then(|i| u32::try_from(i).ok())
                .unwrap_or(0),
            admin: v.get("admin").and_then(Value::as_bool).unwrap_or(false),
            status: match v.get("status").and_then(Value::as_str) {
                Some("idle") => Status::Idle,
                Some("detached") => Status::Detached,
                _ => Status::Active,
            },
            system: v.get("system").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ChatLine {
    /// Present where the server keeps history; the cursor for paging.
    pub id: Option<u64>,
    /// The speaker's uid, live lines only: history leaves it out, as a
    /// uid is someone else's minutes after its holder leaves.
    pub uid: Option<u16>,
    pub nick: String,
    pub text: String,
    /// Unix seconds.
    pub at: u64,
    /// `/me`: shown as the speaker doing it.
    pub action: bool,
    /// A curated room's line; `None` for the lobby. A room's line ids are
    /// a cursor for that room alone.
    pub room: Option<u64>,
    /// Redacted: kept as a gap where it was, with no speaker or words.
    pub deleted: bool,
}

impl ChatLine {
    pub(crate) fn from_json(v: &Value) -> Option<ChatLine> {
        let room = v.get("room").and_then(Value::as_u64).filter(|&r| r != 0);
        if v.get("deleted").and_then(Value::as_bool) == Some(true) {
            return Some(ChatLine {
                id: Some(v.get("id")?.as_u64()?),
                uid: None,
                nick: String::new(),
                text: String::new(),
                at: v.get("at").and_then(Value::as_u64).unwrap_or(0),
                action: false,
                room,
                deleted: true,
            });
        }
        let from = v.get("from")?;
        Some(ChatLine {
            id: v.get("id").and_then(Value::as_u64),
            uid: from
                .get("uid")
                .and_then(Value::as_u64)
                .and_then(|u| u16::try_from(u).ok()),
            nick: from.get("nick")?.as_str()?.to_owned(),
            text: v.get("text")?.as_str()?.to_owned(),
            at: v.get("at").and_then(Value::as_u64).unwrap_or(0),
            action: v.get("style").and_then(Value::as_str) == Some("action"),
            room,
            deleted: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct HistoryPage {
    /// Oldest first.
    pub lines: Vec<ChatLine>,
    /// More lines before the first of these.
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_user_reads_what_is_there_and_defaults_the_rest() {
        let full = json!({ "uid": 3, "nick": "Alice", "icon": 128, "admin": true,
            "status": "detached", "system": false, "transport": "encrypted", "later": 1 });
        assert_eq!(
            User::from_json(&full),
            Some(User {
                uid: 3,
                nick: "Alice".into(),
                icon: 128,
                admin: true,
                status: Status::Detached,
                system: false
            })
        );
        let sparse = json!({ "uid": 4, "nick": "Bob", "status": "away-for-lunch" });
        assert_eq!(User::from_json(&sparse).unwrap().status, Status::Active);
        for broken in [
            json!({ "nick": "x" }),
            json!({ "uid": 70000, "nick": "x" }),
            json!({ "uid": 1 }),
        ] {
            assert_eq!(User::from_json(&broken), None, "{broken}");
        }
    }

    #[test]
    fn a_chat_line_reads_live_and_from_history_alike() {
        let live = json!({ "from": { "uid": 3, "nick": "Alice" }, "text": "waves",
            "style": "action", "at": 1729137541, "id": 1001 });
        let line = ChatLine::from_json(&live).unwrap();
        assert_eq!(
            (line.uid, line.action, line.id, line.room),
            (Some(3), true, Some(1001), None)
        );
        let history = json!({ "id": 1001, "at": 1729137541, "from": { "nick": "alice", "icon": 128 },
            "text": "What's up?", "style": "normal", "room": 0 });
        let line = ChatLine::from_json(&history).unwrap();
        assert_eq!((line.uid, line.action, line.room), (None, false, None));
        assert_eq!(ChatLine::from_json(&json!({ "text": "no speaker" })), None);
        // A redacted line keeps its place, so paging back from it goes on.
        let tombstone = json!({ "id": 999, "at": 1, "deleted": true, "from": { "icon": 0 } });
        let line = ChatLine::from_json(&tombstone).unwrap();
        assert_eq!(
            (line.id, line.deleted, line.nick.as_str()),
            (Some(999), true, "")
        );
    }
}

//! The three shapes of a Hotline-ng message (hotline-ng.md §5): a request
//! the client sends, and a reply or an event it receives, each one JSON
//! object in one text frame.

use serde_json::{Map, Value};

use crate::ProtocolError;

/// A request, as the text frame that carries it. `params` is sent as
/// given: every request this crate makes sends an object, `{}` for none.
pub fn request(id: u64, req: &str, params: Value) -> String {
    serde_json::json!({ "id": id, "req": req, "params": params }).to_string()
}

/// A reply's `error`. Clients act on `code` and never parse `text`.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorReply {
    pub code: String,
    pub text: String,
    /// Seconds, on `rate_limited` and the codes that carry it.
    pub retry_after: Option<u64>,
    /// What else the error carries, kept for the family that defines it.
    pub rest: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Reply {
        id: u64,
        result: Result<Value, ErrorReply>,
    },
    Event {
        seq: u64,
        ev: String,
        data: Value,
    },
}

/// One frame from the server. Fields this crate does not know are
/// ignored, as §5 requires; a frame that is neither shape is an error.
pub fn parse(text: &str) -> Result<Incoming, ProtocolError> {
    let Value::Object(mut m) = serde_json::from_str(text).map_err(|_| ProtocolError::NotJson)?
    else {
        return Err(ProtocolError::Malformed("not an object"));
    };
    match (m.remove("reply"), m.remove("seq")) {
        (Some(id), None) => {
            let id = id.as_u64().ok_or(ProtocolError::Malformed("reply"))?;
            let result = match (m.remove("ok"), m.remove("error")) {
                (Some(ok), None) => Ok(ok),
                (None, Some(error)) => Err(error_reply(error)?),
                _ => return Err(ProtocolError::Malformed("exactly one of ok and error")),
            };
            Ok(Incoming::Reply { id, result })
        }
        (None, Some(seq)) => {
            let seq = seq.as_u64().ok_or(ProtocolError::Malformed("seq"))?;
            let ev = match m.remove("ev") {
                Some(Value::String(ev)) => ev,
                _ => return Err(ProtocolError::Malformed("ev")),
            };
            let data = match m.remove("data") {
                None | Some(Value::Null) => Value::Object(Map::new()),
                Some(data @ Value::Object(_)) => data,
                Some(_) => return Err(ProtocolError::Malformed("data")),
            };
            Ok(Incoming::Event { seq, ev, data })
        }
        _ => Err(ProtocolError::Malformed("neither a reply nor an event")),
    }
}

fn error_reply(v: Value) -> Result<ErrorReply, ProtocolError> {
    let Value::Object(mut m) = v else {
        return Err(ProtocolError::Malformed("error"));
    };
    let mut text = |k| match m.remove(k) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(ProtocolError::Malformed("error")),
    };
    let (code, text) = (text("code")?, text("text")?);
    // A hint, not worth a connection when it is not a count.
    let retry_after = m.remove("retry_after").and_then(|v| v.as_u64());
    Ok(ErrorReply {
        code,
        text,
        retry_after,
        rest: m,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames_read_as_the_shape_they_are() {
        let cases: [(&str, Result<Incoming, ProtocolError>); 9] = [
            (
                r#"{"reply":7,"ok":{"a":1},"later":true}"#,
                Ok(Incoming::Reply {
                    id: 7,
                    result: Ok(json!({"a": 1})),
                }),
            ),
            (
                r#"{"reply":7,"error":{"code":"rate_limited","text":"slow","retry_after":3,"why":"x"}}"#,
                Ok(Incoming::Reply {
                    id: 7,
                    result: Err(ErrorReply {
                        code: "rate_limited".into(),
                        text: "slow".into(),
                        retry_after: Some(3),
                        rest: json!({"why": "x"}).as_object().unwrap().clone(),
                    }),
                }),
            ),
            (
                r#"{"seq":42,"ev":"chat","data":{"text":"hi"}}"#,
                Ok(Incoming::Event {
                    seq: 42,
                    ev: "chat".into(),
                    data: json!({"text": "hi"}),
                }),
            ),
            (
                r#"{"seq":1,"ev":"kicked"}"#,
                Ok(Incoming::Event {
                    seq: 1,
                    ev: "kicked".into(),
                    data: json!({}),
                }),
            ),
            (
                r#"{"reply":7,"ok":{},"error":{"code":"x","text":"y"}}"#,
                Err(ProtocolError::Malformed("exactly one of ok and error")),
            ),
            (
                r#"{"reply":7}"#,
                Err(ProtocolError::Malformed("exactly one of ok and error")),
            ),
            (
                r#"{"reply":-1,"ok":{}}"#,
                Err(ProtocolError::Malformed("reply")),
            ),
            (
                r#"{"reply":1,"seq":2,"ok":{}}"#,
                Err(ProtocolError::Malformed("neither a reply nor an event")),
            ),
            ("[1,2]", Err(ProtocolError::Malformed("not an object"))),
        ];
        for (text, want) in cases {
            assert_eq!(parse(text), want, "{text}");
        }
        assert_eq!(parse("{"), Err(ProtocolError::NotJson));
    }
}

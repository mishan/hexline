//! A [`Session`] run over a real WebSocket: one tokio task per connection
//! owns the socket and the session, and a [`Client`] talks to it.
//!
//! The connection's end is an [`Update::Closed`] carrying the
//! [`Lost`] the session made of it, so the caller decides whether to
//! resume, log in again or stop, with everything the protocol says about
//! which.
//!
//! tungstenite logs every frame it writes at `trace`, payloads included:
//! keep its logging below that, or the login's password and a resume's
//! token are logged with them.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, timeout, Instant};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::{
    ErrorReply, LoginParams, Lost, Output, ProtocolError, Resumable, Session, StateError, SyncOk,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Silence after which a connection is taken for dead: the server pings
/// every 30 s, and a link that a radio or a NAT lost sends no RST to say
/// so (hotline-ng.md §5, hxd-ng's own 90 s).
const SILENCE: Duration = Duration::from_secs(90);
/// How long the socket, TLS and the handshake's answer may take together.
const HANDSHAKE: Duration = Duration::from_secs(20);
/// Updates held for a caller that is not taking them. Past it the task
/// stops reading, the socket backs up, and the server drops the
/// connection as a slow consumer, which is the bound the protocol wants
/// rather than this process's memory.
const UPDATES: usize = 1024;

/// How a connection begins.
#[derive(Debug, Clone)]
pub enum Start {
    Login(LoginParams),
    Resume(Resumable),
}

#[derive(Debug)]
pub enum Error {
    /// The socket could not be opened, or the TLS handshake failed.
    Connect(String),
    /// The server refused the handshake.
    Refused(Box<Refusal>),
    Protocol(ProtocolError),
    /// The connection ended before an answer came, or went silent.
    Closed,
    /// A request this session does not make here (`login`, `resume`, or
    /// `sync` through [`Client::request`]).
    Rejected(StateError),
}

#[derive(Debug)]
pub struct Refusal {
    pub error: ErrorReply,
    /// What is still worth trying again later, if anything.
    pub resumable: Option<Resumable>,
}

/// What the connection's task tells its owner, in order.
#[derive(Debug)]
pub enum Update {
    Event {
        seq: u64,
        ev: String,
        data: Value,
    },
    /// The connection is over. `error` is the protocol fault that ended
    /// it, when it was one.
    Closed {
        lost: Lost,
        error: Option<ProtocolError>,
    },
}

enum Cmd {
    Request {
        req: String,
        params: Value,
        answer: oneshot::Sender<Result<Result<Value, ErrorReply>, Error>>,
    },
    Sync {
        answer: oneshot::Sender<Result<Result<SyncOk, ErrorReply>, Error>>,
    },
}

/// A live connection. Dropping it closes the socket.
pub struct Client {
    cmds: mpsc::UnboundedSender<Cmd>,
}

/// The stream of a connection's [`Update`]s. Dropping it closes the
/// connection, as dropping the [`Client`] does: nobody is listening.
pub type Updates = mpsc::Receiver<Update>;

/// TLS for `wss://`, against the platform's trust store. On Android the
/// verifier needs the app's context first (rustls-platform-verifier's
/// Android init); everywhere else it needs nothing.
pub fn platform_tls() -> Result<Arc<rustls::ClientConfig>, Error> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| b.with_platform_verifier())
        .map(|c| Arc::new(c.with_no_client_auth()))
        .map_err(|e| Error::Connect(e.to_string()))
}

/// Open `url`, make the handshake `start` asks for, and hand back the
/// client, what the handshake answered, and the stream of updates. A
/// `wss` URL is checked against `tls`, or the platform's trust store.
/// `start` is the caller's still on an error: a resume that never got an
/// answer is one to try again.
pub async fn connect(
    url: &str,
    start: &Start,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<(Client, Output, Updates), Error> {
    let tls = match tls {
        Some(t) => Some(t),
        None if url.starts_with("wss:") => Some(platform_tls()?),
        None => None,
    };
    let (mut session, first) = match start {
        Start::Login(p) => {
            let mut s = Session::new();
            let frame = s.login(p).expect("a new session logs in");
            (s, frame)
        }
        Start::Resume(r) => {
            let mut s = Session::resuming(r.clone());
            let frame = s.resume().expect("a resuming session resumes");
            (s, frame)
        }
    };
    let handshake = async {
        let (mut ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            tls.map(Connector::Rustls),
        )
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
        ws.send(Message::text(first.as_str()))
            .await
            .map_err(|_| Error::Closed)?;
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    break Ok((ws, session.receive(&t).map_err(Error::Protocol)?))
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break Err(Error::Closed),
                Some(Ok(_)) => {}
            }
        }
    };
    let (ws, answer) = timeout(HANDSHAKE, handshake)
        .await
        .map_err(|_| Error::Closed)??;
    drop(first);
    if let Output::Refused(error) = answer {
        let resumable = session.closed(1000, "").resumable;
        return Err(Error::Refused(Box::new(Refusal { error, resumable })));
    }
    let (cmds, rx) = mpsc::unbounded_channel();
    let (updates, out) = mpsc::channel(UPDATES);
    tokio::spawn(run(ws, session, rx, updates));
    Ok((Client { cmds }, answer, out))
}

impl Client {
    pub async fn request(
        &self,
        req: &str,
        params: Value,
    ) -> Result<Result<Value, ErrorReply>, Error> {
        let (answer, wait) = oneshot::channel();
        self.cmds
            .send(Cmd::Request {
                req: req.to_owned(),
                params,
                answer,
            })
            .map_err(|_| Error::Closed)?;
        wait.await.map_err(|_| Error::Closed)?
    }

    /// The roster whole and the seq to continue from (§6.3).
    pub async fn sync(&self) -> Result<Result<SyncOk, ErrorReply>, Error> {
        let (answer, wait) = oneshot::channel();
        self.cmds
            .send(Cmd::Sync { answer })
            .map_err(|_| Error::Closed)?;
        wait.await.map_err(|_| Error::Closed)?
    }
}

enum Waiter {
    Request(oneshot::Sender<Result<Result<Value, ErrorReply>, Error>>),
    Sync(oneshot::Sender<Result<Result<SyncOk, ErrorReply>, Error>>),
}

impl Waiter {
    fn fail(self) {
        match self {
            Waiter::Request(w) => drop(w.send(Err(Error::Closed))),
            Waiter::Sync(w) => drop(w.send(Err(Error::Closed))),
        }
    }
}

async fn run(
    mut ws: Socket,
    mut session: Session,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    updates: mpsc::Sender<Update>,
) {
    let mut waiters: HashMap<u64, Waiter> = HashMap::new();
    // Syncs answer as `Output::Synced`, which carries no id; replies come
    // in request order, so the oldest one outstanding is the one.
    let mut syncs: VecDeque<u64> = VecDeque::new();
    let (mut code, mut reason, mut error) = (1006u16, String::new(), None);
    let mut deadline = Instant::now() + SILENCE;
    loop {
        tokio::select! {
            () = sleep_until(deadline) => break,
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(t))) => match session.receive(&t) {
                    Ok(Output::Event { seq, ev, data }) => {
                        deadline = Instant::now() + SILENCE;
                        if updates.send(Update::Event { seq, ev, data }).await.is_err() {
                            let _ = ws.close(None).await;
                            code = u16::from(CloseCode::Normal);
                            break;
                        }
                    }
                    Ok(Output::Reply { id, result }) => {
                        deadline = Instant::now() + SILENCE;
                        if syncs.front() == Some(&id) {
                            syncs.pop_front();
                        }
                        match waiters.remove(&id) {
                            Some(Waiter::Request(w)) => drop(w.send(Ok(result))),
                            // Its ok is `Output::Synced`; only a refusal is a reply.
                            Some(Waiter::Sync(w)) => {
                                if let Err(e) = result {
                                    let _ = w.send(Ok(Err(e)));
                                }
                            }
                            None => {}
                        }
                    }
                    Ok(Output::Synced(ok)) => {
                        deadline = Instant::now() + SILENCE;
                        if let Some(Waiter::Sync(w)) = syncs.pop_front().and_then(|id| waiters.remove(&id)) {
                            let _ = w.send(Ok(Ok(ok)));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error = Some(e);
                        let _ = ws.close(None).await;
                        break;
                    }
                },
                Some(Ok(Message::Close(frame))) => {
                    if let Some(f) = frame {
                        code = u16::from(f.code);
                        reason = f.reason.to_string();
                    }
                    // Answered, so the server sees a close and not a drop.
                    let _ = ws.close(None).await;
                    break;
                }
                // A ping, pong or binary frame says the link is alive.
                Some(Ok(_)) => deadline = Instant::now() + SILENCE,
                Some(Err(_)) | None => break,
            },
            cmd = cmds.recv() => {
                let Some(cmd) = cmd else {
                    let _ = ws.close(None).await;
                    code = u16::from(CloseCode::Normal);
                    break;
                };
                let (id, frame, waiter) = match cmd {
                    Cmd::Request { req, params, answer } => match session.request(&req, params) {
                        Ok((id, frame)) => (id, frame, Waiter::Request(answer)),
                        Err(e) => { let _ = answer.send(Err(Error::Rejected(e))); continue; }
                    },
                    Cmd::Sync { answer } => match session.sync() {
                        Ok((id, frame)) => { syncs.push_back(id); (id, frame, Waiter::Sync(answer)) }
                        Err(e) => { let _ = answer.send(Err(Error::Rejected(e))); continue; }
                    },
                };
                waiters.insert(id, waiter);
                if ws.send(Message::text(frame)).await.is_err() {
                    break;
                }
            }
        }
    }
    for (_, w) in waiters {
        w.fail();
    }
    let lost = session.closed(code, &reason);
    let _ = updates.send(Update::Closed { lost, error }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;

    /// A server that answers the login and then says nothing, as one does
    /// behind a link a radio lost.
    async fn silent_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ng", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.next().await;
            let ok = json!({ "reply": 0, "ok": {
                "session": "s", "token": "t", "self": {}, "server": { "name": "", "subject": "" },
                "users": [], "detach": { "grace": 300 }, "caps": [], "seq": 0 } });
            ws.send(Message::text(ok.to_string())).await.unwrap();
            std::future::pending::<()>().await;
        });
        url
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_gone_silent_is_taken_for_lost() {
        let url = silent_server().await;
        let start = Start::Login(LoginParams::default());
        let (_client, _, mut updates) = connect(&url, &start, None).await.unwrap();
        let before = Instant::now();
        match timeout(SILENCE * 2, updates.recv())
            .await
            .expect("never closed")
        {
            Some(Update::Closed { lost, error: None }) => assert!(lost.resumable.is_some()),
            other => panic!("{other:?}"),
        }
        assert!(Instant::now() - before >= SILENCE);
    }
}

//! One server, as the app sees it: a connection it opens, the requests it
//! makes, and the updates it is handed in batches.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, LazyLock, Mutex};

use hxng_client::driver::{self, Client, Start, Update, Updates};
use hxng_client::{LoginParams, Output};
use serde_json::json;
use tokio::runtime::Runtime;

/// The runtime every connection's task and pump runs on. uniffi's own
/// is one thread, shared with whatever else polls through it; this one is
/// the core's, so the app's callbacks and its calls never wait on each
/// other's thread.
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("hexline-core")
        .enable_all()
        .build()
        .expect("a tokio runtime")
});

/// Updates handed to the app at once: whatever had arrived when the last
/// batch went, so a replay of hundreds of events is one redraw, not
/// hundreds.
const BATCH: usize = 256;

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// The server could not be reached. (`detail`, not `message`, which
    /// Kotlin's exceptions have.)
    Connect { detail: String },
    /// The server answered with an error `code` (hotline-ng.md §10).
    Refused { code: String, detail: String },
    /// The server broke the protocol, and the connection was dropped.
    Protocol { detail: String },
    /// There is no connection to ask.
    Closed,
    /// Logged in, or logging in, already: one connection at a time.
    Busy,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Connect { detail } | CoreError::Protocol { detail } => f.write_str(detail),
            CoreError::Refused { code, detail } => write!(f, "{code}: {detail}"),
            CoreError::Closed => f.write_str("not connected"),
            CoreError::Busy => f.write_str("already connected"),
        }
    }
}

impl From<driver::Error> for CoreError {
    fn from(e: driver::Error) -> Self {
        match e {
            driver::Error::Connect(detail) => CoreError::Connect { detail },
            driver::Error::Refused(r) => CoreError::Refused {
                code: r.error.code,
                detail: r.error.text,
            },
            driver::Error::Protocol(p) => CoreError::Protocol {
                detail: p.to_string(),
            },
            driver::Error::Closed | driver::Error::Rejected(_) => CoreError::Closed,
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct LoginInfo {
    pub server_name: String,
    pub subject: String,
    pub caps: Vec<String>,
    /// Whether the server lets this session survive a lost connection
    /// (§2). Resuming it is the app's to do, from slice 6 on.
    pub can_resume: bool,
}

/// What the app is told, in order. Payloads are the event's JSON until
/// the slices that render them type them.
#[derive(Debug, uniffi::Enum)]
pub enum CoreUpdate {
    Event {
        seq: u64,
        ev: String,
        data: String,
    },
    /// The connection is over: resumable, or taken by another device.
    Closed {
        can_resume: bool,
        replaced: bool,
    },
}

/// Implemented by the app: called on one of the core's threads, a batch
/// at a time, in order. It hands the batch on and returns: blocking here,
/// or waiting on a call into the core, holds up the connection's updates.
/// One that throws is taken for an app no longer listening, and the
/// connection is closed.
#[uniffi::export(with_foreign)]
pub trait UpdateSink: Send + Sync {
    fn deliver(&self, updates: Vec<CoreUpdate>);
}

enum State {
    Idle,
    Connecting,
    /// `pump` hands this connection's updates to the app; `generation`
    /// tells its end from a later connection's.
    Live {
        client: Client,
        generation: u64,
        pump: tokio::task::JoinHandle<()>,
    },
}

#[derive(uniffi::Object)]
pub struct ServerConnection {
    url: String,
    sink: Arc<dyn UpdateSink>,
    /// Held only to look and change, never across an await.
    state: Arc<Mutex<State>>,
    generations: std::sync::atomic::AtomicU64,
}

#[uniffi::export(async_runtime = "tokio")]
impl ServerConnection {
    #[uniffi::constructor]
    pub fn new(url: String, sink: Arc<dyn UpdateSink>) -> Arc<Self> {
        Arc::new(ServerConnection {
            url,
            sink,
            state: Arc::new(Mutex::new(State::Idle)),
            generations: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub async fn login(
        &self,
        login: Option<String>,
        password: Option<String>,
    ) -> Result<LoginInfo, CoreError> {
        {
            let mut state = self.state.lock().unwrap();
            if !matches!(*state, State::Idle) {
                return Err(CoreError::Busy);
            }
            *state = State::Connecting;
        }
        let start = Start::Login(LoginParams {
            login,
            password,
            ..LoginParams::default()
        });
        let url = self.url.clone();
        let connected = RUNTIME
            .spawn(async move { driver::connect(&url, &start, None).await })
            .await
            .expect("connect does not panic");
        let mut state = self.state.lock().unwrap();
        let ok = match connected {
            Ok((client, Output::LoggedIn(ok), updates)) => {
                let generation = self
                    .generations
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let pump = RUNTIME.spawn(pump(
                    updates,
                    self.sink.clone(),
                    self.state.clone(),
                    generation,
                ));
                *state = State::Live {
                    client,
                    generation,
                    pump,
                };
                ok
            }
            Ok(_) => {
                *state = State::Idle;
                return Err(CoreError::Protocol {
                    detail: "a login answered as something else".into(),
                });
            }
            Err(e) => {
                *state = State::Idle;
                return Err(e.into());
            }
        };
        Ok(LoginInfo {
            server_name: ok.server.name,
            subject: ok.server.subject,
            caps: ok.caps,
            can_resume: ok.detach.is_some(),
        })
    }

    pub async fn chat(&self, text: String) -> Result<(), CoreError> {
        let client = self.client()?;
        RUNTIME
            .spawn(async move { client.request("chat", json!({ "text": text })).await })
            .await
            .expect("a request does not panic")?
            .map(|_| ())
            .map_err(|e| CoreError::Refused {
                code: e.code,
                detail: e.text,
            })
    }

    /// Drops the connection; the session detaches if it may. Not `close`,
    /// which Kotlin's `AutoCloseable` has.
    /// Returns once the app has been handed the connection's last update,
    /// so a login after it starts clean.
    pub async fn disconnect(&self) {
        let old = std::mem::replace(&mut *self.state.lock().unwrap(), State::Idle);
        if let State::Live { client, pump, .. } = old {
            client.close();
            let _ = pump.await;
        }
    }
}

impl ServerConnection {
    fn client(&self) -> Result<Client, CoreError> {
        match &*self.state.lock().unwrap() {
            State::Live { client, .. } => Ok(client.clone()),
            _ => Err(CoreError::Closed),
        }
    }
}

/// Hands the app its updates a batch at a time until the connection
/// ends, then leaves the connection free for the next login.
async fn pump(
    mut updates: Updates,
    sink: Arc<dyn UpdateSink>,
    state: Arc<Mutex<State>>,
    generation: u64,
) {
    let mut batch = Vec::with_capacity(BATCH);
    while updates.recv_many(&mut batch, BATCH).await > 0 {
        let done = batch.iter().any(|u| matches!(u, Update::Closed { .. }));
        let updates: Vec<CoreUpdate> = batch.drain(..).map(core_update).collect();
        if done {
            let mut state = state.lock().unwrap();
            if matches!(*state, State::Live { generation: g, .. } if g == generation) {
                *state = State::Idle;
            }
        }
        // A throw from Kotlin arrives as a panic. Returning drops the
        // updates, and with them the connection.
        if catch_unwind(AssertUnwindSafe(|| sink.deliver(updates))).is_err() || done {
            return;
        }
    }
}

fn core_update(u: Update) -> CoreUpdate {
    match u {
        Update::Event { seq, ev, data } => CoreUpdate::Event {
            seq,
            ev,
            data: data.to_string(),
        },
        Update::Closed { lost, .. } => CoreUpdate::Closed {
            can_resume: lost.resumable.is_some(),
            replaced: lost.replaced,
        },
    }
}

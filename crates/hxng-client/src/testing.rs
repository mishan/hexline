//! A real hxd for tests, here so every crate's tests start it the same
//! way.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::task::{AbortHandle, JoinHandle};

/// A real hxd, the binary `HXD_BIN` names, on a config, ports and an
/// accounts directory of its own; killed and removed when dropped.
pub struct Server {
    /// Held so the server is killed with the test, before its directory
    /// goes.
    _proc: Child,
    _dir: TempDir,
    pub url: String,
    /// The ng port.
    pub addr: SocketAddr,
    /// Its HTTP base, where identity and the registrar answer.
    pub http: String,
    /// The listener a [`Proxy`] in front of it takes, bound from the start
    /// so no other test's server can take its port; an identity server
    /// answers as its host too, so a device proved through it is proved
    /// for a host the server is.
    proxy: Mutex<Option<TcpListener>>,
}

/// A directory removed when the test is done.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `guest` is the account a login with no name logs in to, so it has no
/// password.
fn account(name: &str) -> String {
    let password = if name == "guest" {
        String::new()
    } else {
        format!("password = \"pw-{name}\"\n")
    };
    format!(
        "name = \"{name}\"\n{password}[access]\nread_chat = true\nread_chat_history = true\nsend_chat = true\nsend_msgs = true\n"
    )
}

impl Server {
    /// Each of `accounts` has the password `pw-<name>`, but `guest`.
    pub async fn start(accounts: &[&str]) -> Server {
        Server::with_grace(accounts, 300).await
    }

    /// As [`Server::start`], with detached sessions kept `grace` seconds.
    pub async fn with_grace(accounts: &[&str], grace: u64) -> Server {
        Server::launch(accounts, grace, None, false).await
    }

    /// As [`Server::with_grace`], taking identity logins at the host it
    /// listens on and its proxy's: from any identity, registrar or none,
    /// made an account of its own when the client asks for one.
    pub async fn with_identity(accounts: &[&str], grace: u64) -> Server {
        Server::launch(accounts, grace, Some(("allow", "create")), false).await
    }

    /// As [`Server::with_identity`], and a registrar at host `127.0.0.1`
    /// that anyone may register a handle at and that keeps envelopes.
    pub async fn with_registrar(accounts: &[&str]) -> Server {
        Server::launch(accounts, 300, Some(("allow", "create")), true).await
    }

    /// As [`Server::with_registrar`], under the default policy for an
    /// identity no registrar vouches for: a guest.
    pub async fn with_registrar_vouching(accounts: &[&str]) -> Server {
        Server::launch(accounts, 300, Some(("guest", "create")), true).await
    }

    /// As [`Server::with_identity`], under the default policy: an identity
    /// no registrar vouches for, or one with no account, logs in as a guest.
    pub async fn with_guest_identity(accounts: &[&str]) -> Server {
        Server::launch(accounts, 300, Some(("guest", "guest")), false).await
    }

    /// `identity` is the `unattested` and `new_accounts` policies.
    async fn launch(
        accounts: &[&str],
        grace: u64,
        identity: Option<(&str, &str)>,
        registrar: bool,
    ) -> Server {
        let bin = std::env::var("HXD_BIN").expect(
            "HXD_BIN must name an hxd binary for the live tests (`make test-live` sets it)",
        );
        let root =
            std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
        let dir = PathBuf::from(root).join(format!(
            "hexline-live-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(dir.join("accounts")).unwrap();
        for a in accounts {
            std::fs::write(dir.join("accounts").join(format!("{a}.toml")), account(a)).unwrap();
        }
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let (legacy, ng) = (free_port(), free_port());
        let name = format!("hexline-live-{ng}");
        std::fs::write(
            dir.join("hxd-ng.toml"),
            format!(
                "[server]\nbind = \"127.0.0.1:{legacy}\"\nname = \"{name}\"\n\
                 [paths]\naccounts = \"accounts\"\n\
                 [ng]\nbind = \"127.0.0.1:{ng}\"\ngrace = {grace}\n\
                 [limits]\nng_requests = 0\nreconnect_seconds = 0\n\
                 [history]\ndb = \"history.db\"\n{}",
                match identity {
                    Some((unattested, new_accounts)) => format!(
                        "[identity]\nhosts = [\"127.0.0.1:{ng}\", \"127.0.0.1:{proxy_port}\"]\n\
                         unattested = \"{unattested}\"\nnew_accounts = \"{new_accounts}\"\n{}",
                        // Its own registrar's attestations, on the key that
                        // registrar publishes, fetched where it listens.
                        if registrar {
                            format!(
                                "trusted_registrars = [\"127.0.0.1\"]\n\
                                 registrar_urls = {{ \"127.0.0.1\" = \"http://127.0.0.1:{ng}\" }}\n"
                            )
                        } else {
                            String::new()
                        }
                    ),
                    None => String::new(),
                } + if registrar {
                    "[registrar]\nhost = \"127.0.0.1\"\nkey = \"registrar.key\"\n\
                     store = \"registrar.db\"\ninvites = \"invites\"\nsignup = \"open\"\n\
                     envelopes = true\nenvelope_secret = \"envelope.secret\"\n"
                } else {
                    ""
                }
            ),
        )
        .unwrap();
        let proc = Command::new(&bin)
            .arg("--config")
            .arg(dir.join("hxd-ng.toml"))
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("hxd.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("{bin}: {e}"));
        let server = Server {
            _proc: proc,
            _dir: TempDir(dir),
            url: format!("ws://127.0.0.1:{ng}/ng"),
            addr: SocketAddr::from(([127, 0, 0, 1], ng)),
            http: format!("http://127.0.0.1:{ng}"),
            proxy: Mutex::new(Some(proxy)),
        };
        for _ in 0..200 {
            if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", ng)).await {
                drop(s);
                return server;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let log = std::fs::read_to_string(server._dir.0.join("hxd.log")).unwrap_or_default();
        let tail: Vec<&str> = log.lines().rev().take(20).collect();
        panic!(
            "hxd did not listen on {ng}; its log ends:\n{}",
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
    }
}

/// A TCP proxy in front of a server, for a test to take a connection away
/// from under a client: every link cut at once, or new ones turned away.
pub struct Proxy {
    pub url: String,
    links: Arc<Mutex<Vec<AbortHandle>>>,
    refusing: Arc<AtomicBool>,
    cut_after: Arc<Mutex<Option<Duration>>>,
    mangling: Arc<AtomicBool>,
    accept: JoinHandle<()>,
}

impl Proxy {
    pub async fn to(server: &Server) -> Proxy {
        let listener = server
            .proxy
            .lock()
            .unwrap()
            .take()
            .expect("one proxy a server");
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let url = format!("ws://{}/ng", listener.local_addr().unwrap());
        let links = Arc::new(Mutex::new(Vec::new()));
        let refusing = Arc::new(AtomicBool::new(false));
        let cut_after = Arc::new(Mutex::new(None));
        let mangling = Arc::new(AtomicBool::new(false));
        let target = server.addr;
        let accept = tokio::spawn({
            let (links, refusing, cut_after, mangling) = (
                links.clone(),
                refusing.clone(),
                cut_after.clone(),
                mangling.clone(),
            );
            async move {
                while let Ok((mut client, _)) = listener.accept().await {
                    if refusing.load(Ordering::SeqCst) {
                        continue;
                    }
                    let cut: Option<Duration> = *cut_after.lock().unwrap();
                    let mangle = mangling.load(Ordering::SeqCst);
                    let link = tokio::spawn(async move {
                        if let Ok(mut server) = tokio::net::TcpStream::connect(target).await {
                            if mangle && mangle_first(&mut client, &mut server).await.is_err() {
                                return;
                            }
                            let copy = tokio::io::copy_bidirectional(&mut client, &mut server);
                            match cut {
                                Some(after) => drop(tokio::time::timeout(after, copy).await),
                                None => drop(copy.await),
                            }
                        }
                    });
                    links.lock().unwrap().push(link.abort_handle());
                }
            }
        });
        Proxy {
            url,
            links,
            refusing,
            cut_after,
            mangling,
            accept,
        }
    }

    /// Cut every link now open, both ways.
    pub fn sever(&self) {
        for link in self.links.lock().unwrap().drain(..) {
            link.abort();
        }
    }

    /// Links made from now on lose any `Authorization` header in their
    /// first request, as a front that strips it would.
    pub fn strip_authorization(&self) {
        self.mangling.store(true, Ordering::SeqCst);
    }

    /// Every link made from now on is cut once it has lasted `after`.
    pub fn cut_each_after(&self, after: Duration) {
        *self.cut_after.lock().unwrap() = Some(after);
    }

    /// While `refuse`, a new connection is closed as soon as it is made.
    pub fn refuse(&self, refuse: bool) {
        self.refusing.store(refuse, Ordering::SeqCst);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept.abort();
        self.sever();
    }
}

/// A new identity and one device of it, certified for a day and with a
/// card under `name`.
pub fn device(name: &str) -> (hl_identity::IdentityKey, crate::auth::Device) {
    use hl_identity::{Card, DeviceCert, DeviceKey, IdentityKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = IdentityKey::generate();
    let key = DeviceKey::generate();
    let cert = DeviceCert::for_keys(&id, key.public(), key.public_enc(), now, 86_400)
        .unwrap()
        .sign(&id);
    let card = Card::new(&id, name, now).sign(&id, Vec::new()).unwrap();
    (id, crate::auth::Device { key, cert, card })
}

/// Pass on the client's first read with its `authorization:` header
/// renamed; a request is written whole by the clients these tests run.
async fn mangle_first(
    client: &mut tokio::net::TcpStream,
    server: &mut tokio::net::TcpStream,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0; 16 * 1024];
    let n = client.read(&mut buf).await?;
    let mut first = buf[..n].to_vec();
    let needle = b"authorization:";
    if let Some(at) = first
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
    {
        first[at..at + needle.len()].copy_from_slice(b"x-stripped-by:");
    }
    server.write_all(&first).await
}

/// Register `handle` for a new identity at `server`'s registrar and put
/// its key there sealed under `secret`, as `hlid register` and `hlid
/// backup` would.
pub async fn back_up(
    server: &Server,
    handle: &str,
    secret: &hl_identity::envelope::Secret<'_>,
) -> hl_identity::IdentityKey {
    use hl_identity::{EnvelopePut, IdentityKey, KeyEnvelope, RegisterRequest};
    let b64 = |b: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = IdentityKey::generate();
    let http = crate::auth::http_client(&server.http, None).unwrap();
    let register = RegisterRequest {
        identity: id.public(),
        registrar: "127.0.0.1".into(),
        handle: handle.into(),
        time: now,
        successor: None,
        proof: None,
    };
    let req = serde_json::json!({ "request": b64(&register.sign(&id).unwrap()) });
    crate::auth::post(
        &http,
        &format!("{}/registrar/register", server.http),
        Some(req),
    )
    .await
    .unwrap();
    let (envelope, keys) = KeyEnvelope::seal(&id, secret).unwrap();
    let put = EnvelopePut::store(&id, "127.0.0.1", now, &envelope, &keys).unwrap();
    let resp = http
        .put(format!("{}/registrar/envelopes", server.http))
        .json(&serde_json::json!({ "request": b64(&put) }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "{}",
        resp.text().await.unwrap_or_default()
    );
    id
}

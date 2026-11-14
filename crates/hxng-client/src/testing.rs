//! A real hxd for tests, here so every crate's tests start it the same
//! way.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// The file `account` is kept in, which the server reads at each login.
    pub fn account_file(&self, account: &str) -> PathBuf {
        self._dir.0.join("accounts").join(format!("{account}.toml"))
    }

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
        // A port found free is free only until it is bound: another test's
        // server may take it first. Each try is on fresh ports, and taken
        // only once the server there is this one.
        for _ in 0..5 {
            let ng = free_port();
            if let Some(server) = Server::try_launch(accounts, grace, identity, registrar, ng).await
            {
                return server;
            }
        }
        panic!("hxd never came up on ports of its own");
    }

    /// One try at [`Server::start`]'s server with its ng port `ng`, as
    /// another test may have taken the same port: none if this one's hxd
    /// is not the one that answers there.
    pub async fn try_on(ng: u16) -> Option<Server> {
        Server::try_launch(&[], 300, None, false, ng).await
    }

    async fn try_launch(
        accounts: &[&str],
        grace: u64,
        identity: Option<(&str, &str)>,
        registrar: bool,
        ng: u16,
    ) -> Option<Server> {
        let bin = std::env::var("HXD_BIN").expect(
            "HXD_BIN must name an hxd binary for the live tests (`make test-live` sets it)",
        );
        let root =
            std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
        // Its own whatever ports it is given: two launches at once may be
        // given the same one, and only one of them binds it.
        static LAUNCHES: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "hexline-live-{}-{}",
            std::process::id(),
            LAUNCHES.fetch_add(1, Ordering::SeqCst)
        );
        let dir = PathBuf::from(root).join(&name);
        std::fs::create_dir_all(dir.join("accounts")).unwrap();
        for a in accounts {
            std::fs::write(dir.join("accounts").join(format!("{a}.toml")), account(a)).unwrap();
        }
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let legacy = free_port();
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
        let mut server = Server {
            _proc: proc,
            _dir: TempDir(dir),
            url: format!("ws://127.0.0.1:{ng}/ng"),
            addr: SocketAddr::from(([127, 0, 0, 1], ng)),
            http: format!("http://127.0.0.1:{ng}"),
            proxy: Mutex::new(Some(proxy)),
        };
        let http = crate::auth::http_client(&server.http, None).unwrap();
        let discovery = format!("{}/.well-known/hotline", server.http);
        for _ in 0..200 {
            // Gone: it lost a port to another test's server.
            if server._proc.try_wait().ok().flatten().is_some() {
                return None;
            }
            if let Ok((200, body)) = crate::auth::get(&http, &discovery).await {
                let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                // Another test's server, on the port this one was to have.
                return (doc["name"] == name.as_str()).then_some(server);
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
    unauthorized: Arc<Mutex<Upgrades>>,
    heard: Arc<Mutex<Vec<u8>>>,
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
        let unauthorized = Arc::new(Mutex::new(Upgrades::default()));
        let heard = Arc::new(Mutex::new(Vec::new()));
        let target = server.addr;
        let accept = tokio::spawn({
            let (links, refusing, cut_after, mangling, unauthorized, heard) = (
                links.clone(),
                refusing.clone(),
                cut_after.clone(),
                mangling.clone(),
                unauthorized.clone(),
                heard.clone(),
            );
            async move {
                while let Ok((client, _)) = listener.accept().await {
                    if refusing.load(Ordering::SeqCst) {
                        continue;
                    }
                    let cut: Option<Duration> = *cut_after.lock().unwrap();
                    let mangle = mangling.load(Ordering::SeqCst);
                    let (unauthorized, heard) = (unauthorized.clone(), heard.clone());
                    let link = tokio::spawn(async move {
                        if let Ok(server) = tokio::net::TcpStream::connect(target).await {
                            let pass = pass_on(client, server, mangle, unauthorized, heard);
                            match cut {
                                Some(after) => drop(tokio::time::timeout(after, pass).await),
                                None => drop(pass.await),
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
            unauthorized,
            heard,
            accept,
        }
    }

    /// The next `upgrades` WebSocket upgrades are answered 401, as a server
    /// that no longer knows the token would.
    pub fn refuse_upgrades(&self, upgrades: usize) {
        self.unauthorized.lock().unwrap().left = upgrades;
    }

    /// How many upgrades have been answered 401.
    pub fn upgrades_refused(&self) -> usize {
        self.unauthorized.lock().unwrap().refused
    }

    /// Everything clients have sent through the proxy, in the order it came.
    pub fn heard(&self) -> Vec<u8> {
        self.heard.lock().unwrap().clone()
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

/// The upgrades a [`Proxy`] is to refuse, and has.
#[derive(Default)]
struct Upgrades {
    left: usize,
    refused: usize,
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

/// Pass a link on both ways, keeping what the client sends. Its first
/// request's head may be refused (an upgrade while `unauthorized` has
/// some left) or have its `authorization:` header renamed (`mangle`).
async fn pass_on(
    mut client: tokio::net::TcpStream,
    mut server: tokio::net::TcpStream,
    mangle: bool,
    unauthorized: Arc<Mutex<Upgrades>>,
    heard: Arc<Mutex<Vec<u8>>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const MOST: usize = 16 * 1024;
    let mut buf = vec![0; MOST];
    // The head whole, however it was split; what follows it is kept.
    let mut first = Vec::new();
    let head = loop {
        let n = client.read(&mut buf).await?;
        first.extend_from_slice(&buf[..n]);
        if let Some(at) = first.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if n == 0 || first.len() >= MOST {
            break first.len();
        }
    };
    let upgrade = first[..head]
        .windows(9)
        .any(|w| w.eq_ignore_ascii_case(b"websocket"));
    let refused = upgrade && {
        let mut upgrades = unauthorized.lock().unwrap();
        let refused = upgrades.left > 0;
        if refused {
            upgrades.left -= 1;
            upgrades.refused += 1;
        }
        refused
    };
    if refused {
        return client
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
    }
    let needle = b"authorization:";
    if mangle {
        if let Some(at) = first[..head]
            .windows(needle.len())
            .position(|w| w.eq_ignore_ascii_case(needle))
        {
            first[at..at + needle.len()].copy_from_slice(b"x-stripped-by:");
        }
    }
    heard.lock().unwrap().extend_from_slice(&first);
    server.write_all(&first).await?;
    let (mut from_client, mut to_client) = client.split();
    let (mut from_server, mut to_server) = server.split();
    let up = async {
        loop {
            let n = from_client.read(&mut buf).await?;
            if n == 0 {
                return to_server.shutdown().await;
            }
            heard.lock().unwrap().extend_from_slice(&buf[..n]);
            to_server.write_all(&buf[..n]).await?;
        }
    };
    let down = async {
        tokio::io::copy(&mut from_server, &mut to_client).await?;
        to_client.shutdown().await
    };
    tokio::try_join!(up, down).map(|_| ())
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

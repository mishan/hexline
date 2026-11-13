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

fn account(name: &str) -> String {
    format!(
        "name = \"{name}\"\npassword = \"pw-{name}\"\n[access]\nread_chat = true\nread_chat_history = true\nsend_chat = true\nsend_msgs = true\n"
    )
}

impl Server {
    /// Each of `accounts` has the password `pw-<name>`.
    pub async fn start(accounts: &[&str]) -> Server {
        Server::with_grace(accounts, 300).await
    }

    /// As [`Server::start`], with detached sessions kept `grace` seconds.
    pub async fn with_grace(accounts: &[&str], grace: u64) -> Server {
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
        let (legacy, ng) = (free_port(), free_port());
        let name = format!("hexline-live-{ng}");
        std::fs::write(
            dir.join("hxd-ng.toml"),
            format!(
                "[server]\nbind = \"127.0.0.1:{legacy}\"\nname = \"{name}\"\n\
                 [paths]\naccounts = \"accounts\"\n\
                 [ng]\nbind = \"127.0.0.1:{ng}\"\ngrace = {grace}\n\
                 [limits]\nng_requests = 0\nreconnect_seconds = 0\n\
                 [history]\ndb = \"history.db\"\n"
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
    accept: JoinHandle<()>,
}

impl Proxy {
    pub async fn to(server: &Server) -> Proxy {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ng", listener.local_addr().unwrap());
        let links = Arc::new(Mutex::new(Vec::new()));
        let refusing = Arc::new(AtomicBool::new(false));
        let cut_after = Arc::new(Mutex::new(None));
        let target = server.addr;
        let accept = tokio::spawn({
            let (links, refusing, cut_after) = (links.clone(), refusing.clone(), cut_after.clone());
            async move {
                while let Ok((mut client, _)) = listener.accept().await {
                    if refusing.load(Ordering::SeqCst) {
                        continue;
                    }
                    let cut: Option<Duration> = *cut_after.lock().unwrap();
                    let link = tokio::spawn(async move {
                        if let Ok(mut server) = tokio::net::TcpStream::connect(target).await {
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
            accept,
        }
    }

    /// Cut every link now open, both ways.
    pub fn sever(&self) {
        for link in self.links.lock().unwrap().drain(..) {
            link.abort();
        }
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

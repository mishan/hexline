//! A real hxd for tests, here so every crate's tests start it the same
//! way.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

/// A real hxd, the binary `HXD_BIN` names, on a config, ports and an
/// accounts directory of its own; killed and removed when dropped.
pub struct Server {
    /// Held so the server is killed with the test, before its directory
    /// goes.
    _proc: Child,
    _dir: TempDir,
    pub url: String,
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
                 [ng]\nbind = \"127.0.0.1:{ng}\"\n\
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

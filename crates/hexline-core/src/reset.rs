//! A holder's reset of its identity's devices (identity-registrar.md
//! section 4.10 and section 6.2, "A holder's reset"): a device epoch one
//! past the highest floor known, published at every registrar the
//! identity is registered at, so servers refuse every certificate minted
//! below it, and this phone's own certificate minted again above it.
//!
//! A reset keeps nothing about itself between calls. Each reads every
//! registrar's per-identity list, resets one past the highest epoch any
//! list shows or this process has learned, and is done at a registrar
//! once a read of its list shows that epoch in a record this call
//! posted. A call cut short is not finished by the next: the next resets
//! once more, an epoch further. What it could not finish at a registrar
//! that may yet take it, it hands back signed, for [`retry_reset`] to post
//! later without the identity key.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use futures_util::future::join_all;

use hl_identity::{Card, DeviceEpoch, DeviceKey, IdentityKey, PublicKey};
use hxng_client::reqwest::{Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::epoch::{at_floor, floor_of, next_floor, published, registrars_of};
use crate::holder::{refused, seed32};
use crate::restore::{
    b64, certify, endpoint, now, registrar_base, registrar_of, retry_after, unb64, Registrar,
};
use crate::CoreError;

/// How far one published device epoch may move a registrar's floor
/// (section 6.2 step 5).
const STEP_MAX: u64 = 16;

/// Posts whose reply was lost before a registrar is reported not done.
const TRIES: usize = 3;

/// Posts to one registrar for one target, at most. Its daily limit stops
/// a catch-up long before this; the bound is for one that never says so.
const POSTS_MAX: usize = 64;

/// Times the lists are read in one reset: a re-read follows an answer
/// above what was posted, and another holder resetting each time is
/// given up on rather than chased.
const ROUNDS: usize = 5;

/// How long one registrar is given to be discovered, to have its list
/// read, or to be brought to a target: one that takes longer is left
/// behind, as `published_at` leaves it, rather than holding up the rest.
const WAIT: Duration = Duration::from_secs(45);

/// How far ahead of this phone's clock a registrar's record may be dated
/// before a reset is not signed after it, which would date it as far.
const SKEW: u64 = 300;

/// The longest a registrar's `retry_after` is taken for: a day.
const RETRY_MOST: u64 = 24 * 3600;

/// A record post's reply, read at most.
const REPLY_MAX: usize = 64 * 1024;

/// Records kept for one registrar at most: as many as a reset would post
/// it.
const CHAIN_MAX: usize = POSTS_MAX;

/// How long a retry is left where no registrar said, and the least it is
/// left where one did.
const RETRY_EVERY: u64 = 15 * 60;
const RETRY_LEAST: u64 = 60;

/// The longest a retry is left between tries it was not done at, its wait
/// doubling from [`RETRY_EVERY`] each time: a registrar asking to be left a
/// minute is not asked every minute for days.
const BACKOFF_MOST: u64 = 6 * 3600;

/// A registrar is given up on only once it has been asked this many times
/// and this long has passed since the reset, both: a phone offline for a
/// week has made no tries, and one asked often has not yet waited out an
/// outage.
const TRIES_LEAST: u32 = 12;
const RETRY_FOR: u64 = 7 * 24 * 3600;

/// A retry's bytes, read at most, the registrars it is kept for, and the
/// hashes of the reset's own records it remembers: a retry opens a
/// connection to each registrar at once.
const RETRY_MAX: usize = 1024 * 1024;
const CHAINS_MAX: usize = 32;
const POSTED_MAX: usize = 256;

/// The identities a reset is under way for in this process: a second at
/// once would take the first's records for another holder's and reset
/// past them, spending the registrars' daily resets on nothing.
static RESETTING: Mutex<BTreeSet<PublicKey>> = Mutex::new(BTreeSet::new());

/// `identity`'s place in [`RESETTING`], given back when dropped; refused
/// `busy` while another reset holds it.
struct Resetting(PublicKey);

impl Resetting {
    fn take(identity: &PublicKey) -> Result<Resetting, CoreError> {
        let mut under_way = RESETTING.lock().unwrap_or_else(|e| e.into_inner());
        match under_way.insert(*identity) {
            true => Ok(Resetting(*identity)),
            false => Err(refused("busy")),
        }
    }
}

impl Drop for Resetting {
    fn drop(&mut self) {
        let mut under_way = RESETTING.lock().unwrap_or_else(|e| e.into_inner());
        under_way.remove(&self.0);
    }
}

/// What a reset came to, for the app to keep and to say.
#[derive(Debug, uniffi::Record)]
pub struct DevicesReset {
    /// The epoch reset to.
    pub epoch: u64,
    /// The highest epoch a registrar's list showed, done or not: a
    /// certificate below it is refused already.
    pub published: u64,
    /// The registrars whose list shows the reset.
    pub done: Vec<String>,
    pub not_done: Vec<NotYetReset>,
    /// Origins only the card names whose discovery says no registrar is
    /// there: a 404, or a document with no registrar in it.
    pub not_registrars: Vec<String>,
    /// This phone's certificate minted again at the floor, above the one
    /// passed, for the same key and name and, as this phone's own always
    /// is, to log in, message and manage: to keep in its place.
    pub cert: Vec<u8>,
    /// The epoch `cert` was minted at.
    pub cert_epoch: u64,
    /// What [`retry_reset`] posts to the registrars in `not_done` that may
    /// yet take the reset, opaque: None where none may.
    pub retry: Option<Vec<u8>>,
    /// Seconds before `retry` is worth posting: None with no `retry`.
    pub retry_in: Option<u64>,
    /// The registrars `retry` is kept for: of `not_done`, those it may yet
    /// reach, and none of the rest.
    pub later: Vec<String>,
}

/// What a [`retry_reset`] came to, as [`DevicesReset`] says it.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct ResetRetried {
    /// The epoch reset to, which the retry was for.
    pub epoch: u64,
    pub published: u64,
    pub done: Vec<String>,
    pub not_done: Vec<NotYetReset>,
    pub not_registrars: Vec<String>,
    /// To keep in place of the one posted.
    pub retry: Option<Vec<u8>>,
    pub retry_in: Option<u64>,
    /// As [`DevicesReset::later`], those not due counted among them.
    pub later: Vec<String>,
}

/// A registrar the reset is not at yet, and why.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct NotYetReset {
    pub registrar: String,
    pub why: NotYet,
    /// The code it refused the reset with, if it did.
    pub code: Option<String>,
    /// Seconds it asked to be left before it is asked again.
    pub retry_after: Option<u64>,
}

/// Why a registrar is not reset yet: a code for the app to put in words of
/// its own, as nothing a registrar says is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NotYet {
    /// It could not be reached, or did not answer in time.
    Unreachable,
    /// Its host refused the connection: down, or no registrar there.
    ConnectionRefused,
    /// It refused, as `code` says where it said.
    Refused,
    /// It answers, and takes no device epochs.
    Unsupported,
    /// What it answered its list does not bear out.
    Unconfirmed,
    /// What it serves does not read as a registrar's discovery or list.
    Malformed,
    /// More posts than a reset makes did not bring it to the target.
    TooFarBehind,
    /// Another holder reset to this reset's epoch or past it meanwhile.
    Overtaken,
    /// Its last reset is dated ahead of this phone's clock.
    DatedAhead,
    /// Its last reset is dated after the records a retry holds for it,
    /// which it would refuse: only a new reset reaches it.
    DatedBefore,
    /// Asked for long enough without the reset reaching it: only a new
    /// reset asks it again.
    GaveUp,
}

/// Signs out every device the identity whose seed is `identity_seed`
/// certified, at every one of `registrars` and each `card` attests it at,
/// from the highest floor known: `epoch` (the one this phone keeps), the
/// process's, and every list read. `device_seed` and `cert` are this
/// phone's own device, whose certificate is minted again above the
/// floor. Refused `wrong_identity` for a seed, card or certificate that
/// are not one identity's, `no_registrar` where there is nowhere to
/// reset, `no_registrar_reached` where no list could be read (nothing is
/// posted then, and nothing raised), `no_epoch_left` where the floor is
/// at its last, and `busy` while another reset of the identity is under
/// way. Calling it again resets once more.
#[uniffi::export(async_runtime = "tokio")]
pub async fn reset_devices(
    identity_seed: Vec<u8>,
    card: Vec<u8>,
    registrars: Vec<String>,
    epoch: u64,
    device_seed: Vec<u8>,
    cert: Vec<u8>,
) -> Result<DevicesReset, CoreError> {
    let (seed, device) = (seed32(identity_seed)?, seed32(device_seed)?);
    crate::connection::RUNTIME
        .spawn(async move { resetting(&seed, card, registrars, epoch, &device, cert).await })
        .await
        .unwrap_or_else(|_| Err(protocol("the reset stopped")))
}

async fn resetting(
    seed: &Zeroizing<[u8; 32]>,
    card: Vec<u8>,
    registrars: Vec<String>,
    epoch: u64,
    device: &Zeroizing<[u8; 32]>,
    cert: Vec<u8>,
) -> Result<DevicesReset, CoreError> {
    let id = IdentityKey::from_seed(seed);
    let device = DeviceKey::from_seed(device);
    let info = crate::identity::cert_for_device(cert, card.clone(), device.seed().to_vec())
        .map_err(|_| refused("wrong_identity"))?;
    if info.fingerprint != id.fingerprint().to_string() {
        return Err(refused("wrong_identity"));
    }
    let parsed = Card::parse(&card).map_err(|_| refused("wrong_identity"))?;
    let _resetting = Resetting::take(&id.public())?;
    let targets = registrars_of(&registrars, &parsed);
    if targets.is_empty() {
        return Err(refused("no_registrar"));
    }
    let origin = |r: &str| registrar_base(r).ok().map(|b| b.origin());
    let mut remotes: Vec<Remote> = targets
        .iter()
        .map(|t| Remote {
            target: t.clone(),
            identity: id.public(),
            kept: registrars.iter().any(|k| origin(k) == origin(t)),
            reg: None,
        })
        .collect();
    let desks = targets.into_iter().zip(remotes.iter_mut()).collect();
    // Kept only once a list is read: a reset no registrar heard of
    // raises nothing.
    let floor = floor_of(&id.public()).max(epoch).max(info.epoch);
    let report = reset_all(&id, floor, desks, &Floors(id.public())).await?;
    let at = now();
    let retry = lagging(
        &id,
        &report,
        |t| remotes.iter().any(|r| r.target == t && r.kept),
        at,
    )?;
    let retry_in = retry_in(&retry.chains, at);
    let name = info.name.as_deref().unwrap_or("Hexline");
    // The floor is past the target by now, which is past `info.epoch`.
    let (cert, cert_epoch) = at_floor(&id.public(), report.published, |floor| {
        certify(&id, &device, name, floor).map(|c| (c, floor))
    })?;
    Ok(DevicesReset {
        epoch: report.target,
        published: report.published,
        done: report.done,
        not_done: report.not_done,
        not_registrars: report.not_registrars,
        cert,
        cert_epoch,
        later: retry.chains.iter().map(|c| c.registrar.clone()).collect(),
        retry: encode(&retry),
        retry_in,
    })
}

// --- One registrar ----------------------------------------------------------

/// A registrar's current device epoch record for the identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Current {
    /// 0 for none.
    pub(crate) epoch: u64,
    pub(crate) time: u64,
    pub(crate) hash: Option<[u8; 32]>,
}

/// Why a registrar's discovery found none.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unfound {
    NotARegistrar,
    Not(Refusal),
}

/// What a reset needs of a registrar.
pub(crate) trait Desk {
    /// Its discovery read, naming itself as it is reached.
    async fn discover(&mut self) -> Result<(), Unfound>;
    /// Its per-identity list read past any cache, verified against its
    /// keys, reduced to the current device epoch record.
    async fn read(&mut self) -> Result<Current, Refusal>;
    /// Post a record: the status and JSON body, or why there was none.
    async fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String>;
    /// Before a post whose reply was lost is tried again.
    async fn pause(&self) {}
}

/// A registrar over HTTP, reached at `target`, a host or a base URL.
struct Remote {
    target: String,
    identity: PublicKey,
    /// One the app keeps, so a registrar, whatever answers there now.
    kept: bool,
    reg: Option<(Client, Url, Registrar)>,
}

impl Desk for Remote {
    async fn discover(&mut self) -> Result<(), Unfound> {
        let not = |why| Err(Unfound::Not(Refusal::because(why)));
        let Ok(base) = registrar_base(&self.target) else {
            return not(NotYet::Malformed);
        };
        let Ok(http) = hxng_client::auth::http_client(base.as_str(), None) else {
            return not(NotYet::Unreachable);
        };
        let url = base.join("/.well-known/hotline").expect("a path");
        let (status, body) = match hxng_client::auth::get(&http, url.as_str()).await {
            Ok(got) => got,
            Err(_) if refuses(&base).await => return not(NotYet::ConnectionRefused),
            Err(_) => return not(NotYet::Unreachable),
        };
        let doc = serde_json::from_slice::<Value>(&body).ok();
        // Said only of an origin the app does not keep, and only where
        // the answer says so: a registrar down, or kept from view on the
        // path, must not look like no registrar and be left out.
        let none_here = status == 404
            || (status == 200 && doc.as_ref().is_some_and(|d| d.get("registrar").is_none()));
        if none_here && !self.kept {
            return Err(Unfound::NotARegistrar);
        }
        match (status, doc) {
            (429 | 503, _) => Err(Unfound::Not(Refusal {
                why: NotYet::Refused,
                code: Some("rate_limited".into()),
                retry_after: retry_after(&body).map(|s| s.min(RETRY_MOST)),
            })),
            (200, Some(doc)) => match registrar_of(&doc, &base) {
                Ok(reg) => {
                    self.reg = Some((http, base, reg));
                    Ok(())
                }
                Err(_) => not(NotYet::Malformed),
            },
            (200, None) => not(NotYet::Malformed),
            _ => not(NotYet::Unreachable),
        }
    }

    async fn read(&mut self) -> Result<Current, Refusal> {
        let (http, base, reg) = self
            .reg
            .as_ref()
            .ok_or_else(|| Refusal::because(NotYet::Unreachable))?;
        let p = published(http, base, reg, &self.identity)
            .await
            .map_err(unread)?;
        Ok(Current {
            epoch: p.epoch,
            time: p.time,
            hash: p.hash,
        })
    }

    async fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String> {
        let (http, base, reg) = self.reg.as_ref().ok_or("not discovered")?;
        let records = endpoint(base, &reg.records).map_err(|e| e.to_string())?;
        let mut resp = http
            .post(&records)
            .json(&json!({ "record": b64(record) }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > REPLY_MAX {
                return Err("a reply longer than any answer".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    }

    async fn pause(&self) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Whether `base`'s host refuses a connection to its port: nothing listens
/// there.
async fn refuses(base: &Url) -> bool {
    let (Some(host), Some(port)) = (base.host_str(), base.port_or_known_default()) else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let connect = tokio::net::TcpStream::connect((host, port));
    matches!(
        tokio::time::timeout(Duration::from_secs(5), connect).await,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused
    )
}

/// A registrar's reply to a device epoch.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// Where the identity stands there: the current record's `epoch` and
    /// hash. Unsigned, so it is believed only as far as a list bears out.
    At {
        epoch: u64,
        hash: [u8; 32],
    },
    /// No reply, or a failure on the registrar's side.
    Lost,
    Refused(Refusal),
}

/// Why a registrar is not done, as the app is told it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    why: NotYet,
    code: Option<String>,
    retry_after: Option<u64>,
}

impl Refusal {
    fn because(why: NotYet) -> Refusal {
        Refusal {
            why,
            code: None,
            retry_after: None,
        }
    }
}

/// Why a list could not be read: a wait it asked for kept, held to a day.
fn unread(e: CoreError) -> Refusal {
    match e {
        CoreError::RateLimited { retry_after } => Refusal {
            why: NotYet::Refused,
            code: Some("rate_limited".into()),
            retry_after: retry_after.map(|s| s.min(RETRY_MOST)),
        },
        CoreError::Refused { code, .. } => Refusal {
            code: code_of(&code),
            ..Refusal::because(NotYet::Refused)
        },
        CoreError::Protocol { .. } => Refusal::because(NotYet::Malformed),
        _ => Refusal::because(NotYet::Unreachable),
    }
}

/// A registrar's `code`, if it is one: never words of its own, which the
/// app would show as this core's.
fn code_of(code: &str) -> Option<String> {
    let is_code =
        (1..=32).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    is_code.then(|| code.to_owned())
}

fn answer(reply: Result<(u16, Value), String>) -> Answer {
    let (status, body) = match reply {
        Ok(r) => r,
        Err(_) => return Answer::Lost,
    };
    if status == 200 {
        let hash = body["hash"]
            .as_str()
            .and_then(|h| unb64(h)?.try_into().ok());
        return match (body["epoch"].as_u64(), hash) {
            (Some(epoch), Some(hash)) => Answer::At { epoch, hash },
            _ => Answer::Refused(Refusal::because(NotYet::Unsupported)),
        };
    }
    if status >= 500 {
        return Answer::Lost;
    }
    Answer::Refused(Refusal {
        why: NotYet::Refused,
        code: body["error"].as_str().and_then(code_of),
        retry_after: body["retry_after"].as_u64().map(|s| s.min(RETRY_MOST)),
    })
}

/// What bringing one registrar to a target came to.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// It answered at the target with a record this reset posted, which
    /// its list must bear out before it is done.
    Answered,
    /// Every reply was lost, so a post may have landed: its list says.
    Lost,
    NotDone(Refusal),
    /// It answered above what was posted, or at it with a record this
    /// reset did not post: another holder's reset, if its list bears it
    /// out.
    Claimed(u64),
    /// Not posted to again, as another registrar claimed the target.
    Stopped,
}

/// Bring a registrar whose current record is `cur` to `target`, `cur +
/// 16` at a time, each post signed afresh at the later of now and the
/// registrar's current record's `time`, its hash kept in `posted` before
/// it is sent. A claim at or past the target sets `stop`, and a drive
/// that finds it set posts nothing more: the target is stale everywhere,
/// and the other registrars' daily resets are not spent on it.
async fn drive<D: Desk>(
    target: u64,
    mut cur: Current,
    id: &IdentityKey,
    posted: &Mutex<Vec<(u64, [u8; 32])>>,
    stop: &AtomicBool,
    desk: &mut D,
) -> Result<Step, CoreError> {
    let mut lost = 0;
    for _ in 0..POSTS_MAX {
        if stop.load(Ordering::SeqCst) {
            return Ok(Step::Stopped);
        }
        if cur.time > now().saturating_add(SKEW) {
            return Ok(Step::NotDone(Refusal::because(NotYet::DatedAhead)));
        }
        let epoch = target.min(cur.epoch.saturating_add(STEP_MAX));
        let time = now().max(cur.time);
        let bytes = sign_epoch(id, epoch, time)?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        {
            let mut mine = posted.lock().unwrap_or_else(|e| e.into_inner());
            if !mine.contains(&(epoch, hash)) {
                mine.push((epoch, hash));
            }
        }
        match answer(desk.post(&bytes).await) {
            Answer::At { epoch: e, hash: h } => {
                lost = 0;
                if e < epoch {
                    return Ok(Step::NotDone(Refusal::because(NotYet::Unconfirmed)));
                }
                if e > epoch || !mine(posted, &h) {
                    if e >= target {
                        stop.store(true, Ordering::SeqCst);
                    }
                    return Ok(Step::Claimed(e));
                }
                if e == target {
                    return Ok(Step::Answered);
                }
                cur = Current {
                    epoch: e,
                    time,
                    hash: Some(h),
                };
            }
            Answer::Lost => {
                lost += 1;
                if lost >= TRIES {
                    return Ok(Step::Lost);
                }
                desk.pause().await;
            }
            Answer::Refused(r) => return Ok(Step::NotDone(r)),
        }
    }
    Ok(Step::NotDone(Refusal::because(NotYet::TooFarBehind)))
}

fn sign_epoch(id: &IdentityKey, epoch: u64, time: u64) -> Result<Vec<u8>, CoreError> {
    DeviceEpoch {
        identity: id.public(),
        epoch,
        time,
    }
    .sign(id)
    .map_err(|e| protocol(&format!("the device epoch does not sign: {e}")))
}

/// Whether this reset posted the record whose hash is `hash`.
fn mine(posted: &Mutex<Vec<(u64, [u8; 32])>>, hash: &[u8; 32]) -> bool {
    posted
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(_, h)| h == hash)
}

// --- A reset at every registrar ---------------------------------------------

enum State {
    Open,
    /// Answered at the target; to be read again.
    Answered,
    /// Its replies lost; to be read again.
    Lost,
    Done,
    Out(Refusal),
    NotARegistrar,
}

struct Slot<'a, D> {
    target: String,
    desk: &'a mut D,
    state: State,
    cur: Current,
    /// What it answered in the last round that its list must bear out.
    claim: Option<u64>,
    /// Discovered, so its list counts.
    trusted: bool,
}

/// The floor a reset keeps, shared with the reads that raise it as they
/// land.
pub(crate) trait Kept {
    /// Raise it to at least `epoch`.
    fn raise(&self, epoch: u64);
    /// A target past it and `known`, kept as it in the same step.
    fn next(&self, known: u64) -> Result<u64, CoreError>;
}

/// The process's floor for an identity, which every mint signs under.
struct Floors(PublicKey);

impl Kept for Floors {
    fn raise(&self, epoch: u64) {
        at_floor(&self.0, epoch, |_| ());
    }

    fn next(&self, known: u64) -> Result<u64, CoreError> {
        next_floor(&self.0, known).ok_or_else(|| refused("no_epoch_left"))
    }
}

/// What a reset came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) target: u64,
    pub(crate) published: u64,
    pub(crate) done: Vec<String>,
    pub(crate) not_done: Vec<NotYetReset>,
    pub(crate) not_registrars: Vec<String>,
    /// The registrars in `not_done` that may yet take the target, each
    /// with the last of its list read.
    pub(crate) behind: Vec<(String, Current)>,
    /// The hashes of the records this reset posted at `target`.
    pub(crate) posted: Vec<[u8; 32]>,
}

/// Reset at every one of `desks`, from `floor`. `kept` keeps a floor
/// learned: from the lists as they are read, and the target before
/// anything is posted for it, chosen past what it keeps then. With no
/// list read there is no reset, and nothing raised. A registrar is done
/// only once a read of its list shows the target with a record this
/// reset posted: answers are not signed.
pub(crate) async fn reset_all<D: Desk>(
    id: &IdentityKey,
    floor: u64,
    desks: Vec<(String, &mut D)>,
    kept: &impl Kept,
) -> Result<Report, CoreError> {
    let mut desks = desks;
    let found = join_all(desks.iter_mut().map(|(_, desk)| async move {
        tokio::time::timeout(WAIT, desk.discover())
            .await
            .unwrap_or_else(|_| Err(Unfound::Not(Refusal::because(NotYet::Unreachable))))
    }))
    .await;
    let mut slots: Vec<Slot<D>> = Vec::new();
    for ((target, desk), found) in desks.into_iter().zip(found) {
        let state = match found {
            Ok(()) => State::Open,
            Err(Unfound::NotARegistrar) => State::NotARegistrar,
            Err(Unfound::Not(r)) => State::Out(r),
        };
        slots.push(Slot {
            target,
            desk,
            trusted: matches!(state, State::Open),
            state,
            cur: Current::default(),
            claim: None,
        });
    }
    let posted = Mutex::new(Vec::new());
    let ours = |c: &Current, posted: &Mutex<Vec<(u64, [u8; 32])>>| {
        c.hash.is_some_and(|h| mine(posted, &h))
    };
    let mut known = floor;
    let mut target = 0;
    // The target last posted, which a re-target in the last round passed.
    let mut posted_at = None;
    let mut published = 0;
    // The target posted was found stale and not posted past.
    let mut passed = false;
    for round in 0..ROUNDS {
        let mut read = Vec::new();
        let lists = join_all(slots.iter_mut().map(|s| async move {
            match s.state {
                State::Out(_) | State::NotARegistrar => None,
                _ => Some(read_in_time(&mut *s.desk, kept).await),
            }
        }))
        .await;
        for (i, (s, list)) in slots.iter_mut().zip(lists).enumerate() {
            match list {
                None => {}
                Some(Ok(c)) => {
                    s.cur = c;
                    read.push(i);
                }
                Some(Err(r)) => s.state = State::Out(r),
            }
        }
        if round == 0 && read.is_empty() {
            let why: Vec<String> = slots
                .iter()
                .filter_map(|s| match &s.state {
                    State::Out(r) => Some(format!("{}: {:?}", s.target, r.why)),
                    State::NotARegistrar => Some(format!("{}: not a registrar", s.target)),
                    _ => None,
                })
                .collect();
            return Err(CoreError::Refused {
                code: "no_registrar_reached".into(),
                detail: why.join("; "),
                successor: None,
            });
        }
        let listed = read.iter().map(|&i| slots[i].cur.epoch).max().unwrap_or(0);
        known = known.max(listed);
        published = published.max(listed);
        kept.raise(known);

        // An answer is not signed: one its list does not bear out is
        // reported, and not chased.
        for s in &mut slots {
            let landed = s.cur.epoch == target && ours(&s.cur, &posted);
            match (&s.state, landed) {
                (State::Open | State::Answered | State::Lost, true) => s.state = State::Done,
                (State::Lost, false) => s.state = State::Out(Refusal::because(NotYet::Unreachable)),
                // Read again and no longer there, as after a restore.
                (State::Done, false) => s.state = State::Open,
                _ => {}
            }
            let claim = match (s.claim.take(), &s.state) {
                (Some(claim), State::Open) => claim,
                (_, State::Answered) => target,
                _ => continue,
            };
            s.state = match s.cur.epoch < claim {
                true => State::Out(Refusal::because(NotYet::Unconfirmed)),
                false => State::Open,
            };
        }
        // Another holder at or past the target leaves the devices it
        // minted there signed in, so the reset goes past it everywhere.
        let stale = round == 0
            || read.iter().any(|&i| {
                let c = &slots[i].cur;
                c.epoch > target || (c.epoch == target && !ours(c, &posted))
            });
        // The last round only reads: past its target, it keeps the floor
        // it read and reserves no target it would not post.
        let last = round + 1 == ROUNDS;
        passed |= stale && posted_at.is_some();
        if stale {
            if !last {
                target = kept.next(known)?;
                known = target;
            }
            for s in &mut slots {
                if matches!(s.state, State::Done) {
                    s.state = State::Open;
                }
            }
        }
        // So every answer is read back.
        if last || !slots.iter().any(|s| matches!(s.state, State::Open)) {
            break;
        }
        posted_at = Some(target);
        passed = false;
        // Side by side, so the round's posts take one wait however many
        // registrars stall.
        let stop = AtomicBool::new(false);
        let steps = join_all(slots.iter_mut().map(|s| {
            let open = matches!(s.state, State::Open);
            let driven = drive(target, s.cur, id, &posted, &stop, &mut *s.desk);
            async move {
                if !open {
                    return None;
                }
                // Given up on, a post may have landed: its list says.
                Some(
                    tokio::time::timeout(WAIT, driven)
                        .await
                        .unwrap_or(Ok(Step::Lost)),
                )
            }
        }))
        .await;
        for (s, step) in slots.iter_mut().zip(steps) {
            match step.transpose()? {
                Some(Step::Answered) => s.state = State::Answered,
                Some(Step::Lost) => s.state = State::Lost,
                Some(Step::NotDone(r)) => s.state = State::Out(r),
                Some(Step::Claimed(e)) => s.claim = Some(e),
                Some(Step::Stopped) | None => {}
            }
        }
    }
    // What a registrar given up on published before it was is read once
    // more, so the floor it shows counts, and its list may show this
    // reset's record after all.
    let lists = join_all(slots.iter_mut().map(|s| async move {
        match s.trusted && matches!(s.state, State::Out(_)) {
            true => read_in_time(&mut *s.desk, kept).await.ok(),
            false => None,
        }
    }))
    .await;
    // A list past the target, or at it with another's record, leaves the
    // target signing out nothing, here as in a round.
    passed |= lists
        .iter()
        .flatten()
        .any(|c| posted_at.is_some_and(|t| c.epoch > t || (c.epoch == t && !ours(c, &posted))));
    for (s, c) in slots.iter_mut().zip(lists) {
        if let Some(c) = c {
            // What a retry signs after is the newest record seen there.
            s.cur = c;
            published = published.max(c.epoch);
            if posted_at == Some(c.epoch) && ours(&c, &posted) {
                s.state = State::Done;
            }
        }
        if passed && matches!(s.state, State::Done) {
            s.state = State::Open;
        }
    }
    kept.raise(published);
    let target = posted_at.unwrap_or(target);
    let posted = posted.into_inner().unwrap_or_else(|e| e.into_inner());
    let mut report = Report {
        target,
        published,
        done: Vec::new(),
        not_done: Vec::new(),
        not_registrars: Vec::new(),
        behind: Vec::new(),
        posted: posted
            .into_iter()
            .filter_map(|(e, h)| (e == target).then_some(h))
            .take(POSTED_MAX)
            .collect(),
    };
    for s in slots {
        let r = match s.state {
            State::Done => {
                report.done.push(s.target);
                continue;
            }
            State::NotARegistrar => {
                report.not_registrars.push(s.target);
                continue;
            }
            State::Out(r) => r,
            State::Lost => Refusal::because(NotYet::Unreachable),
            State::Open | State::Answered => Refusal::because(NotYet::Overtaken),
        };
        // Past a target another holder passed, there is nothing to finish.
        if !passed && waits(&r) {
            report.behind.push((s.target.clone(), s.cur));
        }
        report.not_done.push(NotYetReset {
            registrar: s.target,
            why: r.why,
            code: r.code,
            retry_after: r.retry_after,
        });
    }
    Ok(report)
}

/// `desk`'s list, or why not, in [`WAIT`], its floor kept as it lands so
/// a mint meanwhile signs at it.
async fn read_in_time<D: Desk>(desk: &mut D, kept: &impl Kept) -> Result<Current, Refusal> {
    let read = tokio::time::timeout(WAIT, desk.read())
        .await
        .unwrap_or(Err(Refusal::because(NotYet::Unreachable)))?;
    kept.raise(read.epoch);
    Ok(read)
}

// --- A reset finished later -------------------------------------------------

/// Whether a registrar not done may take the reset later: one that could
/// not be reached or read, did not bear out what it answered, or asked to
/// be left a while, said for how long or not.
fn waits(r: &Refusal) -> bool {
    match r.why {
        NotYet::Unreachable
        | NotYet::ConnectionRefused
        | NotYet::Unconfirmed
        | NotYet::Malformed => true,
        NotYet::Refused => r.retry_after.is_some() || r.code.as_deref() == Some("rate_limited"),
        _ => false,
    }
}

/// A device epoch record as signed, kept to be posted later.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Signed {
    epoch: u64,
    time: u64,
    bytes: Vec<u8>,
}

/// A registrar a reset is not done at, and the records that bring it to
/// the reset's epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Chain {
    registrar: String,
    /// As [`Remote::kept`].
    kept: bool,
    /// Ascending, each at most a step past the one before, the last at the
    /// reset's epoch.
    records: Vec<Signed>,
    /// When it is next asked, in seconds.
    due: u64,
    /// The times a retry has asked it and it was not done.
    tries: u32,
}

/// What a reset keeps for the registrars it was not done at.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Retry {
    /// The reset's epoch, where every chain ends.
    epoch: u64,
    /// The hashes of the records the reset posted at `epoch`, which a list
    /// may show where the reply was lost.
    posted: Vec<[u8; 32]>,
    /// No two for one origin.
    chains: Vec<Chain>,
}

impl Retry {
    /// Whether `cur` puts a registrar whose chain is `chain` at or past the
    /// reset: past it, or at it with this reset's record. At it with
    /// another's, that holder's devices minted there are not signed out,
    /// as [`reset_all`] decides too.
    fn done(&self, chain: &Chain, cur: &Current) -> bool {
        let ours = |h: &[u8; 32]| {
            self.posted.contains(h)
                || chain
                    .records
                    .last()
                    .is_some_and(|r| <[u8; 32]>::from(Sha256::digest(&r.bytes)) == *h)
        };
        cur.epoch > self.epoch || (cur.epoch == self.epoch && cur.hash.as_ref().is_some_and(ours))
    }
}

/// The records from a registrar whose list showed `cur` up to `target`,
/// counted down from `target` a step at a time so that the first past
/// whatever it shows later is a step past it, as many as a reset would
/// post it, and the record at `target` always, so a registrar already
/// there that is still to confirm it keeps a chain. Dated as a reset's
/// own posts are, so it does not refuse them as dated before its last.
fn chain_to(id: &IdentityKey, target: u64, cur: &Current) -> Result<Vec<Signed>, CoreError> {
    let time = now().max(cur.time);
    let mut records = (0..CHAIN_MAX as u64)
        .map_while(|k| {
            target
                .checked_sub(k * STEP_MAX)
                .filter(|e| k == 0 || *e > cur.epoch)
        })
        .map(|epoch| {
            let bytes = sign_epoch(id, epoch, time)?;
            Ok(Signed { epoch, time, bytes })
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    records.reverse();
    Ok(records)
}

/// What `report` leaves at `at` for a retry, `kept` saying which
/// registrars the app keeps, each due once any wait it asked for is up.
/// Left to a new reset: a registrar whose last record is dated past the
/// skew, which a chain would be dated as, one further behind than a chain
/// reaches, and any past [`CHAINS_MAX`].
fn lagging(
    id: &IdentityKey,
    report: &Report,
    kept: impl Fn(&str) -> bool,
    at: u64,
) -> Result<Retry, CoreError> {
    let reaches = |cur: &Current| {
        cur.time <= now().saturating_add(SKEW)
            && report.target.saturating_sub(cur.epoch) <= CHAIN_MAX as u64 * STEP_MAX
    };
    let wait = |registrar: &str| {
        let n = report.not_done.iter().find(|n| n.registrar == registrar);
        wait_of(n.and_then(|n| n.retry_after))
    };
    let chains = report
        .behind
        .iter()
        .filter(|(_, cur)| reaches(cur))
        .take(CHAINS_MAX)
        .map(|(registrar, cur)| {
            Ok(Chain {
                registrar: registrar.clone(),
                kept: kept(registrar),
                records: chain_to(id, report.target, cur)?,
                // The backoff's first wait, as every later retry's, or longer where it asked.
                due: at.saturating_add(wait(registrar).max(RETRY_EVERY)),
                tries: 0,
            })
        })
        .collect::<Result<_, CoreError>>()?;
    Ok(Retry {
        epoch: report.target,
        posted: report.posted.clone(),
        chains,
    })
}

/// The bytes the app keeps of `retry`: None with no chain.
fn encode(retry: &Retry) -> Option<Vec<u8>> {
    if retry.chains.is_empty() {
        return None;
    }
    let at: Vec<Value> = retry
        .chains
        .iter()
        .map(|c| {
            let records: Vec<String> = c.records.iter().map(|r| b64(&r.bytes)).collect();
            json!({
                "registrar": c.registrar,
                "kept": c.kept,
                "records": records,
                "due": c.due,
                "tries": c.tries,
            })
        })
        .collect();
    let posted: Vec<String> = retry.posted.iter().map(|h| b64(h)).collect();
    Some(
        json!({ "v": 2, "posted": posted, "at": at })
            .to_string()
            .into_bytes(),
    )
}

/// What `bytes` hold, every record `identity`'s own: refused `bad_retry`
/// where they do not read as [`encode`] writes them, and `wrong_identity`
/// where a record is another's.
fn decode(bytes: &[u8], identity: &PublicKey) -> Result<Retry, CoreError> {
    let bad = || refused("bad_retry");
    if bytes.len() > RETRY_MAX {
        return Err(bad());
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
    // One a version before kept no tries, and has made none that count.
    let tries = |c: &Value| match v["v"].as_u64() {
        Some(1) => Some(0),
        Some(2) => c["tries"].as_u64().and_then(|t| u32::try_from(t).ok()),
        _ => None,
    };
    if !matches!(v["v"].as_u64(), Some(1 | 2)) {
        return Err(bad());
    }
    let posted = v["posted"]
        .as_array()
        .filter(|p| p.len() <= POSTED_MAX)
        .ok_or_else(bad)?
        .iter()
        .map(|h| h.as_str().and_then(unb64)?.try_into().ok())
        .collect::<Option<Vec<[u8; 32]>>>()
        .ok_or_else(bad)?;
    let at = v["at"]
        .as_array()
        .filter(|a| (1..=CHAINS_MAX).contains(&a.len()))
        .ok_or_else(bad)?;
    let chains = at
        .iter()
        .map(|c| {
            let raw = c["records"]
                .as_array()
                .filter(|r| (1..=CHAIN_MAX).contains(&r.len()))
                .ok_or_else(bad)?;
            let mut records: Vec<Signed> = Vec::new();
            for r in raw {
                let bytes = r.as_str().and_then(unb64).ok_or_else(bad)?;
                let e = DeviceEpoch::parse(&bytes).map_err(|_| bad())?;
                if e.identity != *identity {
                    return Err(refused("wrong_identity"));
                }
                let follows = records
                    .last()
                    .is_none_or(|p| e.epoch > p.epoch && e.epoch - p.epoch <= STEP_MAX);
                if !follows {
                    return Err(bad());
                }
                records.push(Signed {
                    epoch: e.epoch,
                    time: e.time,
                    bytes,
                });
            }
            Ok(Chain {
                registrar: c["registrar"].as_str().ok_or_else(bad)?.to_owned(),
                kept: c["kept"].as_bool().ok_or_else(bad)?,
                records,
                due: c["due"].as_u64().ok_or_else(bad)?,
                tries: tries(c).ok_or_else(bad)?,
            })
        })
        .collect::<Result<Vec<Chain>, CoreError>>()?;
    let epoch = chains[0].records.last().map_or(0, |r| r.epoch);
    let origin = |r: &str| {
        registrar_base(r).map_or_else(|_| r.to_owned(), |b| b.origin().ascii_serialization())
    };
    let origins: BTreeSet<String> = chains.iter().map(|c| origin(&c.registrar)).collect();
    let one_epoch = chains
        .iter()
        .all(|c| c.records.last().is_some_and(|r| r.epoch == epoch));
    if !one_epoch || origins.len() != chains.len() {
        return Err(bad());
    }
    Ok(Retry {
        epoch,
        posted,
        chains,
    })
}

/// How long a registrar must be left before it is asked again: what it
/// asked for, and nothing where it did not say.
fn wait_of(retry_after: Option<u64>) -> u64 {
    retry_after.map_or(0, |s| s.max(RETRY_LEAST))
}

/// How long a registrar not done after `tries` tries is left at least.
fn backoff(tries: u32) -> u64 {
    let doublings = tries.saturating_sub(1).min(16);
    RETRY_EVERY.saturating_mul(1 << doublings).min(BACKOFF_MOST)
}

/// Whether `chain`, not done at `at`, has been tried enough and for long
/// enough since its reset was signed to be let go of.
fn given_up(chain: &Chain, at: u64) -> bool {
    let since = chain.records.last().map_or(0, |r| r.time);
    chain.tries >= TRIES_LEAST && at >= since.saturating_add(RETRY_FOR)
}

/// Seconds from `at` until the next retry is worth making: when the first
/// of `chains` is due, a while for one due already.
fn retry_in(chains: &[Chain], at: u64) -> Option<u64> {
    chains
        .iter()
        .map(|c| match c.due > at {
            true => c.due - at,
            false => RETRY_EVERY,
        })
        .min()
}

/// Whether `chain` is to be asked at `at`: its time has come, or the
/// clock has been set back past any wait it was given.
fn is_due(chain: &Chain, at: u64) -> bool {
    chain.due <= at || chain.due > at.saturating_add(RETRY_MOST)
}

/// Posts what a reset of the identity whose card is `card` kept in
/// `retry` for the registrars it was not done at, without the identity
/// key: done at one whose list shows the reset's epoch with a record it
/// signed, or past it, and posted nothing a list shows already. Only the
/// registrars due are asked, and reported; the rest are handed back as
/// they were. A registrar that refuses for good is left out of the
/// `retry` handed back, and is reached by a new reset alone. Refused
/// `bad_retry` for bytes a reset did not hand back, `wrong_identity` for
/// another identity's, and `busy` while a reset of
/// the identity is under way.
#[uniffi::export(async_runtime = "tokio")]
pub async fn retry_reset(retry: Vec<u8>, card: Vec<u8>) -> Result<ResetRetried, CoreError> {
    crate::connection::RUNTIME
        .spawn(retrying(retry, card, 0))
        .await
        .unwrap_or_else(|_| Err(protocol("the retry stopped")))
}

/// As [`retry_reset`], by a clock `ahead` seconds on: a live test's retry
/// once a wait is up, without waiting for it.
#[cfg(feature = "live-tests")]
pub async fn retry_reset_ahead(
    retry: Vec<u8>,
    card: Vec<u8>,
    ahead: u64,
) -> Result<ResetRetried, CoreError> {
    crate::connection::RUNTIME
        .spawn(retrying(retry, card, ahead))
        .await
        .unwrap_or_else(|_| Err(protocol("the retry stopped")))
}

async fn retrying(retry: Vec<u8>, card: Vec<u8>, ahead: u64) -> Result<ResetRetried, CoreError> {
    let identity = Card::parse(&card)
        .map_err(|_| refused("wrong_identity"))?
        .identity;
    let mut retry = decode(&retry, &identity)?;
    let _resetting = Resetting::take(&identity)?;
    let chains = std::mem::take(&mut retry.chains);
    let mut remotes: Vec<Remote> = chains
        .iter()
        .map(|c| Remote {
            target: c.registrar.clone(),
            identity,
            kept: c.kept,
            reg: None,
        })
        .collect();
    let desks = chains.into_iter().zip(remotes.iter_mut()).collect();
    let clock = move || now().saturating_add(ahead);
    Ok(retry_all(retry, desks, &Floors(identity), clock).await)
}

/// What a retry came to at one registrar.
enum Caught {
    Done,
    NotARegistrar,
    NotDone(Refusal),
}

/// Bring every one of `desks` due by `clock` to `retry`'s epoch, side by
/// side: `retry` with its chains taken out, each beside its desk. A wait
/// is counted from when the asking is done, which can be long after it
/// began.
async fn retry_all<D: Desk>(
    retry: Retry,
    desks: Vec<(Chain, &mut D)>,
    kept: &impl Kept,
    clock: impl Fn() -> u64,
) -> ResetRetried {
    let at = clock();
    let (desks, waiting): (Vec<_>, Vec<_>) = desks.into_iter().partition(|(c, _)| is_due(c, at));
    let mut left: Vec<Chain> = waiting.into_iter().map(|(c, _)| c).collect();
    let caught = join_all(desks.into_iter().map(|(chain, desk)| {
        let retry = &retry;
        async move {
            let got = catch_up(retry, &chain, desk, kept).await;
            (chain, got)
        }
    }))
    .await;
    let at = clock();
    let mut out = ResetRetried {
        epoch: retry.epoch,
        published: 0,
        done: Vec::new(),
        not_done: Vec::new(),
        not_registrars: Vec::new(),
        retry: None,
        retry_in: None,
        later: Vec::new(),
    };
    for (mut chain, (listed, caught)) in caught {
        out.published = out.published.max(listed);
        match caught {
            Caught::Done => out.done.push(chain.registrar),
            Caught::NotARegistrar => out.not_registrars.push(chain.registrar),
            Caught::NotDone(r) => {
                chain.tries = chain.tries.saturating_add(1);
                let gave_up = waits(&r) && given_up(&chain, at);
                out.not_done.push(NotYetReset {
                    registrar: chain.registrar.clone(),
                    why: if gave_up { NotYet::GaveUp } else { r.why },
                    code: r.code.clone(),
                    retry_after: r.retry_after,
                });
                if waits(&r) && !gave_up {
                    let wait = wait_of(r.retry_after).max(backoff(chain.tries));
                    chain.due = at.saturating_add(wait);
                    left.push(chain);
                }
            }
        }
    }
    out.retry_in = retry_in(&left, at);
    out.later = left.iter().map(|c| c.registrar.clone()).collect();
    out.retry = encode(&Retry {
        chains: left,
        ..retry
    });
    out
}

/// One registrar brought to `retry`'s epoch by `chain`: the highest epoch
/// its list showed, and how it came out, done as [`Retry::done`] says.
async fn catch_up<D: Desk>(
    retry: &Retry,
    chain: &Chain,
    desk: &mut D,
    kept: &impl Kept,
) -> (u64, Caught) {
    let found = tokio::time::timeout(WAIT, desk.discover())
        .await
        .unwrap_or_else(|_| Err(Unfound::Not(Refusal::because(NotYet::Unreachable))));
    match found {
        Ok(()) => {}
        Err(Unfound::NotARegistrar) => return (0, Caught::NotARegistrar),
        Err(Unfound::Not(r)) => return (0, Caught::NotDone(r)),
    }
    let cur = match read_in_time(desk, kept).await {
        Ok(cur) => cur,
        Err(r) => return (0, Caught::NotDone(r)),
    };
    if let Some(caught) = settled(retry, chain, &cur) {
        return (cur.epoch, caught);
    }
    let why = tokio::time::timeout(WAIT, post_past(&chain.records, cur, desk))
        .await
        .unwrap_or(Refusal::because(NotYet::Unreachable));
    // Replies are not signed, and one lost may have landed: its list says.
    match read_in_time(desk, kept).await {
        Ok(c) => match settled(retry, chain, &c) {
            Some(caught) => (c.epoch, caught),
            None => (c.epoch.max(cur.epoch), Caught::NotDone(why)),
        },
        // What the posts came to stands where it is final; otherwise the
        // one of the two asking to be left longer.
        Err(r) => match waits(&why) && r.retry_after > why.retry_after {
            true => (cur.epoch, Caught::NotDone(r)),
            false => (cur.epoch, Caught::NotDone(why)),
        },
    }
}

/// How a list showing `cur` leaves a registrar, where nothing posted could
/// change it: done, or at the epoch with another holder's record.
fn settled(retry: &Retry, chain: &Chain, cur: &Current) -> Option<Caught> {
    if retry.done(chain, cur) {
        Some(Caught::Done)
    } else if cur.epoch >= retry.epoch {
        Some(Caught::NotDone(Refusal::because(NotYet::Overtaken)))
    } else {
        None
    }
}

/// Post `desk` the records past `cur`, its list as read, in order, until
/// one is answered at the last or one is not taken: why it stopped, for
/// where its list does not show the last.
async fn post_past<D: Desk>(records: &[Signed], cur: Current, desk: &mut D) -> Refusal {
    let target = records.last().map_or(0, |r| r.epoch);
    let mut at = cur.epoch;
    for r in records {
        // Below what its list shows, it is not posted at all.
        if r.epoch <= at {
            continue;
        }
        if r.epoch - at > STEP_MAX {
            return Refusal::because(NotYet::TooFarBehind);
        }
        if r.time < cur.time {
            return Refusal::because(NotYet::DatedBefore);
        }
        let mut lost = 0;
        loop {
            match answer(desk.post(&r.bytes).await) {
                Answer::At { epoch, .. } if epoch >= target => {
                    return Refusal::because(NotYet::Unconfirmed)
                }
                Answer::At { epoch, .. } if epoch >= r.epoch => {
                    at = epoch;
                    break;
                }
                Answer::At { .. } => return Refusal::because(NotYet::Unconfirmed),
                Answer::Lost => {
                    lost += 1;
                    if lost >= TRIES {
                        return Refusal::because(NotYet::Unreachable);
                    }
                    desk.pause().await;
                }
                Answer::Refused(refusal) => return refusal,
            }
        }
    }
    Refusal::because(NotYet::Unconfirmed)
}

fn protocol(detail: &str) -> CoreError {
    CoreError::Protocol {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registrar deciding device epochs as section 6.2 does, with what
    /// can go wrong between it and a holder.
    #[derive(Default)]
    struct Sim {
        unreachable: bool,
        not_a_registrar: bool,
        /// Published, in order: epoch, time, hash.
        held: Vec<(u64, u64, [u8; 32])>,
        /// Posts whose reply is lost after they land.
        lose: usize,
        /// Published just before the next post lands, as another
        /// holder's would be.
        race: Option<Vec<u8>>,
        /// Publishes nothing, and answers this.
        lie: Option<u64>,
        /// Publications it takes before it answers `rate_limited`.
        allowance: Option<usize>,
        /// Publishes nothing, and answers each post as if it had.
        pretend: bool,
        /// Publishes nothing, and answers one below each post, naming it.
        below: bool,
        /// Answers `not_registered`.
        unregistered: bool,
        /// Loses every post before it lands.
        drop_posts: bool,
        /// Reads that fail before one succeeds.
        unread: usize,
        /// The read, counted from 1, that fails.
        fail_read: Option<usize>,
        /// Published just before each of the next posts lands, in turn.
        races: Vec<Vec<u8>>,
        /// Drops its latest record at this read, as a restore would.
        rollback_at: Option<usize>,
        /// Holds this record from this read on, as another holder's
        /// landing meanwhile would.
        held_at: Option<(usize, Vec<u8>)>,
        /// The identity whose floor a mint reads as each post arrives,
        /// and what it read.
        minting: Option<PublicKey>,
        minted_at: Vec<u64>,
        /// Never answers a read, or a post.
        silent_reads: bool,
        /// Each read answered after this long.
        slow_reads: Option<Duration>,
        /// Each read refused as a 429 asking for this wait, after the
        /// first `limited_after`.
        limited_reads: Option<u64>,
        limited_after: usize,
        silent_posts: bool,
        /// Posts answered 503 before one lands.
        failing: usize,
        reads: usize,
        posts: usize,
    }

    impl Sim {
        fn epochs(&self) -> Vec<u64> {
            self.held.iter().map(|(e, _, _)| *e).collect()
        }

        fn cur(&self) -> (u64, u64, [u8; 32]) {
            self.held.last().copied().unwrap_or((0, 0, [0; 32]))
        }

        fn land(&mut self, bytes: &[u8]) -> Result<(), (u16, Value)> {
            let r = DeviceEpoch::parse(bytes).unwrap();
            let (cur, cur_time, _) = self.cur();
            if r.epoch <= cur {
                return Ok(());
            }
            assert!(r.epoch <= cur + STEP_MAX, "past the step bound");
            assert!(r.time >= cur_time, "dated before the last one");
            if self.allowance == Some(0) {
                return Err((
                    429,
                    json!({ "error": "rate_limited", "text": "too many requests; try again later",
                            "retry_after": 3600 }),
                ));
            }
            if let Some(n) = &mut self.allowance {
                *n -= 1;
            }
            self.held
                .push((r.epoch, r.time, Sha256::digest(bytes).into()));
            Ok(())
        }
    }

    impl Desk for Sim {
        async fn discover(&mut self) -> Result<(), Unfound> {
            match (self.unreachable, self.not_a_registrar) {
                (true, _) => Err(Unfound::Not(Refusal::because(NotYet::Unreachable))),
                (_, true) => Err(Unfound::NotARegistrar),
                _ => Ok(()),
            }
        }

        async fn read(&mut self) -> Result<Current, Refusal> {
            if self.silent_reads {
                std::future::pending::<()>().await;
            }
            if let Some(after) = self.slow_reads {
                tokio::time::sleep(after).await;
            }
            if let Some(retry_after) = self
                .limited_reads
                .filter(|_| self.reads >= self.limited_after)
            {
                return Err(unread(CoreError::RateLimited {
                    retry_after: Some(retry_after),
                }));
            }
            self.reads += 1;
            if self.unread > 0 || self.fail_read == Some(self.reads) {
                self.unread = self.unread.saturating_sub(1);
                return Err(Refusal::because(NotYet::Unreachable));
            }
            if self.rollback_at == Some(self.reads) {
                self.held.pop();
            }
            if let Some((_, bytes)) = self.held_at.take_if(|(n, _)| *n == self.reads) {
                let r = DeviceEpoch::parse(&bytes).unwrap();
                self.held
                    .push((r.epoch, r.time, Sha256::digest(&bytes).into()));
            }
            Ok(self
                .held
                .last()
                .map_or(Current::default(), |&(epoch, time, hash)| Current {
                    epoch,
                    time,
                    hash: Some(hash),
                }))
        }

        async fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String> {
            self.posts += 1;
            if self.silent_posts {
                std::future::pending::<()>().await;
            }
            if self.failing > 0 {
                self.failing -= 1;
                return Ok((
                    503,
                    json!({ "error": "unavailable", "text": "down for now" }),
                ));
            }
            if let Some(identity) = self.minting {
                self.minted_at.push(at_floor(&identity, 0, |f| f));
            }
            if self.drop_posts {
                return Err("connection reset".into());
            }
            if let Some(epoch) = self.lie {
                return Ok((
                    200,
                    json!({ "seq": 1, "epoch": epoch, "hash": b64(&[7; 32]) }),
                ));
            }
            let hash = b64(&Sha256::digest(record));
            let epoch = DeviceEpoch::parse(record).unwrap().epoch;
            if self.pretend {
                return Ok((200, json!({ "seq": 1, "epoch": epoch, "hash": hash })));
            }
            if self.below {
                return Ok((200, json!({ "seq": 1, "epoch": epoch - 1, "hash": hash })));
            }
            if self.unregistered {
                let body = json!({ "error": "not_registered", "text": "not registered here" });
                return Ok((404, body));
            }
            if !self.races.is_empty() {
                let theirs = self.races.remove(0);
                self.land(&theirs).unwrap();
            }
            if let Some(theirs) = self.race.take() {
                self.land(&theirs).unwrap();
            }
            if let Err(refusal) = self.land(record) {
                return Ok(refusal);
            }
            if self.lose > 0 {
                self.lose -= 1;
                return Err("connection reset".into());
            }
            let (epoch, _, hash) = self.cur();
            Ok((
                200,
                json!({ "seq": 1, "published": true, "epoch": epoch, "hash": b64(&hash) }),
            ))
        }
    }

    fn alice() -> IdentityKey {
        IdentityKey::from_seed(&[1; 32])
    }

    /// A kept floor, raised by another reset in the same process just as
    /// this one chooses its target, when `bump` is set.
    struct Mem {
        floor: std::cell::Cell<u64>,
        bump: std::cell::Cell<Option<u64>>,
    }

    impl Mem {
        fn at(floor: u64) -> Mem {
            Mem {
                floor: floor.into(),
                bump: None.into(),
            }
        }
    }

    impl Kept for Mem {
        fn raise(&self, epoch: u64) {
            self.floor.set(self.floor.get().max(epoch));
        }

        fn next(&self, known: u64) -> Result<u64, CoreError> {
            if let Some(b) = self.bump.take() {
                self.raise(b);
            }
            self.floor.set(self.floor.get().max(known) + 1);
            Ok(self.floor.get())
        }
    }

    async fn reset(floor: u64, sims: &mut [&mut Sim]) -> (Result<Report, CoreError>, u64) {
        reset_with(&Mem::at(floor), sims).await
    }

    async fn reset_with(kept: &Mem, sims: &mut [&mut Sim]) -> (Result<Report, CoreError>, u64) {
        let floor = kept.floor.get();
        let desks = sims
            .iter_mut()
            .enumerate()
            .map(|(i, s)| (format!("r{i}"), &mut **s))
            .collect();
        // What this reset posted is new bytes each run; the tests that need
        // it call [`reset_all`] themselves.
        let report = reset_all(&alice(), floor, desks, kept)
            .await
            .map(|r| Report {
                posted: vec![],
                ..r
            });
        (report, kept.floor.get())
    }

    fn signed(epoch: u64, time: u64) -> Vec<u8> {
        DeviceEpoch {
            identity: alice().public(),
            epoch,
            time,
        }
        .sign(&alice())
        .unwrap()
    }

    fn all_done(target: u64, n: usize) -> Report {
        Report {
            target,
            published: target,
            done: (0..n).map(|i| format!("r{i}")).collect(),
            not_done: vec![],
            not_registrars: vec![],
            behind: vec![],
            posted: vec![],
        }
    }

    fn not_done(registrar: &str, why: NotYet, code: Option<&str>) -> NotYetReset {
        NotYetReset {
            registrar: registrar.into(),
            why,
            code: code.map(str::to_owned),
            retry_after: None,
        }
    }

    #[tokio::test]
    async fn a_registrar_far_behind_is_caught_up_sixteen_at_a_time_and_dated_after_its_last() {
        let later = now() + 100;
        let mut behind = Sim::default();
        behind.land(&signed(3, later)).unwrap();
        let mut ahead = Sim::default();
        ahead.held.push((39, 0, [9; 32]));
        let (report, kept) = reset(0, &mut [&mut behind, &mut ahead]).await;
        assert_eq!(report.unwrap(), all_done(40, 2));
        assert_eq!(behind.epochs(), vec![3, 19, 35, 40]);
        assert_eq!(ahead.epochs(), vec![39, 40]);
        assert_eq!(kept, 40);
    }

    #[tokio::test]
    async fn a_lost_reply_is_posted_again_and_known_by_its_hash() {
        let mut sim = Sim {
            lose: 1,
            ..Sim::default()
        };
        let (report, _) = reset(0, &mut [&mut sim]).await;
        assert_eq!(report.unwrap(), all_done(1, 1));
        assert_eq!((sim.epochs(), sim.posts), (vec![1], 2));

        // Every reply lost, the post that landed is found in the list.
        let mut sim = Sim {
            lose: TRIES,
            ..Sim::default()
        };
        let (report, _) = reset(0, &mut [&mut sim]).await;
        assert_eq!(report.unwrap(), all_done(1, 1));
        assert_eq!(sim.posts, TRIES);

        let mut sim = Sim {
            drop_posts: true,
            ..Sim::default()
        };
        let report = reset(0, &mut [&mut sim]).await.0.unwrap();
        assert_eq!(report.done, Vec::<String>::new());
        assert_eq!(
            report.not_done,
            vec![not_done("r0", NotYet::Unreachable, None)]
        );
    }

    #[tokio::test]
    async fn the_target_is_past_a_floor_another_reset_here_kept_meanwhile() {
        let kept = Mem {
            bump: Some(5).into(),
            ..Mem::at(0)
        };
        let mut sim = Sim::default();
        let (report, floor) = reset_with(&kept, &mut [&mut sim]).await;
        assert_eq!(report.unwrap(), all_done(6, 1));
        assert_eq!((sim.epochs(), floor), (vec![6], 6));
    }

    #[tokio::test]
    async fn a_mint_while_a_reset_posts_signs_at_its_target() {
        let id = IdentityKey::generate();
        let mut sim = Sim {
            minting: Some(id.public()),
            ..Sim::default()
        };
        sim.held.push((4, 0, [9; 32]));
        let desks = vec![("r0".to_string(), &mut sim)];
        let report = reset_all(&id, 2, desks, &Floors(id.public()))
            .await
            .unwrap();
        assert_eq!(report.target, 5);
        assert_eq!(sim.minted_at, vec![5]);
        assert_eq!(at_floor(&id.public(), 0, |f| f), 5);
    }

    #[tokio::test]
    async fn what_a_reset_cut_short_published_is_reported() {
        let mut sim = Sim {
            allowance: Some(4),
            ..Sim::default()
        };
        let report = reset(100, &mut [&mut sim]).await.0.unwrap();
        assert_eq!(sim.epochs(), vec![16, 32, 48, 64]);
        assert_eq!((report.target, report.published), (101, 64));
        assert_eq!(report.done, Vec::<String>::new());

        let mut sim = Sim {
            allowance: Some(0),
            ..Sim::default()
        };
        assert_eq!(reset(100, &mut [&mut sim]).await.0.unwrap().published, 0);
    }

    #[tokio::test]
    async fn a_floor_a_registrar_given_up_on_shows_is_kept() {
        let mut ahead = Sim {
            unread: 1,
            ..Sim::default()
        };
        ahead.held.push((50, 0, [9; 32]));
        let mut other = Sim::default();
        let (report, kept) = reset(10, &mut [&mut ahead, &mut other]).await;
        let report = report.unwrap();
        assert_eq!((report.target, report.published), (11, 50));
        assert_eq!(kept, 50);
        // Its floor leaves epoch 11 signing nothing out: done nowhere.
        assert_eq!(report.done, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_registrar_whose_list_shows_this_resets_record_at_the_end_is_done() {
        let mut sim = Sim {
            fail_read: Some(2),
            ..Sim::default()
        };
        let (report, _) = reset(0, &mut [&mut sim]).await;
        assert_eq!(report.unwrap(), all_done(1, 1));
        assert_eq!(sim.posts, 1);
    }

    #[tokio::test]
    async fn the_read_only_round_keeps_the_floor_it_reads_and_reserves_no_target() {
        // Another holder resets `b` to each target just ahead of this one,
        // the last time in the round before the reads alone; `a` is read
        // in that round, or only once it is given up on, and is not done at
        // a target found stale either way, and nothing is kept for `c`,
        // down throughout, to be brought to it.
        let last = ROUNDS as u64 - 1;
        for fail_read in [None, Some(ROUNDS)] {
            let mut a = Sim {
                fail_read,
                ..Sim::default()
            };
            let mut b = Sim {
                races: (1..=last).map(|e| signed(e, now() + 5 + e)).collect(),
                ..Sim::default()
            };
            let mut c = Sim {
                unreachable: true,
                ..Sim::default()
            };
            let (report, kept) = reset(0, &mut [&mut a, &mut b, &mut c]).await;
            let report = report.unwrap();
            assert_eq!((report.target, report.published, kept), (last, last, last));
            assert_eq!(report.done, Vec::<String>::new(), "{fail_read:?}");
            assert_eq!(report.behind, vec![], "{fail_read:?}");
            assert_eq!(b.epochs(), (1..=last).collect::<Vec<_>>());
        }
    }

    #[tokio::test]
    async fn another_holders_record_at_or_past_the_target_is_reset_past_everywhere() {
        for (theirs, b_first) in [(1, false), (5, false), (5, true)] {
            let mut a = Sim::default();
            // Signed a little later than this holder signs, so the bytes
            // are not this holder's own.
            let mut b = Sim {
                race: Some(signed(theirs, now() + 5)),
                ..Sim::default()
            };
            let (report, kept) = match b_first {
                true => reset(0, &mut [&mut b, &mut a]).await,
                false => reset(0, &mut [&mut a, &mut b]).await,
            };
            let target = theirs + 1;
            assert_eq!(report.unwrap(), all_done(target, 2), "theirs at {theirs}");
            // Once `b` shows the target stale, `a` is not posted it.
            let a_at = match b_first {
                true => vec![target],
                false => vec![1, target],
            };
            assert_eq!(a.epochs(), a_at, "b first: {b_first}");
            assert_eq!(b.epochs(), vec![theirs, target]);
            assert_eq!(kept, target);
        }
    }

    #[tokio::test]
    async fn a_registrar_claiming_more_than_its_list_shows_is_reported_and_spends_nothing() {
        let mut liar = Sim {
            lie: Some(1_000_000),
            ..Sim::default()
        };
        let mut honest = Sim::default();
        let (report, kept) = reset(0, &mut [&mut liar, &mut honest]).await;
        assert_eq!(
            report.unwrap(),
            Report {
                target: 1,
                published: 1,
                done: vec!["r1".into()],
                not_done: vec![not_done("r0", NotYet::Unconfirmed, None)],
                not_registrars: vec![],
                behind: vec![("r0".into(), Current::default())],
                posted: vec![],
            }
        );
        assert_eq!((honest.epochs(), honest.posts), (vec![1], 1));
        assert_eq!(liar.posts, 1);
        assert_eq!(kept, 1);
    }

    #[tokio::test]
    async fn a_rate_limited_registrar_is_not_done_and_says_when_to_try_again() {
        let mut limited = Sim {
            allowance: Some(0),
            ..Sim::default()
        };
        let mut other = Sim::default();
        let report = reset(0, &mut [&mut limited, &mut other]).await.0.unwrap();
        assert_eq!(report.done, vec!["r1".to_string()]);
        assert_eq!(
            report.not_done,
            vec![NotYetReset {
                retry_after: Some(3600),
                ..not_done("r0", NotYet::Refused, Some("rate_limited"))
            }],
            "no words of the registrar's own"
        );
    }

    #[tokio::test]
    async fn a_registrar_failing_on_its_side_is_posted_again() {
        let mut sim = Sim {
            failing: TRIES - 1,
            ..Sim::default()
        };
        let (report, _) = reset(0, &mut [&mut sim]).await;
        assert_eq!(report.unwrap(), all_done(1, 1));
        assert_eq!((sim.epochs(), sim.posts), (vec![1], TRIES));
    }

    #[tokio::test]
    async fn a_registrar_whose_last_reset_is_dated_ahead_is_not_signed_after() {
        let mut ahead = Sim::default();
        ahead.land(&signed(2, now() + 10 * SKEW)).unwrap();
        let mut other = Sim::default();
        let report = reset(0, &mut [&mut ahead, &mut other]).await.0.unwrap();
        assert_eq!((report.target, &report.done), (3, &vec!["r1".to_string()]));
        assert_eq!(
            report.not_done,
            vec![not_done("r0", NotYet::DatedAhead, None)]
        );
        assert_eq!(report.behind, vec![], "left to a new reset");
        assert_eq!(ahead.posts, 0);

        // As far ahead as the skew allows is signed after.
        let mut at_skew = Sim::default();
        at_skew.land(&signed(2, now() + SKEW)).unwrap();
        let (report, _) = reset(0, &mut [&mut at_skew]).await;
        assert_eq!(report.unwrap(), all_done(3, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_floor_read_is_kept_as_it_lands_while_others_are_read() {
        let id = IdentityKey::generate();
        let mut quick = Sim::default();
        quick.held.push((7, 0, [9; 32]));
        let mut slow = Sim {
            slow_reads: Some(Duration::from_secs(10)),
            ..Sim::default()
        };
        let desks = vec![
            ("r0".to_string(), &mut quick),
            ("r1".to_string(), &mut slow),
        ];
        let kept = Floors(id.public());
        let looked = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            at_floor(&id.public(), 0, |f| f)
        };
        let (report, mid_read) = tokio::join!(reset_all(&id, 0, desks, &kept), looked);
        assert_eq!(mid_read, 7);
        assert_eq!(report.unwrap().target, 8);
    }

    #[tokio::test]
    async fn a_list_read_refused_for_now_says_when_to_try_again_held_to_a_day() {
        let mut limited = Sim {
            limited_reads: Some(u64::MAX),
            ..Sim::default()
        };
        let mut other = Sim::default();
        let report = reset(0, &mut [&mut limited, &mut other]).await.0.unwrap();
        assert_eq!(report.done, vec!["r1".to_string()]);
        assert_eq!(
            report.not_done,
            vec![NotYetReset {
                retry_after: Some(RETRY_MOST),
                ..not_done("r0", NotYet::Refused, Some("rate_limited"))
            }]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reset_no_registrar_heard_raises_no_floor() {
        let id = IdentityKey::generate();
        let device = DeviceKey::generate();
        let card = Card::new(&id, "Alice", 10).sign(&id, Vec::new()).unwrap();
        let cert = certify(&id, &device, "Pixel", 0).unwrap();
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let got = reset_devices(
            id.seed().to_vec(),
            card.clone(),
            vec![gone],
            5,
            device.seed().to_vec(),
            cert,
        )
        .await;
        match got {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "no_registrar_reached"),
            other => panic!("{:?}", other.map(|r| r.epoch)),
        }
        assert_eq!(crate::epoch::held_floor(card), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_registrar_that_never_answers_holds_up_the_rest_for_one_wait_at_a_time() {
        let mut quiet = Sim {
            silent_reads: true,
            ..Sim::default()
        };
        let mut also_quiet = Sim {
            silent_reads: true,
            ..Sim::default()
        };
        let mut stalls = Sim {
            silent_posts: true,
            ..Sim::default()
        };
        let mut also_stalls = Sim {
            silent_posts: true,
            ..Sim::default()
        };
        let mut good = Sim::default();
        let began = tokio::time::Instant::now();
        let report = reset(
            0,
            &mut [
                &mut quiet,
                &mut also_quiet,
                &mut stalls,
                &mut also_stalls,
                &mut good,
            ],
        )
        .await
        .0
        .unwrap();
        // The reads in round 0, the stalled posts together, and the last
        // reads.
        assert!(began.elapsed() <= 3 * WAIT, "{:?}", began.elapsed());
        assert_eq!((report.target, &report.done), (1, &vec!["r4".to_string()]));
        let late: Vec<_> = report
            .not_done
            .iter()
            .map(|n| n.registrar.as_str())
            .collect();
        assert_eq!(late, vec!["r0", "r1", "r2", "r3"]);
        assert_eq!(good.epochs(), vec![1]);
    }

    #[test]
    fn a_refusal_is_told_by_a_code_that_is_one_and_a_wait_of_at_most_a_day() {
        let refused = |error: &str, retry_after: u64| match answer(Ok((
            403,
            json!({ "error": error, "retry_after": retry_after }),
        ))) {
            Answer::Refused(r) => (r.code, r.retry_after),
            other => panic!("{other:?}"),
        };
        let long = "a".repeat(33);
        for (error, retry_after, code, wait) in [
            ("rate_limited", 60, Some("rate_limited"), 60),
            ("Your device is lost: call 555", 60, None, 60),
            (long.as_str(), 60, None, 60),
            ("", 60, None, 60),
            ("frozen", u64::MAX, Some("frozen"), RETRY_MOST),
        ] {
            assert_eq!(
                refused(error, retry_after),
                (code.map(str::to_owned), Some(wait)),
                "{error:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reset_under_way_refuses_another_of_its_identity() {
        let id = IdentityKey::generate();
        let device = DeviceKey::generate();
        let card = Card::new(&id, "Alice", 10).sign(&id, Vec::new()).unwrap();
        let cert = certify(&id, &device, "Pixel", 0).unwrap();
        // Its one registrar takes the connection and never answers.
        let registrars = vec![crate::epoch::tests::silent().await];
        let reset = || {
            let (seed, dev) = (id.seed(), device.seed());
            let (card, cert, registrars) = (card.clone(), cert.clone(), registrars.clone());
            async move { resetting(&seed, card, registrars, 0, &dev, cert).await }
        };
        let first = tokio::spawn(reset());
        // Long enough for it to reach its registrar, which holds it there.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second = tokio::time::timeout(Duration::from_secs(5), reset()).await;
        first.abort();
        match second {
            Ok(Err(CoreError::Refused { code, .. })) => assert_eq!(code, "busy"),
            other => panic!("{:?}", other.map(|r| r.map(|_| ()))),
        }
    }

    #[test]
    fn a_second_reset_of_an_identity_waits_for_the_first() {
        let (id, other) = (
            IdentityKey::generate().public(),
            IdentityKey::generate().public(),
        );
        let first = Resetting::take(&id).unwrap();
        match Resetting::take(&id) {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "busy"),
            got => panic!("{:?}", got.map(|_| ())),
        }
        let _another = Resetting::take(&other).unwrap();
        drop(first);
        Resetting::take(&id).unwrap();
    }

    #[test]
    fn a_floor_at_the_last_epoch_has_no_reset_past_it() {
        let id = IdentityKey::generate().public();
        let max = hl_identity::cert::EPOCH_MAX;
        let kept = Floors(id);
        assert_eq!(kept.next(max - 1).unwrap(), max);
        match kept.next(0) {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "no_epoch_left"),
            other => panic!("{other:?}"),
        }
        assert_eq!(at_floor(&id, 0, |f| f), max);
    }

    #[tokio::test]
    async fn with_no_registrar_reached_nothing_is_reset_or_raised() {
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let mut unread = Sim {
            unread: 1,
            ..Sim::default()
        };
        let (report, kept) = reset(3, &mut [&mut down, &mut unread]).await;
        match report {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "no_registrar_reached"),
            other => panic!("{other:?}"),
        }
        assert_eq!((kept, down.posts, unread.posts), (3, 0, 0));
    }

    #[tokio::test]
    async fn a_registrar_read_below_the_target_after_it_was_done_is_posted_again() {
        // Already at 19, it is done at 20 in one post, and loses that
        // record by the time it is read again, which happens because `b`,
        // caught up from 0, met another holder's 16 on the way.
        let mut restored = Sim {
            rollback_at: Some(3),
            ..Sim::default()
        };
        restored.held.push((19, 0, [9; 32]));
        let mut b = Sim {
            race: Some(signed(16, now() + 5)),
            ..Sim::default()
        };
        let (report, _) = reset(19, &mut [&mut restored, &mut b]).await;
        assert_eq!(report.unwrap(), all_done(20, 2));
        assert_eq!((restored.epochs(), restored.posts), (vec![19, 20], 2));
        assert_eq!(b.epochs(), vec![16, 20]);
    }

    #[tokio::test]
    async fn an_answer_its_list_does_not_bear_out_is_not_done() {
        let mut pretender = Sim {
            pretend: true,
            ..Sim::default()
        };
        let mut below = Sim {
            below: true,
            ..Sim::default()
        };
        let mut gone = Sim {
            unregistered: true,
            ..Sim::default()
        };
        let report = reset(0, &mut [&mut pretender, &mut below, &mut gone])
            .await
            .0
            .unwrap();
        assert_eq!(
            report,
            Report {
                target: 1,
                published: 0,
                done: vec![],
                not_done: vec![
                    not_done("r0", NotYet::Unconfirmed, None),
                    not_done("r1", NotYet::Unconfirmed, None),
                    not_done("r2", NotYet::Refused, Some("not_registered")),
                ],
                not_registrars: vec![],
                // Refused for good, `r2` is left to a new reset.
                behind: vec![
                    ("r0".into(), Current::default()),
                    ("r1".into(), Current::default()),
                ],
                posted: vec![],
            }
        );
        assert_eq!((pretender.posts, below.posts), (1, 1));
    }

    #[tokio::test]
    async fn an_origin_that_is_no_registrar_is_told_apart_from_one_not_reset() {
        let mut guess = Sim {
            not_a_registrar: true,
            ..Sim::default()
        };
        let mut good = Sim::default();
        let report = reset(0, &mut [&mut guess, &mut good]).await.0.unwrap();
        assert_eq!(
            report,
            Report {
                not_registrars: vec!["r0".into()],
                done: vec!["r1".into()],
                ..all_done(1, 0)
            }
        );

        let mut guess = Sim {
            not_a_registrar: true,
            ..Sim::default()
        };
        match reset(0, &mut [&mut guess]).await.0 {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "no_registrar_reached"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_origin_only_the_card_names_is_no_registrar_only_where_its_answer_says_so() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        // An origin answering every request with `status` and `body`.
        let answering = |status: u16, body: &'static str| async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move {
                while let Ok((mut s, _)) = l.accept().await {
                    let _ = s.read(&mut [0; 8192]).await;
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                }
            });
            url
        };
        let missing = answering(404, "").await;
        let website = answering(200, r#"{"server": {}}"#).await;
        let failing = answering(502, "").await;
        let garbled = answering(200, "<html>").await;
        let limited = answering(429, r#"{"retry_after": 60}"#).await;
        let registrar = crate::epoch::tests::registrar_publishing(vec![], 8)
            .await
            .to_string();
        let not = |why| Err(Unfound::Not(Refusal::because(why)));
        for (target, kept, found) in [
            (&missing, false, Err(Unfound::NotARegistrar)),
            (&website, false, Err(Unfound::NotARegistrar)),
            // A registrar down, or kept from view, is no evidence.
            (&gone, false, not(NotYet::ConnectionRefused)),
            (&failing, false, not(NotYet::Unreachable)),
            (&garbled, false, not(NotYet::Malformed)),
            (
                &limited,
                false,
                Err(Unfound::Not(Refusal {
                    code: Some("rate_limited".into()),
                    retry_after: Some(60),
                    ..Refusal::because(NotYet::Refused)
                })),
            ),
            // One the app keeps is a registrar, whatever answers there.
            (&missing, true, not(NotYet::Unreachable)),
            (&website, true, not(NotYet::Malformed)),
            (&registrar, false, Ok(())),
        ] {
            let mut remote = Remote {
                target: target.clone(),
                identity: alice().public(),
                kept,
                reg: None,
            };
            assert_eq!(remote.discover().await, found, "{target}, kept: {kept}");
        }
    }

    #[test]
    fn a_list_read_is_told_by_what_stopped_it() {
        let refused = CoreError::Refused {
            code: "not_a_registrar".into(),
            detail: "Down for maintenance".into(),
            successor: None,
        };
        let connect = CoreError::Connect {
            detail: "connection reset".into(),
        };
        for (e, why, code) in [
            (refused, NotYet::Refused, Some("not_a_registrar")),
            (protocol("the records do not read"), NotYet::Malformed, None),
            (connect, NotYet::Unreachable, None),
        ] {
            let r = unread(e);
            assert_eq!((r.why, r.code.as_deref()), (why, code));
        }
    }

    #[tokio::test]
    async fn a_registrar_more_posts_behind_than_a_reset_makes_is_told_so() {
        // Answers each step as taken and publishes none, so the target,
        // more than `POSTS_MAX` steps off, is never reached.
        let mut far = Sim {
            pretend: true,
            ..Sim::default()
        };
        let floor = STEP_MAX * POSTS_MAX as u64 + 1;
        let report = reset(floor, &mut [&mut far]).await.0.unwrap();
        assert_eq!(
            report.not_done,
            vec![not_done("r0", NotYet::TooFarBehind, None)]
        );
        assert_eq!(report.behind, vec![], "left to a new reset");
        assert_eq!(far.posts, POSTS_MAX);
    }

    #[test]
    fn a_registrar_answering_a_device_epoch_with_no_epoch_takes_none() {
        assert_eq!(
            answer(Ok((200, json!({ "seq": 1, "published": true })))),
            Answer::Refused(Refusal::because(NotYet::Unsupported))
        );
    }

    /// Past every wait a reset or a retry gives.
    fn later() -> u64 {
        now() + RETRY_MOST
    }

    /// What `retry` comes to posted to `sims` once every chain is due.
    async fn retry(retry: &Retry, sims: &mut [&mut Sim]) -> ResetRetried {
        retry_at(retry, sims, later()).await
    }

    async fn retry_at(retry: &Retry, sims: &mut [&mut Sim], at: u64) -> ResetRetried {
        retry_by(retry, sims, || at).await
    }

    /// What `retry` comes to posted to `sims` by `clock`, each at the
    /// `r{i}` its chain names.
    async fn retry_by(
        retry: &Retry,
        sims: &mut [&mut Sim],
        clock: impl Fn() -> u64,
    ) -> ResetRetried {
        let desks = sims
            .iter_mut()
            .enumerate()
            .filter_map(|(i, s)| {
                let chain = retry
                    .chains
                    .iter()
                    .find(|c| c.registrar == format!("r{i}"))?;
                Some((chain.clone(), &mut **s))
            })
            .collect();
        let header = Retry {
            chains: vec![],
            ..retry.clone()
        };
        retry_all(header, desks, &Mem::at(0), clock).await
    }

    /// What a reset or a retry handed back.
    fn kept_of(retry: &Option<Vec<u8>>) -> Retry {
        decode(retry.as_ref().unwrap(), &alice().public()).unwrap()
    }

    /// A retry to `epoch` for `r0`, whose list read `cur`, with `posted`.
    fn for_r0(epoch: u64, cur: Current, posted: Vec<[u8; 32]>) -> Retry {
        Retry {
            epoch,
            posted,
            chains: vec![Chain {
                registrar: "r0".into(),
                kept: true,
                records: chain_to(&alice(), epoch, &cur).unwrap(),
                due: 0,
                tries: 0,
            }],
        }
    }

    fn retried(
        epoch: u64,
        published: u64,
        done: &[&str],
        not_done: Vec<NotYetReset>,
    ) -> ResetRetried {
        ResetRetried {
            epoch,
            published,
            done: done.iter().map(|d| d.to_string()).collect(),
            not_done,
            not_registrars: vec![],
            retry: None,
            retry_in: None,
            later: vec![],
        }
    }

    #[tokio::test]
    async fn a_registrar_down_at_a_reset_is_caught_up_by_what_it_kept_at_the_same_epoch() {
        let mut good = Sim::default();
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let desks = vec![("r0".to_string(), &mut good), ("r1".to_string(), &mut down)];
        let report = reset_all(&alice(), 0, desks, &Mem::at(0)).await.unwrap();
        assert_eq!((report.target, &report.done), (1, &vec!["r0".to_string()]));
        assert_eq!(report.posted, vec![good.cur().2]);
        let at = now();
        let kept = lagging(&alice(), &report, |_| true, at).unwrap();
        assert_eq!(retry_in(&kept.chains, at), Some(RETRY_EVERY));

        // Still down, it is kept as it was.
        let got = retry(&kept_of(&encode(&kept)), &mut [&mut good, &mut down]).await;
        assert_eq!(
            got.not_done,
            vec![not_done("r1", NotYet::Unreachable, None)]
        );
        assert_eq!(
            kept_of(&got.retry).chains[0].records,
            kept.chains[0].records
        );
        assert_eq!(got.retry_in, Some(RETRY_EVERY));

        down.unreachable = false;
        let got = retry(&kept, &mut [&mut good, &mut down]).await;
        assert_eq!(got, retried(1, 1, &["r1"], vec![]));
        assert_eq!((good.epochs(), good.posts), (vec![1], 1));
        assert_eq!(down.epochs(), vec![1]);
    }

    #[tokio::test]
    async fn a_registrar_far_behind_is_caught_up_a_step_at_a_time_across_retries() {
        let mut ahead = Sim::default();
        ahead.held.push((39, 0, [9; 32]));
        // Its last reset dated ahead of this clock, as the kept records
        // must be too.
        let mut behind = Sim::default();
        behind.land(&signed(3, now() + 100)).unwrap();
        behind.allowance = Some(1);
        let report = reset(0, &mut [&mut ahead, &mut behind]).await.0.unwrap();
        assert_eq!((report.target, behind.epochs()), (40, vec![3, 19]));
        let kept = lagging(&alice(), &report, |_| true, now()).unwrap();

        behind.allowance = Some(1);
        let at = later();
        let got = retry_at(&kept, &mut [&mut ahead, &mut behind], at).await;
        assert_eq!(behind.epochs(), vec![3, 19, 24]);
        assert_eq!(got.retry_in, Some(3600), "as long as it asked");
        assert_eq!(
            kept_of(&got.retry).chains[0].records,
            kept.chains[0].records
        );

        behind.allowance = None;
        let posts = behind.posts;
        let got = retry_at(
            &kept_of(&got.retry),
            &mut [&mut ahead, &mut behind],
            at + 3600,
        )
        .await;
        assert_eq!(got, retried(40, 40, &["r1"], vec![]));
        assert_eq!(behind.epochs(), vec![3, 19, 24, 40]);
        assert_eq!(behind.posts - posts, 1, "nothing below its list posted");
        assert_eq!(ahead.epochs(), vec![39, 40]);
    }

    #[tokio::test]
    async fn a_registrar_at_the_epoch_with_another_holders_record_is_overtaken_and_past_it_done() {
        let theirs = signed(1, now() + 5);
        let mine: [u8; 32] = Sha256::digest(&theirs).into();
        for (what, record, posted, outcome) in [
            (
                "another holder's at it",
                theirs.clone(),
                vec![],
                Err(NotYet::Overtaken),
            ),
            (
                "this reset's own, its reply lost",
                theirs,
                vec![mine],
                Ok(()),
            ),
            (
                "another holder's past it",
                signed(5, now() + 5),
                vec![],
                Ok(()),
            ),
        ] {
            // Its list read once, so the first read decides.
            let mut sim = Sim {
                fail_read: Some(2),
                ..Sim::default()
            };
            sim.land(&record).unwrap();
            let got = retry(&for_r0(1, Current::default(), posted), &mut [&mut sim]).await;
            let published = sim.cur().0;
            let want = match outcome {
                Ok(()) => retried(1, published, &["r0"], vec![]),
                Err(why) => retried(1, published, &[], vec![not_done("r0", why, None)]),
            };
            assert_eq!(got, want, "{what}");
            assert_eq!(sim.posts, 0, "{what}");
        }
    }

    #[tokio::test]
    async fn a_registrar_a_retry_cannot_bring_to_the_epoch_is_left_to_a_new_reset() {
        let later = now() + 50;
        // Kept from its list at 30: a record at 40 alone.
        let at_30 = Current {
            epoch: 30,
            ..Current::default()
        };
        let cases: [(&str, Sim, Current, NotYetReset, usize); 3] = [
            (
                "not registered",
                Sim {
                    unregistered: true,
                    ..Sim::default()
                },
                Current::default(),
                not_done("r0", NotYet::Refused, Some("not_registered")),
                1,
            ),
            (
                "reset since, dated later",
                {
                    let mut s = Sim::default();
                    s.land(&signed(2, later)).unwrap();
                    s
                },
                Current::default(),
                not_done("r0", NotYet::DatedBefore, None),
                0,
            ),
            (
                "further behind than it read",
                Sim::default(),
                at_30,
                not_done("r0", NotYet::TooFarBehind, None),
                0,
            ),
        ];
        for (what, mut sim, cur, why, posts) in cases {
            let got = retry(&for_r0(40, cur, vec![]), &mut [&mut sim]).await;
            assert_eq!(got, retried(40, sim.cur().0, &[], vec![why]), "{what}");
            assert_eq!(sim.posts, posts, "{what}");
        }
    }

    #[tokio::test]
    async fn a_registrar_asking_for_less_than_the_backoff_is_left_the_backoff() {
        let mut sim = Sim {
            limited_reads: Some(5),
            ..Sim::default()
        };
        let got = retry(&for_r0(1, Current::default(), vec![]), &mut [&mut sim]).await;
        assert_eq!(got.retry_in, Some(RETRY_EVERY));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_retry_while_a_reset_of_its_identity_is_under_way_is_refused() {
        let id = IdentityKey::generate();
        let card = Card::new(&id, "Alice", 10).sign(&id, Vec::new()).unwrap();
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let kept = Retry {
            epoch: 1,
            posted: vec![],
            chains: vec![Chain {
                registrar: gone,
                kept: true,
                records: chain_to(&id, 1, &Current::default()).unwrap(),
                due: 0,
                tries: 0,
            }],
        };
        let _resetting = Resetting::take(&id.public()).unwrap();
        match retrying(encode(&kept).unwrap(), card, 0).await {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "busy"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_retry_reads_as_the_identitys_own_records_in_steps_or_not_at_all() {
        let chain = |registrar: &str, id: &IdentityKey, epochs: &[u64]| Chain {
            registrar: registrar.into(),
            kept: false,
            records: epochs
                .iter()
                .map(|&epoch| Signed {
                    epoch,
                    time: 7,
                    bytes: sign_epoch(id, epoch, 7).unwrap(),
                })
                .collect(),
            due: 9,
            tries: 0,
        };
        let blob = |chains: Vec<Chain>| {
            encode(&Retry {
                epoch: 0,
                posted: vec![],
                chains,
            })
            .unwrap()
        };
        let mut good = Retry {
            epoch: 40,
            posted: vec![[3; 32]],
            chains: vec![
                chain("r0", &alice(), &[8, 24, 40]),
                chain("r1", &alice(), &[40]),
            ],
        };
        good.chains[0].tries = 3;
        let kept = encode(&good).unwrap();
        assert_eq!(decode(&kept, &alice().public()).unwrap(), good);
        // One kept before tries were counted has made none that count.
        let mut first: Value = serde_json::from_slice(&kept).unwrap();
        first["v"] = json!(1);
        first["at"][0].as_object_mut().unwrap().remove("tries");
        let first = decode(&serde_json::to_vec(&first).unwrap(), &alice().public()).unwrap();
        assert_eq!(first.chains[0].tries, 0);

        let mut flipped = chain("r0", &alice(), &[8, 24, 40]);
        let last = flipped.records[2].bytes.len() - 1;
        flipped.records[2].bytes[last] ^= 1;
        let too_many: Vec<u64> = (1..=CHAIN_MAX as u64 + 1).collect();
        let too_wide: Vec<Chain> = (0..=CHAINS_MAX)
            .map(|i| chain(&format!("r{i}"), &alice(), &[1]))
            .collect();
        let other = IdentityKey::from_seed(&[2; 32]);
        let one = |c| blob(vec![c]);
        for (what, bytes, code) in [
            ("not json", b"<html>".to_vec(), "bad_retry"),
            (
                "another version",
                br#"{"v": 3, "posted": [], "at": []}"#.to_vec(),
                "bad_retry",
            ),
            (
                "no chain",
                br#"{"v": 1, "posted": [], "at": []}"#.to_vec(),
                "bad_retry",
            ),
            (
                "another identity's",
                one(chain("r0", &other, &[1])),
                "wrong_identity",
            ),
            (
                "out of order",
                one(chain("r0", &alice(), &[24, 8])),
                "bad_retry",
            ),
            (
                "past a step",
                one(chain("r0", &alice(), &[8, 25])),
                "bad_retry",
            ),
            ("none", one(chain("r0", &alice(), &[])), "bad_retry"),
            (
                "too many",
                one(chain("r0", &alice(), &too_many)),
                "bad_retry",
            ),
            ("a signature broken", one(flipped), "bad_retry"),
            ("too many registrars", blob(too_wide), "bad_retry"),
            (
                "one origin twice",
                blob(vec![
                    chain("hl.example", &alice(), &[1]),
                    chain("https://HL.example:443", &alice(), &[1]),
                ]),
                "bad_retry",
            ),
            (
                "two epochs",
                blob(vec![
                    chain("r0", &alice(), &[1]),
                    chain("r1", &alice(), &[2]),
                ]),
                "bad_retry",
            ),
            (
                "a hash cut short",
                String::from_utf8(kept.clone())
                    .unwrap()
                    .replace(&b64(&[3; 32]), &b64(&[3; 31]))
                    .into_bytes(),
                "bad_retry",
            ),
            (
                "too long",
                [kept.clone(), vec![b' '; RETRY_MAX]].concat(),
                "bad_retry",
            ),
        ] {
            match decode(&bytes, &alice().public()) {
                Err(CoreError::Refused { code: c, .. }) => assert_eq!(c, code, "{what}"),
                other => panic!("{what}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn the_kept_records_are_dated_after_one_its_last_read_showed() {
        let mut ahead = Sim::default();
        ahead.held.push((39, 0, [9; 32]));
        // Refuses the reset for now, and holds another holder's record,
        // dated later, by the time its list is read again.
        let mut limited = Sim {
            allowance: Some(0),
            held_at: Some((2, signed(3, now() + 100))),
            ..Sim::default()
        };
        let report = reset(0, &mut [&mut ahead, &mut limited]).await.0.unwrap();
        assert_eq!((report.target, limited.epochs()), (40, vec![3]));
        let kept = lagging(&alice(), &report, |_| true, now()).unwrap();

        limited.allowance = None;
        let got = retry(&kept, &mut [&mut ahead, &mut limited]).await;
        assert_eq!(got, retried(40, 40, &["r1"], vec![]));
        assert_eq!(limited.epochs(), vec![3, 8, 24, 40]);
    }

    #[test]
    fn a_registrar_asking_to_be_left_waits_whether_it_says_how_long_or_not() {
        let refusal = |code: &str, retry_after| Refusal {
            code: Some(code.into()),
            retry_after,
            ..Refusal::because(NotYet::Refused)
        };
        for (r, waiting) in [
            (refusal("rate_limited", None), true),
            (refusal("rate_limited", Some(60)), true),
            (refusal("not_registered", None), false),
        ] {
            assert_eq!(waits(&r), waiting, "{r:?}");
        }
    }

    #[test]
    fn a_registrar_a_chain_cannot_bring_to_the_epoch_gets_none_and_one_at_it_keeps_one() {
        let list = |epoch, time| Current {
            epoch,
            time,
            hash: None,
        };
        let reach = CHAIN_MAX as u64 * STEP_MAX;
        for (what, target, cur, first) in [
            ("dated past the skew", 40, list(2, now() + 10 * SKEW), None),
            ("dated within it", 40, list(2, now() + SKEW), Some(8)),
            (
                "further behind than a chain reaches",
                reach + 1,
                list(0, 0),
                None,
            ),
            ("as far as one reaches", reach, list(0, 0), Some(16)),
            ("at the epoch, to confirm", 40, list(40, 0), Some(40)),
        ] {
            let report = Report {
                behind: vec![("r0".into(), cur)],
                ..all_done(target, 0)
            };
            let kept = lagging(&alice(), &report, |_| true, 0).unwrap();
            assert_eq!(
                kept.chains.first().map(|c| c.records[0].epoch),
                first,
                "{what}"
            );
            if first.is_some() {
                let blob = encode(&kept).unwrap();
                assert_eq!(decode(&blob, &alice().public()).unwrap(), kept, "{what}");
            }
        }
    }

    #[tokio::test]
    async fn a_registrar_is_asked_again_only_once_its_wait_is_up() {
        let mut good = Sim::default();
        let mut limited = Sim {
            allowance: Some(0),
            ..Sim::default()
        };
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let report = reset(0, &mut [&mut good, &mut limited, &mut down])
            .await
            .0
            .unwrap();
        let at = now();
        let kept = lagging(&alice(), &report, |_| true, at).unwrap();
        assert_eq!(retry_in(&kept.chains, at), Some(RETRY_EVERY));

        (limited.allowance, down.unreachable) = (None, false);
        let asked = (limited.posts, limited.reads);
        let sims = &mut [&mut good, &mut limited, &mut down];
        // One that asked for no wait is asked once the backoff's first wait is up.
        let got = retry_at(&kept, sims, at + RETRY_EVERY).await;
        assert_eq!((got.done, got.not_done), (vec!["r2".to_string()], vec![]));
        assert_eq!(got.retry_in, Some(3600 - RETRY_EVERY));
        assert_eq!((limited.posts, limited.reads), asked, "not asked yet");

        // Asked once the clock is set back past any wait.
        let sims = &mut [&mut good, &mut limited, &mut down];
        let got = retry_at(&kept_of(&got.retry), sims, at - RETRY_MOST - 1).await;
        assert_eq!(got, retried(1, 1, &["r1"], vec![]));
    }

    #[tokio::test]
    async fn a_wait_is_counted_from_when_the_retry_is_done_asking() {
        // Asked at `at` and done asking 90 s later: `r0` asks for a
        // minute, left the backoff, and `r1` is not due.
        let at = now();
        let mut limited = Sim {
            limited_reads: Some(60),
            ..Sim::default()
        };
        let mut untouched = Sim::default();
        let mut kept = for_r0(1, Current::default(), vec![]);
        let mut r1 = kept.chains[0].clone();
        (r1.registrar, r1.due) = ("r1".into(), at + 3600);
        kept.chains.push(r1);
        let ticks = std::cell::Cell::new(0);
        let clock = || {
            ticks.set(ticks.get() + 1);
            at + 90 * (ticks.get() - 1)
        };
        let got = retry_by(&kept, &mut [&mut limited, &mut untouched], clock).await;
        let dues: Vec<u64> = kept_of(&got.retry).chains.iter().map(|c| c.due).collect();
        assert_eq!(dues, vec![at + 3600, at + 90 + RETRY_EVERY]);
        assert_eq!(got.retry_in, Some(RETRY_EVERY));
        assert_eq!(untouched.reads, 0);
    }

    #[tokio::test]
    async fn a_wait_the_confirming_read_asks_for_is_kept() {
        // Takes the post, then refuses the read that would confirm it.
        let mut sim = Sim {
            limited_reads: Some(3600),
            limited_after: 1,
            ..Sim::default()
        };
        let got = retry(&for_r0(1, Current::default(), vec![]), &mut [&mut sim]).await;
        assert_eq!(sim.epochs(), vec![1]);
        assert_eq!(
            got.not_done,
            vec![NotYetReset {
                retry_after: Some(3600),
                ..not_done("r0", NotYet::Refused, Some("rate_limited"))
            }],
            "not done until a list shows it"
        );
        assert_eq!(got.retry_in, Some(3600));
    }

    #[tokio::test]
    async fn a_registrar_a_chain_can_never_reach_is_dropped_whatever_the_confirming_read_asks() {
        // Reset since by another holder, dated after the kept records, then
        // refusing the read after it.
        let mut sim = Sim {
            limited_reads: Some(3600),
            limited_after: 1,
            ..Sim::default()
        };
        sim.land(&signed(2, now() + 50)).unwrap();
        let got = retry(&for_r0(40, Current::default(), vec![]), &mut [&mut sim]).await;
        assert_eq!(
            got,
            retried(40, 2, &[], vec![not_done("r0", NotYet::DatedBefore, None)])
        );
        assert_eq!(sim.posts, 0);
    }

    /// `retry` asked at each of `times` in turn, each time with what the
    /// last handed back, while `down` stays down: each try's not-done
    /// reason, and what is left to post.
    async fn tried_at(retry: Retry, down: &mut Sim, times: &[u64]) -> (Vec<NotYet>, Option<Retry>) {
        let mut whys = Vec::new();
        let mut kept = Some(retry);
        for &at in times {
            let Some(r) = kept.take() else { break };
            let got = retry_at(&r, &mut [&mut *down], at).await;
            whys.extend(got.not_done.iter().map(|n| n.why));
            kept = got.retry.as_ref().map(|_| kept_of(&got.retry));
        }
        (whys, kept)
    }

    #[tokio::test]
    async fn a_registrar_is_given_up_on_only_once_it_was_tried_enough_and_for_long_enough() {
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let kept = for_r0(1, Current::default(), vec![]);
        let since = kept.chains[0].records[0].time;
        let hours = |h: u64| since + h * 3600;

        // Twenty tries inside the week: never given up, however many.
        let often: Vec<u64> = (1..=20).map(|i| hours(7 * i)).collect();
        let (whys, left) = tried_at(kept.clone(), &mut down, &often).await;
        assert_eq!(whys, vec![NotYet::Unreachable; 20]);
        let left = left.unwrap();
        assert_eq!(left.chains[0].tries, 20);
        // Past the week, the next try is the last.
        let (whys, left) = tried_at(left, &mut down, &[hours(7 * 24 + 1)]).await;
        assert_eq!((whys, left), (vec![NotYet::GaveUp], None));

        // Past the week after two tries: tried on until it has made twelve.
        let rare: Vec<u64> = std::iter::once(hours(1))
            .chain((0..12).map(|i| hours(8 * 24 + 6 * i)))
            .collect();
        let (whys, left) = tried_at(kept, &mut down, &rare).await;
        let mut want = vec![NotYet::Unreachable; 11];
        want.push(NotYet::GaveUp);
        assert_eq!((whys, left), (want, None));
    }

    #[tokio::test]
    async fn a_registrar_not_done_is_left_longer_after_each_try() {
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let mut kept = for_r0(1, Current::default(), vec![]);
        let mut at = now();
        let mut waits = Vec::new();
        for _ in 0..7 {
            let got = retry_at(&kept, &mut [&mut down], at).await;
            let wait = got.retry_in.unwrap();
            waits.push(wait);
            kept = kept_of(&got.retry);
            at += wait;
        }
        let m = 60;
        assert_eq!(
            waits,
            vec![15 * m, 30 * m, 60 * m, 120 * m, 240 * m, 360 * m, 360 * m]
        );
    }

    #[tokio::test]
    async fn a_retry_names_the_registrars_it_is_kept_for_and_no_other() {
        let mut down = Sim {
            unreachable: true,
            ..Sim::default()
        };
        let mut refusing = Sim {
            unregistered: true,
            ..Sim::default()
        };
        let mut kept = for_r0(1, Current::default(), vec![]);
        let mut r1 = kept.chains[0].clone();
        r1.registrar = "r1".into();
        kept.chains.push(r1);
        let got = retry(&kept, &mut [&mut down, &mut refusing]).await;
        assert_eq!(got.not_done.len(), 2, "{:?}", got.not_done);
        assert_eq!(got.later, vec!["r0".to_string()]);
        assert_eq!(
            kept_of(&got.retry)
                .chains
                .iter()
                .map(|c| c.registrar.as_str())
                .collect::<Vec<_>>(),
            vec!["r0"]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_a_reset_or_a_retry_reads_of_the_records_is_kept_whatever_the_read_comes_to() {
        let id = IdentityKey::generate();
        let lost = DeviceKey::generate().public();
        // The revocation on the first page, and the second page refused.
        let records = vec![
            crate::epoch::tests::revocation(&id, lost),
            sign_epoch(&id, 3, 1_000).unwrap(),
        ];
        let registrar = crate::epoch::tests::registrar_failing(records, 1, 1)
            .await
            .to_string();
        let mut remote = Remote {
            target: registrar,
            identity: id.public(),
            kept: true,
            reg: None,
        };
        assert_eq!(remote.discover().await, Ok(()));
        assert!(remote.read().await.is_err());
        let evidence = crate::epoch::evidence_of(&id.public());
        assert_eq!(evidence.revoked, vec![lost.to_vec()]);
    }

    #[test]
    fn a_registrars_first_retry_waits_the_backoff_or_longer_where_it_asked() {
        let at = now();
        let limited = |registrar: &str, retry_after: Option<u64>| NotYetReset {
            retry_after,
            ..not_done(registrar, NotYet::Refused, Some("rate_limited"))
        };
        let report = Report {
            target: 1,
            published: 0,
            done: vec![],
            not_done: vec![
                limited("r0", Some(5)),
                limited("r1", Some(3600)),
                not_done("r2", NotYet::Unreachable, None),
            ],
            not_registrars: vec![],
            behind: ["r0", "r1", "r2"]
                .iter()
                .map(|r| (r.to_string(), Current::default()))
                .collect(),
            posted: vec![],
        };
        let kept = lagging(&alice(), &report, |_| true, at).unwrap();
        let dues: Vec<u64> = kept.chains.iter().map(|c| c.due - at).collect();
        assert_eq!(dues, vec![RETRY_EVERY, 3600, RETRY_EVERY]);
    }
}

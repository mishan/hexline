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
//! once more, an epoch further.

use std::collections::BTreeSet;
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
use crate::restore::{b64, certify, discovered, endpoint, now, registrar_base, unb64, Registrar};
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
    /// This phone's certificate minted again at the floor, above the one
    /// passed, for the same key and name and, as this phone's own always
    /// is, to log in, message and manage: to keep in its place.
    pub cert: Vec<u8>,
    /// The epoch `cert` was minted at.
    pub cert_epoch: u64,
}

/// A registrar the reset is not at yet, and why, in this core's words.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct NotYetReset {
    pub registrar: String,
    pub why: String,
    /// The code it refused the reset with, if it did.
    pub code: Option<String>,
    /// Seconds it asked to be left before it is asked again.
    pub retry_after: Option<u64>,
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
    let mut remotes: Vec<Remote> = targets
        .iter()
        .map(|t| Remote {
            target: t.clone(),
            identity: id.public(),
            reg: None,
        })
        .collect();
    let desks = targets.into_iter().zip(remotes.iter_mut()).collect();
    // Kept only once a list is read: a reset no registrar heard of
    // raises nothing.
    let floor = floor_of(&id.public()).max(epoch).max(info.epoch);
    let report = reset_all(&id, floor, desks, &Floors(id.public())).await?;
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
        cert,
        cert_epoch,
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

/// What a reset needs of a registrar.
pub(crate) trait Desk {
    /// Its discovery read, naming itself as it is reached.
    async fn discover(&mut self) -> Result<(), String>;
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
    reg: Option<(Client, Url, Registrar)>,
}

impl Desk for Remote {
    async fn discover(&mut self) -> Result<(), String> {
        let found = async {
            let base = registrar_base(&self.target)?;
            let http = hxng_client::auth::http_client(base.as_str(), None)?;
            let reg = discovered(&http, &base).await?;
            Ok::<_, CoreError>((http, base, reg))
        };
        self.reg = Some(found.await.map_err(|e| e.to_string())?);
        Ok(())
    }

    async fn read(&mut self) -> Result<Current, Refusal> {
        let (http, base, reg) = self
            .reg
            .as_ref()
            .ok_or_else(|| Refusal::because("not discovered".into()))?;
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
    Lost(String),
    Refused(Refusal),
}

/// Why a registrar is not done, as the app is told it: no words of the
/// registrar's own, which the app would show as this core's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    why: String,
    code: Option<String>,
    retry_after: Option<u64>,
}

impl Refusal {
    fn because(why: String) -> Refusal {
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
            why: "it asked to be left a while".into(),
            code: Some("rate_limited".into()),
            retry_after: retry_after.map(|s| s.min(RETRY_MOST)),
        },
        e => Refusal::because(e.to_string()),
    }
}

fn answer(reply: Result<(u16, Value), String>) -> Answer {
    let (status, body) = match reply {
        Ok(r) => r,
        Err(e) => return Answer::Lost(e),
    };
    if status == 200 {
        let hash = body["hash"]
            .as_str()
            .and_then(|h| unb64(h)?.try_into().ok());
        return match (body["epoch"].as_u64(), hash) {
            (Some(epoch), Some(hash)) => Answer::At { epoch, hash },
            _ => Answer::Refused(Refusal::because("it does not take device epochs".into())),
        };
    }
    if status >= 500 {
        return Answer::Lost(format!("it answered {status}"));
    }
    Answer::Refused(Refusal {
        why: "it refused the reset".into(),
        code: body["error"]
            .as_str()
            .filter(|c| {
                (1..=32).contains(&c.len())
                    && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            })
            .map(str::to_owned),
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
    Lost(String),
    NotDone(Refusal),
    /// It answered above what was posted, or at it with a record this
    /// reset did not post: another holder's reset, if its list bears it
    /// out.
    Claimed(u64),
}

/// Bring a registrar whose current record is `cur` to `target`, `cur +
/// 16` at a time, each post signed afresh at the later of now and the
/// registrar's current record's `time`, its hash kept in `posted` before
/// it is sent.
async fn drive<D: Desk>(
    target: u64,
    mut cur: Current,
    id: &IdentityKey,
    posted: &mut Vec<[u8; 32]>,
    desk: &mut D,
) -> Result<Step, CoreError> {
    let mut lost = 0;
    for _ in 0..POSTS_MAX {
        if cur.time > now().saturating_add(SKEW) {
            return Ok(Step::NotDone(Refusal::because(
                "its last reset is dated ahead of this phone's clock".into(),
            )));
        }
        let epoch = target.min(cur.epoch.saturating_add(STEP_MAX));
        let time = now().max(cur.time);
        let bytes = DeviceEpoch {
            identity: id.public(),
            epoch,
            time,
        }
        .sign(id)
        .map_err(|e| protocol(&format!("the device epoch does not sign: {e}")))?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        if !posted.contains(&hash) {
            posted.push(hash);
        }
        match answer(desk.post(&bytes).await) {
            Answer::At { epoch: e, hash: h } => {
                lost = 0;
                if e < epoch {
                    return Ok(Step::NotDone(Refusal::because(format!(
                        "it answered epoch {e} to a post of {epoch}"
                    ))));
                }
                if e > epoch || !posted.contains(&h) {
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
            Answer::Lost(why) => {
                lost += 1;
                if lost >= TRIES {
                    return Ok(Step::Lost(why));
                }
                desk.pause().await;
            }
            Answer::Refused(r) => return Ok(Step::NotDone(r)),
        }
    }
    Ok(Step::NotDone(Refusal::because(format!(
        "{POSTS_MAX} posts did not bring it to epoch {target}"
    ))))
}

// --- A reset at every registrar ---------------------------------------------

enum State {
    Open,
    /// Answered at the target; to be read again.
    Answered,
    /// Its replies lost, with why; to be read again.
    Lost(String),
    Done,
    Out(String),
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
    /// The refusal it was given up on for, if it refused.
    refusal: Option<Refusal>,
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
            .unwrap_or_else(|_| Err(LATE.into()))
    }))
    .await;
    let mut slots: Vec<Slot<D>> = Vec::new();
    for ((target, desk), found) in desks.into_iter().zip(found) {
        let state = match found {
            Ok(()) => State::Open,
            Err(e) => State::Out(e),
        };
        slots.push(Slot {
            target,
            desk,
            trusted: matches!(state, State::Open),
            state,
            cur: Current::default(),
            claim: None,
            refusal: None,
        });
    }
    let mut posted: Vec<[u8; 32]> = Vec::new();
    let ours = |c: &Current, posted: &[[u8; 32]]| c.hash.is_some_and(|h| posted.contains(&h));
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
                State::Out(_) => None,
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
                Some(Err(r)) => {
                    let why = format!("its list could not be read: {}", r.why);
                    s.state = State::Out(why.clone());
                    s.refusal = Some(Refusal { why, ..r });
                }
            }
        }
        if round == 0 && read.is_empty() {
            let why: Vec<String> = slots
                .iter()
                .filter_map(|s| match &s.state {
                    State::Out(why) => Some(format!("{}: {why}", s.target)),
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
                (State::Open | State::Answered | State::Lost(_), true) => s.state = State::Done,
                (State::Lost(why), false) => s.state = State::Out(why.clone()),
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
                true => State::Out(format!(
                    "it answered epoch {claim}, and its list shows {}",
                    s.cur.epoch
                )),
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
        for s in &mut slots {
            if !matches!(s.state, State::Open) {
                continue;
            }
            let driven = drive(target, s.cur, id, &mut posted, &mut *s.desk);
            // Given up on, a post may have landed: its list says.
            let step = match tokio::time::timeout(WAIT, driven).await {
                Ok(step) => step?,
                Err(_) => Step::Lost(LATE.into()),
            };
            match step {
                Step::Answered => s.state = State::Answered,
                Step::Lost(why) => s.state = State::Lost(why),
                Step::NotDone(r) => {
                    s.state = State::Out(r.why.clone());
                    s.refusal = Some(r);
                }
                Step::Claimed(e) => {
                    s.claim = Some(e);
                    // The target is stale for everyone; the rest's daily
                    // resets are not spent on it.
                    if e >= target {
                        break;
                    }
                }
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
    let mut report = Report {
        target: posted_at.unwrap_or(target),
        published,
        done: Vec::new(),
        not_done: Vec::new(),
    };
    for s in slots {
        let r = match s.state {
            State::Done => {
                report.done.push(s.target);
                continue;
            }
            State::Out(why) | State::Lost(why) => s.refusal.unwrap_or(Refusal::because(why)),
            State::Open | State::Answered => Refusal::because(format!(
                "another holder reset past epoch {} meanwhile",
                report.target
            )),
        };
        report.not_done.push(NotYetReset {
            registrar: s.target,
            why: r.why,
            code: r.code,
            retry_after: r.retry_after,
        });
    }
    Ok(report)
}

/// Why a registrar given [`WAIT`] and no more is left behind.
const LATE: &str = "it did not answer in time";

/// `desk`'s list, or why not, in [`WAIT`], its floor kept as it lands so
/// a mint meanwhile signs at it.
async fn read_in_time<D: Desk>(desk: &mut D, kept: &impl Kept) -> Result<Current, Refusal> {
    let read = tokio::time::timeout(WAIT, desk.read())
        .await
        .unwrap_or_else(|_| Err(Refusal::because(LATE.into())))?;
    kept.raise(read.epoch);
    Ok(read)
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
        /// The identity whose floor a mint reads as each post arrives,
        /// and what it read.
        minting: Option<PublicKey>,
        minted_at: Vec<u64>,
        /// Never answers a read, or a post.
        silent_reads: bool,
        /// Each read answered after this long.
        slow_reads: Option<Duration>,
        /// Each read refused as a 429 asking for this wait.
        limited_reads: Option<u64>,
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
        async fn discover(&mut self) -> Result<(), String> {
            match self.unreachable {
                true => Err("connection refused".into()),
                false => Ok(()),
            }
        }

        async fn read(&mut self) -> Result<Current, Refusal> {
            if self.silent_reads {
                std::future::pending::<()>().await;
            }
            if let Some(after) = self.slow_reads {
                tokio::time::sleep(after).await;
            }
            if let Some(retry_after) = self.limited_reads {
                return Err(unread(CoreError::RateLimited {
                    retry_after: Some(retry_after),
                }));
            }
            self.reads += 1;
            if self.unread > 0 || self.fail_read == Some(self.reads) {
                self.unread = self.unread.saturating_sub(1);
                return Err(Refusal::because("connection reset".into()));
            }
            if self.rollback_at == Some(self.reads) {
                self.held.pop();
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
        let report = reset_all(&alice(), floor, desks, kept).await;
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
        }
    }

    fn not_done(registrar: &str, why: &str, code: Option<&str>) -> NotYetReset {
        NotYetReset {
            registrar: registrar.into(),
            why: why.into(),
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
            vec![not_done("r0", "connection reset", None)]
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
        // a target found stale either way.
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
            let (report, kept) = reset(0, &mut [&mut a, &mut b]).await;
            let report = report.unwrap();
            assert_eq!((report.target, report.published, kept), (last, last, last));
            assert_eq!(report.done, Vec::<String>::new(), "{fail_read:?}");
            assert_eq!(b.epochs(), (1..=last).collect::<Vec<_>>());
        }
    }

    #[tokio::test]
    async fn another_holders_record_at_or_past_the_target_is_reset_past_everywhere() {
        for theirs in [1, 5] {
            let mut a = Sim::default();
            // Signed a little later than this holder signs, so the bytes
            // are not this holder's own.
            let mut b = Sim {
                race: Some(signed(theirs, now() + 5)),
                ..Sim::default()
            };
            let (report, kept) = reset(0, &mut [&mut a, &mut b]).await;
            let target = theirs + 1;
            assert_eq!(report.unwrap(), all_done(target, 2), "theirs at {theirs}");
            assert_eq!(a.epochs(), vec![1, target]);
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
                not_done: vec![not_done(
                    "r0",
                    "it answered epoch 1000000, and its list shows 0",
                    None
                )],
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
                ..not_done("r0", "it refused the reset", Some("rate_limited"))
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
            vec![not_done(
                "r0",
                "its last reset is dated ahead of this phone's clock",
                None
            )]
        );
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
                ..not_done(
                    "r0",
                    "its list could not be read: it asked to be left a while",
                    Some("rate_limited")
                )
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
        let mut good = Sim::default();
        let began = tokio::time::Instant::now();
        let report = reset(
            0,
            &mut [&mut quiet, &mut also_quiet, &mut stalls, &mut good],
        )
        .await
        .0
        .unwrap();
        // The reads in round 0, the stalled post, and the last reads.
        assert!(began.elapsed() <= 3 * WAIT, "{:?}", began.elapsed());
        assert_eq!((report.target, &report.done), (1, &vec!["r3".to_string()]));
        let late: Vec<_> = report
            .not_done
            .iter()
            .map(|n| n.registrar.as_str())
            .collect();
        assert_eq!(late, vec!["r0", "r1", "r2"]);
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
                    not_done("r0", "it answered epoch 1, and its list shows 0", None),
                    not_done("r1", "it answered epoch 0 to a post of 1", None),
                    not_done("r2", "it refused the reset", Some("not_registered")),
                ],
            }
        );
        assert_eq!((pretender.posts, below.posts), (1, 1));
    }
}

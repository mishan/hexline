//! A rotation as this phone keeps it between starts: how far it has gone,
//! at each registrar, and when each is posted to next. The app reads and
//! writes the file these bytes are; what they say, which registrars a
//! record is posted to and when, and what each answer leaves, are decided
//! here.

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use serde_json::{json, Map, Value};

use crate::holder::refused;
use crate::{CoreError, Posted};

/// How long a registrar is left after an answer that changed something, in
/// seconds, whatever its clock says of its times; doubled for each post in
/// a row that changed nothing, up to [`REPOST_CEILING`], so a freeze or a
/// registrar that will not answer costs it and the phone's battery little
/// however long it lasts.
const REPOST_FLOOR: i64 = 60;
const REPOST_CEILING: i64 = 3600;

/// The longest a `rate_limited` answer's `retry_after` is waited for, in
/// seconds.
const RETRY_AFTER_CEILING: i64 = 86_400;

/// How far a rotation has gone on this phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RotationState {
    /// About to hold the successor's key: nothing signed.
    Holding,
    /// Signed, and not yet sent anywhere.
    Signed,
    /// A send to a registrar may have reached it: the rotation can only be
    /// finished.
    Sent,
}

/// How far a rotation has gone at one registrar, in the order it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum RegistrarState {
    Signed,
    Sent,
    Pending,
    PendingElsewhere,
    /// Frozen there by its operator: posted again later, published once
    /// the freeze is lifted.
    Frozen,
    /// Refused there for good, as `refused` says: not posted to again. At
    /// the home registrar nothing else is posted either, and the identity
    /// stays as it was; what the person does then is the rotation screen's
    /// to offer.
    Refused,
    /// Another rotation to the same successor was published there first,
    /// under the commitment `superseded_by` names: another phone, or
    /// whoever holds the old key and the successor code. Not posted to
    /// again; at the home registrar, nothing else is.
    Superseded,
    /// The identity was rotated there to a key other than this rotation's,
    /// which `rotated_to` names: whoever holds the old key, or another
    /// phone with a successor code of its own. Not posted to again; at the
    /// home registrar, nothing else is.
    RotatedAway,
    Published,
    Reattested,
    CardPut,
}

/// The names the file gives the states, which every build reads.
const ROTATION_STATES: [(RotationState, &str); 3] = [
    (RotationState::Holding, "Holding"),
    (RotationState::Signed, "Signed"),
    (RotationState::Sent, "Sent"),
];

const REGISTRAR_STATES: [(RegistrarState, &str); 11] = [
    (RegistrarState::Signed, "Signed"),
    (RegistrarState::Sent, "Sent"),
    (RegistrarState::Pending, "Pending"),
    (RegistrarState::PendingElsewhere, "PendingElsewhere"),
    (RegistrarState::Frozen, "Frozen"),
    (RegistrarState::Refused, "Refused"),
    (RegistrarState::Superseded, "Superseded"),
    (RegistrarState::RotatedAway, "RotatedAway"),
    (RegistrarState::Published, "Published"),
    (RegistrarState::Reattested, "Reattested"),
    (RegistrarState::CardPut, "CardPut"),
];

/// A registrar a rotation is posted to, and the handles there to reissue.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RotationRegistrar {
    pub base: String,
    pub handles: Vec<String>,
    pub home: bool,
    pub state: RegistrarState,
    /// Where `state` is `Pending`, when the registrar publishes it, and
    /// where `PendingElsewhere`, when the rotation held before it does, in
    /// seconds: 0 where it did not say.
    #[uniffi(default = 0)]
    pub until: i64,
    /// Where `state` is `Refused`, the registrar's code.
    #[uniffi(default = None)]
    pub refused: Option<String>,
    /// Where `state` is `Superseded`, the commitment the published rotation
    /// names.
    #[uniffi(default = None)]
    pub superseded_by: Option<String>,
    /// Where `state` is `RotatedAway`, the key the identity was rotated to.
    #[uniffi(default = None)]
    pub rotated_to: Option<String>,
    /// When it was last posted to, answered or not, in seconds.
    #[uniffi(default = 0)]
    pub posted_at: i64,
    /// How long after `posted_at` it is posted to again, in seconds.
    #[uniffi(default = 0)]
    pub wait: i64,
    /// The posts in a row that changed nothing, no answer or the same one
    /// again, each doubling `wait`.
    #[uniffi(default = 0)]
    pub failures: i32,
}

/// A rotation of the identity `from` to its successor `to` under way: what
/// a start resumes it from, or discards it by. Not secret, but powerful:
/// anyone may post `record`, to the owner's own successor alone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeptRotation {
    pub from: String,
    pub to: String,
    /// `from`'s card, to read the successor code against again if the
    /// successor's hold is lost.
    pub card0: Vec<u8>,
    pub state: RotationState,
    /// Signed once, and sent as these bytes however often it is sent: there
    /// in every state but `Holding`.
    #[uniffi(default = None)]
    pub record: Option<Vec<u8>>,
    #[uniffi(default = [])]
    pub registrars: Vec<RotationRegistrar>,
    /// The successor's recovery envelope is stored at the home registrar.
    #[uniffi(default = false)]
    pub backed_up: bool,
}

impl KeptRotation {
    /// The registrars `record` is to be posted to at `now`, in seconds:
    /// none before it is marked sent, the home registrar alone until it has
    /// published, none posted to within its `wait` (but one the clock now
    /// puts in the future, set back since), a held one only once its time
    /// has come, and never one that refused it for good, was superseded or
    /// rotated away, or has published it.
    fn due(&self, now: i64) -> impl Iterator<Item = &RotationRegistrar> {
        let sent = self.state == RotationState::Sent;
        let home_published = self
            .registrars
            .iter()
            .filter(|r| r.home)
            .all(|r| r.state >= RegistrarState::Published);
        self.registrars.iter().filter(move |r| {
            // Wrapping, so a file's far-off times cannot panic.
            sent && (home_published || r.home)
                && (r.posted_at > now || now >= r.posted_at.wrapping_add(r.wait))
                && match r.state {
                    RegistrarState::Signed | RegistrarState::Sent | RegistrarState::Frozen => true,
                    RegistrarState::Pending | RegistrarState::PendingElsewhere => now >= r.until,
                    _ => false,
                }
        })
    }

    /// As `registrar`'s `answer` to `record`, posted at `now`, leaves it:
    /// none where none came, with the `retry_after` seconds a
    /// `rate_limited` one asked for, up to [`RETRY_AFTER_CEILING`].
    fn posted(
        &self,
        registrar: &str,
        answer: Option<Posted>,
        now: i64,
        retry_after: Option<i64>,
    ) -> Result<KeptRotation, CoreError> {
        if self.state != RotationState::Sent {
            return Err(refused("not_sent"));
        }
        if !self.registrars.iter().any(|r| r.base == registrar) {
            return Err(refused("not_its_registrar"));
        }
        let mut next = self.clone();
        for r in next.registrars.iter_mut().filter(|r| r.base == registrar) {
            let cleared = RotationRegistrar {
                base: r.base.clone(),
                handles: r.handles.clone(),
                home: r.home,
                state: RegistrarState::Signed,
                until: 0,
                refused: None,
                superseded_by: None,
                rotated_to: None,
                posted_at: 0,
                wait: 0,
                failures: 0,
            };
            let answered = match &answer {
                None => r.clone(),
                Some(Posted::Published) => RotationRegistrar {
                    state: RegistrarState::Published,
                    ..cleared
                },
                Some(Posted::Frozen) => RotationRegistrar {
                    state: RegistrarState::Frozen,
                    ..cleared
                },
                Some(Posted::Pending { until }) => RotationRegistrar {
                    state: RegistrarState::Pending,
                    until: *until as i64,
                    ..cleared
                },
                Some(Posted::PendingElsewhere { until }) => RotationRegistrar {
                    state: RegistrarState::PendingElsewhere,
                    until: until.map_or(0, |u| u as i64),
                    ..cleared
                },
                Some(Posted::Superseded { next }) => RotationRegistrar {
                    state: RegistrarState::Superseded,
                    superseded_by: next.clone(),
                    ..cleared
                },
                Some(Posted::RotatedAway { successor }) => RotationRegistrar {
                    state: RegistrarState::RotatedAway,
                    rotated_to: Some(successor.clone()),
                    ..cleared
                },
                Some(Posted::Refused { code }) => RotationRegistrar {
                    state: RegistrarState::Refused,
                    refused: Some(code.clone()),
                    ..cleared
                },
            };
            // The same answer again, a freeze's or a hold's past its time,
            // is waited on longer each time, as no answer is.
            let was = RotationRegistrar {
                posted_at: 0,
                wait: 0,
                failures: 0,
                ..r.clone()
            };
            *r = if answer.is_some() && answered != was {
                RotationRegistrar {
                    posted_at: now,
                    wait: REPOST_FLOOR,
                    ..answered
                }
            } else {
                // A damaged count below 0 waits the floor.
                let backoff = (REPOST_FLOOR << r.failures.clamp(0, 6)).min(REPOST_CEILING);
                let retry = retry_after.unwrap_or(0).min(RETRY_AFTER_CEILING);
                RotationRegistrar {
                    posted_at: now,
                    wait: backoff.max(retry),
                    failures: r.failures.wrapping_add(1),
                    ..answered
                }
            };
        }
        Ok(next)
    }

    /// The file's bytes. Refused `no_record` for a rotation past `Holding`
    /// without its record, or with an empty one, which the file would read
    /// back as none.
    fn encode(&self) -> Result<Vec<u8>, CoreError> {
        if self.state != RotationState::Holding
            && self.record.as_deref().is_none_or(<[u8]>::is_empty)
        {
            return Err(refused("no_record"));
        }
        let registrars: Vec<Value> = self
            .registrars
            .iter()
            .map(|r| {
                let mut o = json!({
                    "base": r.base,
                    "handles": r.handles,
                    "home": r.home,
                    "state": name(&REGISTRAR_STATES, r.state),
                    "until": r.until,
                    "posted_at": r.posted_at,
                    "wait": r.wait,
                    "failures": r.failures,
                });
                let fields = [
                    ("refused", &r.refused),
                    ("superseded_by", &r.superseded_by),
                    ("rotated_to", &r.rotated_to),
                ];
                for (key, value) in fields {
                    if let Some(v) = value {
                        o[key] = v.as_str().into();
                    }
                }
                o
            })
            .collect();
        let mut o = json!({
            "from": self.from,
            "to": self.to,
            "card0": FILE_B64.encode(&self.card0),
            "state": name(&ROTATION_STATES, self.state),
            "registrars": registrars,
        });
        if let Some(record) = &self.record {
            o["record"] = FILE_B64.encode(record).into();
        }
        if self.backed_up {
            o["backed_up"] = true.into();
        }
        Ok(o.to_string().into_bytes())
    }

    /// What `bytes` say, or none if they do not read as a rotation: a state
    /// this build does not know among them, so a newer build's file is left
    /// alone rather than taken for something it is not.
    fn decode(bytes: &[u8]) -> Option<KeptRotation> {
        let json: Map<String, Value> = serde_json::from_slice(bytes).ok()?;
        let state = named(&ROTATION_STATES, &json)?;
        let record = match optional(&json, "record")? {
            None => None,
            Some(s) => Some(unb64(s)?),
        };
        if state != RotationState::Holding && record.is_none() {
            return None;
        }
        let registrars = json
            .get("registrars")?
            .as_array()?
            .iter()
            .map(|r| {
                let r = r.as_object()?;
                Some(RotationRegistrar {
                    base: string(r, "base")?,
                    handles: r
                        .get("handles")?
                        .as_array()?
                        .iter()
                        .map(|h| h.as_str().map(str::to_owned))
                        .collect::<Option<_>>()?,
                    home: r.get("home")?.as_bool()?,
                    state: named(&REGISTRAR_STATES, r)?,
                    until: r.get("until")?.as_i64()?,
                    refused: optional(r, "refused")?.map(str::to_owned),
                    superseded_by: optional(r, "superseded_by")?.map(str::to_owned),
                    rotated_to: optional(r, "rotated_to")?.map(str::to_owned),
                    posted_at: number(r, "posted_at")?,
                    wait: number(r, "wait")?,
                    failures: i32::try_from(number(r, "failures")?).ok()?,
                })
            })
            .collect::<Option<_>>()?;
        Some(KeptRotation {
            from: string(&json, "from")?,
            to: string(&json, "to")?,
            card0: unb64(json.get("card0")?.as_str()?)?,
            state,
            record,
            registrars,
            backed_up: match json.get("backed_up") {
                None => false,
                Some(b) => b.as_bool()?,
            },
        })
    }
}

/// The first time from `at` that any of `rotations` is due somewhere: none
/// where none will be, or where the run that asks could not keep an answer
/// (`kept_every_answer` false): the record is still due by its file, and
/// posting it again at once would load the registrar and the battery for as
/// long as the disk refuses it, so it waits for the app to ask again.
fn next_due(rotations: &[KeptRotation], at: i64, kept_every_answer: bool) -> Option<i64> {
    if !kept_every_answer {
        return None;
    }
    let due_at = |t: i64| rotations.iter().any(|r| r.due(t).next().is_some());
    // One posted earlier in the run, due again while a later post was out: at once.
    if due_at(at) {
        return Some(at);
    }
    // Due changes only at these: a registrar's wait ending, a held time coming.
    let mut times: Vec<i64> = rotations
        .iter()
        .flat_map(|r| &r.registrars)
        .flat_map(|r| [r.posted_at.wrapping_add(r.wait), r.until])
        .filter(|&t| t > at)
        .collect();
    times.sort_unstable();
    times.into_iter().find(|&t| due_at(t))
}

/// The bases of the registrars `rotation`'s record is to be posted to at
/// `now`, in seconds, home first: see [`KeptRotation::due`].
#[uniffi::export]
pub fn rotation_due(rotation: KeptRotation, now: i64) -> Vec<String> {
    rotation.due(now).map(|r| r.base.clone()).collect()
}

/// `rotation` as `registrar`'s `answer`, posted at `now`, leaves it: none
/// where none came, with the `retry_after` a `rate_limited` one asked for.
/// Refused `not_sent` for a rotation not marked sent, `not_its_registrar`
/// for a registrar it has none of.
#[uniffi::export]
pub fn rotation_posted(
    rotation: KeptRotation,
    registrar: String,
    answer: Option<Posted>,
    now: i64,
    retry_after: Option<i64>,
) -> Result<KeptRotation, CoreError> {
    rotation.posted(&registrar, answer, now, retry_after)
}

/// When a post of any of `rotations` is next due, from `at`, in seconds:
/// see [`next_due`].
#[uniffi::export]
pub fn rotations_next_due(
    rotations: Vec<KeptRotation>,
    at: i64,
    kept_every_answer: bool,
) -> Option<i64> {
    next_due(&rotations, at, kept_every_answer)
}

/// `rotation` as its file's bytes: see [`KeptRotation::encode`].
#[uniffi::export]
pub fn encode_rotation(rotation: KeptRotation) -> Result<Vec<u8>, CoreError> {
    rotation.encode()
}

/// What a rotation's file says: see [`KeptRotation::decode`].
#[uniffi::export]
pub fn decode_rotation(bytes: Vec<u8>) -> Option<KeptRotation> {
    KeptRotation::decode(&bytes)
}

/// Standard base64 with its padding, as the file has always had it, read
/// with or without.
const FILE_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn unb64(s: &str) -> Option<Vec<u8>> {
    FILE_B64.decode(s).ok()
}

fn name<S: Copy + PartialEq>(names: &[(S, &'static str)], state: S) -> &'static str {
    names
        .iter()
        .find(|(s, _)| *s == state)
        .map(|(_, n)| *n)
        .unwrap()
}

fn named<S: Copy>(names: &[(S, &str)], o: &Map<String, Value>) -> Option<S> {
    let n = o.get("state")?.as_str()?;
    names.iter().find(|(_, name)| *name == n).map(|(s, _)| *s)
}

fn string(o: &Map<String, Value>, key: &str) -> Option<String> {
    o.get(key)?.as_str().map(str::to_owned)
}

/// A string the file may leave out, or leave empty, for none: the outer
/// none where it is there and not a string.
fn optional<'a>(o: &'a Map<String, Value>, key: &str) -> Option<Option<&'a str>> {
    match o.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(v) => v.as_str().map(|s| Some(s).filter(|s| !s.is_empty())),
    }
}

/// A number the file may leave out for 0, as files from before it was kept
/// do.
fn number(o: &Map<String, Value>, key: &str) -> Option<i64> {
    match o.get(key) {
        None => Some(0),
        Some(v) => v.as_i64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "https://home.example";
    const OTHER: &str = "https://other.example";
    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn rotation(state: RotationState, registrars: &[RotationRegistrar]) -> KeptRotation {
        KeptRotation {
            from: "k0".into(),
            to: "k1".into(),
            card0: vec![1],
            state,
            record: Some(vec![2]),
            registrars: registrars.to_vec(),
            backed_up: false,
        }
    }

    fn sent(registrars: &[RotationRegistrar]) -> KeptRotation {
        rotation(RotationState::Sent, registrars)
    }

    fn at(base: &str, state: RegistrarState) -> RotationRegistrar {
        RotationRegistrar {
            base: base.into(),
            handles: vec!["alice".into()],
            home: base == HOME,
            state,
            until: 0,
            refused: None,
            superseded_by: None,
            rotated_to: None,
            posted_at: 0,
            wait: 0,
            failures: 0,
        }
    }

    /// Held until `until`, posted at `posted_at` and left the floor after.
    fn held(base: &str, state: RegistrarState, until: i64, posted_at: i64) -> RotationRegistrar {
        RotationRegistrar {
            until,
            posted_at,
            wait: if posted_at > 0 { REPOST_FLOOR } else { 0 },
            ..at(base, state)
        }
    }

    fn due(r: &KeptRotation, now: i64) -> Vec<String> {
        rotation_due(r.clone(), now)
    }

    fn post(r: &KeptRotation, answer: Option<Posted>, now: i64) -> KeptRotation {
        r.posted(HOME, answer, now, None).unwrap()
    }

    fn home(r: &KeptRotation) -> &RotationRegistrar {
        r.registrars.iter().find(|r| r.home).unwrap()
    }

    fn refusal(r: Result<KeptRotation, CoreError>) -> String {
        match r {
            Err(CoreError::Refused { code, .. }) => code,
            other => panic!("not refused: {other:?}"),
        }
    }

    #[test]
    fn a_registrars_answer_is_kept_for_it_alone_and_read_back_from_the_file() {
        use RegistrarState::*;
        // Held before, so what a later answer does not say is cleared.
        let was = held(HOME, Pending, 50, 1);
        let answered = |state, until| held(HOME, state, until, NOW);
        let cases = [
            (Some(Posted::Published), answered(Published, 0)),
            (Some(Posted::Frozen), answered(Frozen, 0)),
            (Some(Posted::Pending { until: 100 }), answered(Pending, 100)),
            (
                Some(Posted::PendingElsewhere { until: Some(200) }),
                answered(PendingElsewhere, 200),
            ),
            (
                Some(Posted::PendingElsewhere { until: None }),
                answered(PendingElsewhere, 0),
            ),
            (
                Some(Posted::Superseded {
                    next: Some("c2".into()),
                }),
                RotationRegistrar {
                    superseded_by: Some("c2".into()),
                    ..answered(Superseded, 0)
                },
            ),
            (
                Some(Posted::Refused {
                    code: "successor_mismatch".into(),
                }),
                RotationRegistrar {
                    refused: Some("successor_mismatch".into()),
                    ..answered(Refused, 0)
                },
            ),
            (
                Some(Posted::RotatedAway {
                    successor: "k2".into(),
                }),
                RotationRegistrar {
                    rotated_to: Some("k2".into()),
                    ..answered(RotatedAway, 0)
                },
            ),
            (
                None,
                RotationRegistrar {
                    posted_at: NOW,
                    failures: 1,
                    ..was.clone()
                },
            ),
        ];
        for (answer, want) in cases {
            let posted = post(
                &sent(&[was.clone(), at(OTHER, Signed)]),
                answer.clone(),
                NOW,
            );
            assert_eq!(posted.registrars, [want, at(OTHER, Signed)], "{answer:?}");
            let read = KeptRotation::decode(&posted.encode().unwrap());
            assert_eq!(read, Some(posted), "{answer:?}, read back");
        }
        let published = Some(Posted::Published);
        assert_eq!(
            refusal(sent(std::slice::from_ref(&was)).posted(OTHER, published.clone(), NOW, None)),
            "not_its_registrar"
        );
        assert_eq!(
            refusal(rotation(RotationState::Signed, &[was]).posted(HOME, published, NOW, None)),
            "not_sent"
        );
    }

    #[test]
    fn a_record_is_posted_home_first_and_not_again_once_held_until_its_time_or_refused_for_good() {
        use RegistrarState::*;
        let posted = |state, posted_at| held(HOME, state, 0, posted_at);
        let none: &[&str] = &[];
        let cases: &[(&str, KeptRotation, &[&str])] = &[
            (
                "not yet sent",
                rotation(RotationState::Signed, &[at(HOME, Signed)]),
                none,
            ),
            (
                "home first",
                sent(&[at(HOME, Sent), at(OTHER, Signed)]),
                &[HOME],
            ),
            ("held", sent(&[held(HOME, Pending, NOW + 1, 0)]), none),
            (
                "held till now",
                sent(&[held(HOME, Pending, NOW, 0)]),
                &[HOME],
            ),
            (
                "behind another",
                sent(&[held(HOME, PendingElsewhere, NOW + 1, 0)]),
                none,
            ),
            (
                "behind another till now",
                sent(&[held(HOME, PendingElsewhere, NOW, 0)]),
                &[HOME],
            ),
            ("frozen", sent(&[at(HOME, Frozen)]), &[HOME]),
            (
                "posted just now",
                sent(&[posted(Sent, NOW - REPOST_FLOOR + 1)]),
                none,
            ),
            (
                "frozen just now",
                sent(&[posted(Frozen, NOW - REPOST_FLOOR + 1)]),
                none,
            ),
            (
                "held past its time by a clock ahead",
                sent(&[held(HOME, Pending, NOW - 5, NOW - 1)]),
                none,
            ),
            (
                "posted in the future by a clock set back since",
                sent(&[posted(Sent, NOW + DAY)]),
                &[HOME],
            ),
            (
                "posted a while ago",
                sent(&[posted(Sent, NOW - REPOST_FLOOR)]),
                &[HOME],
            ),
            (
                "refused at home",
                sent(&[at(HOME, Refused), at(OTHER, Signed)]),
                none,
            ),
            (
                "rotated away at home",
                sent(&[at(HOME, RotatedAway), at(OTHER, Signed)]),
                none,
            ),
            (
                "superseded at home",
                sent(&[at(HOME, Superseded), at(OTHER, Signed)]),
                none,
            ),
            (
                "published at home",
                sent(&[at(HOME, Published), at(OTHER, Signed)]),
                &[OTHER],
            ),
            (
                "reattested at home",
                sent(&[at(HOME, Reattested), at(OTHER, Sent)]),
                &[OTHER],
            ),
            (
                "refused elsewhere",
                sent(&[at(HOME, Published), at(OTHER, Refused)]),
                none,
            ),
            (
                "held elsewhere",
                sent(&[at(HOME, CardPut), held(OTHER, Pending, NOW + 1, 0)]),
                none,
            ),
        ];
        for (what, rotation, want) in cases {
            assert_eq!(due(rotation, NOW), *want, "{what}");
        }
    }

    #[test]
    fn posts_that_get_no_answer_are_left_longer_each_time_until_one_does() {
        let mut r = sent(&[at(HOME, RegistrarState::Sent)]);
        let waits: Vec<i64> = (0..8)
            .map(|i| {
                r = post(&r, None, NOW + i);
                home(&r).wait
            })
            .collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600]);
        let r = KeptRotation::decode(&r.encode().unwrap()).unwrap();
        assert_eq!(
            (home(&r).wait, home(&r).failures),
            (3600, 8),
            "kept in the file"
        );
        let last = NOW + 7;
        assert!(due(&r, last + 3599).is_empty(), "not before its wait");
        assert_eq!(due(&r, last + 3600), [HOME], "after it");

        let limited = sent(&[at(HOME, RegistrarState::Sent)])
            .posted(HOME, None, NOW, Some(7200))
            .unwrap();
        let limited = KeptRotation::decode(&limited.encode().unwrap()).unwrap();
        assert!(
            due(&limited, NOW + 7199).is_empty(),
            "a registrar's retry_after, kept"
        );
        assert_eq!(due(&limited, NOW + 7200), [HOME]);

        let answered = post(
            &r,
            Some(Posted::PendingElsewhere { until: None }),
            last + 3600,
        );
        assert_eq!(
            (home(&answered).wait, home(&answered).failures),
            (REPOST_FLOOR, 0),
            "an answer starts again"
        );
    }

    #[test]
    fn the_same_answer_again_is_left_longer_each_time_until_another_comes() {
        let pending = |until: i64| Posted::Pending {
            until: until as u64,
        };
        for answer in [
            Posted::Frozen,
            Posted::PendingElsewhere { until: None },
            pending(NOW),
        ] {
            let mut r = sent(&[at(HOME, RegistrarState::Sent)]);
            let waits: Vec<i64> = (0..5)
                .map(|i| {
                    r = post(&r, Some(answer.clone()), NOW + i * REPOST_CEILING);
                    home(&r).wait
                })
                .collect();
            assert_eq!(waits, [60, 60, 120, 240, 480], "{answer:?}");
            let other = post(&r, Some(pending(NOW + 99)), NOW + 5 * REPOST_CEILING);
            assert_eq!(
                (home(&other).wait, home(&other).failures),
                (REPOST_FLOOR, 0),
                "{answer:?}, then another"
            );
        }
    }

    #[test]
    fn a_retry_after_past_a_day_is_waited_for_a_day() {
        let r = sent(&[at(HOME, RegistrarState::Sent)])
            .posted(HOME, None, NOW, Some(i64::MAX))
            .unwrap();
        assert_eq!(home(&r).wait, RETRY_AFTER_CEILING);
        assert_eq!(due(&r, NOW + RETRY_AFTER_CEILING), [HOME]);
    }

    #[test]
    fn the_next_post_is_timed_by_the_first_wait_or_hold_to_end_and_not_once_an_answer_was_lost() {
        use RegistrarState::*;
        let waiting = held(HOME, Sent, 0, NOW);
        let cases: &[(&str, Vec<KeptRotation>, bool, Option<i64>)] = &[
            ("due now", vec![sent(&[at(HOME, Sent)])], true, Some(NOW)),
            (
                "its wait",
                vec![sent(std::slice::from_ref(&waiting))],
                true,
                Some(NOW + REPOST_FLOOR),
            ),
            (
                "a hold past its wait",
                vec![sent(&[held(HOME, Pending, NOW + DAY, NOW)])],
                true,
                Some(NOW + DAY),
            ),
            (
                "the first of two",
                vec![
                    sent(&[held(HOME, Pending, NOW + DAY, NOW)]),
                    sent(std::slice::from_ref(&waiting)),
                ],
                true,
                Some(NOW + REPOST_FLOOR),
            ),
            (
                "a wait ending while home has not published",
                vec![sent(&[
                    held(HOME, Pending, NOW + DAY, NOW),
                    held(OTHER, Sent, 0, NOW),
                ])],
                true,
                Some(NOW + DAY),
            ),
            (
                "none due again",
                vec![sent(&[at(HOME, Published)])],
                true,
                None,
            ),
            (
                "an answer not kept",
                vec![sent(&[at(HOME, Sent)])],
                false,
                None,
            ),
        ];
        for (what, rotations, kept, want) in cases {
            assert_eq!(next_due(rotations, NOW, *kept), *want, "{what}");
        }
    }

    #[test]
    fn a_files_numbers_out_of_range_neither_panic_nor_repost_at_once() {
        use RegistrarState::*;
        let backwards = RotationRegistrar {
            failures: -1,
            ..at(HOME, Sent)
        };
        let posted = post(&sent(&[backwards]), None, NOW);
        assert_eq!(
            (home(&posted).wait, home(&posted).failures),
            (REPOST_FLOOR, 0)
        );
        let endless = RotationRegistrar {
            posted_at: NOW - 1,
            wait: i64::MAX,
            ..at(HOME, Sent)
        };
        assert_eq!(due(&sent(&[endless]), NOW), [HOME]);
        let endless = RotationRegistrar {
            posted_at: NOW - 1,
            wait: i64::MAX,
            ..at(HOME, Sent)
        };
        assert_eq!(next_due(&[sent(&[endless])], NOW, true), Some(NOW));
        // Never due, so only its time's sum is at stake.
        let far = RotationRegistrar {
            posted_at: i64::MAX - 10,
            wait: REPOST_FLOOR,
            ..at(HOME, Published)
        };
        assert_eq!(next_due(&[sent(&[far])], NOW, true), None);
    }

    #[test]
    fn a_file_the_previous_build_wrote_reads_and_one_it_would_not_read_does_not() {
        // As earlier builds wrote it: slashes escaped, keys in their order.
        let old = br#"{"from":"k0","to":"k1","card0":"AQ==","state":"Sent","registrars":[{"base":"https:\/\/home.example","handles":["alice"],"home":true,"state":"PendingElsewhere","until":5,"posted_at":4,"wait":60,"failures":2,"superseded_by":"c2"},{"base":"https:\/\/other.example","handles":[],"home":false,"state":"Signed","until":0}],"record":"Ag==","backed_up":true}"#;
        let want = KeptRotation {
            registrars: vec![
                RotationRegistrar {
                    until: 5,
                    posted_at: 4,
                    wait: 60,
                    failures: 2,
                    superseded_by: Some("c2".into()),
                    ..at(HOME, RegistrarState::PendingElsewhere)
                },
                RotationRegistrar {
                    handles: vec![],
                    ..at(OTHER, RegistrarState::Signed)
                },
            ],
            backed_up: true,
            ..sent(&[])
        };
        assert_eq!(KeptRotation::decode(old).as_ref(), Some(&want));
        let text = String::from_utf8(old.to_vec()).unwrap();
        for (what, bytes) in [
            (
                "a rotation state not known",
                text.replace(r#""state":"Sent""#, r#""state":"Finished""#),
            ),
            (
                "a registrar state not known",
                text.replace("PendingElsewhere", "Held"),
            ),
            (
                "sent without its record",
                text.replace(r#""record":"Ag==","#, ""),
            ),
            ("no until", text.replace(r#","until":0"#, "")),
            ("a record that does not read", text.replace("Ag==", "*")),
            (
                "a card that does not read",
                text.replace(r#""card0":"AQ==""#, r#""card0":"*""#),
            ),
            (
                "a field of the wrong type",
                text.replace(r#""home":true"#, r#""home":"true""#),
            ),
            ("not json", "{".into()),
        ] {
            assert_eq!(KeptRotation::decode(bytes.as_bytes()), None, "{what}");
        }
        for record in [None, Some(vec![])] {
            let unrecorded = KeptRotation {
                record: record.clone(),
                ..want.clone()
            };
            assert!(
                matches!(unrecorded.encode(), Err(CoreError::Refused { code, .. }) if code == "no_record"),
                "{record:?}"
            );
        }
    }
}

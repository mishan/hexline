//! What the person is told of a rotation sent: the worst any of its
//! registrars answered, and whether that may be someone else's doing.

use crate::{KeptRotation, RegistrarState, RotationRegistrar};

/// A rotation's notice: what `registrar` answered, and whether it is an
/// alarm, to be shown whichever way the person signs in.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RotationNotice {
    pub registrar: String,
    pub alarm: bool,
    pub kind: RotationNoticeKind,
}

/// What a registrar answered a rotation, as the person is told it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RotationNoticeKind {
    /// Sent, published, or not yet answered: nothing to say beyond that it
    /// is under way.
    UnderWay,
    /// Held for the registrar's delay: `until`, when it publishes, in
    /// seconds, 0 where the file does not say.
    Pending {
        until: i64,
    },
    Frozen,
    /// Refused for good: `revoked`, which anyone holding the old key alone
    /// can do, or `not_registered`.
    Refused {
        code: String,
    },
    /// Another rotation is held there: the window in which the operator can
    /// still freeze it. `until` where the registrar said.
    PendingElsewhere {
        until: Option<i64>,
    },
    /// `successor_mismatch`: the identity or its successor is held to a
    /// commitment this phone did not make.
    Mismatch,
    /// Published to this phone's successor under another commitment:
    /// whoever made it controls the next move.
    Superseded,
    /// Rotated there to a key this phone does not hold: the identity is
    /// whoever holds that key.
    RotatedAway,
}

impl RotationNoticeKind {
    fn at(r: &RotationRegistrar) -> Self {
        match r.state {
            RegistrarState::Pending => Self::Pending { until: r.until },
            RegistrarState::PendingElsewhere => Self::PendingElsewhere {
                until: Some(r.until).filter(|&u| u > 0),
            },
            RegistrarState::Frozen => Self::Frozen,
            RegistrarState::Superseded => Self::Superseded,
            RegistrarState::RotatedAway => Self::RotatedAway,
            RegistrarState::Refused => match r.refused.as_deref() {
                Some("successor_mismatch") => Self::Mismatch,
                code => Self::Refused {
                    code: code.unwrap_or_default().to_owned(),
                },
            },
            _ => Self::UnderWay,
        }
    }

    fn alarm(&self) -> bool {
        match self {
            Self::UnderWay | Self::Pending { .. } | Self::Frozen => false,
            Self::Refused { code } => code == "revoked",
            Self::PendingElsewhere { .. }
            | Self::Mismatch
            | Self::Superseded
            | Self::RotatedAway => true,
        }
    }

    fn severity(&self) -> u8 {
        match self {
            Self::UnderWay => 0,
            Self::Pending { .. } => 1,
            Self::Frozen => 2,
            // A revocation is an alarm, so above the refusals that are not.
            Self::Refused { .. } => 3 + u8::from(self.alarm()),
            Self::PendingElsewhere { .. } => 5,
            Self::Mismatch => 6,
            Self::Superseded => 7,
            Self::RotatedAway => 8,
        }
    }
}

/// `rotation`'s notice: its registrars' worst, the home registrar's where
/// two are as bad; none without a registrar.
#[uniffi::export]
pub fn rotation_notice(rotation: KeptRotation) -> Option<RotationNotice> {
    let homes = rotation.registrars.iter().filter(|r| r.home);
    let others = rotation.registrars.iter().filter(|r| !r.home);
    let mut worst: Option<(&RotationRegistrar, RotationNoticeKind)> = None;
    for r in homes.chain(others) {
        let kind = RotationNoticeKind::at(r);
        if worst
            .as_ref()
            .is_none_or(|(_, w)| kind.severity() > w.severity())
        {
            worst = Some((r, kind));
        }
    }
    worst.map(|(r, kind)| RotationNotice {
        registrar: r.base.clone(),
        alarm: kind.alarm(),
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RotationState;

    const HOME: &str = "https://hl.example";
    const OTHER: &str = "https://other.example";
    const THIRD: &str = "https://third.example";

    fn at(base: &str, state: RegistrarState, refused: Option<&str>) -> RotationRegistrar {
        RotationRegistrar {
            base: base.into(),
            handles: vec!["alice".into()],
            home: base == HOME,
            state,
            until: 0,
            refused: refused.map(str::to_owned),
            superseded_by: None,
            rotated_to: None,
            posted_at: 0,
            wait: 0,
            failures: 0,
        }
    }

    fn notice(base: &str, kind: RotationNoticeKind) -> Option<RotationNotice> {
        Some(RotationNotice {
            registrar: base.into(),
            alarm: kind.alarm(),
            kind,
        })
    }

    #[test]
    fn a_rotation_is_shown_as_its_registrars_worst_answer_home_first() {
        use RegistrarState::*;
        use RotationNoticeKind as K;
        let refused = |code: &str| K::Refused { code: code.into() };
        let cases = [
            (
                vec![at(HOME, Sent, None), at(OTHER, Signed, None)],
                notice(HOME, K::UnderWay),
            ),
            (
                vec![at(HOME, Published, None), at(OTHER, Frozen, None)],
                notice(OTHER, K::Frozen),
            ),
            (
                vec![at(HOME, Published, None), at(OTHER, Superseded, None)],
                notice(OTHER, K::Superseded),
            ),
            (
                vec![
                    at(OTHER, Refused, Some("not_registered")),
                    at(HOME, Refused, Some("not_registered")),
                ],
                notice(HOME, refused("not_registered")),
            ),
            (
                vec![
                    at(HOME, Refused, Some("not_registered")),
                    at(OTHER, Refused, Some("revoked")),
                ],
                notice(OTHER, refused("revoked")),
            ),
            (
                vec![
                    at(HOME, Refused, Some("revoked")),
                    at(OTHER, PendingElsewhere, None),
                ],
                notice(OTHER, K::PendingElsewhere { until: None }),
            ),
            (
                vec![
                    at(HOME, Superseded, None),
                    at(OTHER, Refused, Some("successor_mismatch")),
                ],
                notice(HOME, K::Superseded),
            ),
            (
                vec![
                    at(HOME, PendingElsewhere, None),
                    at(OTHER, Refused, Some("successor_mismatch")),
                ],
                notice(OTHER, K::Mismatch),
            ),
            (
                vec![
                    at(HOME, Published, None),
                    at(OTHER, Superseded, None),
                    at(THIRD, RotatedAway, None),
                ],
                notice(THIRD, K::RotatedAway),
            ),
            (
                vec![RotationRegistrar {
                    until: 7,
                    ..at(HOME, Pending, None)
                }],
                notice(HOME, K::Pending { until: 7 }),
            ),
            (
                vec![RotationRegistrar {
                    until: 5,
                    ..at(HOME, PendingElsewhere, None)
                }],
                notice(HOME, K::PendingElsewhere { until: Some(5) }),
            ),
            (
                vec![
                    RotationRegistrar {
                        home: true,
                        ..at(OTHER, Frozen, None)
                    },
                    at(HOME, Frozen, None),
                ],
                notice(OTHER, K::Frozen),
            ),
            (vec![], None),
        ];
        for (registrars, want) in cases {
            let rotation = KeptRotation {
                from: "k0".into(),
                to: "k1".into(),
                card0: vec![1],
                state: RotationState::Sent,
                record: Some(vec![2]),
                registrars: registrars.clone(),
                backed_up: false,
            };
            assert_eq!(rotation_notice(rotation), want, "{registrars:?}");
        }
    }

    #[test]
    fn what_may_be_someone_elses_doing_is_an_alarm() {
        use RotationNoticeKind as K;
        let refused = |code: &str| K::Refused { code: code.into() };
        for (kind, alarm) in [
            (K::UnderWay, false),
            (K::Pending { until: 1 }, false),
            (K::Frozen, false),
            (refused("not_registered"), false),
            (refused("revoked"), true),
            (K::PendingElsewhere { until: None }, true),
            (K::Mismatch, true),
            (K::Superseded, true),
            (K::RotatedAway, true),
        ] {
            assert_eq!(kind.alarm(), alarm, "{kind:?}");
        }
    }
}

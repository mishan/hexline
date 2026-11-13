# Hexline — design

Hexline is a native Android client for Hotline-ng. This is its design as
first agreed (2026-11-12); decisions since are in §8.

## 0. Frame and decisions so far

- **Problem.** The ng protocol exists for a mobile client, and there is
  none. Hexline is that client: presence that survives network changes
  and backgrounding (detach/resume), notifications while closed, and an
  identity that lives on the phone without a terminal anywhere.
- **Success.** An account (not a guest: guests never detach) stays
  present across Wi-Fi/cellular handoffs and short backgrounding with
  no join/part churn; a PM or a news reply arrives as
  a notification when closed; a user can create an identity on the
  phone, sign in with it on a second phone, and enroll a browser from
  it; interoperates on one server with hx-ng and GtkHx users.
- **v1 scope.** Servers (bookmarks, discovery), roster, lobby chat and
  rooms, history, PMs and the inbox, news (categories, threads,
  posting, the **timeline**, follow/mute, unread), replies, reactions,
  server emoji, avatars, identity (all three modes), push.
- **v1.x.** Classic servers through `hlrelay`; instant messaging and
  friends (`messaging`, `friendships`); sealed messages.
- **Later.** Voice, video, files (once the server has them), iOS.
- **Tiers.** Critical: identity, key storage, anything that signs or
  seals. Service: everything else.
- **Settled.** Shared Rust for protocol and identity — no new
  implementation in Kotlin (option A). minSdk 29 (Android 10). Ship on
  F-Droid; Play later. Own repo, `hexline`.

## 1. Shape

```
┌─────────────────────────── hexline (Android repo) ───────────────────────────┐
│  app/      Kotlin, Jetpack Compose. UI, view models, Room cache, Keystore,   │
│            WorkManager, UnifiedPush / FCM receivers. No protocol logic.     │
│  core/     Rust crate `hexline-core`, exported with uniffi. Owns sockets,   │
│            protocol state, identity flows. Built per ABI by cargo-ndk.      │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ git deps, pinned revs
              ┌────────────────────────┴───────────────────────────┐
              │ hx-libs                                            │
              │   hxng-client   NEW: the ng wire, client side       │
              │   hl-identity   MOVED from hxd-ng                   │
              │   hxsession     (v1.x, classic via hlrelay)         │
              └────────────────────────────────────────────────────┘
```

The rule: **Kotlin never parses a frame, a CBOR object, or a signature.**
It renders typed state the core gives it, and it holds keys at rest.

### 1.1 `hl-identity` moves to hx-libs (before the identity slice)

AGENTS.md already says it "may eventually belong beside `hxproto` in
hx-libs"; a third consumer is the moment. hxd-ng then takes it by the
same pin as `hxproto`. Moving it is a no-behavior change in hxd-ng, done
as its own PR pair (hx-libs adds, hxd-ng advances the pin and deletes
its copy). Until then Hexline could take it as a git dependency on
hxd-ng; cargo builds only the crate, but it couples Hexline's pin to the
server's tree, so the move goes first.

### 1.2 `hxng-client` (new; incubated in Hexline, then hx-libs)

It starts as a workspace crate in the Hexline repo, so the first chat
line on screen does not wait on hx-libs pins, and moves to hx-libs once
its API has held still through a few slices — the same code moved, not
a second copy. Its destination is the ng wire for any Rust client: GtkHx eventually, `hxd-testclient`'s
ng half (its classic half, and the raw-frame escape hatch tests need to
send malformed input, stay its own), and Hexline. hx-ng's
TypeScript library stays the independent second implementation that
hxd-ng's e2e suite relies on, so the "evidence, not tautology" property
survives: server, TS client, and this one were each written from the
spec.

Two layers:

- **Sans-IO core** (`no tokio`): serde types for every request, reply
  and event Hexline uses, plus a `Session` state machine — request id
  allocation and reply correlation, seq accounting (§3 of the spec:
  unknown `ev` still counts; a gap is a protocol error, not a skip),
  the handshake states (login → live; resume → live | resync_required
  → sync), and the detach contract (`detach: null` ⇒ never resume).
  It takes bytes in and gives frames out, so every rule is testable
  without a socket.
- **Driver** (feature `tokio`): tokio-tungstenite + rustls on `ring`
  (aws-lc-rs needs cmake and NDK clang, which F-Droid's builders make
  painful), certificates checked by `rustls-platform-verifier` so the
  Android trust store, user CAs included, applies; keepalive
  answers, and the HTTP side the ng port serves — discovery, the
  challenge binding (`hotline-ng-auth.md` §6.2) and token, identity
  endpoints, the enrollment mailbox, registrar calls, and byte routes
  (avatars, media, `GET /emoji/{hash}`, news attachments) with ETag
  revalidation.

Unknown fields and events are kept as raw JSON beside the typed ones, so
a newer server costs nothing and a frame can be logged for a bug
report (with `token` redacted — the spec forbids logging it).

### 1.3 `hexline-core` (in the Hexline repo)

The app-shaped layer over the two crates, and the only thing uniffi
exports:

- `ServerConnection` — one per bookmarked server, owning its
  `hxng_client::Session`, its reconnect policy (§4) and its identity
  auth. A **trait** in Rust, `Backend`, sits under it with the
  capability set as data; `NgBackend` is v1, `ClassicBackend` over
  `hxsession` through `hlrelay` is v1.x. The UI asks the connection
  what it can do (`caps`) and hides what it cannot, so a classic server
  later is a smaller capability set, not a second UI.
- A typed event stream to Kotlin (uniffi callback interface): roster
  changes, chat lines, PMs, news invalidations, reaction batches, emoji
  catalog changes, connection state. Coalesced per frame-batch so a
  replay of 500 events is one UI update, not 500.
- `IdentityVault` — the flows of §2, calling a Kotlin `KeyStoreBridge`
  for sealed-at-rest storage.

uniffi's async support covers requests (`suspend fun` in Kotlin); a
single tokio runtime lives in the core for the process.

## 2. Identity on the phone

### 2.1 Three ways a phone gets an identity

| Mode | Phone holds | First run | Renewal (90 days, at one-third left) |
|---|---|---|---|
| **Holder** | identity seed (wrapped), device keys | Generate identity + device; self-certify; card; register a handle; make the recovery code (§2.2) and the successor (§2.2) and confirm both were written down **before** the registration that commits them; put a passphrase envelope where the registrar serves them | Self-mint, behind a biometric/PIN prompt |
| **Enrolled device** | device keys only | Scan the QR an `hlid` (or another Hexline holder) draws, or type the code; the mailbox flow of `identity-enrollment.md` §5 | `prev`-renewal through the mailbox to a standing holder (`hlid agent`); `no_holder` falls back to a code, so without an agent expect a code a quarter |
| **Envelope** | device keys only; seed for seconds | Handle + passphrase (or recovery code) → fetch envelope → unwrap → mint own cert → drop seed (`identity-registrar.md` §9.4) | Same: passphrase, unwrap, mint, drop. Needs registrar envelopes, which are not built (§2.4) |

A user can move between them: an envelope device can promote itself to
holder (keep the seed, wrapped), and a holder can demote (forget it).

**What a holder phone can do for others.** Answer enrollment requests:
it opens a holder session at the mailbox and shows the code; a browser
or tunnel types it. (The reverse — the phone scanning a QR of the
enrollee's device key — is not specified; `identity-enrollment.md` §5.6
calls it the native-client future. Not in v1.) Revoke a lost device and
manage links — its own device cert carries `manage`. The identity key
itself never signs a login: the login proof is the device key's.

**The QR.** `hlid enroll` draws an `https://…/app/#enroll=…` URL, and
only when discovery advertises a same-origin `web` (enrollment §5.6).
Hexline scans it with its own camera and reads the fragment; no App
Links needed. The pinned identity and `pair` give the software-checked
binding the browser gets. With a typed code instead, Hexline shows the
device fingerprint and the user compares it, as the spec requires.

**Re-signing, not re-posting.** Registrar replay protection lasts the
skew window (300 s), so an operation interrupted by process death is
signed again with a fresh `time`, never resent from a saved object.

**Certificate size.** The phone's cert stays at most 512 bytes (a short
`name`), or `signs` and `sealed` are refused at login (spec §6.1).

### 2.2 Keys at rest

Every key is a 32-byte seed handled by Rust (`hl-identity`). No
Keystore-native Ed25519: it needs API 33 and KeyMint 2, is absent on
many devices and on every StrongBox, and would split signing between
two implementations. Instead:

| Secret | Wrapped by | Unwrapped when |
|---|---|---|
| Device signing + X25519 seeds, session tokens, saved passwords, push keys (RFC 8291 P-256 key and auth secret, per server), push `devid`s | **Key A**: Keystore AES-256-GCM in the TEE (StrongBox is too slow and too often busy for the push path), blobs in credential-encrypted storage, *no* `setUnlockedDeviceRequired` and no per-use auth — usable after first unlock, so a push woken on a locked phone can decrypt and a background reconnect can authenticate | When needed; device seeds held in Rust memory (`zeroize`) for the process |
| Identity seed (holder mode) | **Key B**: per-use user auth. API 30+: `setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` with a `CryptoObject`. API 29, where a credential cannot authorize a per-use key: a 15-second validity window confirmed by `BiometricPrompt` with device credential allowed. `setInvalidatedByBiometricEnrollment(false)` — adding a fingerprint must not destroy the identity | Per operation — mint, card, revoke, rotate, envelope put — then zeroized |
| Successor seed | **Never on the phone.** Generated, shown once as a code (Crockford base32, groups of five) or saved to a file the user picks, confirmed by re-entry, then zeroized. Only its hash is committed | At rotation, typed back in |
| Recovery code | Never stored. It wraps the identity seed in an §9.1 envelope; the envelope goes to the registrar when it serves envelopes and otherwise to a file the user saves off the phone | At recovery |

Holder mode is not usable until the recovery code exists: with a
Keystore key as the only copy, a factory reset, a removed screen lock
or a lost phone would end the identity. The envelope object and its
derivation go in `hl-identity` with vectors whether or not a registrar
stores them, so the offline-file form needs no server.

Kotlin ByteArrays carrying a plaintext seed are filled with zeros after
the handoff; the residual (JVM copies) is noted in the threat model
entry Hexline adds. Backups: `android:allowBackup="false"` and
`dataExtractionRules` excluding everything; a Keystore key never
leaves the device anyway, so a backed-up blob would be undecryptable.

**Losing the phone.** Holder mode makes the phone the worst-case asset
(threat model, "stolen identity key"). Mitigations Hexline enforces in
holder mode rather than offering: a successor commitment at creation,
the recovery code shown once with a confirm-you-wrote-it step, and the
per-use auth above. A user who wants less exposure picks envelope mode.

### 2.3 Certificate capabilities

The phone's own device cert: `login | message | manage` in holder mode
(`manage` gives nothing the identity key beside it does not); no `vouch`
(§8). In enrolled mode Hexline asks for `login | message |
manage`, but `hlid`'s default grant is `--caps web` (login and message),
so every screen must work without `manage` and say which ones need it.
Push registration needs `message`.

### 2.4 Server work this depends on

| Piece | State | Needed for |
|---|---|---|
| Enrollment mailbox (`hxd-ng-session/enroll.rs`) | Built | Enrolled mode |
| Registrar envelopes (`identity-registrar.md` §9: Argon2id + XChaCha20-Poly1305, put/fetch, lockout) | **Specified, not built** — `[registrar] envelopes` is refused at startup (`crates/hxd/src/registrar.rs`), no Argon2 in `Cargo.lock` | Envelope mode, holder backup |
| Push payload sealed to `device_enc` (push §5.1, P6) | Not built | Nothing in v1 (Web Push's own encryption suffices) |

The envelope object and its derivation belong in `hl-identity` (with
vectors), the endpoints in `hxd-registrar`. That is a server slice
ahead of Hexline's envelope mode.

## 3. Background, presence and push

Android gives an app no reliable background socket without a foreground
service, and v1 does not run one: a permanent notification for a chat
app is the wrong default, and the protocol already has the right
primitive.

| App state | Socket | Session |
|---|---|---|
| Foreground | Open | `active` |
| Background, process alive | Kept for a short linger (about a minute), then **closed on purpose** | `active`, then `detached` |
| Network change (Wi-Fi ↔ cellular) | `ConnectivityManager` callback reconnects at once | `resume` with `last_seq`; takeover of the dead one is fine (last device wins) |
| Process killed | — | `detached` for the server's grace (hxd-ng: 300 s), then ended |
| Opened again | New socket | `resume` within grace; `session_expired` ⇒ fresh login (identity sessions need no user input) |

Closing on purpose matters: a message is pushed only when no session of
the mailbox is `active` (`hxd-core` `chat.rs`), nothing sets `idle`, and
a frozen process looks `active` for up to 90 s of ping silence. While
the socket is open, Hexline posts local notifications from live events;
once it is closed, push takes over. (An hx-ng tab open on a laptop also
suppresses the phone's push — that is the server's policy, accepted.)

`last_seq` advances in the **same Room transaction** that stores what
the events carry that is not disposable — PMs above all, which the
server marks delivered. Advancing it first could lose those to a
process death. A stale value costs a `resync_required` + `sync`, which
is correct, not lossy.

Resync is common, not exceptional: taking over a live socket that was
sent anything past `last_seq` answers `resync_required`
(`roster.rs`, `Sink::Live`), which a network handoff often is.

**Push** covers everything past the grace window — and that is what it
is for: the server pushes for private messages and news (`Notification` is
`Message | News`; there is no mention push) to sessions not
`active` and to accounts with no session (push-notifications.md §6).

- **`fdroid` flavor:** UnifiedPush. One *instance* per server; the
  distributor's endpoint goes to `push_register` as `type:
  "unifiedpush"` with keys Hexline generates (P-256 for RFC 8291),
  and the login block's `push.vapid` handed to the distributor.
  Nothing for operators to configure and nothing for us to run. The
  endpoint must be https and publicly routable unless the operator
  allows otherwise (webpush-gateway.md §6), so a LAN-only ntfy is
  refused `bad_request`; Hexline says why.
- A password session supplies its own `devid` (8–64 printable ASCII,
  random per install per server, kept under key A); an identity
  session's is the device fingerprint.
- Android 13+ asks for `POST_NOTIFICATIONS` before the first
  registration; `content` from the login block is shown at that
  moment, so the user knows whether text will leave the server.
- **`play` flavor (later):** FCM through **Hexline's own push relay**
  (push-notifications.md §8.2): FCM token → relay hands back a Web Push
  endpoint → registered as `webpush`; the relay forwards ciphertext and
  never holds a key for it. The relay is a small service the Hexline
  project runs; it is the one piece of Play support that is not a
  build flavor, which is why Play ships after F-Droid.
- A notification payload is decrypted in the core, rendered by Kotlin;
  tapping it opens the server, which resumes or logs in, and the inbox
  flush (spec §6.4) delivers the message itself. A push is a doorbell,
  never the message of record.
- Unregister on "turn off notifications" (`push_unregister` without
  `devid` = this device); never on logout, matching the spec.

### 3.1 A server issue this surfaced

hxd-ng caps detached sessions per **exact source address**
(`roster.rs`, `max_detached_per_addr`, default 2), ending the oldest.
Behind carrier-grade NAT, many unrelated phones share one address, so
a third stranger's phone dropping its connection ends someone else's
detached session — the case Hexline makes common. The connection
permits already move from address to account at login for exactly this
reason (AGENTS.md, "An address counts a connection only until it logs
in"); the detach cap should follow the same rule. Two more details make
it worse than CGNAT alone: the address is fixed at login and never
updated on resume (`hxd-ng-session` `conn.rs`), so a phone keeps
counting against the home Wi-Fi it logged in from, and three phones in
one household trip it; and it compares exact addresses, not /64s as the
connection limits do. A per-account replacement needs a number of its
own, because a detached session holds no account permit (resume takes
one). A server fix, ahead of Hexline's first release.

## 4. Failure modes

| Failure | Behavior |
|---|---|
| Socket lost mid-request | Outstanding requests fail (spec §5); the UI retries idempotent reads, and for `chat` relies on `chat_guid` so a resend is the same line |
| `resync_required` | Keep events already in hand; `sync`; replace roster and per-room heads; then what spec §7.1 and the family docs require: `inbox` (gap messages were marked delivered), `history after=` per room until `has_more` is false, `emoji_list` from the held revision, and news/caches invalidated |
| `session_expired` / grace lapsed | Fresh login; inbox flush brings PMs; history refetch fills chat |
| `rate_limited` | Wait `retry_after`, jittered; never a tight loop. Reconnect backoff is exponential, capped, reset on a successful handshake |
| `too_many_connections` | Shown, not retried — closing another session is the fix |
| `replaced` (1008) | Each socket carries a generation; a 1008 on one this app already superseded (its own handoff) is ignored. On the current socket it means another device took the session: stop reconnecting until the user opens the server |
| `revoked` | Stop, tell the user this device was revoked; offer re-enrollment |
| Identity re-login | Challenge and auth over HTTP, then a **fresh** socket for the upgrade; `bad_server_challenge` and 421 `wrong_host` are never retried |
| Cert expired while offline | Holder: re-mint on next unlock. Enrolled: renewal needs a holder; a lapsed cert enrolls afresh (enrollment §8) |
| Keystore key lost (screen lock removed, reset, new phone) | Identity seed unrecoverable locally ⇒ recovery code or envelope; device keys gone ⇒ new device, enroll again |
| Slow consumer kick | The core drains the socket on its own thread and coalesces to the UI, so a busy room cannot back the reader up behind Compose |
| Process death during a holder operation | Each identity operation is one signed object, posted idempotently (registrar requests replay-safe by digest); the app re-runs from the start |
| Registrar unreachable | Login to servers is unaffected (servers cache cards); only mint/renew/envelope flows wait |

## 5. Data model (Kotlin side, Room)

- `server` — address, discovery doc (cached, ETag), name, chosen auth
  (identity / password / guest), push instance id.
- `session` — server id, session id, wrapped token, `last_seq`, grace,
  socket generation.
- `push` — server id, UnifiedPush instance, wrapped P-256 key and auth
  secret, `devid`.
- `identity` — fingerprint, mode, wrapped seeds, cert bytes + expiry,
  card bytes, handle, successor commitment set.
- Caches, all disposable: chat lines per room (bounded), news threads
  and articles by id, emoji catalog by revision with images by hash,
  avatars by hash. The server holds the record; a wiped cache costs a
  refetch, never data.

## 6. Test plan

| Layer | What | Why this layer |
|---|---|---|
| `hxng-client` sans-IO unit + proptest | seq accounting, unknown events counted, reply ordering, resync rules (never drop in-hand events; nothing ≤ sync seq after it), detach-null ⇒ no resume | The spec's MUSTs are state-machine rules; property tests find the interleavings |
| `hxng-client` fuzz (cargo-fuzz) | frame and event decoding | Untrusted server input on a phone |
| `hxng-client` against a real `hxd` | handshake, resume, sync, takeover, each v1 family | Moving `hxd-testclient`'s ng half onto it puts the suites that use it (about half; the rest carry their own copies) behind it too |
| `hl-identity` | existing vectors; new envelope vectors | Critical tier; cross-implementation agreement |
| `hexline-core` Rust tests | identity flows end to end against an in-process registrar + mailbox + hxd (`hxd-ng`'s test scaffolding, or the GHCR image) | The flows are multi-party; mocking a party hides the bugs |
| `cargo-mutants` on `hexline-core::identity` | surviving mutants reported | Critical tier |
| JVM unit tests | view models over a fake core stream | UI logic without an emulator |
| Instrumented (emulator in CI) | Keystore wrap/unwrap, auth-bound key behavior, a real login and chat against the hxd Docker image | Keystore is only real on a device; no StrongBox on emulators, so the fallback is what CI proves |
| Manual, real device | push via a real UnifiedPush distributor (ntfy), Wi-Fi↔cellular handoff, chat with GtkHx and hx-ng on one server | What no emulator reproduces |
| Security pass | key handling, logs (no tokens or seeds), exported components, intents, backups | Critical tier |

## 7. Licensing

`hl-identity` and hx-libs are GPL-2.0-or-later, so Hexline is GPL
too. Fine for F-Droid; fine for Play (GPL apps ship there). Firebase in
the `play` flavor is a non-free dependency, which is also why it is a
flavor: the `fdroid` build has none.

## 8. Decisions (2026-11-12)

1. `hl-identity` moves to hx-libs before the identity slice.
2. No `vouch` on the holder phone's cert: the identity key beside it
   signs a vouch behind the per-use prompt.
3. The detach-per-address fix goes to hxd-ng as its own PR now.
4. Registrar envelopes land in hx-libs and hxd-ng before M2. A seal
   draws a fresh salt and a device looks it up before fetching (the
   registrar answers an unknown handle with a decoy); v1's Argon2id
   parameters are fixed; a put names its registrar.
5. Milestones: M1 password login, chat and resume; then identity, push,
   news and the rest.

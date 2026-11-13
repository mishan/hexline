# Hexline — working notes

A native Android client for Hotline-ng. The design and its decisions are in
`docs/design.md`; the protocol is hxd-ng's (`docs/` there), and identity is
hx-libs' `hl-identity`.

## Layout

- `crates/hexline-core` — the Rust core the app loads, exported with uniffi
  (`uniffi.toml` names its Kotlin package, `org.foggyden.hexline.core`).
- `crates/uniffi-bindgen` — the binding generator at the workspace's uniffi.
- `android/` — the Gradle project: `app`, flavors `fdroid` and `play`.
- `scripts/build-core.sh` — the core for each ABI and the host, and its
  Kotlin bindings; Gradle's `buildCore` runs it before every build.
- `scripts/connected-test.sh` — instrumented tests, booting a headless
  emulator when no device is connected.

## Commands

The same ones CI runs:

```sh
make fmt-check   # cargo fmt --check, ktlintCheck
make lint        # clippy -D warnings, Android lint (warnings are errors)
make test        # cargo test, JVM unit tests (through the real bindings)
make build       # assembleFdroidDebug, assemblePlayDebug
make connected   # instrumented tests
```

## Rules

- Kotlin renders; Rust decides. No protocol, CBOR or crypto in Kotlin.
- The `fdroid` flavor carries nothing proprietary.
- Pin versions: the toolchain in `rust-toolchain.toml`, Android libraries in
  `android/gradle/libs.versions.toml`, actions by commit SHA, the Gradle
  distribution by checksum.
- Tests run against the real thing: JVM tests load the host build of the
  core, and instrumented tests run on an emulator.

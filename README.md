# Hexline

A native Android client for [Hotline-ng](https://github.com/mishan/hxd-ng),
the mobile-first protocol beside classic Hotline. Presence that survives a
dropped connection, notifications while the app is closed, and an identity
that lives on the phone.

The UI is Kotlin and Jetpack Compose. Everything of the wire and of identity
is Rust, in `crates/`, exported to the app with
[uniffi](https://mozilla.github.io/uniffi-rs/): the app never parses a frame,
a CBOR object or a signature. Identity objects come from
[hx-libs](https://github.com/mishan/hx-libs)' `hl-identity`, shared with the
server and other clients.

Two flavors: `fdroid`, with nothing proprietary in it, and `play`.

## Building

Needs JDK 21, the Android SDK (`ANDROID_HOME`) with NDK 30 and the API 37.2
platform, [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk), and rustup (the
toolchain is pinned in `rust-toolchain.toml`).

```sh
make check      # format check, lints, unit tests, both flavors' debug builds
make connected  # instrumented tests on a device, or a headless emulator
make fmt        # format Rust and Kotlin
```

Gradle builds the Rust core itself (`scripts/build-core.sh`) for every ABI
and for the host, whose library the JVM tests load. The debug APKs land in
`android/app/build/outputs/apk/`.

## License

GPL-2.0-or-later, as hx-libs is.

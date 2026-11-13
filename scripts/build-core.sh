#!/bin/sh
# Builds the Rust core for every ABI the app ships and for the host (the
# JVM tests load that one), and generates its Kotlin bindings, into OUT.
# Needs ANDROID_NDK_HOME, or ANDROID_HOME with one NDK installed.
set -eu
OUT=${1:?usage: build-core.sh OUT}
PROFILE=${HEXLINE_CORE_PROFILE:-release}
cd "$(dirname "$0")/.."

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_HOME:-}" ]; then
    ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)
    export ANDROID_NDK_HOME
fi

flag=--release
[ "$PROFILE" = debug ] && flag=
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 29 -o "$OUT/jniLibs" \
    build $flag -p hexline-core

cargo build -p hexline-core
mkdir -p "$OUT/host"
cp target/debug/libhexline_core.so "$OUT/host/"

rm -rf "$OUT/kotlin"
cargo run -q -p uniffi-bindgen -- generate --library target/debug/libhexline_core.so \
    --language kotlin --out-dir "$OUT/kotlin"

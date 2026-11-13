#!/bin/sh
# Runs the instrumented tests on a headless emulator, booting one from the
# AVD named by HEXLINE_AVD (made from the API 36 image if missing) unless
# a device is already connected.
set -eu
cd "$(dirname "$0")/../android"
S=${ANDROID_HOME:?set ANDROID_HOME}
AVD=${HEXLINE_AVD:-hexline36}
adb=$S/platform-tools/adb

# adb's server outlives the command that started it and keeps every file
# descriptor it inherited, a build lock among them, so it goes with us.
trap '"$adb" kill-server >/dev/null 2>&1 || true' EXIT

started=
if ! "$adb" get-state >/dev/null 2>&1; then
    if ! "$S/cmdline-tools/latest/bin/avdmanager" list avd -c | grep -qx "$AVD"; then
        echo no | "$S/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" \
            -k "system-images;android-36;default;x86_64" -d pixel_6 >/dev/null
    fi
    "$S/emulator/emulator" -avd "$AVD" -no-window -no-audio -no-snapshot \
        -gpu swiftshader_indirect -no-boot-anim >"${TMPDIR:-/tmp}/hexline-emulator.log" 2>&1 &
    started=$!
    trap '"$adb" emu kill >/dev/null 2>&1 || true; wait "$started" 2>/dev/null || true; "$adb" kill-server >/dev/null 2>&1 || true' EXIT
    "$adb" wait-for-device
    until [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
        sleep 2
    done
fi

./gradlew --no-daemon :app:connectedFdroidDebugAndroidTest

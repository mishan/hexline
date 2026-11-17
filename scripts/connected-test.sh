#!/bin/sh
# Runs the instrumented tests on a headless emulator, booting one from the
# AVD named by HEXLINE_AVD unless a device is already connected.
#
# The AVD is made, if missing, as CI's emulator runner makes one: from the
# image the workflow names, and with no device profile, a 320x640 screen at
# 160 dpi, so what only a small screen breaks is found here as there.
# HEXLINE_DEVICE names a profile (pixel_6, say) for an AVD of another size,
# under a HEXLINE_AVD of its own.
set -eu
cd "$(dirname "$0")/../android"
S=${ANDROID_HOME:?set ANDROID_HOME}
workflow=../.github/workflows/ci.yml
runner() { sed -n "/android-emulator-runner/,\$ s/^ *$1: *//p" "$workflow" | head -1 | tr -d '"'; }
api=$(runner api-level)
target=$(runner target)
arch=$(runner arch)
image="system-images;android-$api;$target;$arch"
AVD=${HEXLINE_AVD:-hexline-$api-$target-$arch}
adb=$S/platform-tools/adb

# adb's server outlives the command that started it and keeps every file
# descriptor it inherited, a build lock among them, so it goes with us.
trap '"$adb" kill-server >/dev/null 2>&1 || true' EXIT

started=
if ! "$adb" get-state >/dev/null 2>&1; then
    if ! "$S/cmdline-tools/latest/bin/avdmanager" list avd -c | grep -qx "$AVD"; then
        [ -d "$S/system-images/android-$api/$target/$arch" ] ||
            yes | "$S/cmdline-tools/latest/bin/sdkmanager" "$image" >/dev/null
        echo no | "$S/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" -k "$image" \
            ${HEXLINE_DEVICE:+-d "$HEXLINE_DEVICE"} >/dev/null
    fi
    "$S/emulator/emulator" -avd "$AVD" -no-window -no-audio -no-snapshot \
        -gpu swiftshader_indirect -no-boot-anim >"${TMPDIR:-/tmp}/hexline-emulator.log" 2>&1 &
    started=$!
    trap '"$adb" emu kill >/dev/null 2>&1 || true; wait "$started" 2>/dev/null || true; "$adb" kill-server >/dev/null 2>&1 || true' EXIT
    "$adb" wait-for-device
    until [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
        sleep 2
    done
    # As the runner leaves it.
    for scale in window_animation_scale transition_animation_scale animator_duration_scale; do
        "$adb" shell settings put global "$scale" 0
    done
fi

results=app/build/outputs/androidTest-results/connected
rm -rf "$results"
failed=
./gradlew --no-daemon :app:connectedFdroidDebugAndroidTest || failed=1

# The Android Gradle plugin records a run whose app crashed as a failed
# test in its results and still reports the build successful, so the
# results are what decide. Its log names no failing test: each is shown
# here with what it failed with, and anything that crashed.
if [ -n "$failed" ] || grep -rqE 'failures="[1-9]|errors="[1-9]' "$results" || ! grep -rq '<testcase' "$results"; then
    find "$results" -name '*.xml' -exec awk '/<testcase/ { test = $0 } /<failure/ { print test; shown = 1 } shown { print } /<\/failure>/ { shown = 0 }' {} + >&2 || true
    "$adb" logcat -d -b crash >&2 || true
    echo "instrumented tests failed" >&2
    exit 1
fi

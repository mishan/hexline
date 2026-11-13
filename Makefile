# One command per check, the same ones CI runs. The Android targets need
# ANDROID_HOME (with an NDK) and JDK 21; cargo-ndk builds the core.
GRADLE = cd android && ./gradlew --no-daemon

.PHONY: check fmt fmt-check lint test build connected

check: fmt-check lint test build

fmt:
	cargo fmt --all
	$(GRADLE) ktlintFormat

fmt-check:
	cargo fmt --all --check
	$(GRADLE) ktlintCheck

lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings
	$(GRADLE) :app:lintFdroidDebug :app:lintPlayDebug

test:
	cargo test --workspace --locked
	$(GRADLE) :app:testFdroidDebugUnitTest

build:
	$(GRADLE) :app:assembleFdroidDebug :app:assemblePlayDebug

# The instrumented tests, on a connected device or a headless emulator.
connected:
	scripts/connected-test.sh

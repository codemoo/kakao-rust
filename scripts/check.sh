#!/bin/sh
set -eu
umask 077
# Respect Cargo and OS defaults; overrides are useful for isolated build caches.
if [ -n "${KAKAO_RUST_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$KAKAO_RUST_TARGET_DIR"
fi
if [ -n "${KAKAO_RUST_CARGO_HOME:-}" ]; then
    export CARGO_HOME="$KAKAO_RUST_CARGO_HOME"
fi
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings

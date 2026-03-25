#!/usr/bin/env bash
set -euo pipefail

cargo build -p simple_add_ffi --release
LIB=$(ls -1 ../target/release/libsimple_add_ffi.* | head -n1)
echo "Built: $LIB"

echo "To build WebAssembly (wasm32-unknown-unknown) wrapper:"
echo "  rustup target add wasm32-unknown-unknown"
echo "  cargo build -p simple_add_wasm --release --target wasm32-unknown-unknown"


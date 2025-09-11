#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

rustup target list | grep -q "wasm32-unknown-unknown (installed)" || rustup target add wasm32-unknown-unknown

cargo build --release --target wasm32-unknown-unknown

OUT=../target/wasm32-unknown-unknown/release/simple_add_wasm.wasm
echo "Built wasm: $OUT"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "Installing wasm-bindgen-cli..."
  rustup toolchain install stable >/dev/null 2>&1 || true
  cargo +stable install wasm-bindgen-cli --version 0.2.88 || true
fi

export PATH="$HOME/.cargo/bin:$PATH"

echo "Generating JS bindings with wasm-bindgen..."
rm -rf www/pkg
"${WASMBIN:-$(command -v wasm-bindgen || echo "$HOME/.cargo/bin/wasm-bindgen")}" "$OUT" --target web --out-dir www/pkg
echo "Wrote JS bindings to simple_add_wasm/www/pkg"


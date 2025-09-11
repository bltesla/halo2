simple_add_wasm: Halo2 simple add (a+b=c) in the browser

This crate exposes two wasm functions via `wasm-bindgen`:
- `create_simple_add_proof_wasm(k, a, b) -> Vec<u8>`
- `verify_simple_add_proof_wasm(k, a, b, proof: &[u8]) -> bool`

It also includes a minimal test page under `www/` that times proving and verifying in the browser.

Prereqs
- Rust toolchain with `wasm32-unknown-unknown` target
- `wasm-bindgen-cli` (JS bindings generator)

Quick start
```bash
cd /workspaces/halo2/simple_add_wasm
# Build wasm and generate JS bindings into www/pkg/
./build_wasm.sh

# Serve the www folder (choose any static server)
npx serve www   # or: python3 -m http.server -d www 8080

# Open the printed URL in a browser, then click Prove/Verify
```

Manual install steps (if you prefer not to use the script)
```bash
# 1) Install wasm target
rustup target add wasm32-unknown-unknown

# 2) Build wasm artifact
cargo build -p simple_add_wasm --release --target wasm32-unknown-unknown

# 3) Install wasm-bindgen-cli (use stable toolchain and a compatible version)
rustup toolchain install stable
cargo +stable install wasm-bindgen-cli --version 0.2.88
export PATH="$HOME/.cargo/bin:$PATH"

# 4) Generate JS bindings for the web target
wasm-bindgen ../target/wasm32-unknown-unknown/release/simple_add_wasm.wasm \
  --target web --out-dir www/pkg

# 5) Serve the www folder
npx serve www
```

Notes
- This wrapper disables `halo2_proofs` default features for wasm to avoid the multicore/rayon requirement.
- The demo circuit uses private `a` and `b`, and an internal `c = a + b`. For a public `c`, use the `simple_add_ffi` variant updated to include a public instance.


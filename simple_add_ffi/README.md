I'll add a README with step-by-step instructions in `simple_add_ffi/README.md`, then mark the instructions task complete.

[4 tools called]

Here’s a concise guide you can keep next to the code.

### Steps overview
- Generate a proof (Rust example)
- Build the FFI library (Rust cdylib)
- Verify from Go (cgo)

### 1) Generate a real proof
```bash
cd /workspaces/halo2
cargo run -p halo2_proofs --example simple-add
# writes /workspaces/halo2/proof.bin and prints the size
```

- Circuit enforces a + b = c with a=2, b=3.
- For a full prove+verify example in Rust:
```bash
cargo run -p halo2_proofs --example simple-add-prover
```

### 2) Build the Rust cdylib
```bash
cargo build -p simple_add_ffi --release
# Linux output: /workspaces/halo2/target/release/libsimple_add_ffi.so
```

Exported C ABI:
- int verify_simple_add_proof(unsigned int k, unsigned long long a, unsigned long long b, const unsigned char* proof_ptr, unsigned long proof_len)
- Returns 0 on success, -1 on failure.

### 3) Verify from Go
```bash
export CGO_LDFLAGS="-L/workspaces/halo2/target/release -lsimple_add_ffi"
export LD_LIBRARY_PATH=/workspaces/halo2/target/release:$LD_LIBRARY_PATH
cd /workspaces/halo2/simple_add_go
# Ensure proof exists
[ -f ../proof.bin ] || (cd .. && cargo run -p halo2_proofs --example simple-add)
go run .
```

Expected: “Go: proof verified successfully”

### Platform notes
- Windows (WSL GNU):
```bash
sudo apt-get update && sudo apt-get install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build -p simple_add_ffi --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/simple_add_ffi.dll
```
- Windows (native MSVC): build on Windows with the MSVC toolchain; output is simple_add_ffi.dll under x86_64-pc-windows-msvc.
- macOS: output is libsimple_add_ffi.dylib.

- Update Go linker/runtime paths accordingly (PATH on Windows, DYLD_LIBRARY_PATH on macOS).

- Troubleshooting: if verification fails, ensure k, a, b in Go match how the proof was generated.
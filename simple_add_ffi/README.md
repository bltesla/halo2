simple_add: prove in Rust, verify from Go

This shows how to:
- Generate a real PLONK proof for a tiny “a + b = c” circuit (Rust)
- Build a Rust shared library (cdylib) exporting a C ABI verifier
- Verify the proof from Go via cgo

Prereqs: Rust toolchain, and Go (1.19+). In the dev container, both are installed above.

Steps overview
- Generate a proof (Rust example)
- Build the FFI library (Rust cdylib)
- Verify from Go (cgo)

1) Generate a real proof
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

2) Build the Rust cdylib (Linux/macOS)
```bash
cargo build -p simple_add_ffi --release
# Linux:   target/release/libsimple_add_ffi.so
# macOS:   target/release/libsimple_add_ffi.dylib
```

Exported C ABI (simplified)
- int verify_simple_add_proof(unsigned int k, unsigned long long a, unsigned long long b, const unsigned char* proof_ptr, unsigned long proof_len)
- Returns 0 on success, -1 on failure.

3) Verify from Go (Linux/macOS)
```bash
export CGO_LDFLAGS="-L/workspaces/halo2/target/release -lsimple_add_ffi"
export LD_LIBRARY_PATH=/workspaces/halo2/target/release:$LD_LIBRARY_PATH
cd /workspaces/halo2/simple_add_go
[ -f ../proof.bin ] || (cd .. && cargo run -p halo2_proofs --example simple-add)
go run .
```
Expected: “Go: proof verified successfully”

Windows build and usage

MSVC toolchain (recommended, native Windows)
1. Install “Visual Studio Build Tools” (Desktop development with C++), then:
```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
```
2. Build DLL:
```powershell
cargo build -p simple_add_ffi --release --target x86_64-pc-windows-msvc
# -> target\x86_64-pc-windows-msvc\release\simple_add_ffi.dll
```
3. Generate proof (one time):
```powershell
cargo run -p halo2_proofs --example simple-add
# -> proof.bin in repo root
```
4. Verify from Go (PowerShell):
```powershell
$env:CGO_LDFLAGS="-L" + (Resolve-Path .\target\x86_64-pc-windows-msvc\release).Path + " -lsimple_add_ffi"
$env:PATH = (Resolve-Path .\target\x86_64-pc-windows-msvc\release).Path + ";" + $env:PATH
cd .\simple_add_go
go run .
```

MinGW-w64 (GNU) from WSL (cross-compile)
```bash
sudo apt-get update && sudo apt-get install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build -p simple_add_ffi --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/simple_add_ffi.dll
```
On Windows, ensure your Go environment can link against the produced DLL (adjust CGO_LDFLAGS and PATH to the DLL directory).

Troubleshooting
- “cannot find library”: set the dynamic linker path:
  - Linux: `export LD_LIBRARY_PATH=.../target/<triple>/release:$LD_LIBRARY_PATH`
  - macOS: `export DYLD_LIBRARY_PATH=.../target/release:$DYLD_LIBRARY_PATH`
  - Windows: add the DLL folder to `PATH` before `go run`.
- Go “cannot find main module”: run `go mod init simple_add_go` inside `simple_add_go` (already present in this repo).
- Verification fails: ensure `k`, `a`, `b` used by Go match those used to generate `proof.bin`.
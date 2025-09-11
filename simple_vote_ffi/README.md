simple_vote_ffi: private vote prove/verify via FFI

This crate exposes Halo2 proof creation and verification for a minimal private voting circuit.

Circuit
- Private input: v ∈ {0,1} (the vote bit)
- Public input (instance): t ∈ {0,1} (claimed tally increment)
- Constraints: v is boolean, and v == t

Exports (C ABI)
- int create_simple_vote_proof(unsigned int k, unsigned long long t_public, unsigned long long v_private, unsigned char** out_ptr, unsigned long* out_len)
- int verify_simple_vote_proof(unsigned int k, unsigned long long t_public, const unsigned char* proof_ptr, unsigned long proof_len)
- void free_simple_vote_bytes(unsigned char* ptr, unsigned long len)

Build (Linux/macOS)
```bash
cargo build -p simple_vote_ffi --release
# Linux: target/release/libsimple_vote_ffi.so
# macOS: target/release/libsimple_vote_ffi.dylib
```

Quick test in Rust (end-to-end)
```bash
cd /workspaces/halo2
RUST_LOG=info cargo build -p simple_vote_ffi --release
python - <<'PY'
import ctypes as C, os
lib = C.CDLL(os.path.join('target','release','libsimple_vote_ffi.so'))
create = lib.create_simple_vote_proof
create.argtypes = [C.c_uint, C.c_ulonglong, C.c_ulonglong, C.POINTER(C.POINTER(C.c_ubyte)), C.POINTER(C.c_size_t)]
verify = lib.verify_simple_vote_proof
verify.argtypes = [C.c_uint, C.c_ulonglong, C.POINTER(C.c_ubyte), C.c_size_t]
freeb = lib.free_simple_vote_bytes
freeb.argtypes = [C.POINTER(C.c_ubyte), C.c_size_t]
ptr = C.POINTER(C.c_ubyte)()
ln = C.c_size_t()
assert create(4, 1, 1, C.byref(ptr), C.byref(ln)) == 0
assert verify(4, 1, ptr, ln.value) == 0
freeb(ptr, ln.value)
print('ok')
PY
```

Go (example)
```go
/*
#cgo LDFLAGS: -L../target/release -lsimple_vote_ffi
extern int create_simple_vote_proof(unsigned int k, unsigned long long t_public, unsigned long long v_private, unsigned char** out_ptr, unsigned long* out_len);
extern int verify_simple_vote_proof(unsigned int k, unsigned long long t_public, const unsigned char* proof_ptr, unsigned long proof_len);
extern void free_simple_vote_bytes(unsigned char* ptr, unsigned long len);
*/
import "C"
// ... call like simple_add example
```

Windows cross-compile (from WSL)
```bash
sudo apt-get update && sudo apt-get install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build -p simple_vote_ffi --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/simple_vote_ffi.dll
```

Notes
- k must match between proving and verifying.
- t_public and v_private are reduced mod 2 internally.


#!/usr/bin/env bash
set -euo pipefail

TARGET=x86_64-pc-windows-gnu

if ! rustup target list | grep -q "^${TARGET} (installed)"; then
    echo "Adding Rust target: ${TARGET}"
    rustup target add ${TARGET}
fi

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "Installing MinGW-w64 (cross-linker)"
    if command -v sudo >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y mingw-w64
    else
        echo "Error: x86_64-w64-mingw32-gcc not found and sudo is unavailable. Please install mingw-w64."
        exit 1
    fi
fi

echo "Building for ${TARGET}..."
cargo build -p simple_add_ffi --release --target ${TARGET}

OUT_DIR="target/${TARGET}/release"
echo "Built artifacts in ${OUT_DIR}:"
ls -l ${OUT_DIR}/libsimple_add_ffi.* 2>/dev/null || true
ls -l ${OUT_DIR}/simple_add_ffi.* 2>/dev/null || true
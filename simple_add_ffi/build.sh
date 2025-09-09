#!/usr/bin/env bash
set -euo pipefail

cargo build -p simple_add_ffi --release
LIB=$(ls -1 target/release/libsimple_add_ffi.* | head -n1)
echo "Built: $LIB"


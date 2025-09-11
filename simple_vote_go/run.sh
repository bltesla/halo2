#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export CGO_LDFLAGS="-L../target/release -lsimple_vote_ffi"
export LD_LIBRARY_PATH="../target/release:${LD_LIBRARY_PATH:-}"

go run .



#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
go_bin="${GO:-go}"
"$go_bin" test -mod=readonly ./... -count=1
"$go_bin" test -mod=readonly -race ./cmd/rdpgw/... -count=1
"$go_bin" vet -mod=readonly ./...
git diff --check

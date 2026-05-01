#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TARGETARCH=${TARGETARCH:-arm64}

case "$TARGETARCH" in
  amd64) PLATFORM=linux/amd64 ;;
  arm64) PLATFORM=linux/arm64 ;;
  *)
    echo "unsupported TARGETARCH: $TARGETARCH" >&2
    exit 1
    ;;
esac

HOST_TARGET_DIR="$ROOT/target-linux-$TARGETARCH"

cd "$ROOT"
docker run --rm \
  --platform "$PLATFORM" \
  -v "$ROOT":/src \
  -w /src \
  -e CARGO_TARGET_DIR="/src/target-linux-$TARGETARCH" \
  rust:1.93-slim \
  bash -c 'apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates cmake && cargo build --release --bin portl'

mkdir -p adapters/docker-portl/images/bin
cp "$HOST_TARGET_DIR/release/portl" "adapters/docker-portl/images/bin/portl-${TARGETARCH}"
docker build \
  --platform "$PLATFORM" \
  -t portl-agent:local \
  --build-arg TARGETARCH="$TARGETARCH" \
  -f adapters/docker-portl/images/Dockerfile.reference \
  adapters/docker-portl/images/

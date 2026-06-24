#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
Usage: build-portl-ffi-xcframework.sh [--out DIR]

Build PortlFFI.xcframework for Apple app embedding.

Outputs:
  DIR/PortlFFI.xcframework

Builds arm64 iOS device, arm64 iOS Simulator, and arm64 macOS slices.
USAGE
}

out_dir="dist/apple"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      out_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$out_dir" ]]; then
  usage
  exit 2
fi

for tool in cargo xcodebuild xcrun rsync; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

root="$(git rev-parse --show-toplevel)"
out_abs="$(mkdir -p "$out_dir" && cd "$out_dir" && pwd)"
header_src="$root/crates/portl-ffi/include"
header_stage="$root/target/portl-ffi-apple/include"

export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.3}"

targets=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  aarch64-apple-darwin
)

for target in "${targets[@]}"; do
  cargo build -p portl-ffi --release --target "$target"
done

rm -rf "$header_stage"
mkdir -p "$header_stage"
rsync -a "$header_src/" "$header_stage/"

rm -rf "$out_abs/PortlFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$root/target/aarch64-apple-ios/release/libportl_ffi.a" \
  -headers "$header_stage" \
  -library "$root/target/aarch64-apple-ios-sim/release/libportl_ffi.a" \
  -headers "$header_stage" \
  -library "$root/target/aarch64-apple-darwin/release/libportl_ffi.a" \
  -headers "$header_stage" \
  -output "$out_abs/PortlFFI.xcframework"

"$root/scripts/verify-portl-ffi-xcframework.sh" "$out_abs/PortlFFI.xcframework"

echo "wrote $out_abs/PortlFFI.xcframework"

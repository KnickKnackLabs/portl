#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
Usage: verify-portl-ffi-xcframework.sh PATH/PortlFFI.xcframework

Verifies the PortlFFI Apple embedding artifact has the required arm64 iOS,
iOS Simulator, and macOS slices, then link-smokes the simulator and macOS
slices against the public C header.
USAGE
}

if [[ $# -ne 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 2
fi

xcframework="$1"

if [[ ! -d "$xcframework" ]]; then
  echo "missing xcframework: $xcframework" >&2
  exit 1
fi

for tool in plutil xcrun; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

require_slice() {
  local identifier="$1"
  local platform="$2"
  local variant="${3:-}"

  if ! plutil -p "$xcframework/Info.plist" | grep -q "\"LibraryIdentifier\" => \"$identifier\""; then
    echo "missing $identifier slice" >&2
    exit 1
  fi
  if ! plutil -p "$xcframework/Info.plist" | grep -q "\"SupportedPlatform\" => \"$platform\""; then
    echo "missing $platform platform entry for $identifier" >&2
    exit 1
  fi
  if [[ -n "$variant" ]] && ! plutil -p "$xcframework/Info.plist" | grep -q "\"SupportedPlatformVariant\" => \"$variant\""; then
    echo "missing $variant variant for $identifier" >&2
    exit 1
  fi
  if [[ ! -f "$xcframework/$identifier/libportl_ffi.a" ]]; then
    echo "missing library for $identifier" >&2
    exit 1
  fi
  if [[ ! -f "$xcframework/$identifier/Headers/PortlFFI.h" ]]; then
    echo "missing header for $identifier" >&2
    exit 1
  fi
}

require_slice ios-arm64 ios
require_slice ios-arm64-simulator ios simulator
require_slice macos-arm64 macos

smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/portl-ffi-link-smoke.XXXXXX")"
cleanup() {
  rm -rf "$smoke_dir"
}
trap cleanup EXIT

cat > "$smoke_dir/main.c" <<'C'
#include "PortlFFI.h"

int main(void) {
    const char *version = portl_ffi_version();
    if (portl_ffi_abi_version() != 1) {
        return 1;
    }
    if (!portl_ffi_iroh_quic_available()) {
        return 2;
    }
    if (version == 0 || version[0] == '\0') {
        return 3;
    }
    return 0;
}
C

link_smoke() {
  local target="$1"
  local sdk_name="$2"
  local min_version_flag="$3"
  local slice="$4"
  local output="$5"
  shift 5

  local sdk_path
  sdk_path="$(xcrun --sdk "$sdk_name" --show-sdk-path)"
  local lib="$xcframework/$slice/libportl_ffi.a"
  local headers="$xcframework/$slice/Headers"

  xcrun lipo -info "$lib"
  xcrun clang \
    -target "$target" \
    -isysroot "$sdk_path" \
    "$min_version_flag" \
    -I "$headers" \
    "$smoke_dir/main.c" \
    "$lib" \
    "$@" \
    -o "$smoke_dir/$output"
}

link_smoke \
  arm64-apple-ios18.0 \
  iphoneos \
  -mios-version-min=18.0 \
  ios-arm64 \
  portl_ffi_link_smoke_ios \
  -framework Network \
  -framework Security \
  -framework SystemConfiguration \
  -framework CoreFoundation \
  -framework Foundation \
  -lresolv

link_smoke \
  arm64-apple-ios18.0-simulator \
  iphonesimulator \
  -mios-simulator-version-min=18.0 \
  ios-arm64-simulator \
  portl_ffi_link_smoke_sim \
  -framework Network \
  -framework Security \
  -framework SystemConfiguration \
  -framework CoreFoundation \
  -framework Foundation \
  -lresolv

link_smoke \
  arm64-apple-macos13.3 \
  macosx \
  -mmacosx-version-min=13.3 \
  macos-arm64 \
  portl_ffi_link_smoke_macos \
  -framework Network \
  -framework Security \
  -framework SystemConfiguration \
  -framework CoreFoundation \
  -framework Foundation \
  -lresolv

echo "verified $xcframework"

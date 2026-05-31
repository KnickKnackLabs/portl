#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
Usage: build-macos-home-pkg.sh --binary PATH --version VERSION --target TARGET --out DIR [--name NAME]

Build a macOS current-user-home product package for Portl.

Inputs:
  --binary   Path to an already Developer ID Application-signed portl binary.
  --version  Portl package version, without a leading v.
  --target   Rust target triple, used only for the default package name.
  --out      Output directory.
  --name     Optional package basename. Defaults to portl-vVERSION-TARGET.

Output:
  DIR/NAME.pkg, unsigned at the package envelope level. Sign the result with
  Developer ID Installer before notarization.
USAGE
}

binary=""
version=""
target=""
out_dir=""
name=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --out)
      out_dir="${2:-}"
      shift 2
      ;;
    --name)
      name="${2:-}"
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

if [[ -z "$binary" || -z "$version" || -z "$target" || -z "$out_dir" ]]; then
  usage
  exit 2
fi

if [[ "$version" == v* ]]; then
  echo "--version must not include a leading v: $version" >&2
  exit 2
fi

if [[ ! -x "$binary" ]]; then
  echo "missing executable binary: $binary" >&2
  exit 1
fi

for tool in cpio gzip mkbom xar du find install; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

if ! (xar --help 2>&1 || true) | grep -q -- '--no-compress'; then
  echo "xar must support --no-compress" >&2
  exit 1
fi

name="${name:-portl-v${version}-${target}}"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
out_pkg="$out_dir/${name}.pkg"

work="$(mktemp -d "${TMPDIR:-/tmp}/portl-home-pkg.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

payload="$work/payload"
bin_dir="$payload/.local/bin"
flat="$work/flat"
component="$flat/portl-user.pkg"

mkdir -p "$bin_dir" "$component"
install -m 0755 "$binary" "$bin_dir/portl"
for sub in portl-agent portl-gateway portl-ssh; do
  # Hard copies avoid the fs::copy symlink truncation footgun guarded in
  # portl install --apply.
  install -m 0755 "$bin_dir/portl" "$bin_dir/$sub"
done

cpio_args=(-o --format odc)
if (cpio --help 2>&1 || true) | grep -q -- '--owner'; then
  # Match pkgbuild/productbuild's root:wheel archive metadata. Current-user-home
  # installs still materialize files as the installing user.
  cpio_args+=(--owner 0:80)
fi

(
  cd "$payload"
  find . | LC_ALL=C sort | cpio "${cpio_args[@]}" | gzip -c > "$component/Payload"
)

if (mkbom -h 2>&1 || true) | grep -q -- '-u'; then
  mkbom -u 0 -g 80 "$payload" "$component/Bom"
else
  mkbom "$payload" "$component/Bom"
fi

number_of_files="$(find "$payload" -mindepth 1 | wc -l | tr -d ' ')"
install_kbytes="$(du -sk "$payload" | awk '{print $1}')"

cat > "$component/PackageInfo" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="com.un.portl.user.pkg" postinstall-action="none" version="$version" format-version="2" generator-version="portl-linux-pkg" install-location="/" auth="root">
  <payload numberOfFiles="$number_of_files" installKBytes="$install_kbytes"/>
  <bundle-version/>
  <upgrade-bundle/>
  <update-bundle/>
  <atomic-update-bundle/>
  <strict-identifier/>
  <relocate/>
</pkg-info>
EOF

cat > "$flat/Distribution" <<EOF
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<installer-gui-script minSpecVersion="1">
  <title>Portl</title>
  <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="false"/>
  <options customize="never" require-scripts="false"/>
  <choices-outline>
    <line choice="default"/>
  </choices-outline>
  <choice id="default" title="Portl">
    <pkg-ref id="com.un.portl.user.pkg"/>
  </choice>
  <pkg-ref id="com.un.portl.user.pkg" version="$version" auth="none" installKBytes="$install_kbytes" updateKBytes="0">#portl-user.pkg</pkg-ref>
  <pkg-ref id="com.un.portl.user.pkg">
    <bundle-version/>
  </pkg-ref>
</installer-gui-script>
EOF

rm -f "$out_pkg"
(
  cd "$flat"
  # Product packages need a Distribution at the archive root. The component
  # reference in Distribution deliberately uses #portl-user.pkg; without the
  # leading #, Apple Notary cannot extract the nested component.
  xar --compression gzip --no-compress 'Payload$' -cf "$out_pkg" portl-user.pkg Distribution
)

echo "wrote $out_pkg"

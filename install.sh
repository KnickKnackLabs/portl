#!/usr/bin/env bash
# portl installer — portable across darwin and linux-musl targets.
#
# usage (one-liners):
#   curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --agent
#   curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --version 0.3.0
#
# modes (all idempotent — re-run any time):
#   default / --client-only : install/upgrade portl binaries, no background service
#   --agent                 : install/upgrade + enable launchd/systemd service
#   --uninstall             : remove binaries and service
#
# The script is explicitly NOT a wrapper around mise / brew / apt —
# it downloads a release tarball from github.com/KnickKnackLabs/portl
# and places the multicall binary at a stable path so plists and
# systemd units can reference it by absolute path without re-pinning
# on every package-manager version bump.
#
# Supported targets: darwin arm64 / x86_64, linux musl arm64 / x86_64.

set -euo pipefail

REPO="KnickKnackLabs/portl"
RELEASES_URL="https://github.com/${REPO}/releases"
API_URL="https://api.github.com/repos/${REPO}"

VERSION=""
INSTALL_DIR=""
MODE="client"   # client | agent | uninstall
FORCE=0
SKIP_INIT=0
DRY_RUN=0
ASSUME_YES=0

log()  { printf '%s\n' "$*" >&2; }
info() { printf '\033[0;36m[info]\033[0m  %s\n' "$*" >&2; }
ok()   { printf '\033[0;32m[ok]\033[0m    %s\n' "$*" >&2; }
warn() { printf '\033[0;33m[warn]\033[0m  %s\n' "$*" >&2; }
err()  { printf '\033[0;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '\033[2m$ %s\033[0m\n' "$*" >&2
        return 0
    fi
    "$@"
}

usage() {
    cat <<'EOF'
portl installer

usage: install.sh [OPTIONS]

  --version <X.Y.Z>      install specific version (default: latest release)
  --install-dir <path>   binaries go here (default: ~/.local/bin, or /usr/local/bin as root)
  --agent                install + enable portl-agent service
  --client-only          install binaries only (default)
  --uninstall            remove binaries + service
  --force                overwrite matching version without prompting
  --no-init              skip `portl init` on fresh machines
  --dry-run              print what would happen, change nothing
  --yes, -y              assume yes for all prompts (safe for curl|bash)
  -h, --help             show this help

examples:
  # client mode, latest release
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash

  # enable agent service (asks for sudo if installing system-wide)
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --agent

  # pin version, skip confirmation
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --version 0.3.0 --yes

  # toggle back to client-only (tears down the service)
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --client-only --yes

  # uninstall everything
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --uninstall --yes
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)       VERSION="$2"; shift 2 ;;
        --version=*)     VERSION="${1#*=}"; shift ;;
        --install-dir)   INSTALL_DIR="$2"; shift 2 ;;
        --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
        --agent)         MODE="agent"; shift ;;
        --client-only)   MODE="client"; shift ;;
        --uninstall)     MODE="uninstall"; shift ;;
        --force)         FORCE=1; shift ;;
        --no-init)       SKIP_INIT=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --yes|-y)        ASSUME_YES=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               err "unknown option: $1 (run with --help for usage)" ;;
    esac
done

# --- detect platform --------------------------------------------------

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-musl" ;;
        *)      err "unsupported OS: $os (supported: Darwin, Linux)" ;;
    esac
    case "$arch" in
        arm64|aarch64)  arch="aarch64" ;;
        x86_64|amd64)   arch="x86_64" ;;
        *)              err "unsupported arch: $arch (supported: aarch64, x86_64)" ;;
    esac
    printf '%s-%s\n' "$arch" "$os"
}

detect_container() {
    # Best-effort: set CONTAINER=1 so we skip service install (launchctl
    # and systemctl don't work inside most containers).
    if [ -f /.dockerenv ]; then return 0; fi
    if [ -r /proc/1/cgroup ] && grep -qE 'docker|containerd|lxc|podman' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    if [ -r /proc/1/sched ] && ! grep -q '^init' /proc/1/sched 2>/dev/null && ! grep -q '^systemd' /proc/1/sched 2>/dev/null; then
        # heuristic: pid 1 isn't init/systemd → probably a container
        return 0
    fi
    return 1
}

TARGET="$(detect_target)"
IS_CONTAINER=0
if detect_container; then IS_CONTAINER=1; fi

# --- locate tools -----------------------------------------------------

DOWNLOAD=""
if has curl; then DOWNLOAD="curl -fsSL"
elif has wget; then DOWNLOAD="wget -qO-"
else err "neither curl nor wget found; install one and retry"
fi

SHA256=""
if has sha256sum; then SHA256="sha256sum"
elif has shasum; then SHA256="shasum -a 256"
else warn "neither sha256sum nor shasum found; checksum verification will be skipped"
fi

EXTRACT=""
ARCHIVE_EXT=""
if has zstd && has tar; then
    EXTRACT="tar --use-compress-program=unzstd -xf"
    ARCHIVE_EXT="tar.zst"
elif has tar; then
    # gzip is in every busybox/alpine; tar.gz fallback.
    EXTRACT="tar -xzf"
    ARCHIVE_EXT="tar.gz"
else
    err "tar not found; install tar and retry"
fi

# --- resolve version --------------------------------------------------

resolve_latest_version() {
    # GitHub API returns the latest release tag; fall back to parsing
    # the redirect target of /releases/latest if the API rate-limits.
    local tag
    if has jq; then
        tag="$($DOWNLOAD "${API_URL}/releases/latest" 2>/dev/null | jq -r .tag_name 2>/dev/null || true)"
    else
        tag="$($DOWNLOAD "${API_URL}/releases/latest" 2>/dev/null | \
            sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
    fi
    if [ -z "$tag" ] || [ "$tag" = "null" ]; then
        # API fallback: follow the /releases/latest HTML redirect
        tag="$($DOWNLOAD -I "${RELEASES_URL}/latest" 2>/dev/null | \
            sed -n 's#.*location:.*/tag/\([^[:space:]]*\).*#\1#pi' | head -n1 | tr -d '\r')"
    fi
    [ -z "$tag" ] && err "could not resolve latest version (github.com unreachable or rate-limited)"
    printf '%s\n' "$tag"
}

# --- install dir -------------------------------------------------------

default_install_dir() {
    if [ "$(id -u)" -eq 0 ]; then
        printf '/usr/local/bin\n'
    else
        printf '%s/.local/bin\n' "${HOME:-/root}"
    fi
}

if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="$(default_install_dir)"
fi

ensure_in_path() {
    # Don't modify any shell rc files — that's a footgun. Just warn.
    case ":${PATH:-}:" in
        *":${INSTALL_DIR}:"*) return 0 ;;
    esac
    warn "${INSTALL_DIR} is not on your \$PATH"
    warn "add this to your shell rc:  export PATH=\"${INSTALL_DIR}:\$PATH\""
}

# --- uninstall ---------------------------------------------------------

do_uninstall() {
    if [ "$ASSUME_YES" -ne 1 ] && [ -t 0 ] && [ -t 1 ]; then
        printf 'uninstall portl binaries and service? [y/N] ' >&2
        read -r reply </dev/tty
        case "$reply" in
            y|Y|yes|YES) ;;
            *) err "aborted" ;;
        esac
    fi
    info "uninstalling portl"
    # tear down service if present (best-effort)
    if [ "$(uname -s)" = "Darwin" ]; then
        run launchctl bootout "gui/$(id -u)/com.portl.agent" 2>/dev/null || true
        if [ -w /Library/LaunchDaemons ] || [ "$(id -u)" -eq 0 ]; then
            run sudo launchctl bootout system/com.portl.agent 2>/dev/null || true
            run sudo rm -f /Library/LaunchDaemons/com.portl.agent.plist
        fi
        run rm -f "${HOME:-/root}/Library/LaunchAgents/com.portl.agent.plist"
    elif [ "$(uname -s)" = "Linux" ]; then
        if has systemctl; then
            run systemctl --user disable --now portl-agent.service 2>/dev/null || true
            run sudo systemctl disable --now portl-agent.service 2>/dev/null || true
        fi
        run rm -f "${HOME:-/root}/.config/systemd/user/portl-agent.service"
        if [ -w /etc/systemd/system ] || [ "$(id -u)" -eq 0 ]; then
            run sudo rm -f /etc/systemd/system/portl-agent.service
        fi
    fi
    # remove binaries from both common locations
    for p in portl portl-agent portl-gateway; do
        for dir in "$INSTALL_DIR" "${HOME:-/root}/.local/bin" /usr/local/bin; do
            [ -e "$dir/$p" ] && run rm -f "$dir/$p"
        done
    done
    ok "uninstalled portl (identity and peers.json left intact under \$PORTL_HOME)"
    info "to fully wipe state:"
    info "  rm -rf \"\${PORTL_HOME:-\$HOME/Library/Application Support/computer.KnickKnackLabs.portl}\"  # macOS"
    info "  rm -rf \"\${PORTL_HOME:-\$HOME/.local/share/computer.KnickKnackLabs.portl}\"                 # linux"
}

# --- version check (idempotency core) ---------------------------------

installed_version() {
    # Returns e.g. "0.3.0" or empty string if not installed.
    local bin="$INSTALL_DIR/portl"
    [ -x "$bin" ] || return 0
    "$bin" --version 2>/dev/null | awk 'NR==1 {print $2}' || true
}

# --- download + install -----------------------------------------------

do_install() {
    if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
        info "resolving latest version…"
        VERSION="$(resolve_latest_version)"
    fi
    # Normalize to tag form (prefix with v if missing).
    case "$VERSION" in
        v*) TAG="$VERSION" ;;
        *)  TAG="v$VERSION" ;;
    esac
    VER="${TAG#v}"

    info "target     : ${TARGET}"
    info "version    : ${TAG}"
    info "install dir: ${INSTALL_DIR}"
    info "mode       : ${MODE}"
    [ "$IS_CONTAINER" -eq 1 ] && info "container  : detected (service install will be skipped)"

    local current
    current="$(installed_version || true)"
    if [ -n "$current" ] && [ "$current" = "$VER" ] && [ "$FORCE" -ne 1 ]; then
        ok "portl ${VER} already installed at ${INSTALL_DIR}/portl"
    else
        if [ -n "$current" ]; then
            info "upgrading portl ${current} → ${VER}"
        else
            info "installing portl ${VER}"
        fi
        download_and_place
    fi

    ensure_in_path

    # init identity on fresh machines
    if [ "$SKIP_INIT" -ne 1 ]; then
        if ! "$INSTALL_DIR/portl" doctor 2>/dev/null | grep -q '\[ok *\] identity:'; then
            info "initializing portl identity…"
            run "$INSTALL_DIR/portl" init
        fi
    fi

    case "$MODE" in
        agent)  install_service ;;
        client) uninstall_service_if_present ;;
    esac

    echo
    ok "done"
    "$INSTALL_DIR/portl" doctor 2>/dev/null || true
}

download_and_place() {
    local name url tmp
    name="portl-${TAG}-${TARGET}.${ARCHIVE_EXT}"
    url="${RELEASES_URL}/download/${TAG}/${name}"
    tmp="$(mktemp -d)"
    # tmp is only needed inside this function; clean up on return.
    TMPDIR_PORTL_INSTALL="$tmp"
    trap 'rm -rf "${TMPDIR_PORTL_INSTALL:-}"' EXIT

    info "downloading ${name}"
    if [ "$DOWNLOAD" = "curl -fsSL" ]; then
        run curl -fsSL -o "$tmp/$name" "$url" || err "download failed: $url"
        run curl -fsSL -o "$tmp/$name.sha256" "${url}.sha256" || warn "sha256 download failed (continuing without verification)"
    else
        run wget -qO "$tmp/$name" "$url" || err "download failed: $url"
        run wget -qO "$tmp/$name.sha256" "${url}.sha256" || warn "sha256 download failed (continuing without verification)"
    fi

    if [ -n "$SHA256" ] && [ -s "$tmp/$name.sha256" ]; then
        info "verifying checksum…"
        # The .sha256 file is `<hash>  <filename>\n`. Run verification
        # in the tmp dir so the relative filename matches.
        if [ "$DRY_RUN" -eq 0 ]; then
            (cd "$tmp" && $SHA256 -c "$name.sha256") || err "checksum verification failed for $name"
        fi
        ok "checksum verified"
    fi

    info "extracting…"
    run mkdir -p "$tmp/unpack"
    run $EXTRACT "$tmp/$name" -C "$tmp/unpack"
    local src
    src="$tmp/unpack/portl-${TAG}-${TARGET}"
    if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$src/portl" ]; then
        err "extracted archive has no portl binary at $src/portl"
    fi

    run mkdir -p "$INSTALL_DIR"
    run install -m 0755 "$src/portl" "$INSTALL_DIR/portl"
    # portl is a multicall binary — link portl-agent and portl-gateway
    # at the same path so plists / units invoking by absolute path work.
    for sub in portl-agent portl-gateway; do
        run ln -sf "$INSTALL_DIR/portl" "$INSTALL_DIR/$sub"
    done
    ok "installed ${VER} at ${INSTALL_DIR}/portl"
}

# --- service management -----------------------------------------------

install_service() {
    if [ "$IS_CONTAINER" -eq 1 ]; then
        warn "container detected — skipping service install"
        warn "run the agent manually:  ${INSTALL_DIR}/portl-agent"
        return 0
    fi
    info "installing portl-agent service"
    # Delegate to `portl install --apply`. It writes launchd plist /
    # systemd unit referencing the binary we just placed. Re-running
    # is idempotent.
    if [ "$(id -u)" -eq 0 ]; then
        run "$INSTALL_DIR/portl" install --apply --yes
    else
        run "$INSTALL_DIR/portl" install --apply --yes
    fi
    ok "service installed"
    info "to check status: portl doctor"
}

uninstall_service_if_present() {
    # --client-only re-run: if a service is loaded, tear it down.
    local touched=0
    if [ "$(uname -s)" = "Darwin" ]; then
        if launchctl print "gui/$(id -u)/com.portl.agent" >/dev/null 2>&1; then
            info "tearing down user LaunchAgent (switching to client-only)"
            run launchctl bootout "gui/$(id -u)/com.portl.agent" || true
            run rm -f "${HOME:-/root}/Library/LaunchAgents/com.portl.agent.plist"
            touched=1
        fi
        if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then
            if sudo launchctl print system/com.portl.agent >/dev/null 2>&1; then
                info "tearing down system LaunchDaemon (switching to client-only)"
                run sudo launchctl bootout system/com.portl.agent || true
                run sudo rm -f /Library/LaunchDaemons/com.portl.agent.plist
                touched=1
            fi
        fi
    elif [ "$(uname -s)" = "Linux" ] && has systemctl; then
        if systemctl --user is-enabled portl-agent.service >/dev/null 2>&1; then
            info "tearing down user systemd unit (switching to client-only)"
            run systemctl --user disable --now portl-agent.service || true
            run rm -f "${HOME:-/root}/.config/systemd/user/portl-agent.service"
            touched=1
        fi
        if systemctl is-enabled portl-agent.service >/dev/null 2>&1; then
            info "tearing down system systemd unit (switching to client-only)"
            run sudo systemctl disable --now portl-agent.service || true
            run sudo rm -f /etc/systemd/system/portl-agent.service
            touched=1
        fi
    fi
    [ "$touched" -eq 1 ] && ok "service removed (binaries retained)"
    return 0
}

# --- main --------------------------------------------------------------

case "$MODE" in
    uninstall) do_uninstall ;;
    client|agent) do_install ;;
esac

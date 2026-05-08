#!/usr/bin/env bash
# portl installer — portable across darwin and linux-musl targets.
#
# usage (one-liners):
#   curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | PORTL_AGENT=1 bash
#
# modes (all idempotent — re-run any time):
#   default     : install/upgrade portl binaries, preserving existing service mode
#   PORTL_AGENT=1 / --agent=on  : enable launchd/systemd service
#   PORTL_AGENT=0 / --agent=off : disable launchd/systemd service
#   --uninstall : remove binaries and service
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

VERSION="${PORTL_VERSION:-}"
INSTALL_DIR=""
MODE=""         # empty = preserve existing service mode; otherwise client | agent | uninstall
FORCE=0
SKIP_INIT=0
DRY_RUN=0
ASSUME_YES=0
CONTAINER_RUNTIME_HANDOFF_ACTION=""

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

  --version <X.Y.Z>      install specific version (default: $PORTL_VERSION or latest release)
  --install-dir <path>   binaries go here (default: ~/.local/bin, or /usr/local/bin as root)
  --agent[=on|off]       enable/disable portl-agent service (default: preserve current mode)
  --uninstall            remove binaries + service
  --force                overwrite matching version without prompting
  --no-init              skip `portl init` on fresh machines
  --dry-run              print what would happen, change nothing
  --yes, -y              assume yes for all prompts (safe for curl|bash)
  -h, --help             show this help

examples:
  # install or upgrade; preserves the current client/agent mode
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash

  # install or upgrade and make this machine shareable
  curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | PORTL_AGENT=1 bash
EOF
}

parse_agent_mode() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on|agent) printf 'agent\n' ;;
        0|false|no|off|client) printf 'client\n' ;;
        *) err "invalid agent mode: $1 (expected on/off)" ;;
    esac
}

if [ -n "${PORTL_AGENT:-}" ]; then
    MODE="$(parse_agent_mode "$PORTL_AGENT")"
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --version)       VERSION="$2"; shift 2 ;;
        --version=*)     VERSION="${1#*=}"; shift ;;
        --install-dir)   INSTALL_DIR="$2"; shift 2 ;;
        --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
        --agent)         MODE="agent"; shift ;;
        --agent=*)       MODE="$(parse_agent_mode "${1#*=}")"; shift ;;
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
    # and systemctl don't work inside most containers). Keep this in
    # sync with the Rust-side installer detection.
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then return 0; fi
    if [ -r /proc/1/cgroup ] && grep -qE 'docker|containerd|kubepods|crio|cri-o|lxc|podman|libpod' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    if [ -r /proc/1/comm ] && grep -qE '^(s6-svscan|tini|dumb-init|supervisord|pause|bash|sh|zsh)$' /proc/1/comm 2>/dev/null; then
        return 0
    fi
    if [ -r /proc/1/sched ] && grep -qE '^(s6-svscan|tini|dumb-init|supervisord|pause|bash|sh|zsh)[[:space:](]' /proc/1/sched 2>/dev/null; then
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
    info "mode       : ${MODE:-preserve}"
    [ "$IS_CONTAINER" -eq 1 ] && info "container  : detected (service install will be skipped)"

    local service_was_configured expected_service_running container_runtime_was_running
    service_was_configured=0
    expected_service_running=0
    container_runtime_was_running=0
    if [ "$IS_CONTAINER" -eq 1 ] && agent_runtime_available; then
        container_runtime_was_running=1
    fi
    if [ "$IS_CONTAINER" -eq 0 ] && service_configured; then
        service_was_configured=1
    fi
    case "$MODE" in
        agent) expected_service_running=1 ;;
        "") [ "$service_was_configured" -eq 1 ] && expected_service_running=1 ;;
    esac
    if [ "$IS_CONTAINER" -eq 0 ] && { [ "$service_was_configured" -eq 1 ] || [ "$MODE" = "agent" ]; }; then
        stop_existing_service_before_upgrade
    fi

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
    install_man_pages_best_effort
    install_completions_best_effort
    ensure_home_layout_with_new_binary

    # init identity on fresh machines. Use a narrow identity probe —
    # `doctor` can fail for unrelated health issues (for example an
    # expired saved ticket) and must not block service reinstall/restart.
    if [ "$SKIP_INIT" -ne 1 ]; then
        if ! "$INSTALL_DIR/portl" whoami --eid >/dev/null 2>&1; then
            info "initializing portl identity…"
            if ! run "$INSTALL_DIR/portl" init; then
                if "$INSTALL_DIR/portl" whoami --eid >/dev/null 2>&1; then
                    warn "init reported health issues after creating/loading identity; continuing"
                else
                    err "failed to initialize portl identity"
                fi
            fi
        fi
    fi

    if [ "$IS_CONTAINER" -eq 1 ]; then
        apply_container_runtime_mode "$container_runtime_was_running"
    else
        apply_service_mode
        if [ "$expected_service_running" -eq 1 ]; then
            verify_agent_service_ready
        fi
    fi

    echo
    if [ "$DRY_RUN" -eq 1 ]; then
        ok "dry-run complete (no changes made)"
        info "to check status after a real install: portl doctor"
    else
        if [ -n "$CONTAINER_RUNTIME_HANDOFF_ACTION" ]; then
            ok "done (portl-agent ${CONTAINER_RUNTIME_HANDOFF_ACTION} handed off)"
            warn "the current Portl-backed shell may disconnect shortly; reconnect and run `portl doctor --verbose`"
        else
            ok "done"
            "$INSTALL_DIR/portl" doctor 2>/dev/null || true
        fi
    fi
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
    # portl is a multicall binary — copy (NOT symlink) portl-agent and
    # portl-gateway at the same path so plists / units invoking by
    # absolute path work. Symlinks would be clobbered by
    # `portl install --apply`, whose `fs::copy(current_exe, dst)` opens
    # dst with O_TRUNC and follows the symlink, truncating the source
    # before the read happens. Hardcopies are ~10MB each; trivially
    # cheap and eliminates the footgun class entirely.
    for sub in portl-agent portl-gateway; do
        run install -m 0755 "$INSTALL_DIR/portl" "$INSTALL_DIR/$sub"
    done
    ok "installed ${VER} at ${INSTALL_DIR}/portl"
}

install_prefix() {
    case "$INSTALL_DIR" in
        */bin) printf '%s\n' "${INSTALL_DIR%/bin}" ;;
        *)     dirname "$INSTALL_DIR" ;;
    esac
}

install_man_pages_best_effort() {
    [ "${PORTL_INSTALL_MAN:-1}" = "0" ] && return 0
    local man_dir
    man_dir="$(install_prefix)/share/man/man1"
    [ -d "$man_dir" ] || return 0
    [ -w "$man_dir" ] || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        run "$INSTALL_DIR/portl" man --out-dir "$man_dir"
        return 0
    fi
    "$INSTALL_DIR/portl" man --out-dir "$man_dir" >/dev/null 2>&1 || true
}

install_completion_file() {
    local shell_name="$1" target="$2" dir
    dir="$(dirname "$target")"
    if [ "$DRY_RUN" -eq 1 ]; then
        run mkdir -p "$dir"
        log "\$ $INSTALL_DIR/portl completions $shell_name > $target"
        return 0
    fi
    mkdir -p "$dir" >/dev/null 2>&1 || return 0
    [ -w "$dir" ] || return 0
    "$INSTALL_DIR/portl" completions "$shell_name" >"$target" 2>/dev/null || true
}

install_completions_best_effort() {
    [ "${PORTL_INSTALL_COMPLETIONS:-1}" = "0" ] && return 0
    local shell_name base
    shell_name="$(basename "${SHELL:-}")"
    if [ -z "$shell_name" ] && has ps; then
        shell_name="$(ps -p "${PPID:-0}" -o comm= 2>/dev/null | awk 'NR==1 {print $1}')"
        shell_name="$(basename "$shell_name")"
    fi
    case "$shell_name" in
        bash)
            base="${XDG_DATA_HOME:-${HOME:-/root}/.local/share}"
            install_completion_file bash "$base/bash-completion/completions/portl"
            ;;
        zsh)
            base="${XDG_DATA_HOME:-${HOME:-/root}/.local/share}"
            install_completion_file zsh "$base/zsh/site-functions/_portl"
            ;;
        fish)
            base="${XDG_CONFIG_HOME:-${HOME:-/root}/.config}"
            install_completion_file fish "$base/fish/completions/portl.fish"
            ;;
    esac
}

# --- service management -----------------------------------------------

service_configured() {
    if [ "$DRY_RUN" -eq 0 ] && "$INSTALL_DIR/portl-agent" status --service >/dev/null 2>&1; then
        return 0
    fi
    # Transitional fallback for upgrading from releases before
    # `portl-agent status --service` existed. Newer installs answer
    # through the Rust lifecycle command above.
    case "$(uname -s)" in
        Darwin)
            launchctl print "gui/$(id -u)/com.portl.agent" >/dev/null 2>&1 && return 0
            [ -f "${HOME:-/root}/Library/LaunchAgents/com.portl.agent.plist" ] && return 0
            [ -f /Library/LaunchDaemons/com.portl.agent.plist ] && return 0
            ;;
        Linux)
            if has systemctl; then
                systemctl --user is-enabled portl-agent.service >/dev/null 2>&1 && return 0
                systemctl is-enabled portl-agent.service >/dev/null 2>&1 && return 0
            fi
            if has rc-service; then
                rc-service portl-agent status >/dev/null 2>&1 && return 0
            fi
            [ -f "${HOME:-/root}/.config/systemd/user/portl-agent.service" ] && return 0
            [ -f /etc/systemd/system/portl-agent.service ] && return 0
            [ -f /etc/init.d/portl-agent ] && return 0
            ;;
    esac
    return 1
}

service_loaded() {
    case "$(uname -s)" in
        Darwin)
            launchctl print "gui/$(id -u)/com.portl.agent" >/dev/null 2>&1 && return 0
            launchctl print system/com.portl.agent >/dev/null 2>&1 && return 0
            ;;
        Linux)
            if has systemctl; then
                systemctl --user is-active portl-agent.service >/dev/null 2>&1 && return 0
                systemctl is-active portl-agent.service >/dev/null 2>&1 && return 0
            fi
            if has rc-service; then
                rc-service portl-agent status >/dev/null 2>&1 && return 0
            elif has service; then
                service portl-agent status >/dev/null 2>&1 && return 0
            fi
            ;;
    esac
    return 1
}

run_quiet_best_effort() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '\033[2m$ %s\033[0m\n' "$*" >&2
        return 0
    fi
    "$@" >/dev/null 2>&1
}

stop_existing_service_before_upgrade() {
    if [ "$IS_CONTAINER" -eq 1 ]; then
        return 0
    fi
    info "stopping existing portl-agent service before upgrade"
    case "$(uname -s)" in
        Darwin)
            local user_domain user_plist
            user_domain="gui/$(id -u)"
            user_plist="${HOME:-/root}/Library/LaunchAgents/com.portl.agent.plist"
            run_quiet_best_effort launchctl bootout "$user_domain" "$user_plist" || true
            run_quiet_best_effort launchctl bootout "${user_domain}/com.portl.agent" || true
            if [ "$(id -u)" -eq 0 ]; then
                run_quiet_best_effort launchctl bootout system /Library/LaunchDaemons/com.portl.agent.plist || true
                run_quiet_best_effort launchctl bootout system/com.portl.agent || true
            fi
            ;;
        Linux)
            if has systemctl; then
                run_quiet_best_effort systemctl --user stop portl-agent.service || true
                if [ "$(id -u)" -eq 0 ]; then
                    run_quiet_best_effort systemctl stop portl-agent.service || true
                fi
            fi
            if has rc-service; then
                run_quiet_best_effort rc-service portl-agent stop || true
            elif has service; then
                run_quiet_best_effort service portl-agent stop || true
            fi
            ;;
    esac
    if [ "$DRY_RUN" -eq 0 ]; then
        local stop_waits
        stop_waits=0
        while [ "$stop_waits" -lt 10 ] && service_loaded; do
            sleep 0.5
            stop_waits=$((stop_waits + 1))
        done
        if service_loaded; then
            err "portl-agent service is still running after stop; stop it with your service manager or rerun this installer with sufficient privileges before migrating state"
        fi
    fi
}

ensure_home_layout_with_new_binary() {
    info "ensuring Portl home layout"
    if [ "$DRY_RUN" -eq 1 ]; then
        run "$INSTALL_DIR/portl" config path
    else
        "$INSTALL_DIR/portl" config path >/dev/null
    fi
}

verify_agent_service_ready() {
    info "waiting for portl-agent service readiness"
    if [ "$DRY_RUN" -eq 1 ]; then
        run "$INSTALL_DIR/portl-agent" status
        return 0
    fi
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if "$INSTALL_DIR/portl-agent" status >/dev/null 2>&1; then
            ok "portl-agent service is running"
            return 0
        fi
        sleep 0.5
    done
    "$INSTALL_DIR/portl-agent" status || true
    err "portl-agent service did not become ready after upgrade"
}

verify_agent_runtime_ready() {
    info "waiting for portl-agent runtime readiness"
    if [ "$DRY_RUN" -eq 1 ]; then
        run "$INSTALL_DIR/portl-agent" status
        return 0
    fi
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if "$INSTALL_DIR/portl-agent" status >/dev/null 2>&1; then
            ok "portl-agent runtime is reachable"
            return 0
        fi
        sleep 0.5
    done
    "$INSTALL_DIR/portl-agent" status || true
    err "portl-agent runtime did not become ready"
}

agent_status_field() {
    local field
    field="$1"
    [ -x "$INSTALL_DIR/portl-agent" ] || return 0
    "$INSTALL_DIR/portl-agent" status 2>/dev/null | awk -v key="${field}:" '$1 == key { print $2; exit }' || true
}

agent_runtime_available() {
    [ -n "$(agent_status_field pid)" ]
}

portl_home_dir() {
    local config_path
    config_path="$({ "$INSTALL_DIR/portl" config path 2>/dev/null || true; } | awk 'NR == 1 { print; exit }')"
    if [ -n "$config_path" ]; then
        dirname "$(dirname "$config_path")"
    else
        printf '%s\n' "${PORTL_HOME:-${HOME:-/root}/.portl}"
    fi
}

container_agent_log_path() {
    local home
    home="$(portl_home_dir)"
    printf '%s\n' "$home/logs/portl-agent.log"
}

normalize_agent_version() {
    local version
    version="$1"
    version="${version#v}"
    printf '%s\n' "$version"
}

container_handoff_delay() {
    printf '%s\n' "${PORTL_CONTAINER_HANDOFF_DELAY:-5}"
}

agent_runtime_restart_reason() {
    local pid version normalized_version exe
    pid="$1"
    version="$2"
    normalized_version="$(normalize_agent_version "$version")"
    if [ -n "$normalized_version" ] && [ "$normalized_version" != "$VER" ]; then
        printf 'running version %s differs from installed %s\n' "$version" "$VER"
        return 0
    fi
    if [ -n "$pid" ] && [ -e "/proc/$pid/exe" ]; then
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        case "$exe" in
            *" (deleted)"*)
                printf 'process %s is running from a deleted binary (%s)\n' "$pid" "$exe"
                return 0
                ;;
        esac
    fi
    return 1
}

start_detached_container_agent() {
    local log_path log_dir
    log_path="$(container_agent_log_path)"
    log_dir="$(dirname "$log_path")"
    info "starting unmanaged portl-agent runtime"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "\$ mkdir -p $log_dir"
        if has setsid; then
            log "\$ setsid $INSTALL_DIR/portl-agent >> $log_path 2>&1 < /dev/null &"
        else
            log "\$ nohup $INSTALL_DIR/portl-agent >> $log_path 2>&1 < /dev/null &"
        fi
        return 0
    fi
    mkdir -p "$log_dir"
    if has setsid; then
        setsid "$INSTALL_DIR/portl-agent" >>"$log_path" 2>&1 < /dev/null &
    else
        nohup "$INSTALL_DIR/portl-agent" >>"$log_path" 2>&1 < /dev/null &
    fi
}

schedule_detached_container_agent_restart() {
    local pid reason log_path log_dir delay
    pid="$1"
    reason="$2"
    delay="$(container_handoff_delay)"
    log_path="$(container_agent_log_path)"
    log_dir="$(dirname "$log_path")"
    warn "stale unmanaged portl-agent runtime detected: ${reason}"
    info "scheduling detached runtime restart after installer exits"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "\$ mkdir -p $log_dir"
        if has setsid; then
            log "\$ setsid sh -c 'sleep $delay; revalidate pid $pid; exec $INSTALL_DIR/portl-agent' >> $log_path 2>&1 < /dev/null &"
        else
            log "\$ nohup sh -c 'sleep $delay; revalidate pid $pid; exec $INSTALL_DIR/portl-agent' >> $log_path 2>&1 < /dev/null &"
        fi
        CONTAINER_RUNTIME_HANDOFF_ACTION="restart"
        return 0
    fi
    mkdir -p "$log_dir"
    if has setsid; then
        setsid sh -c '
            delay="$1"; scheduled_pid="$2"; agent="$3"; log_path="$4"; installed_version="$5"
            trap "" HUP
            normalize_version() { version="$1"; version="${version#v}"; printf "%s" "$version"; }
            status_field() {
                field="$1:"
                printf "%s\n" "$status" | while IFS= read -r line; do
                    case "$line" in
                        "$field"*) value="${line#"$field"}"; set -- $value; printf "%s" "${1:-}"; break ;;
                    esac
                done
            }
            process_looks_like_portl() {
                target_pid="$1"
                comm="$(cat "/proc/$target_pid/comm" 2>/dev/null || true)"
                exe="$(readlink "/proc/$target_pid/exe" 2>/dev/null || true)"
                case "$comm:$exe" in
                    portl:*|portl-agent:*|*:*/portl|*:*/portl-agent|*:*/portl\ \(deleted\)|*:*/portl-agent\ \(deleted\)) return 0 ;;
                    *) return 1 ;;
                esac
            }
            process_is_zombie() {
                grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
            }
            sleep "$delay"
            {
                printf "[%s] revalidating stale portl-agent pid %s before restart\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid"
                status="$("$agent" status 2>/dev/null || true)"
                current_pid="$(status_field pid)"
                current_version="$(normalize_version "$(status_field version)")"
                if [ -z "$current_pid" ]; then
                    printf "[%s] no runtime reachable; starting %s\n" "$(date -Is 2>/dev/null || date)" "$agent"
                elif [ "$current_pid" != "$scheduled_pid" ]; then
                    printf "[%s] IPC owner changed from pid %s to pid %s; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid" "$current_pid"
                    exit 0
                elif ! process_looks_like_portl "$current_pid"; then
                    printf "[%s] pid %s no longer looks like portl-agent; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    exit 0
                else
                    stale=0
                    exe="$(readlink "/proc/$current_pid/exe" 2>/dev/null || true)"
                    if [ -n "$current_version" ] && [ "$current_version" != "$installed_version" ]; then stale=1; fi
                    case "$exe" in *" (deleted)"*) stale=1 ;; esac
                    if [ "$stale" -ne 1 ]; then
                        printf "[%s] pid %s is no longer stale; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                        exit 0
                    fi
                    printf "[%s] stopping stale portl-agent pid %s\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    kill "$current_pid" 2>/dev/null || true
                    i=0
                    while [ "$i" -lt 20 ] && kill -0 "$current_pid" 2>/dev/null; do
                        if process_is_zombie "$current_pid"; then
                            break
                        fi
                        sleep 0.25
                        i=$((i + 1))
                    done
                    if kill -0 "$current_pid" 2>/dev/null; then
                        kill -KILL "$current_pid" 2>/dev/null || true
                    fi
                    printf "[%s] starting %s\n" "$(date -Is 2>/dev/null || date)" "$agent"
                fi
            } >>"$log_path" 2>&1
            exec "$agent" >>"$log_path" 2>&1 < /dev/null
        ' portl-agent-restart "$delay" "$pid" "$INSTALL_DIR/portl-agent" "$log_path" "$VER" >/dev/null 2>&1 < /dev/null &
    else
        nohup sh -c '
            delay="$1"; scheduled_pid="$2"; agent="$3"; log_path="$4"; installed_version="$5"
            trap "" HUP
            normalize_version() { version="$1"; version="${version#v}"; printf "%s" "$version"; }
            status_field() {
                field="$1:"
                printf "%s\n" "$status" | while IFS= read -r line; do
                    case "$line" in
                        "$field"*) value="${line#"$field"}"; set -- $value; printf "%s" "${1:-}"; break ;;
                    esac
                done
            }
            process_looks_like_portl() {
                target_pid="$1"
                comm="$(cat "/proc/$target_pid/comm" 2>/dev/null || true)"
                exe="$(readlink "/proc/$target_pid/exe" 2>/dev/null || true)"
                case "$comm:$exe" in
                    portl:*|portl-agent:*|*:*/portl|*:*/portl-agent|*:*/portl\ \(deleted\)|*:*/portl-agent\ \(deleted\)) return 0 ;;
                    *) return 1 ;;
                esac
            }
            process_is_zombie() {
                grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
            }
            sleep "$delay"
            {
                printf "[%s] revalidating stale portl-agent pid %s before restart\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid"
                status="$("$agent" status 2>/dev/null || true)"
                current_pid="$(status_field pid)"
                current_version="$(normalize_version "$(status_field version)")"
                if [ -z "$current_pid" ]; then
                    printf "[%s] no runtime reachable; starting %s\n" "$(date -Is 2>/dev/null || date)" "$agent"
                elif [ "$current_pid" != "$scheduled_pid" ]; then
                    printf "[%s] IPC owner changed from pid %s to pid %s; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid" "$current_pid"
                    exit 0
                elif ! process_looks_like_portl "$current_pid"; then
                    printf "[%s] pid %s no longer looks like portl-agent; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    exit 0
                else
                    stale=0
                    exe="$(readlink "/proc/$current_pid/exe" 2>/dev/null || true)"
                    if [ -n "$current_version" ] && [ "$current_version" != "$installed_version" ]; then stale=1; fi
                    case "$exe" in *" (deleted)"*) stale=1 ;; esac
                    if [ "$stale" -ne 1 ]; then
                        printf "[%s] pid %s is no longer stale; skipping restart\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                        exit 0
                    fi
                    printf "[%s] stopping stale portl-agent pid %s\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    kill "$current_pid" 2>/dev/null || true
                    i=0
                    while [ "$i" -lt 20 ] && kill -0 "$current_pid" 2>/dev/null; do
                        if process_is_zombie "$current_pid"; then
                            break
                        fi
                        sleep 0.25
                        i=$((i + 1))
                    done
                    if kill -0 "$current_pid" 2>/dev/null; then
                        kill -KILL "$current_pid" 2>/dev/null || true
                    fi
                    printf "[%s] starting %s\n" "$(date -Is 2>/dev/null || date)" "$agent"
                fi
            } >>"$log_path" 2>&1
            exec "$agent" >>"$log_path" 2>&1 < /dev/null
        ' portl-agent-restart "$delay" "$pid" "$INSTALL_DIR/portl-agent" "$log_path" "$VER" >/dev/null 2>&1 < /dev/null &
    fi
    CONTAINER_RUNTIME_HANDOFF_ACTION="restart"
    warn "if this shell is attached through Portl, it may disconnect shortly after the installer exits"
}

schedule_detached_container_agent_stop() {
    local pid log_path log_dir delay
    pid="$1"
    delay="$(container_handoff_delay)"
    log_path="$(container_agent_log_path)"
    log_dir="$(dirname "$log_path")"
    info "scheduling detached runtime stop after installer exits"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "\$ mkdir -p $log_dir"
        if has setsid; then
            log "\$ setsid sh -c 'sleep $delay; revalidate pid $pid; kill portl-agent runtime' >> $log_path 2>&1 < /dev/null &"
        else
            log "\$ nohup sh -c 'sleep $delay; revalidate pid $pid; kill portl-agent runtime' >> $log_path 2>&1 < /dev/null &"
        fi
        CONTAINER_RUNTIME_HANDOFF_ACTION="stop"
        return 0
    fi
    mkdir -p "$log_dir"
    if has setsid; then
        setsid sh -c '
            delay="$1"; scheduled_pid="$2"; agent="$3"; log_path="$4"
            trap "" HUP
            status_field() {
                field="$1:"
                printf "%s\n" "$status" | while IFS= read -r line; do
                    case "$line" in
                        "$field"*) value="${line#"$field"}"; set -- $value; printf "%s" "${1:-}"; break ;;
                    esac
                done
            }
            process_looks_like_portl() {
                target_pid="$1"
                comm="$(cat "/proc/$target_pid/comm" 2>/dev/null || true)"
                exe="$(readlink "/proc/$target_pid/exe" 2>/dev/null || true)"
                case "$comm:$exe" in
                    portl:*|portl-agent:*|*:*/portl|*:*/portl-agent|*:*/portl\ \(deleted\)|*:*/portl-agent\ \(deleted\)) return 0 ;;
                    *) return 1 ;;
                esac
            }
            process_is_zombie() {
                grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
            }
            sleep "$delay"
            {
                printf "[%s] revalidating portl-agent pid %s before stop\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid"
                status="$("$agent" status 2>/dev/null || true)"
                current_pid="$(status_field pid)"
                if [ -z "$current_pid" ]; then
                    printf "[%s] no runtime reachable; nothing to stop\n" "$(date -Is 2>/dev/null || date)"
                    exit 0
                elif [ "$current_pid" != "$scheduled_pid" ]; then
                    printf "[%s] IPC owner changed from pid %s to pid %s; skipping stop\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid" "$current_pid"
                    exit 0
                elif ! process_looks_like_portl "$current_pid"; then
                    printf "[%s] pid %s no longer looks like portl-agent; skipping stop\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    exit 0
                fi
                printf "[%s] stopping unmanaged portl-agent pid %s\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                kill "$current_pid" 2>/dev/null || true
                i=0
                while [ "$i" -lt 20 ] && kill -0 "$current_pid" 2>/dev/null; do
                    if process_is_zombie "$current_pid"; then
                        break
                    fi
                    sleep 0.25
                    i=$((i + 1))
                done
                if kill -0 "$current_pid" 2>/dev/null; then
                    kill -KILL "$current_pid" 2>/dev/null || true
                fi
            } >>"$log_path" 2>&1
        ' portl-agent-stop "$delay" "$pid" "$INSTALL_DIR/portl-agent" "$log_path" >/dev/null 2>&1 < /dev/null &
    else
        nohup sh -c '
            delay="$1"; scheduled_pid="$2"; agent="$3"; log_path="$4"
            trap "" HUP
            status_field() {
                field="$1:"
                printf "%s\n" "$status" | while IFS= read -r line; do
                    case "$line" in
                        "$field"*) value="${line#"$field"}"; set -- $value; printf "%s" "${1:-}"; break ;;
                    esac
                done
            }
            process_looks_like_portl() {
                target_pid="$1"
                comm="$(cat "/proc/$target_pid/comm" 2>/dev/null || true)"
                exe="$(readlink "/proc/$target_pid/exe" 2>/dev/null || true)"
                case "$comm:$exe" in
                    portl:*|portl-agent:*|*:*/portl|*:*/portl-agent|*:*/portl\ \(deleted\)|*:*/portl-agent\ \(deleted\)) return 0 ;;
                    *) return 1 ;;
                esac
            }
            process_is_zombie() {
                grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
            }
            sleep "$delay"
            {
                printf "[%s] revalidating portl-agent pid %s before stop\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid"
                status="$("$agent" status 2>/dev/null || true)"
                current_pid="$(status_field pid)"
                if [ -z "$current_pid" ]; then
                    printf "[%s] no runtime reachable; nothing to stop\n" "$(date -Is 2>/dev/null || date)"
                    exit 0
                elif [ "$current_pid" != "$scheduled_pid" ]; then
                    printf "[%s] IPC owner changed from pid %s to pid %s; skipping stop\n" "$(date -Is 2>/dev/null || date)" "$scheduled_pid" "$current_pid"
                    exit 0
                elif ! process_looks_like_portl "$current_pid"; then
                    printf "[%s] pid %s no longer looks like portl-agent; skipping stop\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                    exit 0
                fi
                printf "[%s] stopping unmanaged portl-agent pid %s\n" "$(date -Is 2>/dev/null || date)" "$current_pid"
                kill "$current_pid" 2>/dev/null || true
                i=0
                while [ "$i" -lt 20 ] && kill -0 "$current_pid" 2>/dev/null; do
                    if process_is_zombie "$current_pid"; then
                        break
                    fi
                    sleep 0.25
                    i=$((i + 1))
                done
                if kill -0 "$current_pid" 2>/dev/null; then
                    kill -KILL "$current_pid" 2>/dev/null || true
                fi
            } >>"$log_path" 2>&1
        ' portl-agent-stop "$delay" "$pid" "$INSTALL_DIR/portl-agent" "$log_path" >/dev/null 2>&1 < /dev/null &
    fi
    CONTAINER_RUNTIME_HANDOFF_ACTION="stop"
    warn "agent mode is off; unmanaged portl-agent runtime will be stopped after the installer exits"
}

apply_container_runtime_mode() {
    local was_running should_run pid version reason
    was_running="$1"
    should_run=0
    warn "container detected — skipping service management"
    case "$MODE" in
        client)
            pid="$(agent_status_field pid)"
            if [ -n "$pid" ]; then
                schedule_detached_container_agent_stop "$pid"
            else
                ok "no unmanaged portl-agent runtime is reachable"
            fi
            return 0
            ;;
        agent)
            should_run=1
            ;;
        "")
            [ "$was_running" -eq 1 ] && should_run=1
            ;;
    esac
    if [ "$should_run" -ne 1 ]; then
        warn "run the agent manually:  ${INSTALL_DIR}/portl-agent"
        return 0
    fi

    pid="$(agent_status_field pid)"
    version="$(agent_status_field version)"
    if [ -z "$pid" ]; then
        start_detached_container_agent
        verify_agent_runtime_ready
        return 0
    fi

    if reason="$(agent_runtime_restart_reason "$pid" "$version")"; then
        schedule_detached_container_agent_restart "$pid" "$reason"
        return 0
    fi

    if [ -n "$version" ]; then
        ok "unmanaged portl-agent runtime is running (pid ${pid}, v$(normalize_agent_version "$version"))"
    else
        ok "unmanaged portl-agent runtime is running (pid ${pid}, version unknown)"
    fi
}

apply_service_mode() {
    if [ "$IS_CONTAINER" -eq 1 ]; then
        warn "container detected — skipping service management"
        warn "run the agent manually:  ${INSTALL_DIR}/portl-agent"
        return 0
    fi

    case "$MODE" in
        agent)
            info "ensuring portl-agent service is enabled"
            run "$INSTALL_DIR/portl-agent" up
            ;;
        client)
            info "ensuring portl-agent service is disabled"
            run "$INSTALL_DIR/portl-agent" down
            ;;
        "")
            if service_configured; then
                info "existing portl-agent service detected; restarting"
                run "$INSTALL_DIR/portl-agent" restart
            else
                info "no managed portl-agent service detected; leaving client-only"
            fi
            ;;
    esac
}

# --- main --------------------------------------------------------------

case "$MODE" in
    uninstall) do_uninstall ;;
    ""|client|agent) do_install ;;
esac

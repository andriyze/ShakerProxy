#!/bin/sh
# ShakerProxy installer for Ubuntu Server 24.04 and 26.04 (amd64).
#
#   curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy/main/install/index.sh | sh
#
# A friendly front door: it checks this machine, finds the release to install
# and hands over to that release's signed bootstrap. The bootstrap verifies the
# release signature against ShakerProxy's pinned key, and the installer checks every
# file against the signed manifest, before anything on the system changes.
#
# Run it again at any time to upgrade to the current stable release.
#
# Options (environment variables, all optional):
#   SHAKERPROXY_VERSION=1.2.3        install this release instead of the latest stable one
#                                (a version such as 1.2.3-beta.1 is a beta release)
#   SHAKERPROXY_CHANNEL=beta         the release channel, when it differs from what the version implies
#   SHAKERPROXY_DRY_RUN=1            check this machine and the release; change nothing
#   SHAKERPROXY_OFFLINE_BUNDLE=/dir  install from signed release files already on this machine
#   SHAKERPROXY_GITHUB_USER, SHAKERPROXY_GITHUB_TOKEN
#                                read access to a private ShakerProxy repository
#
# Example: curl -fsSL <installer URL> | SHAKERPROXY_DRY_RUN=1 sh

# Everything runs inside main(), so a partly downloaded script does nothing.
main() {
    set -eu

    REPOSITORY="andriyze/ShakerProxy"
    RELEASES_URL="https://github.com/$REPOSITORY/releases"
    DOCS_URL="https://github.com/$REPOSITORY/blob/main/docs/installation.md"
    VERSION="${SHAKERPROXY_VERSION:-}"
    VERSION="${VERSION#v}"
    CHANNEL="${SHAKERPROXY_CHANNEL:-}"
    # Releases tagged with a prerelease suffix (1.2.3-beta.1) are published as betas.
    if [ -z "$CHANNEL" ]; then
        case "$VERSION" in
            *-*) CHANNEL=beta ;;
            *) CHANNEL=stable ;;
        esac
    fi
    case "$CHANNEL" in
        stable|beta|nightly) ;;
        *) fail "SHAKERPROXY_CHANNEL must be stable, beta or nightly, not '$CHANNEL'." ;;
    esac
    DRY_RUN="${SHAKERPROXY_DRY_RUN:-0}"
    OFFLINE_BUNDLE="${SHAKERPROXY_OFFLINE_BUNDLE:-}"
    WORK_DIR=""
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    say "ShakerProxy installer"
    check_machine
    ensure_curl
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shakerproxy-install.XXXXXX")"

    set --
    [ "$DRY_RUN" = 1 ] && set -- --dry-run
    if [ -n "$OFFLINE_BUNDLE" ]; then
        install_offline "$@"
    else
        install_online "$@"
    fi

    if [ "$DRY_RUN" = 1 ]; then
        say ""
        say "Dry run finished: nothing was changed. Run again without SHAKERPROXY_DRY_RUN=1 to install."
    else
        say "To upgrade later, run the same command again. Guide: $DOCS_URL"
    fi
}

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
fail() {
    printf '\nError: %s\n' "$1" >&2
    [ $# -lt 2 ] || printf '%s\n' "$2" >&2
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    [ -z "${WORK_DIR:-}" ] || rm -rf -- "$WORK_DIR"
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif have sudo; then
        sudo "$@"
    else
        fail "installing ShakerProxy needs root, because it manages this machine's network." \
            "Run this as root, or install sudo and try again."
    fi
}

fetch() {
    if [ -n "${SHAKERPROXY_GITHUB_TOKEN:-}" ]; then
        (umask 077 && printf 'Authorization: Bearer %s\n' "$SHAKERPROXY_GITHUB_TOKEN" > "$WORK_DIR/auth-header")
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 -H "@$WORK_DIR/auth-header" -o "$2" "$1"
    else
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
    fi
}

check_machine() {
    step "Checking this machine"
    [ "$(uname -s)" = Linux ] || fail "ShakerProxy installs on Ubuntu Linux, not $(uname -s)." \
        "Use a dedicated Ubuntu Server 24.04 or 26.04 machine. To try ShakerProxy on a laptop, run the demo from source: $DOCS_URL"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "ShakerProxy supports amd64 (x86_64) machines; this one is $(uname -m)." ;;
    esac
    [ -r /etc/os-release ] || fail "cannot tell which Linux this is (/etc/os-release is missing)."
    # Read os-release in a subshell: it defines VERSION, NAME and more, which
    # must not overwrite this script's own variables (SHAKERPROXY_VERSION).
    # shellcheck disable=SC1091
    os_release="$(. /etc/os-release && printf '%s:%s' "${ID:-}" "${VERSION_ID:-}")"
    # shellcheck disable=SC1091
    os_name="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-an unknown system}")"
    case "$os_release" in
        ubuntu:24.04|ubuntu:26.04) say "  Ubuntu ${os_release#ubuntu:}, amd64: supported" ;;
        *) fail "ShakerProxy supports Ubuntu Server 24.04 and 26.04; this is $os_name." ;;
    esac
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        fail "this is a container. Install ShakerProxy on the machine itself: it manages the machine's network ports."
    fi
    have systemctl || fail "ShakerProxy needs systemd, which this machine is not running."
}

ensure_curl() {
    have curl && return 0
    step "Installing curl"
    as_root apt-get update -qq
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl >/dev/null
}

valid_version() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'
}

install_online() {
    if [ -n "$VERSION" ]; then
        valid_version "$VERSION" || fail "SHAKERPROXY_VERSION must look like 1.2.3, not '$VERSION'."
        url="$RELEASES_URL/download/v$VERSION/bootstrap.sh"
        label="ShakerProxy $VERSION"
        set -- --release "$VERSION" --channel "$CHANNEL" -- "$@"
    else
        [ "$CHANNEL" = stable ] || fail "a $CHANNEL release needs an exact version." \
            "Set SHAKERPROXY_VERSION, for example SHAKERPROXY_VERSION=1.2.3-beta.1."
        # The bootstrap accepts only a release whose signed manifest says "stable".
        url="$RELEASES_URL/latest/download/bootstrap.sh"
        label="the latest stable ShakerProxy release"
        set -- -- "$@"
    fi
    step "Downloading $label"
    fetch "$url" "$WORK_DIR/bootstrap.sh" || {
        [ -n "$VERSION" ] || fail "no stable ShakerProxy release could be downloaded." \
            "Check this machine's internet connection. If none is published yet, run ShakerProxy from source: $DOCS_URL"
        fail "could not download ShakerProxy $VERSION." "Check the version number, or leave SHAKERPROXY_VERSION unset for the latest stable release."
    }
    step "Verifying and installing"
    # stdin is this script when piped from curl; the installer must not read it.
    as_root_with_github_access bash "$WORK_DIR/bootstrap.sh" "$@" < /dev/null
}

# sudo drops the environment; keep only the private-repository credentials,
# without putting the token on a command line.
as_root_with_github_access() {
    if [ -n "${SHAKERPROXY_GITHUB_TOKEN:-}" ] && [ "$(id -u)" -ne 0 ] && have sudo; then
        sudo --preserve-env=SHAKERPROXY_GITHUB_USER,SHAKERPROXY_GITHUB_TOKEN "$@"
    else
        as_root "$@"
    fi
}

install_offline() {
    case "$OFFLINE_BUNDLE" in
        /*) ;;
        *) fail "SHAKERPROXY_OFFLINE_BUNDLE must be an absolute path, such as /home/you/shakerproxy-release." ;;
    esac
    [ -f "$OFFLINE_BUNDLE/install.sh" ] || fail "$OFFLINE_BUNDLE has no install.sh." \
        "Copy every file of one ShakerProxy release into that directory."
    step "Verifying and installing from $OFFLINE_BUNDLE"
    set -- --channel "$CHANNEL" "$@"
    [ -z "$VERSION" ] || set -- --version "$VERSION" "$@"
    as_root bash "$OFFLINE_BUNDLE/install.sh" --offline-bundle "$OFFLINE_BUNDLE" "$@" < /dev/null
}

main "$@"

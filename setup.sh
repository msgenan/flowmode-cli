#!/bin/sh
# Flowmode: install the flowmode CLI from this clone and sign this computer in.
#
#   ./setup.sh <server> <code>   install, then sign in with the one-time code from the team site
#   ./setup.sh <server>          install, then sign in with GitHub in a browser on any device (SSH, no browser here)
#   ./setup.sh                   only install or update (after `git pull`)
#
# It installs uv when it is missing (Astral's installer, pinned version, downloaded to a temp file first), installs
# the CLI with `uv tool install` from this folder with the dependency versions in uv.lock, and runs
# `flowmode login`. It changes no shell file and never prints the code. Your own uv settings (UV_PYTHON,
# UV_CACHE_DIR, UV_TOOL_DIR, UV_TOOL_BIN_DIR) are left as they are.
set -eu

# POSIX sh keeps the export flag of a variable the caller's environment already holds: drop every name this script
# assigns first, so neither the code nor anything else leaks into a child's environment (SR-4).
unset -v server code tab nl bad_code here uv_script pins uv_exe bin_dir flowmode version config signed_in \
    candidate uv_installer_url

uv_installer_url=https://astral.sh/uv/0.12.10/install.sh

say() { printf '%s\n' "$*"; }
die() {
    printf 'setup.sh: %s\n' "$*" >&2
    exit 1
}
usage() {
    printf '%s\n' "usage: ./setup.sh [<server> [<code>]]   (server: https://... ; code: from the team site)" >&2
    exit 2
}

# --- 1. arguments (nothing runs before they pass; the code is never printed) ------------------------------------
[ "$#" -le 2 ] || usage
server=${1:-}
code=${2:-}
if [ "$#" -ge 1 ]; then
    case $server in
        "http://"?* | "https://"?*) ;;
        *)
            say "setup.sh: the server address must start with http:// or https://" >&2
            usage
            ;;
    esac
    tab=$(printf '\t')
    nl='
'
    case $server in
        *" "* | *"$tab"* | *"$nl"* | *\"* | *\'*)
            say "setup.sh: the server address must hold no spaces or quotes" >&2
            usage
            ;;
    esac
fi
if [ "$#" -eq 2 ]; then
    # ^[A-Za-z0-9-]{4,64}$, spelled out so no locale widens the ranges
    case $code in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-]*) bad_code=1 ;;
        *) bad_code=0 ;;
    esac
    if [ "$bad_code" = 1 ] || [ "${#code}" -lt 4 ] || [ "${#code}" -gt 64 ]; then
        say "setup.sh: that code is not valid (letters, digits and '-', 4 to 64 characters); get a new one on the team site" >&2
        usage
    fi
fi

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$here"
[ -f uv.lock ] && [ -f pyproject.toml ] || die "$here is not a flowmode-cli clone (no uv.lock or pyproject.toml)"

uv_script=''
pins=''
cleanup() {
    if [ -n "$uv_script" ]; then rm -f "$uv_script"; fi
    if [ -n "$pins" ]; then rm -f "$pins"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- 2. uv -------------------------------------------------------------------------------------------------------
uv_exe=$(command -v uv || true)
if [ -n "$uv_exe" ]; then
    say "uv: $uv_exe"
else
    say "uv is not installed: installing uv 0.12.10 with Astral's installer ($uv_installer_url)"
    uv_script=$(mktemp "${TMPDIR:-/tmp}/flowmode-uv-install.XXXXXX")
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL -o "$uv_script" "$uv_installer_url" || die "could not download uv's installer"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$uv_script" "$uv_installer_url" ||
            die "could not download uv's installer with wget; install curl and run this again"
    else
        die "neither curl nor wget is installed; install one of them (or uv: https://github.com/astral-sh/uv) and run this again"
    fi
    UV_NO_MODIFY_PATH=1 sh "$uv_script" || die "uv's installer failed"
    for candidate in "${UV_UNMANAGED_INSTALL:-}/uv" "${UV_INSTALL_DIR:-}/uv" "${XDG_BIN_HOME:-}/uv" \
        "${XDG_DATA_HOME:-$HOME/.local/share}/../bin/uv" "$HOME/.local/bin/uv" \
        "${CARGO_HOME:-$HOME/.cargo}/bin/uv"; do
        if [ "$candidate" != /uv ] && [ -x "$candidate" ]; then
            uv_exe=$candidate
            break
        fi
    done
    [ -n "$uv_exe" ] || die "uv was installed but cannot be found; open a new terminal and run ./setup.sh again"
    say "uv: $uv_exe"
fi

# --- 3. install from this clone, pinned to uv.lock ----------------------------------------------------------------
say "Installing flowmode from $here (dependency versions from uv.lock)"
pins=$(mktemp "${TMPDIR:-/tmp}/flowmode-pins.XXXXXX")
"$uv_exe" export --frozen --no-dev --no-emit-project --no-hashes --no-header --quiet --project "$here" -o "$pins" ||
    die "could not read uv.lock (uv export failed)"
"$uv_exe" tool install --force --reinstall --constraints "$pins" "$here" || die "uv tool install failed"
rm -f "$pins"
pins=''

bin_dir=$("$uv_exe" tool dir --bin) || die "uv cannot name its tool folder (uv tool dir --bin failed)"
flowmode=$bin_dir/flowmode
[ -x "$flowmode" ] || die "flowmode was installed but $flowmode is missing"
version=$("$flowmode" --version) || die "$flowmode --version failed"
version=${version#flowmode }

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) say "Note: $bin_dir is not on your PATH; add it to your shell's startup file: export PATH=\"$bin_dir:\$PATH\"" ;;
esac

# --- 4. sign in (the exit code is this step's) --------------------------------------------------------------------
if [ "$#" -eq 2 ]; then
    say "Signing in to $server with your one-time code"
    "$flowmode" login --server "$server" --code "$code"
elif [ "$#" -eq 1 ]; then
    say "Signing in to $server with GitHub"
    "$flowmode" login --server "$server"
else
    config=${FLOWMODE_HOME:-$HOME/.flowmode}/config.toml
    if [ -f "$config" ]; then
        signed_in=$(sed -n 's/^ *server_url *= *"\([^"]*\)".*$/\1/p' "$config" | head -n 1)
        say "Updated flowmode $version; signed in to ${signed_in:-the server in $config}"
    else
        say "Installed flowmode $version. Next: flowmode login --server <your team's address>"
    fi
fi

#!/bin/sh
# Installs the secrethandoff binary for AI agents into ~/.local/bin.
# Connect your MCP client using https://secrethandoff.com/download.
# No administrator rights are needed.
#
#   curl -fsSL https://secrethandoff.com/install.sh | sh
#
# Settings: SECRETHANDOFF_VERSION (default: latest),
# SECRETHANDOFF_BIN_DIR (default: ~/.local/bin),
# SECRETHANDOFF_REPO (default: geland/secrethandoff),
# SECRETHANDOFF_NO_SETUP=1 (skip plugin setup even with a marketplace),
# SECRETHANDOFF_MARKETPLACE (optional plugin source: owner/repo or a folder).
set -eu

repo="${SECRETHANDOFF_REPO:-geland/secrethandoff}"
version="${SECRETHANDOFF_VERSION:-latest}"
bin_dir="${SECRETHANDOFF_BIN_DIR:-$HOME/.local/bin}"

fail() { echo "secrethandoff install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "this script supports macOS and Linux. On Windows, use install.ps1." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported CPU: $(uname -m)" ;;
esac

if [ "$version" = latest ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"cli-v\([0-9.]*\)".*/\1/p' | head -n 1)"
  [ -n "$version" ] || fail "could not find the latest release"
fi
base="${SECRETHANDOFF_DOWNLOAD_URL:-https://github.com/$repo/releases/download/cli-v$version}"
name="secrethandoff_${version}_${os}_${arch}.tar.gz"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL "$base/$name" -o "$work/$name" || fail "download failed: $base/$name"
curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

expected="$(awk -v n="$name" '$2 == n { print $1 }' "$work/SHA256SUMS")"
[ -n "$expected" ] || fail "$name is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$work/$name" | awk '{ print $1 }')"
else
  actual="$(shasum -a 256 "$work/$name" | awk '{ print $1 }')"
fi
[ "$actual" = "$expected" ] || fail "checksum mismatch for $name; nothing was installed"

if command -v gh >/dev/null 2>&1 && [ -z "${SECRETHANDOFF_DOWNLOAD_URL:-}" ]; then
  if gh attestation verify "$work/$name" --repo "$repo" >/dev/null 2>&1; then
    echo "Build provenance verified with gh."
  else
    echo "Note: gh could not verify the build provenance. The checksum matched." >&2
  fi
fi

tar -xzf "$work/$name" -C "$work" secrethandoff
# The native binary owns installation, PATH, and agent setup on every OS.
# A piped bootstrap must never read project consent from its script input.
set -- setup --no-init --bin-dir "$bin_dir"
if [ -n "${SECRETHANDOFF_NO_SETUP:-}" ] || [ -z "${SECRETHANDOFF_MARKETPLACE:-}" ]; then
  set -- "$@" --binary-only
fi
if [ -n "${SECRETHANDOFF_MARKETPLACE:-}" ]; then
  set -- "$@" --marketplace "$SECRETHANDOFF_MARKETPLACE"
fi
"$work/secrethandoff" "$@"

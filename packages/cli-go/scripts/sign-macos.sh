#!/usr/bin/env bash
# Signs the macOS binaries in dist/bin with Developer ID and the hardened
# runtime, then notarizes them. Runs in CI on a macOS runner (task P0-7).
#
# Required environment (GitHub secrets):
#   APPLE_CERT_P12_BASE64   Developer ID Application certificate and key, .p12, base64
#   APPLE_CERT_PASSWORD     password of the .p12
#   APPLE_SIGNING_IDENTITY  for example "Developer ID Application: Name (TEAMID)"
#   APPLE_API_KEY_P8_BASE64 App Store Connect API key, .p8, base64
#   APPLE_API_KEY_ID        key ID
#   APPLE_API_ISSUER_ID     issuer ID
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

for required in APPLE_CERT_P12_BASE64 APPLE_CERT_PASSWORD APPLE_SIGNING_IDENTITY APPLE_API_KEY_P8_BASE64 APPLE_API_KEY_ID APPLE_API_ISSUER_ID; do
  [ -n "${!required:-}" ] || { echo "Missing signing input: $required" >&2; exit 1; }
done

original_keychain_list="$(security list-keychains -d user)"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/secrethandoff-signing.XXXXXX")"
keychain="$work/signing.keychain-db"
keychain_password="$(uuidgen)"
original_keychains=()
while IFS= read -r original; do
  [ -n "$original" ] && original_keychains+=("$original")
done < <(printf '%s\n' "$original_keychain_list" | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//')
search_list_changed=false
cleanup() {
  if [ "$search_list_changed" = true ]; then
    security list-keychains -d user -s ${original_keychains[@]+"${original_keychains[@]}"} || echo "Could not restore keychain search list" >&2
  fi
  security delete-keychain "$keychain" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 900 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode >"$work/cert.p12"
security import "$work/cert.p12" -k "$keychain" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" ${original_keychains[@]+"${original_keychains[@]}"}
search_list_changed=true
printf '%s' "$APPLE_API_KEY_P8_BASE64" | base64 --decode >"$work/key.p8"

for arch in amd64 arm64; do
  bin="dist/bin/darwin-$arch/secrethandoff"
  # --options runtime turns on the hardened runtime. No entitlements are
  # passed, so get-task-allow stays off (threat model T-24).
  codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$APPLE_SIGNING_IDENTITY" "$bin"
  codesign --verify --strict --verbose=2 "$bin"
  ditto -c -k --keepParent "$bin" "$work/notarize-$arch.zip"
  xcrun notarytool submit "$work/notarize-$arch.zip" \
    --key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" \
    --wait --timeout 15m --output-format json > "$work/notary-$arch.json"
  status="$(plutil -extract status raw -o - "$work/notary-$arch.json")"
  [ "$status" = Accepted ] || { echo "Notarization for $arch was not accepted: $status" >&2; exit 1; }
  echo "Developer ID signature verified and notarization accepted for $arch."
done

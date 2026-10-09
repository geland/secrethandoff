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
cd "$(dirname "$0")/.."

work="${RUNNER_TEMP:-$(mktemp -d)}"
keychain="$work/signing.keychain-db"
keychain_password="$(uuidgen)"
cleanup() {
  rm -f "$work/cert.p12" "$work/key.p8"
  security delete-keychain "$keychain" 2>/dev/null || true
}
trap cleanup EXIT

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 900 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode >"$work/cert.p12"
security import "$work/cert.p12" -k "$keychain" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
printf '%s' "$APPLE_API_KEY_P8_BASE64" | base64 --decode >"$work/key.p8"

for arch in amd64 arm64; do
  bin="dist/bin/darwin-$arch/secrethandoff"
  # --options runtime turns on the hardened runtime. No entitlements are
  # passed, so get-task-allow stays off (threat model T-24).
  codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$bin"
  codesign --verify --strict --verbose=2 "$bin"
  ditto -c -k --keepParent "$bin" "$work/notarize-$arch.zip"
  xcrun notarytool submit "$work/notarize-$arch.zip" \
    --key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" --wait
done

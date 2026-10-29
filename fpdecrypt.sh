#!/bin/bash
# End-to-end: embed IPA -> build/sign/install FairPlayed -> decrypt on device -> pull + verify the decrypted IPA.
# The device must be signed into the Apple ID that owns the license for the IPA.
set -euo pipefail
IPA="${1:?usage: fpdecrypt.sh app.ipa}"
DEVICE="${DEVICE:?set DEVICE to your iPhone UDID (xcrun devicectl list devices)}"
BUNDLE_ID="${BUNDLE_ID:?set BUNDLE_ID to your app identifier (for example com.example.fairplayed)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$HERE/FairPlayed"
OUT="$PROJ/out"; mkdir -p "$OUT"

"$HERE/embed_ipa.sh" "$IPA"
NAME="$(ls "$PROJ/payload")"

xcodebuild -project "$PROJ/FairPlayed.xcodeproj" -scheme FairPlayed -configuration Debug \
  PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
  -destination "id=$DEVICE" -derivedDataPath "$PROJ/build" -allowProvisioningUpdates build \
  | grep -E 'embedded:|BUILD (SUCCEEDED|FAILED)'
xcrun devicectl device install app --device "$DEVICE" "$PROJ/build/Build/Products/Debug-iphoneos/FairPlayed.app" >/dev/null

xcrun devicectl device process launch --console --terminate-existing --device "$DEVICE" \
  --environment-variables '{"FPD_AUTORUN":"export","FPD_EXIT":"1"}' "$BUNDLE_ID" 2>&1 | tee "$OUT/export-$NAME.txt"

for suffix in decrypted PARTIAL; do
  if xcrun devicectl device copy from --device "$DEVICE" --domain-type appDataContainer --domain-identifier "$BUNDLE_ID" \
       --source "Documents/Decrypted/$NAME-$suffix.ipa" --destination "$OUT/$NAME-$suffix.ipa" >/dev/null 2>&1; then
    echo "pulled $OUT/$NAME-$suffix.ipa"
    "$HERE/verify_ipa.sh" "$OUT/$NAME-$suffix.ipa"
    exit $?
  fi
done
echo "no output IPA found on device" >&2
exit 1

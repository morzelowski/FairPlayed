#!/bin/bash
# Download (optional), embed, build, sign, install, decrypt, pull, and verify an IPA.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./fpdecrypt.sh path/to/encrypted.ipa [options]
  ./fpdecrypt.sh --download <target-app-bundle-id> [options]

Options:
  --download <id>              Download the target app with ipatool first.
  --device <udid>              Physical iPhone UDID. Auto-detected when exactly one is connected.
  --fairplayed-bundle-id <id>  Bundle ID of the FairPlayed helper app.
                               Default: com.m0u.fairplayed
  --team-id <id>               Override the Team selected in Xcode (mainly for CI).
  --platform <name>            ipatool platform (iphone, ipad, etc.) for --download.
  --skip-trust-prompt          Do not pause after installation to verify the developer certificate.
  -h, --help                   Show this help.

Environment equivalents:
  DEVICE, FAIRPLAYED_BUNDLE_ID, TEAM_ID, PLATFORM, SKIP_TRUST_PROMPT=1

Important:
  The target app bundle ID is used only with --download. FairPlayed must use its
  own bundle ID; never use the target app's bundle ID as FAIRPLAYED_BUNDLE_ID.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

HERE="$(cd "$(dirname "$0")" && pwd)"
LOCAL_CONFIG="$HERE/.fairplayed.env"
SAVED_TEAM_ID=""
if [ -f "$LOCAL_CONFIG" ]; then
  SAVED_TEAM_ID="$(sed -n 's/^TEAM_ID=//p' "$LOCAL_CONFIG" | tail -1)"
fi

IPA=""
TARGET_BUNDLE_ID=""
DEVICE="${DEVICE:-}"
FAIRPLAYED_BUNDLE_ID="${FAIRPLAYED_BUNDLE_ID:-com.m0u.fairplayed}"
TEAM_ID_FROM_ENV="${TEAM_ID:-}"
TEAM_ID="${TEAM_ID_FROM_ENV:-$SAVED_TEAM_ID}"
TEAM_ID_EXPLICIT=0
[ -z "$TEAM_ID_FROM_ENV" ] || TEAM_ID_EXPLICIT=1
SAVE_TEAM_ID=0
PLATFORM="${PLATFORM:-}"
SKIP_TRUST_PROMPT="${SKIP_TRUST_PROMPT:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --download)
      [ "$#" -ge 2 ] || fail "--download requires the target app bundle ID"
      TARGET_BUNDLE_ID="$2"; shift 2 ;;
    --device)
      [ "$#" -ge 2 ] || fail "--device requires a UDID"
      DEVICE="$2"; shift 2 ;;
    --fairplayed-bundle-id)
      [ "$#" -ge 2 ] || fail "--fairplayed-bundle-id requires a value"
      FAIRPLAYED_BUNDLE_ID="$2"; shift 2 ;;
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      TEAM_ID="$2"; TEAM_ID_EXPLICIT=1; SAVE_TEAM_ID=1; shift 2 ;;
    --platform)
      [ "$#" -ge 2 ] || fail "--platform requires a value"
      PLATFORM="$2"; shift 2 ;;
    --skip-trust-prompt)
      SKIP_TRUST_PROMPT=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --)
      shift; break ;;
    -*)
      fail "unknown option: $1 (run ./fpdecrypt.sh --help)" ;;
    *)
      [ -z "$IPA" ] || fail "provide only one IPA path"
      IPA="$1"; shift ;;
  esac
done

[ -z "$IPA" ] || [ -z "$TARGET_BUNDLE_ID" ] || \
  fail "provide an IPA path or --download, not both"
[ -n "$IPA" ] || [ -n "$TARGET_BUNDLE_ID" ] || { usage >&2; exit 2; }

case "$FAIRPLAYED_BUNDLE_ID" in
  com.example.fairplay|com.example.fairplayed)
    echo "warning: replacing placeholder $FAIRPLAYED_BUNDLE_ID with com.m0u.fairplayed" >&2
    FAIRPLAYED_BUNDLE_ID="com.m0u.fairplayed" ;;
esac

PROJ="$HERE/FairPlayed"
OUT="$PROJ/out"
mkdir -p "$OUT"

PROJECT_FILE="$PROJ/FairPlayed.xcodeproj/project.pbxproj"
PROJECT_TEAM_IDS="$(sed -nE 's/^[[:space:]]*DEVELOPMENT_TEAM = ([[:alnum:]]{10});$/\1/p' \
  "$PROJECT_FILE" | sort -u)"
PROJECT_TEAM_COUNT="$(printf '%s\n' "$PROJECT_TEAM_IDS" | sed '/^$/d' | wc -l | tr -d ' ')"

if [ "$PROJECT_TEAM_COUNT" -gt 1 ]; then
  printf 'Multiple development teams are configured in Xcode:\n%s\n' "$PROJECT_TEAM_IDS" >&2
  fail "select one Team for every FairPlayed build configuration, then close Xcode"
elif [ "$PROJECT_TEAM_COUNT" = "1" ]; then
  if [ "$TEAM_ID_EXPLICIT" = "0" ]; then
    TEAM_ID="$PROJECT_TEAM_IDS"
    SAVE_TEAM_ID=1
    echo "==> Imported the Team selected in Xcode"
  elif [ "$TEAM_ID" != "$PROJECT_TEAM_IDS" ]; then
    echo "warning: --team-id/TEAM_ID overrides the different Team selected in Xcode" >&2
  fi

  SANITIZED_PROJECT="$(mktemp "${TMPDIR:-/tmp}/fairplayed-project.XXXXXX")"
  sed -E '/^[[:space:]]*DEVELOPMENT_TEAM = [[:alnum:]]{10};$/d' \
    "$PROJECT_FILE" > "$SANITIZED_PROJECT"
  cp "$SANITIZED_PROJECT" "$PROJECT_FILE"
  rm -f "$SANITIZED_PROJECT"
  echo "==> Removed the private Team ID from project.pbxproj"
fi

if [ -z "$TEAM_ID" ]; then
  echo "No local Apple Development Team is configured." >&2
  echo "Open FairPlayed/FairPlayed.xcodeproj in Xcode, select the FairPlayed target," >&2
  echo "enable Signing & Capabilities > Automatically manage signing, choose your Team," >&2
  echo "save the project, close Xcode, and run this command again." >&2
  fail "Team setup is required once before the first run"
fi

[[ "$TEAM_ID" =~ ^[[:alnum:]]{10}$ ]] || fail "Team ID must contain exactly 10 letters or digits"
if [ "$SAVE_TEAM_ID" = "1" ]; then
  printf 'TEAM_ID=%s\n' "$TEAM_ID" > "$LOCAL_CONFIG"
  chmod 600 "$LOCAL_CONFIG"
  echo "==> Saved Team locally in $LOCAL_CONFIG (ignored by Git)"
fi

for tool in xcodebuild xcrun unzip ditto otool; do
  command -v "$tool" >/dev/null || fail "required tool not found: $tool"
done

if [ -n "$TARGET_BUNDLE_ID" ]; then
  command -v ipatool >/dev/null || fail "ipatool is required for --download (brew install ipatool)"
  IPA="$OUT/encrypted.ipa"
  rm -f "$IPA"
  echo "==> Downloading target app: $TARGET_BUNDLE_ID"
  DOWNLOAD_ARGS=(download --bundle-identifier "$TARGET_BUNDLE_ID" --purchase --output "$IPA")
  [ -z "$PLATFORM" ] || DOWNLOAD_ARGS+=(--platform "$PLATFORM")
  ipatool "${DOWNLOAD_ARGS[@]}"
fi

[ -f "$IPA" ] || fail "IPA not found: $IPA"

if [ -z "$DEVICE" ]; then
  echo "==> Detecting a connected physical iPhone"
  DEVICE_LIST="$(xcrun devicectl list devices 2>/dev/null || true)"
  DEVICE_CANDIDATES="$(printf '%s\n' "$DEVICE_LIST" | grep -Eo '0000[[:xdigit:]]{4}-[[:xdigit:]]{16}' | sort -u || true)"
  DEVICE_COUNT="$(printf '%s\n' "$DEVICE_CANDIDATES" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$DEVICE_COUNT" = "1" ]; then
    DEVICE="$DEVICE_CANDIDATES"
  elif [ "$DEVICE_COUNT" = "0" ]; then
    fail "no physical iPhone found; connect and unlock it, then use --device <udid>"
  else
    printf 'Multiple physical devices found:\n%s\n' "$DEVICE_CANDIDATES" >&2
    fail "select one with --device <udid>"
  fi
fi

case "$DEVICE" in
  ????????-????-????-????-????????????)
    fail "$DEVICE looks like a simulator UUID; use the physical iPhone UDID from 'xcrun devicectl list devices'" ;;
esac

echo "==> Configuration"
echo "    Device:              $DEVICE"
echo "    FairPlayed bundle:   $FAIRPLAYED_BUNDLE_ID"
echo "    Development team:    $TEAM_ID"
echo "    Encrypted IPA:       $IPA"

echo "==> Embedding IPA"
"$HERE/embed_ipa.sh" "$IPA"
NAME="$(find "$PROJ/payload" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | head -1)"
[ -n "$NAME" ] || fail "embedded payload name could not be determined"

BUILD_LOG="$OUT/build.log"
echo "==> Building and signing FairPlayed (full log: $BUILD_LOG)"
set +e
xcodebuild -project "$PROJ/FairPlayed.xcodeproj" -scheme FairPlayed -configuration Debug \
  -destination "id=$DEVICE" -derivedDataPath "$PROJ/build" -allowProvisioningUpdates \
  PRODUCT_BUNDLE_IDENTIFIER="$FAIRPLAYED_BUNDLE_ID" DEVELOPMENT_TEAM="$TEAM_ID" build \
  2>&1 | tee "$BUILD_LOG"
BUILD_STATUS=${PIPESTATUS[0]}
set -e
if [ "$BUILD_STATUS" -ne 0 ]; then
  echo "Build failed. Relevant diagnostics:" >&2
  grep -E '(^| )error:|BUILD FAILED|provisioning profile|Signing' "$BUILD_LOG" | tail -30 >&2 || true
  if grep -q 'No Account for Team' "$BUILD_LOG"; then
    echo "Xcode has no signed-in Apple account for this Team ID." >&2
    echo "Open Xcode > Settings > Apple Accounts and add or re-authenticate that Apple account." >&2
    echo "Keep $LOCAL_CONFIG unless the Team ID itself is incorrect." >&2
  fi
  exit "$BUILD_STATUS"
fi

APP_PATH="$PROJ/build/Build/Products/Debug-iphoneos/FairPlayed.app"
[ -d "$APP_PATH" ] || fail "built app not found: $APP_PATH"

echo "==> Installing FairPlayed"
xcrun devicectl device install app --device "$DEVICE" "$APP_PATH"

if [ "$SKIP_TRUST_PROMPT" != "1" ]; then
  echo
  echo "==> Verify the developer certificate on the iPhone"
  echo "    Keep the iPhone unlocked and connected. Open:"
  echo "    Settings > General > VPN & Device Management > Developer App"
  echo "    Select your developer account and tap Trust/Verify if it is shown."
  echo
  if [ -t 0 ]; then
    read -r -p "Press Enter after the developer certificate is trusted... " _
  else
    fail "certificate verification requires an interactive terminal; rerun normally or use --skip-trust-prompt"
  fi
fi

echo "==> Decrypting embedded payload"
xcrun devicectl device process launch --console --terminate-existing --device "$DEVICE" \
  --environment-variables '{"FPD_AUTORUN":"export","FPD_EXIT":"1"}' \
  "$FAIRPLAYED_BUNDLE_ID" 2>&1 | tee "$OUT/export-$NAME.txt"

echo "==> Pulling decrypted IPA"
for suffix in decrypted PARTIAL; do
  DESTINATION="$OUT/$NAME-$suffix.ipa"
  rm -f "$DESTINATION"
  if xcrun devicectl device copy from --device "$DEVICE" \
       --domain-type appDataContainer --domain-identifier "$FAIRPLAYED_BUNDLE_ID" \
       --source "Documents/Decrypted/$NAME-$suffix.ipa" --destination "$DESTINATION" \
       >/dev/null 2>&1; then
    echo "pulled $DESTINATION"
    "$HERE/verify_ipa.sh" "$DESTINATION"
    exit $?
  fi
done

fail "no output IPA found on device; inspect $OUT/export-$NAME.txt"

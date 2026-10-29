#!/bin/bash
# Stage an (encrypted, App Store) IPA into FairPlayed/payload/ so the next FairPlayed build embeds it.
# fairplayd only reads SINFs/binaries from installed bundles, so the target must ship inside FairPlayed.app.
set -euo pipefail
IPA="${1:?usage: embed_ipa.sh app.ipa}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$HERE/FairPlayed/payload"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

unzip -q "$IPA" -d "$TMP"
APP="$(find "$TMP/Payload" -maxdepth 1 -name '*.app' -type d | head -1)"
[ -n "$APP" ] || { echo "no Payload/*.app in $IPA" >&2; exit 1; }
NAME="$(basename "$APP" .app)"

rm -rf "$PAYLOAD"; mkdir -p "$PAYLOAD"
ditto "$APP" "$PAYLOAD/$NAME"          # stored without the .app suffix so codesign treats it as plain resources
rm -rf "$PAYLOAD/$NAME/Watch"          # watchOS binaries are not decryptable on the iPhone

# Nested SC_Info dirs ship without a .sinf; installd copies the main SINF to every SinfReplicationPaths
# entry at install time. FairPlayed's install will not do that for embedded payload, so replicate here.
MAN="$PAYLOAD/$NAME/SC_Info/Manifest.plist"
if [ -f "$MAN" ]; then
  MAIN_SINF="$(/usr/libexec/PlistBuddy -c 'Print :SinfPaths:0' "$MAN")"
  i=0; rep=0
  while p="$(/usr/libexec/PlistBuddy -c "Print :SinfReplicationPaths:$i" "$MAN" 2>/dev/null)"; do
    i=$((i + 1))
    case "$p" in Watch/*|*..*) continue ;; esac
    if [ ! -f "$PAYLOAD/$NAME/$p" ]; then
      mkdir -p "$(dirname "$PAYLOAD/$NAME/$p")"
      cp "$PAYLOAD/$NAME/$MAIN_SINF" "$PAYLOAD/$NAME/$p"
      rep=$((rep + 1))
    fi
  done
  echo "replicated $MAIN_SINF to $rep nested SC_Info location(s)"
fi

enc=0; total=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'Mach-O' || continue
  total=$((total + 1))
  otool -l "$f" 2>/dev/null | grep -A4 LC_ENCRYPTION_INFO | grep -q 'cryptid 1' && enc=$((enc + 1))
done < <(find "$PAYLOAD/$NAME" -type f -size +4k -print0)
echo "embedded $NAME ($(du -sh "$PAYLOAD/$NAME" | cut -f1)): $total Mach-O files, $enc encrypted"

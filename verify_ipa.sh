#!/bin/bash
# Report the encryption state of every Mach-O in an IPA. Exit 1 if any 64-bit slice is still encrypted.
set -euo pipefail
IPA="${1:?usage: verify_ipa.sh app.ipa}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
unzip -q "$IPA" -d "$TMP"

enc=0; dec=0; plain=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'Mach-O' || continue
  rel="${f#$TMP/Payload/}"
  ids="$(otool -arch arm64 -l "$f" 2>/dev/null | grep -A4 LC_ENCRYPTION_INFO_64 | awk '/cryptid/{print $2}' | tr '\n' ' ' || true)"
  case "$ids" in
    *1*) enc=$((enc + 1)); echo "ENCRYPTED  $rel" ;;
    *0*) dec=$((dec + 1)); echo "cryptid=0  $rel" ;;
    *)   plain=$((plain + 1)) ;;
  esac
done < <(find "$TMP/Payload" -type f -size +4k -print0)
echo "summary: $dec with cryptid 0, $enc still encrypted, $plain without LC_ENCRYPTION_INFO_64"
[ "$enc" -eq 0 ]

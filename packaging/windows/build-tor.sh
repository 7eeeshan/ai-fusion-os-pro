#!/usr/bin/env bash
# Downloads the Tor Expert Bundle for Windows into build/tor and verifies it: the signed checksum list must carry a
# valid signature from the Tor Browser developers' key (fingerprint pinned below) and the archive must match it.
set -euo pipefail
FPR="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/tor"
DL="$ROOT/build/downloads"
mkdir -p "$DL"
VERSION="${TOR_BUNDLE_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL https://aus1.torproject.org/torbrowser/update_3/release/downloads.json | python -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
fi
BASE="https://archive.torproject.org/tor-package-archive/torbrowser/$VERSION"
FILE="tor-expert-bundle-windows-x86_64-$VERSION.tar.gz"
curl -fsSL -o "$DL/$FILE" "$BASE/$FILE"
curl -fsSL -o "$DL/sha256sums-signed-build.txt" "$BASE/sha256sums-signed-build.txt"
curl -fsSL -o "$DL/sha256sums-signed-build.txt.asc" "$BASE/sha256sums-signed-build.txt.asc"
export GNUPGHOME="$DL/gnupg"
rm -rf "$GNUPGHOME" && mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
curl -fsSL "https://keys.openpgp.org/vks/v1/by-fingerprint/$FPR" | gpg --batch --import
gpg --batch --status-fd 1 --verify "$DL/sha256sums-signed-build.txt.asc" "$DL/sha256sums-signed-build.txt" > "$DL/gpg.status"
grep -Eq "^\[GNUPG:\] VALIDSIG .* ${FPR}\$" "$DL/gpg.status" || { echo "bad signature"; cat "$DL/gpg.status"; exit 1; }
EXPECTED="$(grep " $FILE\$" "$DL/sha256sums-signed-build.txt" | awk '{print $1}')"
ACTUAL="$(sha256sum "$DL/$FILE" | awk '{print $1}')"
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || { echo "checksum mismatch for $FILE"; exit 1; }
rm -rf "$OUT" && mkdir -p "$OUT"
tar -xzf "$DL/$FILE" -C "$OUT"
test -f "$OUT/tor/tor.exe"
echo "$VERSION" > "$OUT/VERSION"
echo "tor $VERSION ready in $OUT"

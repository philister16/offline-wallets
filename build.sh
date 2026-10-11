#!/bin/bash
# Builds dist/ofwl, a standalone executable (Node.js SEA): a copy of the local
# Node.js binary with the bundled ofwl code injected.
#
# Nothing is downloaded. The build already trusts the local `node` (it runs
# npm, esbuild and the tests), so reusing it adds no new trust root. It must be
# an official, self-contained build (nodejs.org, nvm, fnm, Volta); builds that
# link shared libraries, such as Homebrew's or a distro's `node`, would not run
# on the offline machine.
set -euo pipefail

MIN_NODE_MAJOR=22
SEA_FUSE=NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
PLATFORM=$(uname -s)

fail() {
  echo "Error: $*" >&2
  exit 1
}

NODE_BIN=$(node -p 'process.execPath')
NODE_VERSION=$(node -v)
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge "$MIN_NODE_MAJOR" ] || fail "Node.js $MIN_NODE_MAJOR or newer is required (found $NODE_VERSION)."

echo "==> Checking that Node.js $NODE_VERSION at $NODE_BIN is self-contained..."
case "$PLATFORM" in
  Darwin)
    # First line of `otool -L` is the binary itself; the rest are its libraries.
    NON_SYSTEM_LIBS=$(otool -L "$NODE_BIN" | tail -n +2 | awk '{print $1}' \
      | grep -v -E '^(/usr/lib/|/System/Library/)' || true)
    ;;
  Linux)
    NON_SYSTEM_LIBS=$(ldd "$NODE_BIN" | awk '{print $1}' | sed 's|.*/||' \
      | grep -v -E '^(linux-vdso|linux-gate|ld-linux[^.]*|libc|libm|libdl|libpthread|librt|libstdc\+\+|libgcc_s|libatomic)\.so' \
      | grep -v -E '^statically$' || true)
    ;;
  *)
    fail "unsupported platform: $PLATFORM (macOS and Linux only)."
    ;;
esac
if [ -n "$NON_SYSTEM_LIBS" ]; then
  echo "$NON_SYSTEM_LIBS" | sed 's/^/    /' >&2
  fail "this Node.js links the libraries above, so a binary built from it would not run on
another machine. Install an official build (nodejs.org installer, nvm, fnm or Volta) and
run the build with it."
fi
grep -q "$SEA_FUSE" "$NODE_BIN" || fail "this Node.js build does not support single executable applications."

for tool in esbuild postject; do
  [ -x "node_modules/.bin/$tool" ] || fail "node_modules/.bin/$tool not found. Run \"npm ci\" first."
done

rm -rf dist
mkdir -p dist

echo "==> Bundling with esbuild..."
node_modules/.bin/esbuild index.js --bundle --platform=node --format=cjs --outfile=dist/bundle.js

echo "==> Generating SEA blob..."
"$NODE_BIN" --experimental-sea-config sea-config.json

echo "==> Copying Node.js binary..."
cp "$NODE_BIN" dist/ofwl
chmod u+w dist/ofwl

if [ "$PLATFORM" = "Darwin" ]; then
  echo "==> Removing macOS signature..."
  codesign --remove-signature dist/ofwl
fi

echo "==> Injecting SEA blob..."
node_modules/.bin/postject dist/ofwl NODE_SEA_BLOB dist/sea-prep.blob \
  --sentinel-fuse "$SEA_FUSE" \
  $([ "$PLATFORM" = "Darwin" ] && echo "--macho-segment-name NODE_SEA")

if [ "$PLATFORM" = "Darwin" ]; then
  echo "==> Re-signing binary..."
  codesign --sign - dist/ofwl
fi

echo "==> Smoke-testing the binary..."
EXPECTED_VERSION=$(node -p 'require("./package.json").version')
[ "$(dist/ofwl --version)" = "$EXPECTED_VERSION" ] || fail "dist/ofwl --version does not print $EXPECTED_VERSION."
# Public test vector (Hardhat/Anvil default account); never fund it.
SMOKE=$(printf 'test test test test test test test test test test test junk\n\n' \
  | dist/ofwl restore --allow-online 2>&1) || fail "dist/ofwl restore failed:
$SMOKE"
echo "$SMOKE" | grep -q '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' || fail "dist/ofwl restored the wrong address."
rm -f dist/bundle.js dist/sea-prep.blob

if [ "$PLATFORM" = "Darwin" ]; then
  HASH=$(shasum -a 256 dist/ofwl | awk '{print $1}')
else
  HASH=$(sha256sum dist/ofwl | awk '{print $1}')
fi

echo "==> Done! Binary at dist/ofwl (Node.js $NODE_VERSION, $(node -p 'process.platform + "-" + process.arch'))"
ls -lh dist/ofwl
echo ""
echo "SHA-256: $HASH"
echo "Record this hash and check it on the offline machine before running ofwl."

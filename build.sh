#!/bin/bash
set -euo pipefail

NODE_VERSION=$(node -v)
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(node -e "console.log(process.arch === 'x64' ? 'x64' : 'arm64')")

if [ "$PLATFORM" = "darwin" ]; then
  TARBALL="node-${NODE_VERSION}-darwin-${ARCH}.tar.gz"
  NODE_DIR="node-${NODE_VERSION}-darwin-${ARCH}"
elif [ "$PLATFORM" = "linux" ]; then
  TARBALL="node-${NODE_VERSION}-linux-${ARCH}.tar.gz"
  NODE_DIR="node-${NODE_VERSION}-linux-${ARCH}"
else
  echo "Unsupported platform: $PLATFORM"
  exit 1
fi

DOWNLOAD_URL="https://nodejs.org/dist/${NODE_VERSION}/${TARBALL}"

echo "==> Bundling with esbuild..."
npx esbuild index.js --bundle --platform=node --outfile=dist/bundle.js

echo "==> Generating SEA blob..."
node --experimental-sea-config sea-config.json

echo "==> Downloading clean Node.js binary (${NODE_VERSION} ${PLATFORM}-${ARCH})..."
curl -sL "$DOWNLOAD_URL" -o "dist/${TARBALL}"
tar -xzf "dist/${TARBALL}" -C dist/
cp "dist/${NODE_DIR}/bin/node" dist/ofwl
rm -rf "dist/${NODE_DIR}" "dist/${TARBALL}"

if [ "$PLATFORM" = "darwin" ]; then
  echo "==> Removing macOS signature..."
  codesign --remove-signature dist/ofwl
fi

echo "==> Injecting SEA blob..."
npx postject dist/ofwl NODE_SEA_BLOB dist/sea-prep.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
  $([ "$PLATFORM" = "darwin" ] && echo "--macho-segment-name NODE_SEA")

if [ "$PLATFORM" = "darwin" ]; then
  echo "==> Re-signing binary..."
  codesign --sign - dist/ofwl
fi

echo "==> Done! Binary at dist/ofwl"
ls -lh dist/ofwl

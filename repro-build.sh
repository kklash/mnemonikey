#!/bin/bash

set -e -o pipefail

mkdir -p build

export CGO_ENABLED=0
export GOAMD64=v1
export GO386=sse2

GOVERSION="$(go env GOVERSION)"
echo "Compiling reproducible builds."
echo "  compiler version: $GOVERSION"
echo "  git commit hash:  $(git rev-parse HEAD)"
echo ""
echo "The same compiler and source files must be used when reproducing builds."
echo ""

for os in linux windows darwin; do
  for arch in 386 amd64 arm64; do
    if [[ $arch == "386" ]] && [[ $os == "darwin" ]]; then
      continue
    fi

    outfile="mnemonikey-$os-$arch"
    echo "Building $outfile..."

    GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false -ldflags='-s -w' -o "../../build/$outfile" ./cmd/mnemonikey
  done
done

echo "Done. Artifacts compiled in ./build"
echo ""
shasum -a 256 build/*

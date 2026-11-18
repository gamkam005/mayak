#!/usr/bin/env bash
# Собирает образы контейнера МАЯК (формат docker save) для RouterOS / docker / podman:
#   mayak-container-{lite,full}-{amd64,arm64,armv7}.tar
# lite — без Xray (только свой сервер МАЯК, ~11 МБ), full — с запасным входом из подписок (~33 МБ).
# RB4011, hAP ac², RB3011 и другие 32-битные ARM — armv7; RB5009, hAP ax³, CCR2004 — arm64; CHR — amd64.
#   OUT=./out mikrotik/build-images.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$HERE/..
OUT=${OUT:-$ROOT/build/images}; VER=${VER:-$(sed -n 's/^var version = "\(.*\)"/\1/p' "$ROOT/cmd/mayak/main.go")}
mkdir -p "$OUT"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cd "$ROOT"; export CGO_ENABLED=0
for a in "amd64 amd64 amd64 " "arm64 arm64 arm64 " "armv7 arm arm/v7 7"; do
  set -- $a; name=$1 goarch=$2 plat=$3 goarm=${4:-}
  for kind in lite full; do
    tags=""; [ $kind = lite ] && tags="-tags lite"
    GOOS=linux GOARCH=$goarch GOARM=$goarm go build $tags -trimpath -ldflags "-s -w -buildid=" -o "$T/mayak-$kind-$name" ./cmd/mayak
    python3 "$HERE/mkimage.py" -bin "$T/mayak-$kind-$name" -arch "$plat" -tag "mayak:$VER-$kind" -o "$OUT/mayak-container-$kind-$name.tar"
  done
done

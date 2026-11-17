#!/usr/bin/env bash
# Сборка libhev-socks5-tunnel.so для APK (VPN-режим). Нужен Android NDK.
#
#   NDK=/путь/к/ndk scripts/build-hev.sh [hev-src] [куда/hevbuild]
#
# Если hev-src не указан, скрипт клонирует
# https://github.com/heiher/hev-socks5-tunnel (MIT) в .deps/hev-socks5-tunnel.
# Исходники hev в репозиторий МАЯК не входят.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${NDK:?укажите NDK=/путь/к/android-ndk}"
SRC=${1:-}
OUT=${2:-"$ROOT/hevbuild"}
if [ -z "$SRC" ]; then
  SRC="$ROOT/.deps/hev-socks5-tunnel"
  if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$ROOT/.deps"
    git clone --depth 1 https://github.com/heiher/hev-socks5-tunnel.git "$SRC"
  fi
fi
SRC=$(readlink -f "$SRC")
mkdir -p "$OUT" && cd "$OUT" && rm -f jni && ln -s "$SRC" jni
"$NDK/ndk-build" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk \
  APP_ABI="arm64-v8a x86_64" APP_CFLAGS="-O3 -DPKGNAME=ru/mayak/app -DCLSNAME=TProxy" -j8

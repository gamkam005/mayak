#!/usr/bin/env bash
# Собирает mayak_<ver>_<arch>.ipk (lite, без Xray) и mayak-full_<ver>_<arch>.ipk (с Xray) (формат opkg: tar.gz с debian-binary, control.tar.gz, data.tar.gz).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
VER=${VER:-0.3.4}; BIN=${BIN:-$HERE/../build}; OUT=${OUT:-$HERE/../build}
mkdir -p "$OUT"; BIN=$(cd "$BIN" && pwd); OUT=$(cd "$OUT" && pwd)
cd "$HERE"
build() { # opkg-arch go-suffix [full]
  [ -z "${ONLY:-}" ] || [ "$1" = "$ONLY" ] || return 0
  local arch=$1 suf=$2 kind=${3:-} T pkg=mayak src extra="" desc="MAYAK mosaic tunnel client (lite, no Xray): local SOCKS5/HTTP proxy for podkop"; T=$(mktemp -d)
  if [ "$kind" = full ]; then pkg=mayak-full; src="$BIN/mayak-linux-$suf"; extra=$'Conflicts: mayak\n'; desc="MAYAK tunnel client with Xray reserve (VLESS/VMess/Trojan/SS/Hy2 subscriptions)"; else src="$BIN/mayak-lite-linux-$suf"; extra=$'Conflicts: mayak-full\n'; fi
  mkdir -p "$T/data/usr/bin" "$T/control"
  cp -r files/etc "$T/data/"; mkdir -p "$T/data/usr/bin"; cp files/usr/bin/mayak-update "$T/data/usr/bin/"
  cp "$src" "$T/data/usr/bin/mayak"; chmod 755 "$T/data/usr/bin/mayak" "$T/data/usr/bin/mayak-update" "$T/data/etc/init.d/mayak"
  local size; size=$(du -sb "$T/data" | cut -f1)
  cat > "$T/control/control" <<CTL
Package: $pkg
Version: $VER
Depends: libc
${extra}Architecture: $arch
Installed-Size: $size
Maintainer: Kamil Gamidov
Section: net
Description: $desc
CTL
  echo "/etc/config/mayak" > "$T/control/conffiles"
  cat > "$T/control/postinst" <<'PI'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || /etc/init.d/mayak enable
exit 0
PI
  cat > "$T/control/prerm" <<'PR'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || { /etc/init.d/mayak stop; /etc/init.d/mayak disable; sed -i '/mayak-auto-update/d' /etc/crontabs/root 2>/dev/null; }
exit 0
PR
  chmod 755 "$T/control/postinst" "$T/control/prerm"
  echo "2.0" > "$T/debian-binary"
  (cd "$T/control" && tar --owner=0 --group=0 -czf ../control.tar.gz .)
  (cd "$T/data" && tar --owner=0 --group=0 -czf ../data.tar.gz .)
  (cd "$T" && tar --owner=0 --group=0 -czf "$OUT/${pkg}_${VER}_${arch}.ipk" ./debian-binary ./control.tar.gz ./data.tar.gz)
  rm -rf "$T"; echo "built $OUT/${pkg}_${VER}_${arch}.ipk"
}
build x86_64 amd64
build aarch64_generic arm64
build mipsel_24kc mipsle-softfloat
build arm_cortex-a7_neon-vfpv4 armv7
build mips_24kc mips-softfloat
build aarch64_cortex-a53 arm64
build x86_64 amd64 full
build aarch64_generic arm64 full
build aarch64_cortex-a53 arm64 full

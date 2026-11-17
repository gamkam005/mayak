#!/usr/bin/env bash
# Собирает mayak_<ver>_<arch>.ipk (формат opkg: tar.gz с debian-binary, control.tar.gz, data.tar.gz).
set -euo pipefail
cd "$(dirname "$0")"
VER=${VER:-0.3.0}; BIN=${BIN:-../../build}; OUT=${OUT:-../../build}
build() { # opkg-arch go-suffix
  local arch=$1 suf=$2 T; T=$(mktemp -d)
  mkdir -p "$T/data/usr/bin" "$T/control"
  cp -r files/etc "$T/data/"
  cp "$BIN/mayak-linux-$suf" "$T/data/usr/bin/mayak"; chmod 755 "$T/data/usr/bin/mayak" "$T/data/etc/init.d/mayak"
  local size; size=$(du -sb "$T/data" | cut -f1)
  cat > "$T/control/control" <<CTL
Package: mayak
Version: $VER
Depends: libc
Architecture: $arch
Installed-Size: $size
Maintainer: Kamil Gamidov
Section: net
Description: MAYAK mosaic tunnel client: local SOCKS5/HTTP proxy for podkop
CTL
  echo "/etc/config/mayak" > "$T/control/conffiles"
  cat > "$T/control/postinst" <<'PI'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || /etc/init.d/mayak enable
exit 0
PI
  cat > "$T/control/prerm" <<'PR'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || { /etc/init.d/mayak stop; /etc/init.d/mayak disable; }
exit 0
PR
  chmod 755 "$T/control/postinst" "$T/control/prerm"
  echo "2.0" > "$T/debian-binary"
  (cd "$T/control" && tar --owner=0 --group=0 -czf ../control.tar.gz .)
  (cd "$T/data" && tar --owner=0 --group=0 -czf ../data.tar.gz .)
  (cd "$T" && tar --owner=0 --group=0 -czf "$OLDPWD/$OUT/mayak_${VER}_${arch}.ipk" ./debian-binary ./control.tar.gz ./data.tar.gz)
  rm -rf "$T"; echo "built $OUT/mayak_${VER}_${arch}.ipk"
}
build x86_64 amd64
build aarch64_generic arm64
build mipsel_24kc mipsle-softfloat
build arm_cortex-a7_neon-vfpv4 armv7

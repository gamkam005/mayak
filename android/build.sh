#!/usr/bin/env bash
# Сборка APK без Gradle: aapt2 + javac + d8 + zipalign + apksigner.
# Нужны: JAVA_HOME (JDK 17), ANDROID_HOME (platforms;android-34, build-tools;34.0.0)
# и готовые Go-бинарники: $BIN/mayak-android-arm64 (телефон); X86=1 — ещё $BIN/mayak-linux-amd64 для эмулятора x86_64.
set -euo pipefail
cd "$(dirname "$0")"
BT=$ANDROID_HOME/build-tools/34.0.0; JAR=$ANDROID_HOME/platforms/android-34/android.jar
BIN=${BIN:-../../build}; OUT=${OUT:-out}
rm -rf "$OUT" && mkdir -p "$OUT"/{res,gen,classes,dex,stage/lib/arm64-v8a,stage/lib/x86_64}
"$BT/aapt2" compile --dir res -o "$OUT/res.zip"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$JAR" --manifest AndroidManifest.xml -A assets --java "$OUT/gen" "$OUT/res.zip" --min-sdk-version 24 --target-sdk-version 34
"$JAVA_HOME/bin/javac" -source 8 -target 8 -bootclasspath "$JAR" -Xlint:-options -d "$OUT/classes" $(find src "$OUT/gen" -name '*.java')
"$BT/d8" --release --min-api 24 --lib "$JAR" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
cp "$BIN/mayak-android-arm64" "$OUT/stage/lib/arm64-v8a/libmayak.so"
if [ "${X86:-0}" = 1 ]; then cp "$BIN/mayak-linux-amd64" "$OUT/stage/lib/x86_64/libmayak.so"; fi
# tun → SOCKS5 для VPN-режима: hev-socks5-tunnel (MIT), собран ndk-build с
# -DPKGNAME=ru/mayak/app -DCLSNAME=TProxy (см. scripts/build-hev.sh)
HEV=${HEV:-../../hevbuild/libs}
cp "$HEV/arm64-v8a/libhev-socks5-tunnel.so" "$OUT/stage/lib/arm64-v8a/"
if [ "${X86:-0}" = 1 ]; then cp "$HEV/x86_64/libhev-socks5-tunnel.so" "$OUT/stage/lib/x86_64/"; else rmdir "$OUT/stage/lib/x86_64"; fi
cp "$OUT/dex/classes.dex" "$OUT/stage/"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
python3 - "$OUT" <<'PYZ'
import sys, os, zipfile
out = sys.argv[1]
with zipfile.ZipFile(os.path.join(out, 'unsigned.apk'), 'a', zipfile.ZIP_DEFLATED) as z:
    st = os.path.join(out, 'stage')
    for root, _, files in os.walk(st):
        for f in files:
            full = os.path.join(root, f)
            z.write(full, os.path.relpath(full, st))
PYZ
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# Подпись: keystore и пароль не в git. Скопируйте keystore.pass.example → keystore.pass
# или задайте KS_PASS / KS_PASS_FILE / KEYSTORE.
KS=${KEYSTORE:-mayak.keystore}
if [ -z "${KS_PASS:-}" ]; then KS_PASS=$(cat "${KS_PASS_FILE:-./keystore.pass}" 2>/dev/null || true); fi
export KS_PASS
[ -n "$KS_PASS" ] || { echo "нет пароля ключа: задайте KS_PASS или KS_PASS_FILE" >&2; exit 1; }
[ -f "$KS" ] || "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KS_PASS" -alias mayak -keyalg EC -groupname secp256r1 -validity 9000 -dname "CN=MAYAK" >/dev/null 2>&1
"$BT/apksigner" sign --ks "$KS" --ks-pass env:KS_PASS --key-pass env:KS_PASS --out "$OUT/MAYAK.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify --print-certs "$OUT/MAYAK.apk" | head -2
ls -la "$OUT/MAYAK.apk"
[ -n "${APK_OUT:-}" ] && cp "$OUT/MAYAK.apk" "$APK_OUT" && echo "-> $APK_OUT"

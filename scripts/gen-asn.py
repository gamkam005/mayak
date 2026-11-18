#!/usr/bin/env python3
"""Собирает internal/asn/ip2asn-v4.bin.gz из базы IPtoASN (https://iptoasn.com, PDDL v1.0).

  curl -sSLO https://iptoasn.com/data/ip2asn-v4.tsv.gz
  python3 scripts/gen-asn.py ip2asn-v4.tsv.gz internal/asn/ip2asn-v4.bin.gz

Формат (до gzip): "MASN1", uint32 LE число диапазонов, uint32 LE число AS;
диапазоны: uvarint(начало − предыдущее начало), uvarint(ASN) — подряд, без
дыр (дыра = ASN 0); затем AS: uvarint(ASN), uvarint(длина), "CC|имя".
"""
import gzip, ipaddress, io, struct, sys

def uv(x):
    o = bytearray()
    while x >= 0x80:
        o.append(x & 0x7f | 0x80); x >>= 7
    o.append(x); return bytes(o)

src, dst = sys.argv[1], sys.argv[2]
rng, names = [], {}
for l in gzip.open(src, 'rt', encoding='utf-8', errors='replace'):
    s, e, a, c, n = l.rstrip('\n').split('\t')
    a = int(a); s = int(ipaddress.IPv4Address(s)); e = int(ipaddress.IPv4Address(e))
    if rng and rng[-1][2] == a and rng[-1][1] + 1 == s:
        rng[-1][1] = e; continue
    if rng and rng[-1][1] + 1 != s:
        rng.append([rng[-1][1] + 1, s - 1, 0])
    rng.append([s, e, a])
    if a:
        names[a] = (c, n[:48])
b = io.BytesIO()
b.write(b'MASN1'); b.write(struct.pack('<II', len(rng), len(names)))
prev = 0
for s, e, a in rng:
    b.write(uv(s - prev)); b.write(uv(a)); prev = s
for a, (c, n) in sorted(names.items()):
    t = (c + '|' + n).encode(); b.write(uv(a)); b.write(uv(len(t))); b.write(t)
open(dst, 'wb').write(gzip.compress(b.getvalue(), 9))
print(len(rng), 'ranges,', len(names), 'AS')

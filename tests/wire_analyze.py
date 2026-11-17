#!/usr/bin/env python3
"""Анализ дампа: размеры TCP-соединений, SNI и JA4 из ClientHello."""
import sys, json, hashlib, collections
from scapy.all import rdpcap, TCP, IP

GREASE = {0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa}

def ja4(ch):
    """JA4 (TLS, TCP) по разобранному ClientHello."""
    p = 4 + 2 + 32
    sid = ch[p]; p += 1 + sid
    cl = int.from_bytes(ch[p:p+2], 'big'); p += 2
    ciphers = [int.from_bytes(ch[p+i:p+i+2], 'big') for i in range(0, cl, 2)]; p += cl
    p += 1 + ch[p]
    el = int.from_bytes(ch[p:p+2], 'big'); p += 2
    end = p + el
    exts, sni, alpn, sigs, vers = [], '', [], [], []
    while p + 4 <= end:
        t = int.from_bytes(ch[p:p+2], 'big'); l = int.from_bytes(ch[p+2:p+4], 'big'); d = ch[p+4:p+4+l]; p += 4 + l
        exts.append(t)
        if t == 0 and len(d) > 5: sni = d[5:5+int.from_bytes(d[3:5], 'big')].decode(errors='replace')
        if t == 16:
            q = 2
            while q < len(d): n = d[q]; alpn.append(d[q+1:q+1+n].decode(errors='replace')); q += 1 + n
        if t == 13: sigs = [s for s in (int.from_bytes(d[2+i:4+i], 'big') for i in range(0, int.from_bytes(d[0:2], 'big'), 2)) if s not in GREASE]
        if t == 43: vers = [int.from_bytes(d[1+i:3+i], 'big') for i in range(0, d[0], 2)]
    c = [x for x in ciphers if x not in GREASE]; e = [x for x in exts if x not in GREASE]
    v = max([x for x in vers if x not in GREASE] or [0x0303])
    vs = {0x0304: '13', 0x0303: '12'}.get(v, '00')
    a = alpn[0] if alpn else ''
    al = (a[0] + a[-1]) if a else '00'
    ja4a = f"t{vs}{'d' if sni else 'i'}{min(len(c),99):02d}{min(len(e),99):02d}{al}"
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    ja4b = h(','.join(f'{x:04x}' for x in sorted(c)))
    ec = sorted(x for x in e if x not in (0, 16))
    ja4c = h(','.join(f'{x:04x}' for x in ec) + '_' + ','.join(f'{x:04x}' for x in sigs))
    return f"{ja4a}_{ja4b}_{ja4c}", sni, alpn, len(exts)

def main(path, port):
    port = int(port)
    pk = rdpcap(path)
    conns = collections.OrderedDict()
    seen = set()
    for p in pk:
        if TCP not in p or IP not in p: continue
        t = p[TCP]
        key = (t.sport, t.dport, t.seq, t.ack, int(t.flags), len(t.payload))
        if key in seen: continue  # на lo пакет виден дважды
        seen.add(key)
        if port not in (t.sport, t.dport): continue
        cli = (t.sport if t.dport == port else t.dport)
        c = conns.setdefault(cli, {'down': 0, 'up': 0, 't0': float(p.time), 't1': float(p.time), 'hello': None})
        c['t1'] = float(p.time)
        pl = bytes(t.payload)
        if t.sport == port: c['down'] += len(pl)
        else:
            c['up'] += len(pl)
            if c['hello'] is None and len(pl) > 9 and pl[0] == 0x16 and pl[5] == 1:
                c['hello'] = pl[5:]
    out = {'connections': len(conns), 'down_per_conn': [c['down'] for c in conns.values()], 'up_per_conn': [c['up'] for c in conns.values()], 'ja4': collections.Counter(), 'sni': collections.Counter(), 'alpn': collections.Counter()}
    for c in conns.values():
        if c['hello']:
            try:
                j, s, a, n = ja4(c['hello'])
                out['ja4'][j] += 1; out['sni'][s] += 1; out['alpn'][','.join(a)] += 1
            except Exception as e:
                out['ja4']['parse-error'] += 1
    d = out['down_per_conn']
    print(json.dumps({'connections': out['connections'], 'down_max': max(d) if d else 0, 'down_avg': int(sum(d)/len(d)) if d else 0,
                      'over_16384': sum(1 for x in d if x > 16384), 'ja4': out['ja4'], 'sni': out['sni'], 'alpn': out['alpn']}, ensure_ascii=False, indent=1))
    json.dump(out, open(path + '.json', 'w'), default=list)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

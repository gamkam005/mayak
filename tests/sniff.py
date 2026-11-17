#!/usr/bin/env python3
"""Мини-tcpdump на AF_PACKET (нужен root): печатает TCP-сегменты с данными
на порт/с порта PORT в JSON-строках: TTL, seq, длина, флаги, есть ли SNI-имя."""
import json, socket, struct, sys, time
iface, port, needle, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), float(sys.argv[4])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0)); s.settimeout(0.2)
t_end = time.time() + secs; t0 = None
while time.time() < t_end:
    try: pkt = s.recv(65535)
    except socket.timeout: continue
    if len(pkt) < 34 or pkt[12:14] != b'\x08\x00': continue
    ip = pkt[14:]; ihl = (ip[0] & 15) * 4
    if ip[9] != 6: continue
    ttl = ip[8]; tot = struct.unpack('!H', ip[2:4])[0]
    tcp = ip[ihl:tot]; sp, dp, seq = struct.unpack('!HHI', tcp[:8]); off = (tcp[12] >> 4) * 4
    flags = tcp[13]; data = tcp[off:]
    if port not in (sp, dp) or not data: continue
    if t0 is None: t0 = time.time()
    print(json.dumps({"t": round(time.time() - t0, 4), "dir": "up" if dp == port else "down", "ttl": ttl,
        "seq": seq, "len": len(data), "psh": bool(flags & 8), "urg": bool(flags & 32),
        "has_sni": needle in data, "fake_sni": b'.vk.com' in data,
        "tls_rec": data[:5].hex() if data[:1] in (b'\x16', b'\x17') else ""}), flush=True)

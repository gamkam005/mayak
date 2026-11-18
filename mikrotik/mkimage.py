#!/usr/bin/env python3
"""Собирает образ контейнера МАЯК в формате `docker save` без docker.

Такой .tar понимают RouterOS (/container add file=…), `docker load` и `podman load`.
Внутри: статический mayak, корневые сертификаты, пустые /etc/mayak и /data.
Сборка воспроизводимая: одинаковые входы дают побайтно одинаковый tar.

    mkimage.py -bin mayak-lite-linux-armv7 -arch arm/v7 -tag mayak:0.3.4-lite -o mayak-lite-armv7.tar
"""
import argparse, hashlib, io, json, os, tarfile

CA_PATHS = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]
EPOCH = "1970-01-01T00:00:00Z"
ENV = [
    "PATH=/",
    "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
    "MAYAK_LISTEN=0.0.0.0:1080",
    "MAYAK_UI=0.0.0.0:9090",
    "MAYAK_OPEN=false",
    "MAYAK_NOUPDATE=true",
    "MAYAK_SUB_STATE=/data/subs",
    "MAYAK_REDIRECT=0.0.0.0:8443",
]


def add(t, name, data=None, mode=0o644, kind=tarfile.REGTYPE):
    i = tarfile.TarInfo(name)
    i.type, i.mode, i.mtime, i.uid, i.gid, i.uname, i.gname = kind, mode, 0, 0, 0, "", ""
    if data is not None:
        i.size = len(data)
        t.addfile(i, io.BytesIO(data))
    else:
        t.addfile(i)


def tarbytes(fill):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
        fill(t)
    return b.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-bin", required=True, help="статический mayak под нужную архитектуру")
    ap.add_argument("-arch", required=True, help="amd64 | arm64 | arm/v7")
    ap.add_argument("-tag", default="mayak:latest")
    ap.add_argument("-ca", default="", help="файл корневых сертификатов (по умолчанию системный)")
    ap.add_argument("-o", required=True)
    a = ap.parse_args()

    ca = a.ca or next((p for p in CA_PATHS if os.path.exists(p)), "")
    if not ca:
        raise SystemExit("нет файла корневых сертификатов, укажите -ca")
    binary = open(a.bin, "rb").read()
    cadata = open(ca, "rb").read()

    def rootfs(t):
        for d in ("etc/", "etc/ssl/", "etc/ssl/certs/", "etc/mayak/", "data/", "data/subs/"):
            add(t, d, mode=0o755, kind=tarfile.DIRTYPE)
        add(t, "tmp/", mode=0o1777, kind=tarfile.DIRTYPE)
        add(t, "etc/ssl/certs/ca-certificates.crt", cadata)
        add(t, "mayak", binary, mode=0o755)

    layer = tarbytes(rootfs)
    diff = hashlib.sha256(layer).hexdigest()
    arch, _, variant = a.arch.partition("/")
    cfg = {
        "architecture": arch, "os": "linux", "created": EPOCH,
        "config": {
            "Entrypoint": ["/mayak", "client"],
            "Env": ENV,
            "WorkingDir": "/data",
            "ExposedPorts": {"1080/tcp": {}, "9090/tcp": {}},
            "Volumes": {"/data": {}},
            "Labels": {"org.opencontainers.image.source": "https://github.com/gamkam005/mayak",
                       "org.opencontainers.image.title": "MAYAK client"},
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + diff]},
        "history": [{"created": EPOCH, "created_by": "mikrotik/mkimage.py"}],
    }
    if variant:
        cfg["variant"] = variant
    cfgb = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    cid = hashlib.sha256(cfgb).hexdigest()
    manifest = json.dumps([{"Config": cid + ".json", "RepoTags": [a.tag], "Layers": [diff + "/layer.tar"]}],
                          separators=(",", ":")).encode()
    repo, _, tag = a.tag.rpartition(":")
    repos = json.dumps({repo or a.tag: {tag or "latest": diff}}, separators=(",", ":")).encode()

    def image(t):
        add(t, diff + "/", mode=0o755, kind=tarfile.DIRTYPE)
        add(t, diff + "/VERSION", b"1.0")
        add(t, diff + "/json", json.dumps({"id": diff, "os": "linux"}).encode())
        add(t, diff + "/layer.tar", layer)
        add(t, cid + ".json", cfgb)
        add(t, "manifest.json", manifest)
        add(t, "repositories", repos)

    with open(a.o, "wb") as f:
        f.write(tarbytes(image))
    print(f"{a.o}: {a.tag} {a.arch}, {os.path.getsize(a.o)/1e6:.1f} МБ, config sha256:{cid[:12]}")


if __name__ == "__main__":
    main()

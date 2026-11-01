#!/usr/bin/env python3
"""Validate proposal artifacts without trusting Publisher metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

FALLBACK_TRACKERS = [
    "http://tracker.opentrackr.org:1337/announce",
    "https://tracker.opentrackr.org:443/announce",
    "http://tracker.dler.org:6969/announce",
    "http://tracker.renfei.net:8080/announce",
    "https://tracker.bug38.com:443/announce",
]

def decode(data, offset=0):
    marker = data[offset:offset + 1]
    if marker == b"i":
        end = data.index(b"e", offset); return int(data[offset + 1:end]), end + 1
    if marker == b"l":
        values, offset = [], offset + 1
        while data[offset:offset + 1] != b"e":
            value, offset = decode(data, offset); values.append(value)
        return values, offset + 1
    if marker == b"d":
        values, offset = {}, offset + 1
        while data[offset:offset + 1] != b"e":
            key, offset = decode(data, offset); value, offset = decode(data, offset); values[key] = value
        return values, offset + 1
    colon = data.index(b":", offset); length = int(data[offset:colon]); start = colon + 1
    return data[start:start + length], start + length

def verify_torrent(torrent_path, package_path, size):
    payload = torrent_path.read_bytes()
    document, end = decode(payload)
    if end != len(payload) or b"info" not in document: raise ValueError("torrent inválido")
    info = document[b"info"]
    if b"files" in info or info.get(b"name", b"").decode() != package_path.name or info.get(b"length") != size:
        raise ValueError("torrent não corresponde ao pacote")
    actual = b""
    with package_path.open("rb") as package:
        while chunk := package.read(info[b"piece length"]): actual += hashlib.sha1(chunk).digest()
    if actual != info[b"pieces"]: raise ValueError("pieces do torrent não correspondem ao pacote")

def torrent_package_metadata(torrent_path):
    payload = torrent_path.read_bytes()
    document, end = decode(payload)
    if end != len(payload) or b"info" not in document: raise ValueError("torrent inválido")
    info = document[b"info"]
    if b"files" in info: raise ValueError("torrent com múltiplos arquivos não é aceito")
    return info[b"name"].decode(), info[b"length"]

def fetch_package(torrent_path, destination, timeout):
    destination.mkdir(parents=True, exist_ok=True)
    command = ["aria2c", "--seed-time=0", "--check-integrity=true", "--file-allocation=none",
        f"--bt-tracker={','.join(FALLBACK_TRACKERS)}",
        "--allow-overwrite=true", "--auto-file-renaming=false", f"--dir={destination}", str(torrent_path.resolve())]
    try:
        subprocess.run(command, check=True, timeout=timeout)
    except FileNotFoundError as error:
        raise ValueError("aria2c não está instalado para obter o pacote pelo swarm") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"tempo esgotado ao obter pacote pelo swarm ({timeout}s)") from error
    except subprocess.CalledProcessError as error:
        raise ValueError(f"download BitTorrent falhou com código {error.returncode}") from error

def validate(submission_path, fetch_missing=False, download_timeout=600):
    base = submission_path.parent.resolve()
    document = json.loads(submission_path.read_text())
    torrents = list((base / "torrents").glob("*.torrent"))
    if not torrents: raise ValueError("torrent não encontrado")
    for variant in document["release"]["variants"]:
        spec = variant["package"]
        package_path = (base / spec["path"]).resolve()
        if base not in package_path.parents: raise ValueError("caminho do pacote fora da proposta")
        package_name = package_path.name
        matches = []
        for torrent in torrents:
            try:
                name, length = torrent_package_metadata(torrent)
                if name == package_name and length == spec["sizeBytes"]: matches.append(torrent)
            except (ValueError, KeyError, UnicodeDecodeError): pass
        if len(matches) != 1: raise ValueError(f"esperado um torrent correspondente para {package_name}")
        temporary = None
        if not package_path.is_file():
            if not fetch_missing: raise ValueError("pacote ausente; use --fetch-missing para obtê-lo pelo swarm")
            temporary = tempfile.TemporaryDirectory(prefix="kmp-submission-")
            fetch_root = Path(temporary.name)
            fetch_package(matches[0], fetch_root, download_timeout)
            package_path = fetch_root / package_name
            if not package_path.is_file(): raise ValueError("torrent concluído sem produzir o ZIP esperado")
        digest = hashlib.sha256()
        size = 0
        with package_path.open("rb") as package:
            while chunk := package.read(1024 * 1024): digest.update(chunk); size += len(chunk)
        if size != spec["sizeBytes"]: raise ValueError("tamanho do pacote divergente")
        if digest.hexdigest() != spec["sha256"]: raise ValueError("SHA-256 do pacote divergente")
        verify_torrent(matches[0], package_path, size)
        if temporary: temporary.cleanup()
    print(f"proposta válida: {submission_path}")

parser = argparse.ArgumentParser()
parser.add_argument("--fetch-missing", action="store_true")
parser.add_argument("--download-timeout", type=int, default=600)
parser.add_argument("submissions", nargs="+")
args = parser.parse_args()
for argument in args.submissions:
    try: validate(Path(argument), fetch_missing=args.fetch_missing, download_timeout=args.download_timeout)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"erro: {argument}: {error}", file=sys.stderr); raise SystemExit(1)

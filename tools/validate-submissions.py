#!/usr/bin/env python3
"""Validate proposal artifacts without trusting Publisher metadata."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

FALLBACK_TRACKERS = [
    "http://tracker.opentrackr.org:1337/announce",
    "https://tracker.opentrackr.org:443/announce",
    "http://tracker.dler.org:6969/announce",
    "http://tracker.renfei.net:8080/announce",
    "https://tracker.bug38.com:443/announce",
]
# Webseeds aceitos: o próprio catálogo e assets de Release em forks do catálogo,
# que o Publisher usa como semente inicial de pacotes maiores que o limite do Git.
ALLOWED_WEBSEED = re.compile(r"^https://(?:ferreiratechlab\.github\.io/KMP-catalog/packages/|"
    r"raw\.githubusercontent\.com/FerreiraTechLab/KMP-catalog/main/docs/packages/|"
    r"github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/KMP-catalog/releases/download/[^/?#\s]+/)[^/?#\s]+$")

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

def encode(value):
    if isinstance(value, int): return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes): return str(len(value)).encode() + b":" + value
    if isinstance(value, list): return b"l" + b"".join(encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        return b"d" + b"".join(encode(key) + encode(value[key]) for key in sorted(value)) + b"e"
    raise TypeError(type(value))

def prepare_torrent(torrent_path, destination):
    """Copia o torrent mantendo o infohash, só com webseeds confiáveis e trackers HTTP extras."""
    payload = torrent_path.read_bytes()
    document, end = decode(payload)
    if end != len(payload) or b"info" not in document: raise ValueError("torrent inválido")
    if encode(document[b"info"]) not in payload: raise ValueError("torrent com bloco info não canônico")
    webseeds = document.get(b"url-list", [])
    if isinstance(webseeds, bytes): webseeds = [webseeds]
    accepted = [item for item in webseeds if ALLOWED_WEBSEED.match(item.decode("utf-8", "replace"))]
    for item in webseeds:
        if item not in accepted: print(f"webseed ignorado: {item.decode('utf-8', 'replace')}", flush=True)
    if accepted: document[b"url-list"] = accepted
    else: document.pop(b"url-list", None)
    tiers = document.get(b"announce-list", [])
    known = {tracker for tier in tiers for tracker in tier}
    document[b"announce-list"] = tiers + [[tracker.encode()] for tracker in FALLBACK_TRACKERS
        if tracker.encode() not in known]
    prepared = destination / f".{torrent_path.name}"
    prepared.write_bytes(encode(document))
    return prepared

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

def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]

def rpc(endpoint, secret, method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": "catalog-validator", "method": method,
        "params": [f"token:{secret}", *(params or [])]}).encode()
    request = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    if body.get("error"): raise ValueError(f"kmp-torrentd: {body['error'].get('message', 'erro RPC')}")
    return body.get("result")

def fetch_with_kmp_torrentd(executable, torrent_path, destination, timeout, stall_timeout, seed_nodes):
    rpc_port, listen_port = available_port(), available_port()
    while listen_port == rpc_port: listen_port = available_port()
    secret = secrets.token_hex(24)
    state = destination / ".kmp-torrentd"
    command = [executable, f"--rpc-listen=127.0.0.1:{rpc_port}", f"--rpc-secret={secret}",
        f"--state-dir={state}", f"--data-dir={destination}", f"--listen-port={listen_port}",
        "--upload-limit=0", "--download-limit=0"]
    process = subprocess.Popen(command)
    endpoint = f"http://127.0.0.1:{rpc_port}/jsonrpc"
    started = time.monotonic()
    try:
        while True:
            try:
                rpc(endpoint, secret, "aria2.getVersion")
                break
            except (OSError, ValueError):
                if process.poll() is not None: raise ValueError(f"kmp-torrentd encerrou com código {process.returncode}")
                if time.monotonic() - started > 15: raise ValueError("kmp-torrentd não iniciou a API RPC")
                time.sleep(.25)
        encoded = base64.b64encode(torrent_path.read_bytes()).decode()
        gid = rpc(endpoint, secret, "aria2.addTorrent", [encoded, [], {"dir": str(destination)}])
        name, length = torrent_package_metadata(torrent_path)
        package = destination / name
        last_report = last_peers = -60
        best, progressed = -1, time.monotonic()
        while True:
            status = rpc(endpoint, secret, "aria2.tellStatus", [gid])
            total, completed = int(status["totalLength"]), int(status["completedLength"])
            # O anacrolix grava em "<nome>.part" e só renomeia depois de concluir a última peça.
            if total > 0 and completed >= total and package.is_file() and package.stat().st_size == length: return
            now = time.monotonic()
            elapsed = now - started
            if completed > best: best, progressed = completed, now
            # O anacrolix descarta peers que falharam; os nós públicos voltam à lista
            # enquanto o publicador ainda envia as peças a eles.
            if seed_nodes and elapsed - last_peers >= 60:
                try: rpc(endpoint, secret, "kmp.addPeers", [gid, seed_nodes])
                except ValueError as error: print(f"nós públicos não adicionados: {error}", flush=True)
                last_peers = elapsed
            if elapsed - last_report >= 60:
                network = rpc(endpoint, secret, "kmp.getNetworkStats")
                torrent = next((item for item in network.get("torrents", []) if item.get("gid") == gid), {})
                print(f"kmp-torrentd: {completed >> 20}/{total >> 20} MiB; {status['connections']} conexões; "
                    f"peers conhecidos={torrent.get('knownPeers')} origens={torrent.get('peerSources')}", flush=True)
                last_report = elapsed
            if now - progressed >= stall_timeout:
                raise ValueError(f"download parado: nenhum byte novo em {stall_timeout}s ({completed >> 20}/{total >> 20} MiB)")
            if elapsed >= timeout: raise ValueError(f"tempo esgotado ao obter pacote pelo swarm ({timeout}s)")
            if process.poll() is not None: raise ValueError(f"kmp-torrentd encerrou com código {process.returncode}")
            time.sleep(2)
    finally:
        try: rpc(endpoint, secret, "aria2.shutdown")
        except Exception: process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill()

def seed_nodes():
    path = Path(__file__).resolve().parents[1] / "seed-nodes.json"
    return json.loads(path.read_text()) if path.is_file() else []

def fetch_package(torrent_path, destination, timeout, stall_timeout=1200):
    destination.mkdir(parents=True, exist_ok=True)
    torrent_path = prepare_torrent(torrent_path, destination)
    kmp_torrentd = os.environ.get("KMP_TORRENTD")
    if kmp_torrentd:
        fetch_with_kmp_torrentd(kmp_torrentd, torrent_path, destination, timeout, stall_timeout, seed_nodes())
        return
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

def validate(submission_path, fetch_missing=False, download_timeout=600, stall_timeout=1200):
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
            fetch_package(matches[0], fetch_root, download_timeout, stall_timeout)
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
parser.add_argument("--stall-timeout", type=int, default=1200,
    help="falha se o download ficar este tempo sem receber bytes novos")
parser.add_argument("submissions", nargs="+")
args = parser.parse_args()
for argument in args.submissions:
    try: validate(Path(argument), fetch_missing=args.fetch_missing, download_timeout=args.download_timeout,
        stall_timeout=args.stall_timeout)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"erro: {argument}: {error}", file=sys.stderr); raise SystemExit(1)

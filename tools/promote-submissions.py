#!/usr/bin/env python3
"""Promote merged Publisher submissions into the next catalog snapshot."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
from urllib.parse import quote

TRACKERS = ["udp://tracker.opentrackr.org:1337/announce", "udp://open.stealth.si:80/announce"]
PIECE_LENGTH = 256 * 1024
# Pacotes acima do limite do Git não vão para docs/packages; o Publisher os semeia
# por HTTP com um asset de Release no fork do catálogo.
RELEASE_WEBSEED = re.compile(r"^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/KMP-catalog/"
    r"releases/download/[^/?#\s]+/[^/?#\s]+$")


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


def text(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def torrent_metadata(torrent_path):
    payload = torrent_path.read_bytes()
    document, end = decode(payload)
    if end != len(payload) or b"info" not in document: raise ValueError(f"torrent inválido: {torrent_path}")
    info_hash = hashlib.sha1(encode(document[b"info"])).hexdigest()
    trackers = []
    for tier in document.get(b"announce-list", []):
        for tracker in tier:
            if text(tracker) not in trackers: trackers.append(text(tracker))
    if not trackers and document.get(b"announce"): trackers.append(text(document[b"announce"]))
    webseeds = [text(item) for item in document.get(b"url-list", [])]
    name = text(document[b"info"][b"name"])
    parts = [f"xt=urn:btih:{info_hash}", f"dn={quote(name)}"]
    parts += [f"tr={quote(item, safe='')}" for item in trackers]
    parts += [f"ws={quote(item, safe='')}" for item in webseeds]
    return info_hash, "magnet:?" + "&".join(parts), base64.b64encode(payload).decode("ascii")


def create_catalog_torrent(snapshot_path):
    raw = snapshot_path.read_bytes()
    pieces = b"".join(hashlib.sha1(raw[offset:offset + PIECE_LENGTH]).digest()
        for offset in range(0, len(raw), PIECE_LENGTH))
    name = snapshot_path.name
    webseeds = [f"https://ferreiratechlab.github.io/KMP-catalog/snapshots/{name}",
        f"https://raw.githubusercontent.com/FerreiraTechLab/KMP-catalog/main/docs/snapshots/{name}"]
    document = {b"announce": TRACKERS[0].encode(),
        b"announce-list": [[tracker.encode()] for tracker in TRACKERS],
        b"info": {b"length": len(raw), b"name": name.encode(), b"piece length": PIECE_LENGTH,
            b"pieces": pieces}, b"url-list": [item.encode() for item in webseeds]}
    torrent_path = snapshot_path.with_suffix(".torrent")
    torrent_path.write_bytes(encode(document))
    _, magnet, _ = torrent_metadata(torrent_path)
    snapshot_path.with_suffix(".magnet").write_text(magnet + "\n")


def published_releases(snapshot_directory):
    published = set()
    for snapshot in snapshot_directory.glob("catalog-*.json"):
        document = json.loads(snapshot.read_text())
        for item in document.get("items", []):
            release = item.get("release", {})
            published.add((item.get("id"), release.get("version"), release.get("revision")))
    return published


def copy_or_verify(source, destination):
    if destination.exists():
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(destination.read_bytes()).digest():
            raise ValueError(f"destino já existe com conteúdo diferente: {destination}")
        source.unlink()
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(source, destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    snapshots = root / "docs/snapshots"
    latest_path = max(snapshots.glob("catalog-*.json"))
    catalog = json.loads(latest_path.read_text())
    already_published = published_releases(snapshots)
    pending = []
    for submission_path in sorted((root / "submissions").glob("**/submission.json")):
        submission = json.loads(submission_path.read_text())
        release = submission["release"]
        identity = (submission["project"]["id"], release["version"], release["revision"])
        if identity not in already_published: pending.append((submission_path, submission))
    if not pending:
        print("sequence=", file=args.output.open("a") if args.output else __import__("sys").stdout)
        return

    sequence = catalog["sequence"] + 1
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    by_id = {item["id"]: item for item in catalog["items"]}
    for submission_path, submission in pending:
        base = submission_path.parent
        project = submission["project"]
        release = submission["release"]
        variants = []
        for variant in release["variants"]:
            package_name = Path(variant["package"]["path"]).name
            torrents = list((base / "torrents").glob("*.torrent"))
            matches = []
            for candidate in torrents:
                try:
                    document, _ = decode(candidate.read_bytes())
                    info = document[b"info"]
                    if (text(info[b"name"]) == package_name and
                            info.get(b"length") == variant["package"]["sizeBytes"]):
                        matches.append(candidate)
                except (ValueError, KeyError, UnicodeDecodeError): pass
            if len(matches) != 1: raise ValueError(f"torrent correspondente não encontrado para {package_name}")
            package_source = (base / variant["package"]["path"]).resolve()
            package_is_hosted = package_source.is_file()
            torrent_target = root / "docs/packages" / matches[0].name
            torrent_payload = matches[0].read_bytes()
            torrent_document, torrent_end = decode(torrent_payload)
            if torrent_end != len(torrent_payload): raise ValueError(f"torrent inválido: {matches[0]}")
            if not package_is_hosted:
                webseeds = torrent_document.pop(b"url-list", [])
                if isinstance(webseeds, bytes): webseeds = [webseeds]
                webseeds = [item for item in webseeds if RELEASE_WEBSEED.match(text(item))]
                if webseeds: torrent_document[b"url-list"] = webseeds
            matches[0].write_bytes(encode(torrent_document))
            info_hash, magnet, encoded_torrent = torrent_metadata(matches[0])
            if package_is_hosted:
                copy_or_verify(package_source, root / "docs/packages" / package_name)
            copy_or_verify(matches[0], torrent_target)
            variants.append({key: value for key, value in variant.items() if key not in ("package", "checks")} | {
                "download": {"packageFile": package_name, "sizeBytes": variant["package"]["sizeBytes"],
                    "sha256": variant["package"]["sha256"], "infoHash": info_hash,
                    "magnet": magnet, "torrent": encoded_torrent}})
        checks = ["manual-run" if check == "local-run" else check for check in release["variants"][0]["checks"]]
        redistribution = {key: value for key, value in project["redistribution"].items() if key != "allowed"}
        item = {key: project[key] for key in ("id", "name", "description", "homepage", "source", "license", "porter")}
        item["redistribution"] = redistribution
        item["release"] = {key: release[key] for key in ("version", "revision", "channel", "publishedAt", "notes")}
        item["release"]["review"] = {"status": "approved",
            "decisionId": f"submissions/{project['id']}/{release['version']}", "reviewedAt": now,
            "reviewer": {"name": "FerreiraTechLab", "url": "https://github.com/FerreiraTechLab"},
            "checks": checks}
        item["release"]["variants"] = variants
        by_id[project["id"]] = item
        archive = root / "reviews/accepted" / project["id"] / release["version"]
        archive.mkdir(parents=True, exist_ok=True)
        shutil.move(submission_path, archive / "submission.json")
        shutil.rmtree(base)

    catalog["sequence"] = sequence
    catalog["generatedAt"] = now
    catalog["items"] = sorted(by_id.values(), key=lambda item: item["id"])
    target = snapshots / f"catalog-{sequence:08d}.json"
    target.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n")
    create_catalog_torrent(target)
    stream = args.output.open("a") if args.output else __import__("sys").stdout
    print(f"sequence={sequence}", file=stream)
    if args.output: stream.close()


if __name__ == "__main__": main()

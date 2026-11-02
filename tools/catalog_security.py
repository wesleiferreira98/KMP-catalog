#!/usr/bin/env python3
"""Verification primitives for signed KMP catalogue releases."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone


MAX_HEAD_BYTES = 32 * 1024
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 4096
HEX64 = set("0123456789abcdef")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
INFO_HASH = re.compile(r"^[0-9a-fA-F]{40}$")
EXTENSION_NAME = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9-]+)+$")
SEED_NODE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
                       r":(?:6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3})$")


class VerificationError(ValueError):
    pass


def public_key_fingerprint(public_key: Path) -> str:
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode != 0 or not result.stdout:
        raise VerificationError("chave pública inválida")
    return hashlib.sha256(result.stdout).hexdigest()


def validate_public_key(data: bytes) -> str:
    if not 1 <= len(data) <= MAX_PUBLIC_KEY_BYTES:
        raise VerificationError("nova chave pública inválida")
    with tempfile.TemporaryDirectory(prefix="kmp-key-") as temporary:
        path = Path(temporary, "public.pem")
        path.write_bytes(data)
        return public_key_fingerprint(path)


def _read_limited(path: Path, limit: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VerificationError(f"arquivo indisponível: {path}") from exc
    if size <= 0 or size > limit:
        raise VerificationError(f"tamanho inválido: {path}")
    return path.read_bytes()


def verify_signature(data: bytes, signature: bytes, public_key: Path) -> None:
    if not public_key.is_file():
        raise VerificationError("chave pública indisponível")
    with tempfile.TemporaryDirectory(prefix="kmp-verify-") as temporary:
        data_path = Path(temporary, "data")
        signature_path = Path(temporary, "signature")
        data_path.write_bytes(data)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-rawin",
             "-inkey", str(public_key), "-in", str(data_path),
             "-sigfile", str(signature_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False,
        )
    if result.returncode != 0:
        raise VerificationError("assinatura inválida")


def parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError(f"{field} inválido")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerificationError(f"{field} inválido") from exc
    return parsed.astimezone(timezone.utc)


def validate_head(document: object, now: datetime | None = None) -> dict:
    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        raise VerificationError("schema do head incompatível")
    sequence = document.get("sequence")
    size = document.get("catalogSize")
    digest = document.get("catalogSha256")
    magnet = document.get("catalogMagnet")
    encoded_signature = document.get("catalogSignature")
    encoded_torrent = document.get("catalogTorrent")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise VerificationError("sequência inválida")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_CATALOG_BYTES:
        raise VerificationError("tamanho do catálogo inválido")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in HEX64 for c in digest):
        raise VerificationError("SHA-256 do catálogo inválido")
    if not isinstance(magnet, str) or not magnet.startswith("magnet:?xt=urn:btih:"):
        raise VerificationError("magnet do catálogo inválido")
    if not isinstance(encoded_signature, str):
        raise VerificationError("assinatura do catálogo ausente")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("assinatura do catálogo inválida") from exc
    if len(signature) != 64:
        raise VerificationError("assinatura do catálogo inválida")
    if encoded_torrent is not None:
        if not isinstance(encoded_torrent, str):
            raise VerificationError("torrent do catálogo inválido")
        try:
            torrent = base64.b64decode(encoded_torrent, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VerificationError("torrent do catálogo inválido") from exc
        if not 1 <= len(torrent) <= 16384:
            raise VerificationError("torrent do catálogo inválido")
    rotation = document.get("nextKey")
    if rotation is not None:
        if not isinstance(rotation, dict) or rotation.get("effectiveAfterSequence") != sequence:
            raise VerificationError("rotação de chave inválida")
        encoded_key = rotation.get("publicKey")
        fingerprint = rotation.get("sha256")
        if not isinstance(encoded_key, str) or not isinstance(fingerprint, str) or \
                len(fingerprint) != 64 or any(c not in HEX64 for c in fingerprint):
            raise VerificationError("rotação de chave inválida")
        try:
            key_data = base64.b64decode(encoded_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VerificationError("rotação de chave inválida") from exc
        if validate_public_key(key_data) != fingerprint:
            raise VerificationError("fingerprint da nova chave não confere")
    published = parse_time(document.get("publishedAt"), "publishedAt")
    expires = parse_time(document.get("expiresAt"), "expiresAt")
    now = now or datetime.now(timezone.utc)
    if published > now + timedelta(minutes=10):
        raise VerificationError("data de publicação está no futuro")
    if expires <= published or expires <= now:
        raise VerificationError("head expirado")
    return document


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/"):
        return False
    if "\\" in value or "//" in value or ":" in value or any(ord(char) < 32 for char in value):
        return False
    return all(part not in {".", ".."} for part in value.split("/"))


def _validate_v3_catalog(document: dict, sequence: int) -> None:
    if document.get("sequence") != sequence:
        raise VerificationError("sequência do catálogo não confere")
    if not isinstance(document.get("generatedAt"), str):
        raise VerificationError("generatedAt do catálogo inválido")
    parse_time(document["generatedAt"], "generatedAt")
    extensions = document.get("extensions", {})
    if not isinstance(extensions, dict) or not all(
            isinstance(name, str) and EXTENSION_NAME.fullmatch(name) for name in extensions):
        raise VerificationError("extensões do catálogo inválidas")
    seed_nodes = extensions.get("kmp.seed-nodes", [])
    if (not isinstance(seed_nodes, list) or len(seed_nodes) > 16 or
            not all(isinstance(node, str) and SEED_NODE.fullmatch(node) for node in seed_nodes) or
            len(set(seed_nodes)) != len(seed_nodes)):
        raise VerificationError("nós públicos do catálogo inválidos")
    items, revocations = document.get("items"), document.get("revocations")
    if not isinstance(items, list) or not isinstance(revocations, list):
        raise VerificationError("itens ou revogações do catálogo inválidos")
    blocked, revoked_hashes = set(), set()
    for index, revocation in enumerate(revocations, 1):
        prefix = f"revogação {index}: "
        if not isinstance(revocation, dict):
            raise VerificationError(prefix + "formato inválido")
        digest, action = revocation.get("packageSha256"), revocation.get("action")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in HEX64 for c in digest):
            raise VerificationError(prefix + "SHA-256 inválido")
        if digest in revoked_hashes or action not in {"warn", "block-install"}:
            raise VerificationError(prefix + "entrada duplicada ou ação inválida")
        if not isinstance(revocation.get("reason"), str) or not revocation["reason"].strip():
            raise VerificationError(prefix + "motivo ausente")
        parse_time(revocation.get("publishedAt"), "publishedAt")
        revoked_hashes.add(digest)
        if action == "block-install":
            blocked.add(digest)
    ids, port_owners, root_owners, package_hashes = set(), {}, {}, set()
    for index, item in enumerate(items, 1):
        prefix = f"item {index}: "
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or \
                not SAFE_ID.fullmatch(item["id"]) or item["id"] in ids:
            raise VerificationError(prefix + "id inválido ou duplicado")
        item_id = item["id"]
        for field in ("name", "description", "license", "homepage", "source"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise VerificationError(prefix + field + " ausente")
        release = item.get("release")
        if not isinstance(release, dict) or not isinstance(release.get("version"), str) or \
                not release["version"].strip() or not isinstance(release.get("revision"), int) or \
                isinstance(release.get("revision"), bool) or release["revision"] < 1 or \
                release.get("channel") not in {"stable", "beta"}:
            raise VerificationError(prefix + "release inválida")
        parse_time(release.get("publishedAt"), "publishedAt")
        review = release.get("review")
        required_checks = {"zip-layout", "hash", "launcher", "license"}
        review_checks = review.get("checks") if isinstance(review, dict) else None
        if not isinstance(review, dict) or review.get("status") != "approved" or \
                not isinstance(review_checks, list) or \
                not required_checks.issubset(set(review_checks)):
            raise VerificationError(prefix + "revisão editorial inválida")
        variants = release.get("variants")
        if not isinstance(variants, list) or not variants:
            raise VerificationError(prefix + "variantes ausentes")
        variant_ids = set()
        for variant in variants:
            variant_id = variant.get("id") if isinstance(variant, dict) else None
            context = prefix + f"variante {variant_id}: "
            if not isinstance(variant_id, str) or not SAFE_ID.fullmatch(variant_id) or \
                    variant_id in variant_ids:
                raise VerificationError(context + "id inválido ou duplicado")
            variant_ids.add(variant_id)
            priority = variant.get("priority")
            if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 1000:
                raise VerificationError(context + "prioridade inválida")
            capabilities = variant.get("requiredCapabilities")
            if not isinstance(capabilities, list) or any(not isinstance(value, str) for value in capabilities):
                raise VerificationError(context + "capacidades inválidas")
            compatibility, requirements = variant.get("compatibility"), variant.get("requirements")
            if not isinstance(compatibility, dict) or not isinstance(requirements, dict) or \
                    not isinstance(compatibility.get("architectures"), list) or \
                    not compatibility["architectures"]:
                raise VerificationError(context + "compatibilidade inválida")
            download = variant.get("download")
            if not isinstance(download, dict):
                raise VerificationError(context + "download inválido")
            size, digest = download.get("sizeBytes"), download.get("sha256")
            info_hash, magnet = download.get("infoHash"), download.get("magnet")
            if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 2**53 - 1:
                raise VerificationError(context + "sizeBytes inválido")
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in HEX64 for c in digest):
                raise VerificationError(context + "SHA-256 inválido")
            if digest in package_hashes or digest in blocked:
                raise VerificationError(context + "pacote duplicado ou bloqueado")
            if not isinstance(info_hash, str) or not INFO_HASH.fullmatch(info_hash) or \
                    not isinstance(magnet, str) or not re.search(
                        r"(?:^magnet:\?xt=|[?&]xt=)urn:btih:" + re.escape(info_hash) + r"(?:&|$)",
                        magnet, re.IGNORECASE):
                raise VerificationError(context + "magnet ou infoHash inválido")
            package = download.get("packageFile")
            if not _safe_path(package) or "/" in package or not package.lower().endswith(".zip"):
                raise VerificationError(context + "packageFile inválido")
            try:
                torrent = base64.b64decode(download.get("torrent"), validate=True)
            except (binascii.Error, ValueError, TypeError) as exc:
                raise VerificationError(context + "torrent inválido") from exc
            if not 1 <= len(torrent) <= 64 * 1024:
                raise VerificationError(context + "torrent inválido")
            install = variant.get("install")
            if not isinstance(install, dict) or not isinstance(install.get("portId"), str) or \
                    not SAFE_ID.fullmatch(install["portId"]):
                raise VerificationError(context + "install inválido")
            owner = port_owners.setdefault(install["portId"], item_id)
            if owner != item_id:
                raise VerificationError(context + "portId compartilhado")
            paths, user_paths = install.get("paths"), install.get("userDataPaths")
            if not isinstance(paths, list) or not paths or not isinstance(user_paths, list):
                raise VerificationError(context + "caminhos inválidos")
            client_package = item_id == "kmp-client" and \
                install["portId"] == "kmp-client" and paths == ["KMP.sh", "KMP/"]
            if item_id == "kmp-client" and not client_package:
                raise VerificationError(context + "destinos da atualização do Client inválidos")
            install_roots = set()
            for path in paths:
                if not _safe_path(path):
                    raise VerificationError(context + "caminho de instalação inválido")
                root = path.rstrip("/").split("/", 1)[0]
                if root == ".kmp" or (root == "KMP" and not client_package):
                    raise VerificationError(context + "caminho reservado")
                owner = root_owners.setdefault(root, item_id)
                if owner != item_id:
                    raise VerificationError(context + "destino compartilhado")
                install_roots.add(root)
            for path in user_paths:
                if not _safe_path(path) or path.rstrip("/").split("/", 1)[0] not in install_roots:
                    raise VerificationError(context + "userDataPath inválido")
            package_hashes.add(digest)
        ids.add(item_id)


def validate_catalog_document(document: object, sequence: int) -> None:
    if isinstance(document, dict) and document.get("schemaVersion") == 3:
        _validate_v3_catalog(document, sequence)
        return
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        raise VerificationError("schema do catálogo incompatível")
    if document.get("sequence") != sequence:
        raise VerificationError("sequência do catálogo não confere")
    if not isinstance(document.get("generatedAt"), str):
        raise VerificationError("generatedAt do catálogo inválido")
    parse_time(document["generatedAt"], "generatedAt")
    items = document.get("items")
    if not isinstance(items, list):
        raise VerificationError("itens do catálogo inválidos")
    ids, ports, roots = set(), set(), {}
    for index, item in enumerate(items, 1):
        prefix = f"item {index}: "
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not SAFE_ID.fullmatch(item["id"]):
            raise VerificationError(prefix + "id inválido")
        if item["id"] in ids:
            raise VerificationError(prefix + "id duplicado")
        for field in ("name", "version", "description", "license"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise VerificationError(prefix + field + " ausente")
        size = item.get("sizeBytes")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 2**53 - 1:
            raise VerificationError(prefix + "sizeBytes inválido")
        info_hash = item.get("infoHash")
        magnet = item.get("magnet")
        torrent = item.get("torrent")
        if not isinstance(info_hash, str) or not INFO_HASH.fullmatch(info_hash):
            raise VerificationError(prefix + "infoHash inválido")
        if not isinstance(magnet, str) or not re.search(
                r"(?:^magnet:\?xt=|[?&]xt=)urn:btih:" + re.escape(info_hash) + r"(?:&|$)",
                magnet, re.IGNORECASE):
            raise VerificationError(prefix + "magnet não corresponde ao infoHash")
        if torrent is not None:
            if not isinstance(torrent, str):
                raise VerificationError(prefix + "torrent inválido")
            try:
                torrent_bytes = base64.b64decode(torrent, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise VerificationError(prefix + "torrent inválido") from exc
            if not 1 <= len(torrent_bytes) <= 64 * 1024:
                raise VerificationError(prefix + "torrent inválido")
        package = item.get("packageFile")
        if not _safe_path(package) or "/" in package or not package.lower().endswith(".zip"):
            raise VerificationError(prefix + "packageFile inválido")
        package_digest = item.get("packageSha256")
        if sequence >= 3 and (not isinstance(package_digest, str) or
                              len(package_digest) != 64 or
                              any(c not in HEX64 for c in package_digest)):
            raise VerificationError(prefix + "packageSha256 inválido ou ausente")
        if package_digest is not None and (not isinstance(package_digest, str) or
                                           len(package_digest) != 64 or
                                           any(c not in HEX64 for c in package_digest)):
            raise VerificationError(prefix + "packageSha256 inválido")
        install = item.get("install")
        if not isinstance(install, dict) or not isinstance(install.get("portId"), str) or \
                not SAFE_ID.fullmatch(install["portId"]) or install["portId"] in ports:
            raise VerificationError(prefix + "install inválido")
        paths = install.get("paths")
        if not isinstance(paths, list) or not paths:
            raise VerificationError(prefix + "caminhos de instalação ausentes")
        for path in paths:
            if not _safe_path(path):
                raise VerificationError(prefix + "caminho de instalação inválido")
            root = path.split("/", 1)[0]
            if root in {".kmp", "KMP"} or (root in roots and roots[root] != item["id"]):
                raise VerificationError(prefix + "destino compartilhado ou reservado")
            roots[root] = item["id"]
        ids.add(item["id"])
        ports.add(install["portId"])


def load_verified_head(head_path: Path, signature_path: Path,
                       public_key: Path, now: datetime | None = None) -> dict:
    raw = _read_limited(head_path, MAX_HEAD_BYTES)
    signature = _read_limited(signature_path, 1024)
    verify_signature(raw, signature, public_key)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("head não é JSON válido") from exc
    return validate_head(document, now)


def verify_catalog(catalog_path: Path, head: dict, public_key: Path) -> bytes:
    raw = _read_limited(catalog_path, MAX_CATALOG_BYTES)
    if len(raw) != head["catalogSize"]:
        raise VerificationError("tamanho do catálogo não confere")
    if hashlib.sha256(raw).hexdigest() != head["catalogSha256"]:
        raise VerificationError("SHA-256 do catálogo não confere")
    signature = base64.b64decode(head["catalogSignature"], validate=True)
    verify_signature(raw, signature, public_key)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("catálogo não é JSON válido") from exc
    validate_catalog_document(document, head["sequence"])
    return raw


def load_state(state_path: Path) -> dict:
    if not state_path.exists():
        return {"highestSequence": 0}
    try:
        state = json.loads(_read_limited(state_path, 4096))
    except (VerificationError, TypeError, json.JSONDecodeError) as exc:
        raise VerificationError("estado de sequência inválido") from exc
    previous = state.get("highestSequence")
    if not isinstance(previous, int) or isinstance(previous, bool) or previous < 0:
        raise VerificationError("estado de sequência inválido")
    return state


def enforce_monotonic(sequence: int, state_path: Path) -> None:
    previous = load_state(state_path)["highestSequence"]
    if sequence < previous:
        raise VerificationError("catálogo rejeitado por proteção contra downgrade")


def validate_clock(now: datetime, state_path: Path) -> None:
    state = load_state(state_path)
    last_time = state.get("lastTrustedTime")
    if last_time is not None:
        trusted = parse_time(last_time, "lastTrustedTime")
        if now < trusted - timedelta(minutes=10):
            raise VerificationError("relógio local inválido ou atrasado")


def save_sequence(sequence: int, state_path: Path, trusted_time: datetime | None = None,
                  key_fingerprint: str | None = None) -> None:
    state = load_state(state_path)
    state["highestSequence"] = max(sequence, state["highestSequence"])
    if trusted_time is not None:
        previous = state.get("lastTrustedTime")
        previous_time = parse_time(previous, "lastTrustedTime") if previous else None
        if previous_time is None or trusted_time > previous_time:
            state["lastTrustedTime"] = trusted_time.astimezone(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z")
    if key_fingerprint is not None:
        state["trustedKeySha256"] = key_fingerprint
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_name(state_path.name + ".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, state_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--head-signature", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    try:
        head = load_verified_head(args.head, args.head_signature, args.public_key)
        enforce_monotonic(head["sequence"], args.state)
        verify_catalog(args.catalog, head, args.public_key)
        save_sequence(head["sequence"], args.state)
    except VerificationError as exc:
        parser.exit(1, f"erro: {exc}\n")
    print(f"catálogo verificado: sequência {head['sequence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

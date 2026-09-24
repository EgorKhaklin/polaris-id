"""polaris_web/secretstore.py — the sealed secret store (roadmap P1.3).

Until now the production secrets (the session key, the DB passwords, the
replicator password, the signing key file, the TLS keys, the pgBackRest key
pair) lived as plaintext files in polaris_web/secrets/ and nowhere else. That
directory is now the MATERIALIZED form only. The source of truth is a sealed
store, polaris_web/secrets.sealed/, whose contents are useless without a key
that is not on the disk next to them:

  age      each secret encrypted to the operator's age recipients (a public
           key; the identity that decrypts can live on a hardware token via an
           age plugin). Decrypt needs POLARIS_SECRETS_AGE_IDENTITY.
  awskms   envelope encryption: per file, KMS GenerateDataKey (AES-256) gives a
           data key and its KMS-wrapped form; the file is AES-256-GCM encrypted
           with the data key (the file name is the AAD) and the wrapped key is
           stored beside it. Decrypt needs kms:Decrypt on the key, which is an
           IAM decision, not a file on the host.
  file     no sealing (the pre-P1.3 layout). Kept for development.

Operations: seal (plaintext dir -> sealed dir), unseal (sealed dir -> a
destination the deploy points at a tmpfs, so plaintext exists only in RAM
while the stack runs), verify (unseal to memory, compare every sha256 with the
manifest), rotate-wrapping (re-seal under a NEW recipient / KMS key without
changing any secret's value). MANIFEST.json records backend, key, and per-file
sha256 + mode; modes are restored on unseal because the container users read
these files (the v9.140 lesson: a 0600 host file is unreadable by uid 70).

`scripts/polaris-secrets.sh` is the operator wrapper; `polaris-deploy.sh` and
`polaris.service` unseal before the stack starts when POLARIS_SECRETS_BACKEND
is set; `polaris-rotate-secret.sh` writes a rotated secret through to the
sealed store so the store never lags the running stack.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Dict, Optional

MANIFEST = "MANIFEST.json"
_SKIP_DIRS = {".archive"}
_SKIP_SUFFIXES = (".new", ".tmp", ".prev")


class SecretStoreError(RuntimeError):
    """Misconfiguration, a missing key, a tampered blob, or a failed backend call.
    Always fatal: a deploy must not proceed on partial or unverifiable secrets."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _list_plain(src: str) -> list:
    names = []
    for entry in sorted(os.listdir(src)):
        path = os.path.join(src, entry)
        if entry in _SKIP_DIRS or entry == MANIFEST or entry.endswith(_SKIP_SUFFIXES) or not os.path.isfile(path):
            continue
        names.append(entry)
    if not names:
        raise SecretStoreError(f"seal: no secret files in {src} (run polaris-generate-secrets.sh first)")
    return names


def _mode_of(path: str) -> str:
    return "%04o" % stat.S_IMODE(os.stat(path).st_mode)


def _write_private(path: str, data: bytes, mode: str) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, int(mode, 8))
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# backends: seal_bytes(name, data) -> bytes ; unseal_bytes(name, blob) -> bytes
# ---------------------------------------------------------------------------
class AgeBackend:
    name = "age"
    ext = ".age"

    def __init__(self, recipients_file: Optional[str], identity_file: Optional[str]):
        self.recipients_file = recipients_file
        self.identity_file = identity_file
        if shutil.which("age") is None:
            raise SecretStoreError("age: the `age` CLI is not installed (apt/dnf/brew install age)")

    def describe(self) -> dict:
        d = {"backend": "age"}
        if self.recipients_file:
            try:
                with open(self.recipients_file) as fh:
                    d["recipients"] = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            except OSError as exc:
                raise SecretStoreError(f"age: cannot read recipients file {self.recipients_file}: {exc}") from exc
        return d

    def seal_bytes(self, name: str, data: bytes) -> bytes:
        if not self.recipients_file:
            raise SecretStoreError("age: POLARIS_SECRETS_AGE_RECIPIENTS (a recipients file) is required to seal")
        r = subprocess.run(["age", "-R", self.recipients_file, "-o", "-"], input=data,
                           capture_output=True, check=False)
        if r.returncode != 0:
            raise SecretStoreError(f"age: sealing {name} failed: {r.stderr.decode(errors='replace').strip()}")
        return r.stdout

    def unseal_bytes(self, name: str, blob: bytes) -> bytes:
        if not self.identity_file:
            raise SecretStoreError("age: POLARIS_SECRETS_AGE_IDENTITY (an identity file) is required to unseal")
        r = subprocess.run(["age", "-d", "-i", self.identity_file, "-o", "-"], input=blob,
                           capture_output=True, check=False)
        if r.returncode != 0:
            raise SecretStoreError(f"age: unsealing {name} failed: {r.stderr.decode(errors='replace').strip()}")
        return r.stdout


class AwsKmsBackend:
    name = "awskms"
    ext = ".kms"

    def __init__(self, key_id: str, region: Optional[str] = None, endpoint_url: Optional[str] = None):
        if not key_id:
            raise SecretStoreError("awskms: POLARIS_SECRETS_AWSKMS_KEY_ID is required")
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise SecretStoreError("awskms: boto3 is required "
                                   f"(pip install -r polaris_web/requirements-custody.txt): {exc}") from exc
        kw = {}
        if region:
            kw["region_name"] = region
        if endpoint_url:
            kw["endpoint_url"] = endpoint_url
        self.key_id = key_id
        self._kms = boto3.client("kms", **kw)

    def describe(self) -> dict:
        return {"backend": "awskms", "key_id": self.key_id}

    def seal_bytes(self, name: str, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        try:
            dk = self._kms.generate_data_key(KeyId=self.key_id, KeySpec="AES_256")
        except Exception as exc:
            raise SecretStoreError(f"awskms: GenerateDataKey on {self.key_id!r} failed: {exc}") from exc
        plaintext_key, wrapped = bytes(dk["Plaintext"]), bytes(dk["CiphertextBlob"])
        nonce = os.urandom(12)
        ct = AESGCM(plaintext_key).encrypt(nonce, data, name.encode())
        return json.dumps({"v": 1, "backend": "awskms", "key_id": dk.get("KeyId", self.key_id), "name": name,
                           "edk": base64.b64encode(wrapped).decode(), "nonce": base64.b64encode(nonce).decode(),
                           "ct": base64.b64encode(ct).decode()}).encode()

    def unseal_bytes(self, name: str, blob: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        try:
            doc = json.loads(blob)
            edk, nonce, ct = (base64.b64decode(doc[k]) for k in ("edk", "nonce", "ct"))
        except (ValueError, KeyError, TypeError) as exc:
            raise SecretStoreError(f"awskms: {name} is not a sealed blob: {exc}") from exc
        if doc.get("name") != name:
            raise SecretStoreError(f"awskms: blob for {doc.get('name')!r} presented as {name!r} (renamed/tampered)")
        try:
            # KeyId pinned: KMS refuses a blob wrapped under another key
            # (IncorrectKeyException), so a re-wrapped store is not silently
            # readable through a stale backend that still names the old key.
            plaintext_key = bytes(self._kms.decrypt(CiphertextBlob=edk, KeyId=self.key_id)["Plaintext"])
        except Exception as exc:
            raise SecretStoreError(f"awskms: Decrypt of the data key for {name} failed: {exc}") from exc
        try:
            return AESGCM(plaintext_key).decrypt(nonce, ct, name.encode())
        except Exception as exc:
            raise SecretStoreError(f"awskms: {name} failed authentication (tampered or wrong key)") from exc


class FileBackend:
    """No sealing: the plaintext directory IS the store (development)."""
    name = "file"
    ext = ""

    def describe(self) -> dict:
        return {"backend": "file"}

    def seal_bytes(self, name: str, data: bytes) -> bytes:
        return data

    def unseal_bytes(self, name: str, blob: bytes) -> bytes:
        return blob


def backend_from_env(env: Optional[Dict[str, str]] = None):
    e = os.environ if env is None else env
    kind = (e.get("POLARIS_SECRETS_BACKEND") or "file").strip().lower()
    if kind == "file":
        return FileBackend()
    if kind == "age":
        return AgeBackend(e.get("POLARIS_SECRETS_AGE_RECIPIENTS") or None, e.get("POLARIS_SECRETS_AGE_IDENTITY") or None)
    if kind == "awskms":
        return AwsKmsBackend(e.get("POLARIS_SECRETS_AWSKMS_KEY_ID", ""), e.get("POLARIS_SECRETS_AWSKMS_REGION") or None,
                             e.get("POLARIS_SECRETS_AWSKMS_ENDPOINT_URL") or None)
    raise SecretStoreError(f"POLARIS_SECRETS_BACKEND={kind!r} is not one of file, age, awskms")


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------
def seal(backend, src: str, dst: str, only: Optional[str] = None) -> dict:
    """Plaintext dir -> sealed dir. `only` re-seals one file (rotation write-
    through) and keeps the previous sealed blob as <name><ext>.prev."""
    os.makedirs(dst, mode=0o700, exist_ok=True)
    manifest_path = os.path.join(dst, MANIFEST)
    if only:
        if not os.path.exists(manifest_path):
            raise SecretStoreError(f"seal --only: {dst} has no manifest; seal everything first")
        with open(manifest_path) as fh:
            manifest = json.load(fh)
        names = [only]
    else:
        names = _list_plain(src)
        manifest = {"v": 1, "files": {}}
    manifest.update(backend.describe())
    manifest["sealed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for name in names:
        path = os.path.join(src, name)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise SecretStoreError(f"seal: cannot read {path}: {exc}") from exc
        out = os.path.join(dst, name + backend.ext)
        if only and os.path.exists(out):
            os.replace(out, out + ".prev")
        _write_private(out, backend.seal_bytes(name, data), "0600")
        manifest["files"][name] = {"sha256": _sha256(data), "mode": _mode_of(path), "size": len(data)}
    _write_private(manifest_path, json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n", "0600")
    return manifest


def _read_manifest(sealed: str) -> dict:
    try:
        with open(os.path.join(sealed, MANIFEST)) as fh:
            m = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SecretStoreError(f"unseal: {sealed} has no readable {MANIFEST}: {exc}") from exc
    if not isinstance(m.get("files"), dict) or not m["files"]:
        raise SecretStoreError(f"unseal: {MANIFEST} lists no files")
    # A manifest name becomes a path under the destination, and the manifest is not
    # authenticated: under age anybody with the public recipients can seal a blob. A name
    # that is not a plain file name ("../x", "/etc/x", "a/b") wrote outside the tmpfs the
    # secrets belong in. Found 2026-09-24; refused before any blob is read.
    for name in m["files"]:
        if (not isinstance(name, str) or name in ("", ".", "..") or "\x00" in name
                or name != os.path.basename(name) or "\\" in name):
            raise SecretStoreError(f"unseal: {MANIFEST} names {name!r}, which is not a plain "
                                   "file name; refusing a store that would write outside its "
                                   "destination")
    return m


def unseal_to_memory(backend, sealed: str) -> Dict[str, tuple]:
    """{name: (bytes, mode)} after verifying every sha256 against the manifest."""
    m = _read_manifest(sealed)
    if m.get("backend") != backend.name:
        raise SecretStoreError(f"unseal: store was sealed with backend {m.get('backend')!r}, "
                               f"POLARIS_SECRETS_BACKEND is {backend.name!r}")
    out = {}
    for name, meta in m["files"].items():
        path = os.path.join(sealed, name + backend.ext)
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            raise SecretStoreError(f"unseal: {path} missing: {exc}") from exc
        data = backend.unseal_bytes(name, blob)
        if _sha256(data) != meta["sha256"]:
            raise SecretStoreError(f"unseal: {name} does not match its manifest sha256 (tampered or stale)")
        out[name] = (data, meta.get("mode", "0600"))
    return out


def unseal(backend, sealed: str, dst: str) -> list:
    """Sealed dir -> destination dir (a tmpfs in production). Files are written
    atomically with their recorded modes; stale files not in the manifest are
    removed so a retired secret does not linger."""
    files = unseal_to_memory(backend, sealed)
    os.makedirs(dst, mode=0o700, exist_ok=True)
    os.chmod(dst, 0o700)
    for name, (data, mode) in files.items():
        _write_private(os.path.join(dst, name), data, mode)
    for entry in os.listdir(dst):
        p = os.path.join(dst, entry)
        if os.path.isfile(p) and entry not in files and entry != MANIFEST:
            os.remove(p)
    return sorted(files)


def verify(backend, sealed: str, plain: Optional[str] = None) -> dict:
    """Unseal to memory and check the manifest; with `plain`, also assert the
    materialized directory matches byte for byte (the write-through invariant)."""
    files = unseal_to_memory(backend, sealed)
    report = {"files": len(files), "backend": backend.name, "drift": []}
    if plain:
        for name, (data, mode) in files.items():
            p = os.path.join(plain, name)
            try:
                with open(p, "rb") as fh:
                    live = fh.read()
            except OSError:
                report["drift"].append(f"{name}: missing in {plain}")
                continue
            if live != data:
                report["drift"].append(f"{name}: differs from the sealed store")
        if report["drift"]:
            raise SecretStoreError("verify: the materialized directory has drifted from the sealed store: "
                                   + "; ".join(report["drift"]))
    return report


def rotate_wrapping(old_backend, new_backend, sealed: str) -> dict:
    """Re-seal every secret under a NEW recipient / KMS key. Values unchanged;
    the old sealed dir is kept beside the new one as <sealed>.prev."""
    files = unseal_to_memory(old_backend, sealed)
    with tempfile.TemporaryDirectory(prefix="polaris-rewrap-") as tmp:
        plain = os.path.join(tmp, "plain")
        os.makedirs(plain, mode=0o700)
        for name, (data, mode) in files.items():
            _write_private(os.path.join(plain, name), data, mode)
        newdir = os.path.join(tmp, "sealed")
        manifest = seal(new_backend, plain, newdir)
        prev = sealed.rstrip("/") + ".prev"
        if os.path.exists(prev):
            shutil.rmtree(prev)
        os.replace(sealed, prev)
        shutil.copytree(newdir, sealed)
        os.chmod(sealed, 0o700)
    return manifest


# ---------------------------------------------------------------------------
def _main(argv=None) -> int:  # pragma: no cover (exercised via polaris-secrets.sh and the drill)
    import argparse
    ap = argparse.ArgumentParser(description="Polaris sealed secret store (P1.3)")
    ap.add_argument("--plain", default=os.environ.get("POLARIS_SECRETS_PLAIN_DIR", "polaris_web/secrets"))
    ap.add_argument("--sealed", default=os.environ.get("POLARIS_SECRETS_SEALED_DIR", "polaris_web/secrets.sealed"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal"); s.add_argument("--only")
    u = sub.add_parser("unseal"); u.add_argument("--dst", required=True)
    sub.add_parser("verify")
    sub.add_parser("status")
    r = sub.add_parser("rotate-wrapping")
    r.add_argument("--new-recipients"); r.add_argument("--new-key-id")
    a = ap.parse_args(argv)
    try:
        b = backend_from_env()
        if a.cmd == "seal":
            m = seal(b, a.plain, a.sealed, only=a.only)
            print(json.dumps({"sealed": len(m["files"]), "backend": b.name, "dir": a.sealed}))
        elif a.cmd == "unseal":
            names = unseal(b, a.sealed, a.dst)
            print(json.dumps({"unsealed": len(names), "backend": b.name, "dst": a.dst}))
        elif a.cmd == "verify":
            print(json.dumps(verify(b, a.sealed, a.plain if os.path.isdir(a.plain) else None)))
        elif a.cmd == "status":
            d = b.describe()
            if os.path.exists(os.path.join(a.sealed, MANIFEST)):
                m = _read_manifest(a.sealed)
                d.update({"sealed_files": len(m["files"]), "sealed_at": m.get("sealed_at")})
            print(json.dumps(d))
        else:
            env = dict(os.environ)
            if a.new_recipients:
                env["POLARIS_SECRETS_AGE_RECIPIENTS"] = a.new_recipients
            if a.new_key_id:
                env["POLARIS_SECRETS_AWSKMS_KEY_ID"] = a.new_key_id
            m = rotate_wrapping(b, backend_from_env(env), a.sealed)
            print(json.dumps({"rewrapped": len(m["files"]), "backend": b.name}))
        return 0
    except SecretStoreError as exc:
        print(f"secretstore: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())

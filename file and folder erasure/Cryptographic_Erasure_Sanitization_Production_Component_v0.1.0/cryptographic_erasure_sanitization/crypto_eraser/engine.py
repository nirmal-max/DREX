from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import base64, hashlib, json, os, secrets, time
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoErasureError(RuntimeError):
    pass


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _id_hash(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


def _zeroize(buf: bytearray):
    # Best-effort application-memory zeroization. Python does not guarantee that all
    # copies created by the interpreter/runtime are removed.
    for i in range(len(buf)):
        buf[i]=0


class KeyStore(Protocol):
    def create_key(self, key_id: str) -> None: ...
    def get_key(self, key_id: str) -> bytes: ...
    def destroy_key(self, key_id: str) -> None: ...
    def exists(self, key_id: str) -> bool: ...


class LocalKeyStore:
    """Reference backend.

    Keys are stored as individual files with restrictive permissions. This backend is
    for integration/testing; an enterprise build should implement KeyStore using a
    KMS/HSM that provides authenticated key destruction and independent audit logging.
    """

    def __init__(self, directory):
        self.directory=Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        try: os.chmod(self.directory,0o700)
        except OSError: pass

    def _path(self,key_id):
        if not key_id or "/" in key_id or "\\" in key_id or key_id in {".",".."}:
            raise CryptoErasureError("invalid key identifier")
        return self.directory/(key_id+".key")

    def create_key(self,key_id):
        p=self._path(key_id)
        if p.exists():
            raise CryptoErasureError("key already exists")
        key=secrets.token_bytes(32)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
        fd=os.open(p,flags,0o600)
        try:
            os.write(fd,key)
            os.fsync(fd)
        finally:
            os.close(fd)
        return True

    def get_key(self,key_id):
        p=self._path(key_id)
        if not p.exists():
            raise CryptoErasureError("key not found")
        data=p.read_bytes()
        if len(data)!=32:
            raise CryptoErasureError("invalid key length")
        return data

    def destroy_key(self,key_id):
        p=self._path(key_id)
        if not p.exists():
            raise CryptoErasureError("key not found")
        # The decisive operation is key removal from the authoritative store. A local
        # filesystem cannot provide HSM-grade guarantees about every storage copy.
        with p.open("r+b",buffering=0) as f:
            f.write(secrets.token_bytes(32))
            f.flush(); os.fsync(f.fileno())
        p.unlink()
        return True

    def exists(self,key_id):
        return self._path(key_id).exists()


@dataclass(frozen=True)
class Envelope:
    version: int
    key_id: str
    nonce_b64: str
    ciphertext_b64: str
    aad_b64: str
    target_id: str

    def to_dict(self):
        return asdict(self)


def create_envelope(key_store: KeyStore, key_id: str, plaintext: bytes, target_id: str):
    key=key_store.get_key(key_id)
    nonce=secrets.token_bytes(12)
    aad=target_id.encode()
    ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad)
    return Envelope(
        version=1,
        key_id=key_id,
        nonce_b64=base64.b64encode(nonce).decode(),
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        aad_b64=base64.b64encode(aad).decode(),
        target_id=target_id
    )


def save_envelope(path, envelope: Envelope):
    p=Path(path)
    tmp=p.with_suffix(p.suffix+".tmp")
    tmp.write_text(json.dumps(envelope.to_dict(),sort_keys=True),encoding="utf-8")
    os.replace(tmp,p)


def load_envelope(path):
    return Envelope(**json.loads(Path(path).read_text(encoding="utf-8")))


def decrypt_envelope(key_store: KeyStore, envelope: Envelope):
    key=key_store.get_key(envelope.key_id)
    nonce=base64.b64decode(envelope.nonce_b64)
    ciphertext=base64.b64decode(envelope.ciphertext_b64)
    aad=base64.b64decode(envelope.aad_b64)
    return AESGCM(key).decrypt(nonce,ciphertext,aad)


def destroy_key(key_store: KeyStore, key_id: str):
    if not key_store.exists(key_id):
        raise CryptoErasureError("key does not exist")
    key_store.destroy_key(key_id)
    if key_store.exists(key_id):
        raise CryptoErasureError("key still exists after destroy")
    return True


def verify_erasure(key_store: KeyStore, envelope: Envelope):
    # Two independent checks:
    # 1. authoritative key store reports the key absent;
    # 2. decryption through the key store is impossible.
    if key_store.exists(envelope.key_id):
        return False, "key-still-present"
    try:
        decrypt_envelope(key_store,envelope)
    except CryptoErasureError:
        return True, "key-unavailable"
    except Exception:
        # A missing key is the expected reason in the reference backend.
        return True, "decryption-failed-after-key-destruction"
    return False, "decryption-still-succeeded"


def write_audit(path, *, action, key_id, target_id, status, details=None):
    record={
        "schema":"secure-erasure.audit.v1",
        "method":"cryptographic-erasure",
        "action":action,
        "created_utc":_utc_now(),
        "key_id_hash":_id_hash(key_id),
        "target_id_hash":_id_hash(target_id),
        "status":status,
        "details":details or {},
        "secrets_recorded":False
    }
    out=Path(path); out.parent.mkdir(parents=True,exist_ok=True)
    tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf-8")
    os.replace(tmp,out)
    return out

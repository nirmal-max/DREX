import json
from pathlib import Path
from crypto_eraser.engine import LocalKeyStore, create_envelope, save_envelope, load_envelope, decrypt_envelope, destroy_key, verify_erasure, write_audit, CryptoErasureError

def test_key_lifecycle(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys")
    ks.create_key("customer-data")
    assert ks.exists("customer-data")
    key=ks.get_key("customer-data")
    assert len(key)==32
    destroy_key(ks,"customer-data")
    assert not ks.exists("customer-data")

def test_encryption_roundtrip(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret", "object-1")
    assert decrypt_envelope(ks,env)==b"secret"

def test_cryptographic_erasure_makes_data_undecryptable(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret-data", "object-1")
    p=tmp_path/"encrypted.json"; save_envelope(p,env)
    destroy_key(ks,"k")
    ok,reason=verify_erasure(ks,load_envelope(p))
    assert ok and reason=="key-unavailable"
    try:
        decrypt_envelope(ks,env)
    except CryptoErasureError:
        pass
    else:
        raise AssertionError("decryption unexpectedly succeeded")

def test_ciphertext_survives_key_destruction(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret-data","object-1")
    before=env.ciphertext_b64
    destroy_key(ks,"k")
    assert env.ciphertext_b64==before

def test_audit_has_no_secret(tmp_path):
    out=write_audit(tmp_path/"audit.json",action="destroy-key",key_id="k",target_id="object",status="SANITIZED")
    data=json.loads(out.read_text())
    assert data["secrets_recorded"] is False
    assert "key_id" not in data
    assert len(data["key_id_hash"])==64

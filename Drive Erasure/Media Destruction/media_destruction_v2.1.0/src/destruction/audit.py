import json
import os
import tempfile

from .models import evidence_hash, utc


def write(out, record):
    os.makedirs(out, exist_ok=True)
    rec = dict(record)
    rec["timestamp_utc"] = utc()
    rec["schema_version"] = "2.0"
    rec["evidence_sha256"] = evidence_hash(rec)

    p = os.path.join(out, "evidence.json")
    payload = json.dumps(rec, indent=2, sort_keys=True) + "\n"
    digest = rec["evidence_sha256"] + "  evidence.json\n"

    def atomic_write(path, data):
        fd, tmp = tempfile.mkstemp(prefix=".evidence-", dir=out, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    atomic_write(p, payload)
    atomic_write(p + ".sha256", digest)
    return p

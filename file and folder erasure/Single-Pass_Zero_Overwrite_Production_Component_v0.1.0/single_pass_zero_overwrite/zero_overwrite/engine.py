from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import os
import stat
import time
from typing import Callable


class OverwriteError(RuntimeError):
    pass


@dataclass(frozen=True)
class ErasureResult:
    target: str
    bytes_overwritten: int
    verified: bool
    removed: bool
    started_utc: str
    completed_utc: str
    sha256_before: str | None
    sha256_after: str | None
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate_regular_file(path: Path) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise OverwriteError(f"target does not exist: {path}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise OverwriteError(f"refusing symbolic link: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise OverwriteError(f"target is not a regular file: {path}")


def _hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _verify_zero_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            if any(block):
                raise OverwriteError("verification failed: non-zero byte remains")
            h.update(block)
    return h.hexdigest()


def _clear_readonly(path: Path) -> None:
    mode = path.stat().st_mode
    if not (mode & stat.S_IWUSR):
        path.chmod(mode | stat.S_IWUSR)


def overwrite_file(
    target: str | os.PathLike,
    *,
    verify: bool = True,
    remove: bool = True,
    chunk_size: int = 1024 * 1024,
    progress: Callable[[int, int], None] | None = None,
) -> ErasureResult:
    path = Path(target)
    _validate_regular_file(path)
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    started = _utc_now()
    before = _hash_file(path)
    total = path.stat().st_size
    written = 0

    try:
        _clear_readonly(path)
        with path.open("r+b", buffering=0) as f:
            remaining = total
            zero_block = b"\x00" * min(chunk_size, 1024 * 1024)
            while remaining:
                n = min(remaining, len(zero_block))
                f.write(zero_block[:n])
                written += n
                remaining -= n
                if progress:
                    progress(written, total)
            f.flush()
            os.fsync(f.fileno())

        after = _verify_zero_file(path) if verify else None
        verified = bool(verify and after is not None)

        if remove:
            # Remove the directory entry only after successful overwrite/verification.
            path.unlink()
            removed = True
        else:
            removed = False

        return ErasureResult(
            target=str(path),
            bytes_overwritten=written,
            verified=verified,
            removed=removed,
            started_utc=started,
            completed_utc=_utc_now(),
            sha256_before=before,
            sha256_after=after,
        )
    except Exception as exc:
        return ErasureResult(
            target=str(path),
            bytes_overwritten=written,
            verified=False,
            removed=False,
            started_utc=started,
            completed_utc=_utc_now(),
            sha256_before=before,
            sha256_after=None,
            error=str(exc),
        )


def _safe_tree(root: Path) -> list[Path]:
    if root.is_symlink():
        raise OverwriteError(f"refusing symbolic-link root: {root}")
    if not root.is_dir():
        raise OverwriteError(f"target is not a directory: {root}")

    files: list[Path] = []
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            files.append(p)
    return sorted(files)


def overwrite_tree(
    target: str | os.PathLike,
    *,
    verify: bool = True,
    remove: bool = True,
    chunk_size: int = 1024 * 1024,
) -> list[ErasureResult]:
    root = Path(target)
    files = _safe_tree(root)
    results = []
    for p in files:
        results.append(
            overwrite_file(
                p,
                verify=verify,
                remove=remove,
                chunk_size=chunk_size,
            )
        )
    if remove and all(r.error is None and r.removed for r in results):
        # Only remove empty directories; symlinked directories are never followed.
        for d in sorted((p for p in root.rglob("*") if p.is_dir() and not p.is_symlink()),
                        reverse=True):
            try:
                d.rmdir()
            except OSError:
                pass
        try:
            root.rmdir()
        except OSError:
            pass
    return results


def write_audit(path: str | os.PathLike, results: list[ErasureResult], *, method="single-pass-zero-overwrite"):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": method,
        "created_utc": _utc_now(),
        "results": [r.to_dict() for r in results],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out

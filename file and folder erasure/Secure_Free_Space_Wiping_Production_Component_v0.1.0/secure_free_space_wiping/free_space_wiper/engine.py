from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import os
import secrets
import stat
import time
from typing import Callable, Protocol


class WipeError(RuntimeError):
    pass


@dataclass(frozen=True)
class WipeResult:
    target: str
    pattern: str
    files_created: int
    bytes_allocated: int
    bytes_written: int
    verified: bool
    cleaned_up: bool
    started_utc: str
    completed_utc: str
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate_target(path: Path):
    if not path.exists():
        raise WipeError(f"target does not exist: {path}")
    if path.is_symlink():
        raise WipeError(f"refusing symbolic-link target: {path}")
    if not path.is_dir():
        raise WipeError(f"target must be a directory/mount point: {path}")
    # Never permit the component to be invoked on a filesystem root through the library.
    # A commercial application should provide a separately reviewed privileged raw-device
    # workflow if root-level sanitization is ever required.
    if path.parent == path:
        raise WipeError("refusing filesystem root target")


def estimate_free_space(path: str | os.PathLike) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


class AllocationBackend(Protocol):
    def allocate_and_fill(self, directory: Path, size: int, pattern: str, chunk_size: int) -> tuple[Path, int]:
        ...

    def remove(self, path: Path) -> None:
        ...


class RealAllocationBackend:
    def allocate_and_fill(self, directory: Path, size: int, pattern: str, chunk_size: int):
        if size <= 0:
            raise ValueError("size must be positive")
        name = f".sanitization-free-space-{os.getpid()}-{secrets.token_hex(8)}"
        path = directory / name
        written = 0
        try:
            with path.open("xb", buffering=0) as f:
                while written < size:
                    n = min(chunk_size, size - written)
                    if pattern == "zero":
                        block = b"\x00" * n
                    elif pattern == "random":
                        block = secrets.token_bytes(n)
                    else:
                        raise ValueError(f"unsupported pattern: {pattern}")
                    f.write(block)
                    written += n
                f.flush()
                os.fsync(f.fileno())
            return path, written
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise

    def remove(self, path: Path):
        path.unlink()


def _verify_file(path: Path, pattern: str, chunk_size: int) -> bool:
    with path.open("rb", buffering=0) as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                return True
            if pattern == "zero":
                if any(b):
                    return False
            elif pattern == "random":
                # Random output is not reproducibly verifiable from the output alone.
                # Integrity is instead established by successful write+fsync and a stable
                # size/read pass. We deliberately do not claim content equality proof.
                continue
            else:
                raise ValueError(f"unsupported pattern: {pattern}")


def wipe_free_space(
    target: str | os.PathLike,
    *,
    pattern: str = "zero",
    reserve_bytes: int = 64 * 1024 * 1024,
    chunk_size: int = 1024 * 1024,
    min_chunk_size: int = 4096,
    verify: bool = True,
    backend: AllocationBackend | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> WipeResult:
    directory = Path(target)
    _validate_target(directory)
    if pattern not in {"zero", "random"}:
        raise ValueError("pattern must be 'zero' or 'random'")
    if reserve_bytes < 0:
        raise ValueError("reserve_bytes must be non-negative")
    if chunk_size <= 0 or min_chunk_size <= 0:
        raise ValueError("chunk sizes must be positive")

    backend = backend or RealAllocationBackend()
    started = _utc_now()
    created: list[Path] = []
    allocated = 0
    written = 0

    try:
        initial_free = estimate_free_space(directory)
        target_bytes = max(0, initial_free - reserve_bytes)
        remaining = target_bytes

        # Adaptive allocation: start large, shrink on ENOSPC. The reserve is recomputed
        # each iteration so the process does not intentionally consume it.
        allocation_size = min(max(chunk_size * 16, 16 * 1024 * 1024), max(remaining, 0))

        while remaining >= min_chunk_size:
            current_free = estimate_free_space(directory)
            allowed = max(0, current_free - reserve_bytes)
            if allowed < min_chunk_size:
                break
            size = min(allocation_size, allowed, remaining)

            try:
                p, n = backend.allocate_and_fill(directory, size, pattern, chunk_size)
                created.append(p)
                allocated += n
                written += n
                remaining -= n
                if progress:
                    progress(allocated, target_bytes)
                allocation_size = min(max(allocation_size, min_chunk_size) * 2, 256 * 1024 * 1024)
            except OSError as exc:
                # Retry only for a genuine no-space condition. Other I/O failures
                # must propagate so the audit result cannot falsely report success.
                if exc.errno == getattr(__import__('errno'), 'ENOSPC', 28):
                    if allocation_size > min_chunk_size:
                        allocation_size = max(min_chunk_size, allocation_size // 2)
                        continue
                    break
                raise

        # Verify before deleting filler files. For zero mode, this is a byte-for-byte
        # content check. For random mode, a complete read verifies readability/size.
        verified = True
        if verify:
            for p in created:
                if not _verify_file(p, pattern, chunk_size):
                    verified = False
                    raise WipeError(f"verification failed for filler file: {p}")

        for p in created:
            backend.remove(p)

        return WipeResult(
            target=str(directory),
            pattern=pattern,
            files_created=len(created),
            bytes_allocated=allocated,
            bytes_written=written,
            verified=verified,
            cleaned_up=True,
            started_utc=started,
            completed_utc=_utc_now(),
        )
    except Exception as exc:
        # Best effort cleanup; never hide the primary failure.
        cleanup_ok = True
        for p in created:
            try:
                backend.remove(p)
            except OSError:
                cleanup_ok = False
        return WipeResult(
            target=str(directory),
            pattern=pattern,
            files_created=len(created),
            bytes_allocated=allocated,
            bytes_written=written,
            verified=False,
            cleaned_up=cleanup_ok,
            started_utc=started,
            completed_utc=_utc_now(),
            error=str(exc),
        )


def write_audit(path: str | os.PathLike, result: WipeResult):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "secure-free-space-wiping",
        "created_utc": _utc_now(),
        "result": result.to_dict(),
        "assurance_note": "Allocation-based logical free-space sanitization; not a universal physical purge."
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out

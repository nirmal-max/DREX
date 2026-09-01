from __future__ import annotations

import shutil
import subprocess

from .adapter import build_native_command
from .audit import write
from .policy import plan
from .safety import guard


def make_plan(device, requested="best"):
    return plan(device, requested)


def _sanitize_status_command(device):
    media = device.media_type.upper()
    if media == "NVME":
        return ["nvme", "sanitize-log", device.path]
    if media in ("SAS", "SCSI"):
        return ["sg_requests", "--", device.path]
    if media in ("SATA", "HDD", "SSD"):
        return ["hdparm", "--sanitize-status", device.path]
    raise ValueError("unsupported media")


def execute_plan(device, requested="best", out="evidence", *, arm=False, runner=None):
    """Execute native sanitize only after an explicit destructive opt-in.

    `runner` is injectable for tests. Real execution uses subprocess.run and
    requires the selected backend utility to be installed.
    """
    if not arm:
        raise PermissionError("destructive native sanitize requires arm=True")

    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)

    command = build_native_command(device.media_type, device.path, _action_for_plan(p.method))
    run = runner or _run_command

    result = run(command)
    if result.returncode != 0:
        record = {"plan": p.to_dict(), "command": command, "status": "FAILED",
                  "returncode": result.returncode, "stderr": result.stderr[-4000:]}
        return {"plan": p.to_dict(), "status": "FAILED",
                "evidence": write(out, record)}

    verify_command = _sanitize_status_command(device)
    verification = run(verify_command)
    if verification.returncode != 0:
        record = {"plan": p.to_dict(), "command": command, "status": "INDETERMINATE",
                  "verification_command": verify_command,
                  "verification_returncode": verification.returncode,
                  "verification_stderr": verification.stderr[-4000:]}
        return {"plan": p.to_dict(), "status": "INDETERMINATE",
                "evidence": write(out, record)}

    record = {"plan": p.to_dict(), "command": command, "status": "VERIFIED",
              "verification_command": verify_command,
              "verification_stdout": verification.stdout[-4000:]}
    return {"plan": p.to_dict(), "status": "VERIFIED",
            "evidence": write(out, record)}


def _action_for_plan(method):
    return {
        "NVME_SANITIZE": "2",
        "ATA_SANITIZE": "block-erase",
        "SCSI_SANITIZE": "block-erase",
    }.get(method, "")


def _run_command(command):
    if shutil.which(command[0]) is None:
        raise RuntimeError(f"required utility not installed: {command[0]}")
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=86400)

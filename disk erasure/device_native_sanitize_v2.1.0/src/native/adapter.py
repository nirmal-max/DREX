from __future__ import annotations


def build_native_command(media_type: str, device: str, action: str):
    """Build a device-native sanitization command.

    Actions are deliberately mapped to vendor/transport utilities rather than
    invented executables. Callers must validate the action against device
    capabilities before execution.
    """
    if not isinstance(device, str) or not device or device.startswith("-"):
        raise ValueError("invalid device path")
    if not isinstance(action, str) or not action:
        raise ValueError("invalid sanitize action")

    m = media_type.upper()
    if m == "NVME":
        # nvme-cli: sanact 1=exit failure state, 2=block erase,
        # 3=overwrite, 4=crypto erase.
        allowed = {"1", "2", "3", "4"}
        if action not in allowed:
            raise ValueError("unsupported NVMe sanitize action")
        return ["nvme", "sanitize", device, f"--sanact={action}", "--wait"]

    if m in ("SATA", "HDD", "SSD"):
        # hdparm exposes ATA Sanitize commands. Keep the command explicit so
        # DREX never relies on a non-standard `ata-sanitize` executable.
        mapping = {
            "block-erase": "--sanitize-block-erase",
            "overwrite": "--sanitize-overwrite",
            "crypto-erase": "--sanitize-crypto-scramble",
        }
        try:
            option = mapping[action]
        except KeyError as exc:
            raise ValueError("unsupported ATA sanitize action") from exc
        return ["hdparm", option, device]

    if m in ("SAS", "SCSI"):
        if action not in ("block-erase", "overwrite", "crypto-erase"):
            raise ValueError("unsupported SCSI sanitize action")
        return ["sg_sanitize", "--", device, action]

    raise ValueError("unsupported media")

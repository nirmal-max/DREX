from __future__ import annotations


def build_command(device, method):
    """Build a real backend command for the selected sanitization method.

    The smart layer is a router; it must never invent a `native-sanitize`
    executable. Device-specific backends are used for methods already
    qualified by the policy layer.
    """
    media = device.media_type.upper()
    path = device.path

    if method == "NVME_SANITIZE":
        return ["nvme", "sanitize", path, "--sanact=0x02", "--wait"]
    if method == "ATA_SECURE_ERASE":
        return ["hdparm", "--security-erase", "--user-master", "u", "--yes-i-know-what-i-am-doing", path]
    if method == "CRYPTOGRAPHIC_ERASE":
        command = device.caps().get("crypto_erase_command")
        if not isinstance(command, list) or not command:
            raise ValueError("qualified cryptographic erase command is required")
        return [str(x) for x in command]
    if method == "VERIFIED_OVERWRITE":
        return ["python", "-m", "smart.overwrite_backend", path]
    raise ValueError(f"unsupported smart sanitization method: {method}")


def verification_command(device, method):
    media = device.media_type.upper()
    if method == "NVME_SANITIZE":
        return ["nvme", "sanitize-log", device.path, "-o", "json"]
    if method == "ATA_SECURE_ERASE":
        return ["hdparm", "-I", device.path]
    if method == "CRYPTOGRAPHIC_ERASE":
        command = device.caps().get("crypto_verify_command")
        if not isinstance(command, list) or not command:
            raise ValueError("qualified cryptographic verification command is required")
        return [str(x) for x in command]
    if method == "VERIFIED_OVERWRITE":
        return ["python", "-m", "smart.overwrite_verify", device.path]
    raise ValueError(f"unsupported smart verification method: {method}")

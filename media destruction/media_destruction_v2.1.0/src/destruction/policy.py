from .models import Device, Plan

MODULE = "Media Destruction"


def validate(d: Device):
    if not isinstance(d.path, str) or not d.path.strip():
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid target path.")
    if not isinstance(d.media_type, str) or not d.media_type.strip():
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid media type.")
    if d.mounted:
        return Plan(
            MODULE,
            "BLOCKED",
            "NONE",
            "NONE",
            "Target is mounted; offline execution required.",
            warnings=("mounted_target",),
        )
    if d.system_disk:
        return Plan(
            MODULE,
            "BLOCKED",
            "NONE",
            "NONE",
            "Current system disk is protected.",
            warnings=("system_disk",),
        )
    if not isinstance(d.size_bytes, int) or d.size_bytes < 0:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid capacity.")
    if not isinstance(d.capabilities, (dict, type(None))):
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid capability metadata.")
    return None


def plan(d: Device, requested="best"):
    bad = validate(d)
    if bad:
        return bad

    caps = d.caps()
    if not isinstance(caps, dict):
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid capability metadata.")
    if not caps.get("destruction_equipment_qualified"):
        return Plan(
            MODULE,
            "BLOCKED",
            "NONE",
            "NONE",
            "No qualified physical destruction equipment attestation.",
        )

    qualified_media = caps.get("qualified_media", ())
    if not isinstance(qualified_media, (list, tuple, set)):
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid qualified-media metadata.")
    qualified_media = {str(m).strip().upper() for m in qualified_media}
    if d.media_type.strip().upper() not in qualified_media:
        return Plan(
            MODULE,
            "BLOCKED",
            "NONE",
            "NONE",
            "Equipment is not qualified for this media class.",
        )

    return Plan(
        MODULE,
        "PLANNED",
        "PHYSICAL_DESTRUCTION",
        "DESTROY",
        "Use qualified destruction equipment and import machine attestation.",
        (),
        ("equipment event", "post-destruction inspection", "certificate"),
    )

import sys
sys.path.insert(0, "src")

from destruction.models import Device
from destruction.policy import plan


def D(**kw):
    x = Device("/dev/test", "HDD", size_bytes=100, capabilities={})
    return Device(
        x.path,
        kw.get("media_type", x.media_type),
        size_bytes=kw.get("size_bytes", 100),
        mounted=kw.get("mounted", False),
        system_disk=kw.get("system_disk", False),
        capabilities=kw.get("capabilities", {}),
    )


def test_mount_block():
    assert plan(D(mounted=True)).outcome == "BLOCKED"


def test_system_block():
    assert plan(D(system_disk=True)).outcome == "BLOCKED"


def test_unqualified_block():
    assert plan(D()).outcome == "BLOCKED"


def test_media_qualification_is_case_insensitive():
    d = D(
        media_type="hdd",
        capabilities={
            "destruction_equipment_qualified": True,
            "qualified_media": ["HDD"],
        },
    )
    assert plan(d).outcome == "PLANNED"


def test_invalid_capability_metadata_blocks():
    assert plan(D(capabilities=[])).outcome == "BLOCKED"


def test_negative_capacity_blocks():
    assert plan(D(size_bytes=-1)).outcome == "BLOCKED"

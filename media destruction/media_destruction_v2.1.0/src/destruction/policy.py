from .models import Plan,Device
MODULE='Media Destruction'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    if not d.caps().get("destruction_equipment_qualified"): return Plan(MODULE,"BLOCKED","NONE","NONE","No qualified physical destruction equipment attestation.")
    if d.media_type.upper() not in d.caps().get("qualified_media",[]): return Plan(MODULE,"BLOCKED","NONE","NONE","Equipment is not qualified for this media class.")
    return Plan(MODULE,"PLANNED","PHYSICAL_DESTRUCTION","DESTROY","Use qualified destruction equipment and import machine attestation.",(),("equipment event","post-destruction inspection","certificate"))

from .models import Plan,Device
MODULE='Verified Overwrite'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    if d.media_type.upper() in ("SSD","NVME","FLASH","EMMC","UFS") and not requested.get("allow_flash",False) if isinstance(requested,dict) else d.media_type.upper() in ("SSD","NVME","FLASH","EMMC","UFS"):
        return Plan(MODULE,"BLOCKED","NONE","NONE","Host overwrite is rejected for flash/wear-leveled media by default.",warnings=("use-native-sanitize",))
    return Plan(MODULE,"PLANNED","HOST_OVERWRITE","CLEAR","Overwrite the addressable target and immediately read back every chunk.",("random pass","zero pass"),("chunk read-back","final digest"))

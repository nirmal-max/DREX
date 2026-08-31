from .models import Plan,Device
MODULE='Smart Sanitization'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    c=d.caps()
    if c.get("native_sanitize"): return Plan(MODULE,"PLANNED","DEVICE_NATIVE_SANITIZE","PURGE","Native device sanitization is advertised; route to the device-native engine.",("native-sanitize",),("native completion log","device identity"))
    if d.media_type.upper()=="NVME" and c.get("nvme_sanitize"): return Plan(MODULE,"PLANNED","NVME_SANITIZE","PURGE","NVMe Sanitize is advertised.",("nvme sanitize",),("sanitize-log",))
    if d.media_type.upper() in ("SATA","HDD","SSD") and c.get("ata_secure_erase"): return Plan(MODULE,"PLANNED","ATA_SECURE_ERASE","PURGE","ATA Security Erase is advertised.",("security erase",),("security-state re-identification",))
    if c.get("crypto_erase"): return Plan(MODULE,"PLANNED","CRYPTOGRAPHIC_ERASE","PURGE","Cryptographic erase is advertised and policy permits it.",("key-destruction",),("key-provider attestation",))
    if d.media_type.upper() in ("HDD","USB","SD") and requested in ("best","overwrite"): return Plan(MODULE,"PLANNED","VERIFIED_OVERWRITE","CLEAR","Host overwrite is the remaining qualified path.",("overwrite",),("read-back",), ("Not a Purge method on flash/wear-leveled media",))
    return Plan(MODULE,"BLOCKED","NONE","NONE","No qualified method advertised; refuse silent downgrade.")

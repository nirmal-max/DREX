from .models import Plan,Device
MODULE='NIST SP 800-88 Rev.2'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    c=d.caps()
    assurance=requested if requested in ("CLEAR","PURGE","DESTROY") else "PURGE"
    if assurance=="DESTROY": return Plan(MODULE,"PLANNED","MEDIA_DESTRUCTION","DESTROY","Physical destruction is selected by policy; exact equipment qualification is required.",(),("equipment attestation","post-destruction evidence"))
    if assurance=="PURGE" and c.get("native_sanitize"): return Plan(MODULE,"PLANNED","DEVICE_NATIVE_SANITIZE","PURGE","Qualified device-native sanitization is available.",(),("native completion","identity"))
    if assurance=="PURGE" and c.get("crypto_erase"): return Plan(MODULE,"PLANNED","CRYPTOGRAPHIC_ERASE","PURGE","Qualified cryptographic erase is available.",(),("key-destruction attestation",))
    if assurance=="CLEAR": return Plan(MODULE,"PLANNED","VERIFIED_OVERWRITE","CLEAR","Organization-approved Clear technique selected.",(),("full read-back",))
    return Plan(MODULE,"BLOCKED","NONE","NONE","NIST Rev.2 requires an applicable qualified technique; no silent fallback.")

def build_native_command(media_type,device,action):
    m=media_type.upper()
    if m=="NVME": return ["nvme","sanitize",device,f"--sanact={action}","--wait"]
    if m in ("SATA","HDD","SSD"): return ["ata-sanitize",device,action]
    if m in ("SAS","SCSI"): return ["sg_sanitize",device,action]
    raise ValueError("unsupported media")

def attest(machine_id, qualified, media_type, evidence):
    if not qualified: raise ValueError("equipment is not qualified")
    if not evidence: raise ValueError("external machine attestation required")
    return {"machine_id":machine_id,"qualified":True,"media_type":media_type,"evidence":evidence}

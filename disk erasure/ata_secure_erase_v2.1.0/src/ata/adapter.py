def build_commands(device,enhanced=False):
    erase="--security-erase-enhanced" if enhanced else "--security-erase"
    return [["hdparm","--security-set-pass","<EPHEMERAL>",device],["hdparm",erase,"<EPHEMERAL>",device],["hdparm","--security-disable","<EPHEMERAL>",device]]

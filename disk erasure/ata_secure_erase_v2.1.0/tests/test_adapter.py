import sys; sys.path.insert(0,"src")
from ata.adapter import build_commands
def test_enhanced(): assert "--security-erase-enhanced" in build_commands("/dev/sda",True)[1]

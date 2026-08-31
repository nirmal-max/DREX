import sys; sys.path.insert(0,"src")
from nvme.adapter import build_command
def test_codes():
 assert build_command("/dev/nvme0","block")[3]=="--sanact=0x02"
 assert build_command("/dev/nvme0","crypto")[3]=="--sanact=0x04"

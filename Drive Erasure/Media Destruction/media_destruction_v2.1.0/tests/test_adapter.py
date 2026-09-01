import sys; sys.path.insert(0,"src")
from destruction.adapter import attest
def test_attestation(): assert attest("M1",True,"HDD",{"id":"E1"})["qualified"]

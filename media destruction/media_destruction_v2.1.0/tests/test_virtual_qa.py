import sys; sys.path.insert(0,"src")
from destruction.simulation import FakeDestructionMachine
def test_qualified_media_only():
 assert FakeDestructionMachine(True,{"HDD"}).attest("HDD"); assert not FakeDestructionMachine(True,{"HDD"}).attest("SSD")
def test_unqualified_machine_rejected(): assert not FakeDestructionMachine(False,{"HDD"}).attest("HDD")

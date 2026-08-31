class FakeDestructionMachine:
    def __init__(self,qualified=True,media_types=None): self.qualified=qualified; self.media_types=set(media_types or [])
    def attest(self,media_type):
        if not self.qualified or media_type not in self.media_types: return False
        return True

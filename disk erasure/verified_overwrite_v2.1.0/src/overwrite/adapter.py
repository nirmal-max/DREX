import hashlib, os, secrets
CHUNK=4*1024*1024
def execute_file(path, passes=("random","zero")):
    size=os.path.getsize(path); out=[]
    with open(path,"r+b",buffering=0) as f:
      for p in passes:
        f.seek(0); w=hashlib.sha256(); v=hashlib.sha256(); off=0
        while off<size:
          n=min(CHUNK,size-off); data=secrets.token_bytes(n) if p=="random" else b"\0"*n
          f.write(data); f.flush(); f.seek(off); got=f.read(n)
          if got!=data: raise IOError(f"read-back mismatch at {off}")
          w.update(data); v.update(got); f.seek(off+n); off+=n
        os.fsync(f.fileno()); out.append({"pattern":p,"bytes":size,"write_sha256":w.hexdigest(),"readback_sha256":v.hexdigest()})
    return out

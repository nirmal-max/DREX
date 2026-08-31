from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import inspect_metadata, sanitize_metadata, write_audit


def main(argv=None):
    p=argparse.ArgumentParser(description="Filesystem metadata sanitization.")
    p.add_argument("target")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--confirm")
    p.add_argument("--clear-xattrs",action="store_true")
    p.add_argument("--normalize-times",action="store_true")
    p.add_argument("--normalize-permissions",action="store_true")
    p.add_argument("--rename",action="store_true")
    p.add_argument("--name-token",default="sanitized")
    p.add_argument("--recursive",action="store_true")
    p.add_argument("--audit")
    args=p.parse_args(argv)
    target=Path(args.target)

    if not args.execute:
        print(json.dumps({
            "mode":"dry-run",
            "inspection":inspect_metadata(target),
            "requested_actions":{
                "clear_xattrs":args.clear_xattrs,
                "normalize_times":args.normalize_times,
                "normalize_permissions":args.normalize_permissions,
                "rename":args.rename,
                "recursive":args.recursive
            },
            "warning":"No data or metadata was changed."
        },indent=2))
        return 0

    if args.confirm != str(target):
        print("error: --confirm must exactly match target",file=sys.stderr)
        return 2

    result=sanitize_metadata(
        target,
        clear_xattrs=args.clear_xattrs,
        normalize_times=args.normalize_times,
        normalize_permissions=args.normalize_permissions,
        rename=args.rename,
        name_token=args.name_token,
        recursive=args.recursive,
    )
    if args.audit:
        write_audit(args.audit,result)
    print(json.dumps(result.to_dict(),indent=2))
    return 0 if result.status=="SANITIZED" else 1


if __name__=="__main__":
    raise SystemExit(main())

"""
cli.py  --  the keyring from a script or a terminal, for a person and for Claude Code alike.

    keyring list [provider]            every key, masked, with its state (never a value)
    keyring get <provider> [label]     ONE value on stdout, nothing else: the first key of that
                                       provider that is not rejected and not out of credit,
                                       preferring one that works; by label when given.
                                       For use by reference:  -H "x-api-key: $(keyring get anthropic)"
    keyring secret <provider> [label]  the secret of a two-part credential, the same way
    keyring import <file|folder>...    keys by shape from notes, or a keyring v1 file
    keyring export <out.txt> [provider] the keyring v1 format; every key, or one provider's
    keyring test <provider|all|id>     the probes, one line per key, masked
    keyring where                      the vault and the version

Exit 0 with a value, 1 with a sentence on stderr and nothing on stdout, so `$(keyring get x)` is
either the key or empty, never a message.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ring          # noqa: E402
import version       # noqa: E402

RANK = {"works": 0, "untested": 1, "throttled": 2, "unclear": 3, "no credit": 8, "rejected": 9}


def fail(msg, code=1):
    sys.stderr.write(msg.rstrip("\n") + "\n")
    sys.exit(code)


def pick(provider, label=""):
    entries = [e for e in ring.load() if e["provider"] == provider]
    if label:
        entries = [e for e in entries if label.lower() in (e.get("label") or "").lower()]
    entries = [e for e in entries if e["state"] not in ("rejected", "no credit")]
    entries.sort(key=lambda e: RANK.get(e["state"], 5))
    return entries[0] if entries else None


def main(argv):
    if not argv:
        return fail(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        entries = ring.load()
        if args:
            entries = [e for e in entries if e["provider"] == args[0]]
        if not entries:
            print("no keys" + (" for " + args[0] if args else "") + " in " + ring.VAULT)
            return 0
        for i, e in enumerate(entries, 1):
            print("%3d  %-11s %-22s %-10s %s  %s" % (i, e["provider"], (e.get("label") or "")[:22], e["state"], ring.mask(e["value"]), (e.get("detail") or "")[:50]))
        return 0
    if cmd in ("get", "secret"):
        if not args:
            return fail("keyring %s <provider> [label]" % cmd)
        e = pick(args[0], args[1] if len(args) > 1 else "")
        if not e:
            return fail("no usable %s key in %s (keyring list %s)" % (args[0], ring.VAULT, args[0]))
        v = e["value"] if cmd == "get" else e.get("secret", "")
        if not v:
            return fail("that key has no secret part")
        sys.stdout.write(v + "\n")
        return 0
    if cmd == "import":
        if not args:
            return fail("keyring import <file|folder>...")
        total_added = 0
        for path in args:
            path = os.path.expanduser(path)
            files = []
            if os.path.isdir(path):
                files = [os.path.join(path, n) for n in sorted(os.listdir(path)) if os.path.isfile(os.path.join(path, n))]
            elif os.path.isfile(path):
                files = [path]
            else:
                print("no such file or folder: " + path)
                continue
            for f in files:
                try:
                    with open(f, "rb") as fh:
                        raw = fh.read(8 * 1024 * 1024)
                except OSError as e:
                    print("  %s: %s" % (os.path.basename(f), e.strerror)); continue
                if b"\x00" in raw[:4096]:
                    continue
                found = ring.parse(raw.decode("utf-8", "replace"), os.path.basename(f))
                entries = ring.load()
                entries, added, dups = ring.merge(entries, found)
                if added:
                    ring.save(entries)
                ring.log("imported from %s (cli)" % os.path.basename(f), found=len(found), added=len(added), duplicates=dups)
                total_added += len(added)
                print("  %-36s found %2d  added %2d  duplicates %2d" % (os.path.basename(f), len(found), len(added), dups))
        print("%d added; %d keys in %s" % (total_added, len(ring.load()), ring.VAULT))
        return 0
    if cmd == "export":
        if not args:
            return fail("keyring export <out.txt> [provider]")
        entries = ring.load()
        if len(args) > 1:
            entries = [e for e in entries if e["provider"] == args[1]]
        if not entries:
            return fail("nothing to export")
        out = os.path.expanduser(args[0])
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ring.export_text(entries))
        ring.log("exported %d (cli)" % len(entries), fps=[e["fp"] for e in entries])
        print("%d entr%s -> %s" % (len(entries), "y" if len(entries) == 1 else "ies", out))
        return 0
    if cmd == "test":
        import probes
        if not args:
            return fail("keyring test <provider|all|id>")
        entries = ring.load()
        sel = entries if args[0] == "all" else [e for e in entries if e["provider"] == args[0] or e["id"] == args[0]]
        if not sel:
            return fail("nothing to test")
        import time
        for e in sel:
            v = probes.test_entry(e)
            e["state"], e["state_at"], e["detail"] = v["state"], time.strftime("%Y-%m-%dT%H:%M:%S"), v["detail"][:200]
            if v.get("provider") and v["provider"] != e["provider"]:
                e["provider"] = v["provider"]
            ring.save(entries)
            ring.log("tested (cli)", fp=e["fp"], provider=e["provider"], state=v["state"], status=v.get("status"))
            print("  %-11s %-22s %-10s %s  %s" % (e["provider"], (e.get("label") or "")[:22], v["state"], ring.mask(e["value"]), v["detail"][:70]))
        return 0
    if cmd == "where":
        print("%s   v%d   %d keys" % (ring.VAULT, version.APP_VERSION, len(ring.load())))
        return 0
    return fail(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)

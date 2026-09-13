"""
app.py  --  the Keyring: the key repository on the phone. Flask, 127.0.0.1 only, one page.

    keyring            start it; the page opens; the console has q / o / u / r
    keyring get groq   one key, by reference, for a script:  -H "Authorization: Bearer $(keyring get groq)"

The shape of MAHA_TRANSCRIBE_TERMUX_TERMINAL (app.py, console.py, localguard.py, portpick.py,
selfupdate.py): the guard's three checks on every /api/ call (a page open in another tab must not be
able to read a key), a port that never fails to open, the console every app here has.

What the page can do (modules/keyring.md §6): see every key masked with its provider and its state
and the date it was learned; test one, or the selected ones, deliberately (the exception to "never
test speculatively": a person asking is not the app guessing); import from a picked file, a pasted
note, or a whole folder of notes; export one, some or all in the keyring v1 format; copy a value to
the clipboard; relabel, reassign the provider, revive, delete.

Nothing here prints a value: the log holds fingerprints and positions; the list endpoint strips the
value and the secret; only /api/keys/<id>/reveal answers with a value, on a POST with the guard
header, for the copy button.
"""

import io
import json
import os
import sys
import threading
import time

from flask import Flask, Response, jsonify, request, send_file

import localguard
import portpick
import probes
import ring
import version

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "keyring.html")
DEFAULT_PORT = 8842
LIVE_PORT = DEFAULT_PORT
START = time.time()

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024        # a key file is a note; eight megabytes is not a key file
_lock = threading.Lock()                                     # choosing and marking, never around the network (quota-and-fallback.md §5.3)

FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b0d10"/>'
           '<circle cx="24" cy="30" r="11" fill="none" stroke="#f59e0b" stroke-width="5"/><path d="M33 30h22v8h-6v-5h-4v6h-6v-6h-6z" fill="#f59e0b"/></svg>')


@app.before_request
def _guard():
    return localguard.check(LIVE_PORT)


@app.after_request
def _headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return resp


@app.route("/")
def index():
    with open(PAGE, encoding="utf-8") as f:
        html = f.read()
    return Response(html.replace("{{VERSION}}", str(version.APP_VERSION)), mimetype="text/html; charset=utf-8")


@app.route("/favicon.svg")
def favicon():
    return Response(FAVICON, mimetype="image/svg+xml")


@app.route("/favicon.ico")
def favicon_ico():
    return Response(FAVICON, mimetype="image/svg+xml")


@app.route("/health")
def health():
    return jsonify({"ok": True, "version": version.APP_VERSION, "keys": len(ring.load()), "vault": ring.VAULT, "uptime": round(time.time() - START)})


def _err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _find(entries, kid):
    for e in entries:
        if e["id"] == kid:
            return e
    return None


# ---------------------------------------------------------------- the list
@app.route("/api/keys")
def api_keys():
    entries = ring.load()
    return jsonify({"ok": True, "keys": [ring.public(e) for e in entries], "providers": ring.PROVIDERS, "states": ring.STATES})


@app.route("/api/keys/<kid>", methods=["POST"])
def api_key_edit(kid):
    body = request.get_json(silent=True) or {}
    with _lock:
        entries = ring.load()
        e = _find(entries, kid)
        if not e:
            return _err("no such key", 404)
        if "label" in body:
            e["label"] = str(body["label"]).strip()[:80]
        if "provider" in body:
            p = str(body["provider"]).strip().lower()
            if p not in ring.PROVIDERS:
                return _err("unknown provider")
            if p != e["provider"]:
                e["provider"], e["state"], e["state_at"], e["detail"] = p, "untested", "", "provider changed, not tested since"
        if body.get("revive"):
            e["state"], e["state_at"], e["detail"] = "untested", "", "revived by hand"
        ring.save(entries)
    ring.log("edited", fp=e["fp"], provider=e["provider"])
    return jsonify({"ok": True, "key": ring.public(e)})


@app.route("/api/keys/<kid>", methods=["DELETE"])
def api_key_delete(kid):
    with _lock:
        entries = ring.load()
        e = _find(entries, kid)
        if not e:
            return _err("no such key", 404)
        entries = [x for x in entries if x["id"] != kid]
        ring.save(entries)
    ring.log("deleted", fp=e["fp"], provider=e["provider"])
    return jsonify({"ok": True, "keys": len(entries)})


@app.route("/api/keys/<kid>/reveal", methods=["POST"])
def api_key_reveal(kid):
    """The copy button: the one place a value leaves the vault, to this page, over loopback."""
    e = _find(ring.load(), kid)
    if not e:
        return _err("no such key", 404)
    ring.log("revealed for copy", fp=e["fp"], provider=e["provider"])
    return jsonify({"ok": True, "value": e["value"], "secret": e.get("secret", "")})


# ---------------------------------------------------------------- import
def _import_text(text, source):
    found = ring.parse(text, source)
    with _lock:
        entries = ring.load()
        entries, added, dups = ring.merge(entries, found)
        if added:
            ring.save(entries)
    ring.log("imported from %s" % source, found=len(found), added=len(added), duplicates=dups,
             providers=sorted({e["provider"] for e in added}))
    return {"source": source, "found": len(found), "added": len(added), "duplicates": dups,
            "keys": [ring.public(e) for e in added]}


@app.route("/api/import", methods=["POST"])
def api_import():
    """A picked file (multipart, any number), or {"text": ..., "source": ...} pasted."""
    results = []
    if request.files:
        for f in request.files.getlist("file"):
            raw = f.read(app.config["MAX_CONTENT_LENGTH"])
            if b"\x00" in raw[:4096]:
                results.append({"source": f.filename, "found": 0, "added": 0, "duplicates": 0, "keys": [], "error": "not a text file"})
                continue
            results.append(_import_text(raw.decode("utf-8", "replace"), f.filename or "picked file"))
    else:
        body = request.get_json(silent=True) or {}
        text = str(body.get("text") or "")
        if not text.strip():
            return _err("nothing to import")
        results.append(_import_text(text, str(body.get("source") or "pasted")[:60]))
    return jsonify({"ok": True, "results": results, "total": len(ring.load())})


@app.route("/api/import-folder", methods=["POST"])
def api_import_folder():
    """Every text file in a folder on this phone: the API folder he keeps the notes in."""
    body = request.get_json(silent=True) or {}
    path = os.path.expanduser(str(body.get("path") or "").strip())
    if not path or not os.path.isdir(path):
        return _err("no such folder: " + (path or "(empty)"))
    results = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full) or os.path.getsize(full) > app.config["MAX_CONTENT_LENGTH"]:
            continue
        try:
            with open(full, "rb") as f:
                raw = f.read(65536)
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        results.append(_import_text(raw.decode("utf-8", "replace"), name))
    return jsonify({"ok": True, "results": results, "total": len(ring.load())})


# ---------------------------------------------------------------- test
@app.route("/api/keys/<kid>/test", methods=["POST"])
def api_key_test(kid):
    e = _find(ring.load(), kid)
    if not e:
        return _err("no such key", 404)
    verdict = probes.test_entry(e)                          # the network call, outside the lock
    with _lock:
        entries = ring.load()
        e2 = _find(entries, kid)
        if e2:
            e2["state"] = verdict["state"]
            e2["state_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            e2["detail"] = verdict["detail"][:200]
            if verdict.get("provider") and verdict["provider"] != e2["provider"]:
                e2["provider"] = verdict["provider"]          # sk_ tried as Speechify, adopted as ElevenLabs
            ring.save(entries)
            e = e2
    ring.log("tested", fp=e["fp"], provider=e["provider"], state=verdict["state"], status=verdict.get("status"))
    return jsonify({"ok": True, "key": ring.public(e), "verdict": verdict})


# ---------------------------------------------------------------- export
@app.route("/api/export", methods=["POST"])
def api_export():
    body = request.get_json(silent=True) or {}
    entries = ring.load()
    ids = body.get("ids")
    if ids is not None:
        want = set(map(str, ids))
        entries = [e for e in entries if e["id"] in want]
    if body.get("provider"):
        entries = [e for e in entries if e["provider"] == body["provider"]]
    if not entries:
        return _err("nothing selected")
    text = ring.export_text(entries)
    name = "keyring-%s.keys.txt" % time.strftime("%Y%m%d-%H%M")
    ring.log("exported %d" % len(entries), fps=[e["fp"] for e in entries])
    return send_file(io.BytesIO(text.encode("utf-8")), mimetype="text/plain; charset=utf-8", as_attachment=True, download_name=name)


@app.route("/api/log")
def api_log():
    try:
        n = min(max(int(request.args.get("n", 30)), 1), 500)
    except ValueError:                                       # ?n=x: the monkey found this one (G6, 13.9.2026)
        n = 30
    try:
        with open(ring.LOG, encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except OSError:
        lines = []
    return jsonify({"ok": True, "lines": [json.loads(l) for l in lines if l.strip()]})


def console_snapshot():
    return {"version": version.APP_VERSION, "keys": len(ring.load()), "vault": ring.VAULT}


if __name__ == "__main__":
    import console as term
    import selfupdate
    requested = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            requested = int(sys.argv[1])
        except ValueError:
            print("ignoring invalid port argument %r, using %d" % (sys.argv[1], DEFAULT_PORT))
    LIVE_PORT, note = portpick.pick("127.0.0.1", requested)
    portpick.announce("keyring", LIVE_PORT)      # ~/.mantra/ports, for the launcher (ports.md §3)
    ring.ensure_vault()
    action = term.run(app, "127.0.0.1", LIVE_PORT, snapshot=console_snapshot, note=note,
                      on_check_update=selfupdate.check_remote, on_perform_update=selfupdate.perform_update)
    if action == "restart":
        os.execv(sys.executable, [sys.executable] + sys.argv)

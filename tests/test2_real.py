#!/usr/bin/env python3
"""TEST 2 - inside the running app, with real things: the real page and API through Flask's client
(the guard satisfied the way the page satisfies it), the real console on a pty with the keyring
command's own entry point, and ONE real call each against Anthropic, Google (the Maps key that a
Geocoding-only tester calls dead) and Cloudflare (the account token that /user/tokens/verify calls
invalid) with keys from the real vault: the two false negatives Marko named, proven against the
provider rather than against a mock."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import APP, Console, check, client, fake, finish, fresh_vault, http, real_key, wait_port  # noqa: E402

vault = fresh_vault()
appmod, c, H = client()

# the page
r = c.get("/", headers=H)
check("the page is served", r.status_code == 200 and b"<title>Keyring</title>" in r.data)
check("the page carries the version", ("v%d" % appmod.version.APP_VERSION).encode() in r.data)
check("every control is in the first frame: file picker, folder, paste, test, export", all(s in r.data for s in (b'type="file"', b'id="folderBtn"', b'id="pasteBtn"', b'id="testSel"', b'id="exportAll"')))
check("a favicon, never the empty globe", c.get("/favicon.svg", headers=H).status_code == 200 and c.get("/favicon.svg", headers=H).mimetype == "image/svg+xml")
check("CSP and no-store on every answer", "default-src 'self'" in r.headers.get("Content-Security-Policy", "") and r.headers.get("Cache-Control") == "no-store")

# import, the three ways the page offers
note = "kalabhumi\nAPI key\n%s\nSecret key\n%s\n\nmain groq\n%s\n" % (fake("", 48, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), fake("", 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), fake("gsk" + "_", 52))
r = c.post("/api/import", json={"text": note, "source": "pasted"}, headers=H)
j = r.get_json()
check("paste: 2 found, 2 added (a hume pair and a groq)", r.status_code == 200 and j["results"][0]["found"] == 2 and j["results"][0]["added"] == 2, j)
import io
r = c.post("/api/import", data={"file": (io.BytesIO(note.encode()), "notes.txt")}, headers={k: v for k, v in H.items()}, content_type="multipart/form-data")
j = r.get_json()
check("the picked file: the same keys are duplicates now", j["results"][0]["found"] == 2 and j["results"][0]["duplicates"] == 2, j)
import tempfile
folder = tempfile.mkdtemp()
with open(os.path.join(folder, "one.txt"), "w") as f:
    f.write("acct a\n" + fake("AQ" + ".Ab8", 50, seed=1) + "\n")
with open(os.path.join(folder, "two.txt"), "w") as f:
    f.write(fake("sk-" + "ant-api03-", 95, seed=2) + "\n")
with open(os.path.join(folder, "pic.png"), "wb") as f:
    f.write(b"\x89PNG\x00\x00binary")
r = c.post("/api/import-folder", json={"path": folder}, headers=H)
j = r.get_json()
check("the folder: two text files read, the png skipped", len(j["results"]) == 2 and sum(x["added"] for x in j["results"]) == 2, j)
r = c.get("/api/keys", headers=H); keys = r.get_json()["keys"]
check("the list has 4 keys, masked, no value field", len(keys) == 4 and all("value" not in k and "secret" not in k and "…" in k["masked"] for k in keys))
hume = next(k for k in keys if k["provider"] == "hume")
check("the pair shows as a pair with its label", hume["has_secret"] and hume["label"] == "kalabhumi")

# edit, reveal, export, delete
r = c.post("/api/keys/" + hume["id"], json={"label": "Kala", "provider": "hume"}, headers=H)
check("relabel", r.get_json()["key"]["label"] == "Kala")
r = c.post("/api/keys/" + hume["id"] + "/reveal", json={}, headers=H)
check("reveal answers the value and the secret, for the copy button", len(r.get_json()["value"]) == 48 and len(r.get_json()["secret"]) == 64)
r = c.post("/api/export", json={"ids": [hume["id"]]}, headers=H)
check("export one: a keyring v1 file with the pair", r.status_code == 200 and r.data.startswith(b"# keyring v1") and b"secret: " in r.data and "attachment" in r.headers.get("Content-Disposition", ""))
r = c.post("/api/export", json={}, headers=H)
check("export all: 4 entries", r.data.count(b"provider: ") == 4)
r = c.post("/api/export", json={"provider": "groq"}, headers=H)
check("export one provider", r.data.count(b"provider: ") == 1 and b"provider: groq" in r.data)
gro = next(k for k in keys if k["provider"] == "groq")
r = c.delete("/api/keys/" + gro["id"], headers=H)
check("delete", r.get_json()["keys"] == 3)
r = c.get("/api/log", headers=H)
lines = r.get_json()["lines"]
check("the log has the imports, the reveal, the export and the delete", any("imported" in l["what"] for l in lines) and any("revealed" in l["what"] for l in lines) and any("exported" in l["what"] for l in lines) and any("deleted" in l["what"] for l in lines))
logtext = open(os.path.join(vault, "log.jsonl")).read()
check("no key value in the log", not any(k["masked"][:6] in logtext for k in keys if len(k["masked"]) > 8) and "gsk_" not in logtext)

# the guard: another page's request is refused, a request with the wrong Host is refused
r = c.get("/api/keys", headers={"Host": "evil.example:8842"})
check("a foreign Host is refused (DNS rebinding)", r.status_code == 403)
r = c.get("/api/keys", headers={"Host": "127.0.0.1:%d" % appmod.LIVE_PORT})
check("an /api call without the page's header is refused", r.status_code == 403)
r = c.post("/api/keys/%s/reveal" % hume["id"], json={}, headers={"Host": "127.0.0.1:%d" % appmod.LIVE_PORT, "Origin": "http://evil.example"})
check("a cross-site POST is refused", r.status_code == 403)
r = c.get("/", headers={"Host": "localhost:%d" % appmod.LIVE_PORT})
check("the page itself needs no header", r.status_code == 200)

# the console on a pty, through the real entry point, with the real command name
import tempfile as _tf
stub = _tf.mkdtemp(prefix="keyring-stub-")
with open(os.path.join(stub, "termux-open-url"), "w") as f:
    f.write("#!/bin/sh\necho \"$1\" >> '%s/opened.txt'\n" % stub)
os.chmod(os.path.join(stub, "termux-open-url"), 0o755)  # nosec B103: a stand-in command must be executable
cons = Console(vault=vault, env={"PATH": stub + os.pathsep + os.environ["PATH"]})
try:
    check("the banner and the key row", cons.wait_for("q quit   o open page   u check for update   r restart", 15), cons.screen()[-300:])
    check("the banner counts the keys of the vault", "3 keys in" in cons.screen())
    check("the port answers", wait_port(cons.port))
    st, body = http("http://127.0.0.1:%d/" % cons.port)
    check("the page over the real socket", st == 200 and b"<title>Keyring</title>" in body)
    cons.key("o")
    check("o opens the page (the stand-in opener got the address)", cons.wait_for("opening the browser", 5))
    time.sleep(1.0)
    opened = open(os.path.join(stub, "opened.txt")).read() if os.path.exists(os.path.join(stub, "opened.txt")) else ""
    check("the opener was handed the served address (once at start, once for o)", opened.count("http://127.0.0.1:%d" % cons.port) == 2, opened)
    cons.key("q")
    check("q stops it", cons.wait_exit(8) and "stopped." in cons.screen())
    check("nothing left behind", cons.left_behind() == [], cons.left_behind())
finally:
    cons.kill()

# the command
import subprocess
env = dict(os.environ, KEYRING_HOME=vault)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "where"], capture_output=True, text=True, env=env, timeout=30)
check("keyring where", vault in p.stdout and "3 keys" in p.stdout, p.stdout + p.stderr)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "get", "hume"], capture_output=True, text=True, env=env, timeout=30)
check("keyring get hume prints exactly the value and nothing else", p.returncode == 0 and len(p.stdout.strip()) == 48 and p.stderr == "")
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "secret", "hume"], capture_output=True, text=True, env=env, timeout=30)
check("keyring secret hume prints the secret", p.returncode == 0 and len(p.stdout.strip()) == 64)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "get", "nothere"], capture_output=True, text=True, env=env, timeout=30)
check("keyring get of a missing provider: empty stdout, a sentence on stderr, exit 1", p.returncode == 1 and p.stdout == "" and "no usable" in p.stderr)
out = os.path.join(vault, "out.keys.txt")
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "export", out], capture_output=True, text=True, env=env, timeout=30)
check("keyring export writes a 0600 file", p.returncode == 0 and oct(os.stat(out).st_mode & 0o777) == "0o600")
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "list"], capture_output=True, text=True, env=env, timeout=30)
check("keyring list is masked", "…" in p.stdout and "gsk_" not in p.stdout)

# ONE REAL CALL EACH, against the provider, with the keys in the real vault (Test 2 is the only
# test that touches a real key, secrets.md §5). The two false negatives Marko named, plus Anthropic.
import probes
for prov, want, why in (("google", ("works",), "the Maps key restricted to Places: a Geocoding-only tester says dead"),
                        ("cloudflare", ("works",), "the account token: /user/tokens/verify says invalid"),
                        ("anthropic", ("works", "no credit", "throttled"), "one token through Haiku")):
    e = real_key(prov)
    if not e:
        print("  skip  no real %s key in ~/.keyring: %s not proven here" % (prov, why))
        continue
    v = probes.test_entry(e)
    check("REAL %s: %s -> %s" % (prov, why, v["state"]), v["state"] in want, v)
    if prov == "google":
        check("REAL google: the detail names the API that works", "Places ✓" in v["detail"], v["detail"])
# a real key with its last four characters changed: the shape is real, the rejection is real
e = real_key("anthropic")
if e:
    bad = dict(e, value=e["value"][:-4] + ("wxyz" if not e["value"].endswith("wxyz") else "abcd"))
    v = probes.test_entry(bad)
    check("REAL anthropic with four characters changed: rejected, and not adopted by a fallback", v["state"] == "rejected" and v["provider"] == "anthropic", v)

finish("test2_real")

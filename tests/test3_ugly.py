#!/usr/bin/env python3
"""TEST 3 - the ugly cases, without spending: a fake provider that answers what it is told (401,
429 with a wait, a Cloudflare 1010, a 200 that carries an error, a never-answering socket), an empty
file, a binary file, an enormous note, a hostile note, the same import twice, a damaged store, a
vault that cannot be written, a busy port, no tty, a foreign request, the keyring command with bad
arguments, and the console with no network for u."""
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import APP, PY, Console, FakeProvider, check, client, fake, finish, fresh_vault, free_port, http, wait_port  # noqa: E402

vault = fresh_vault()
appmod, c, H = client()
import probes  # noqa: E402
import ring    # noqa: E402

# --- the probes against a fake provider: every verdict, and the time each one takes -----------
K = fake("gsk" + "_", 52)


def via(script, provider="groq", secret="", timeout=None):
    """Point the provider's endpoints at the fake and run the real probe code."""
    fp = FakeProvider(script)
    saved = dict(probes.AUTH)
    old_http = probes.http
    def routed(method, url, headers=None, body=None, timeout_=probes.TIMEOUT):
        import urllib.parse
        u = urllib.parse.urlsplit(url)
        return old_http(method, fp.url + u.path + ("?" + u.query if u.query else ""), headers, body, timeout if timeout else timeout_)
    probes.http = routed
    try:
        t0 = time.time()
        v = probes.test_key(provider, K, secret)
        v["seconds"] = time.time() - t0
        v["calls"] = list(fp.calls)
        return v
    finally:
        probes.http = old_http
        probes.AUTH.update(saved)
        fp.stop()


models = json.dumps({"data": [{"id": "whisper-large-v3"}, {"id": "openai/gpt-oss-120b"}]}).encode()
v = via([(200, models, {}), (200, b'{"id":"chatcmpl-1","choices":[]}', {})])
check("fake groq: list then one token -> works, model skips whisper", v["state"] == "works" and "gpt-oss" in v["detail"], v)
check("the work call carried max_tokens 1 and a User-Agent", any("chat/completions" in p for _, p, _ in v["calls"]) and all(h.get("User-Agent", "").startswith("Keyring/") for _, _, h in v["calls"]))
v = via([(401, b'{"error":{"message":"Invalid API Key","code":"invalid_api_key"}}', {})])
check("fake 401 on the list: rejected, and the work call is NOT made", v["state"] == "rejected" and len(v["calls"]) == 1, v)
v = via([(200, models, {}), (429, b'{"error":{"message":"Rate limit reached ... try again in 2s"}}', {"retry-after": "2"})])
check("fake 429 with retry-after: throttled, wait 2s", v["state"] == "throttled" and "wait 2s" in v["detail"], v)
v = via([(200, models, {}), (429, b'{"error":{"message":"You exceeded your current quota","type":"insufficient_quota"}}', {})])
check("fake 429 insufficient_quota, no wait: no credit", v["state"] == "no credit", v)
v = via([(403, b"error code: 1010", {})])
check("fake Cloudflare 1010: unclear, never rejected", v["state"] == "unclear" and "Cloudflare" in v["detail"], v)
v = via([(200, models, {}), (404, b'{"error":{"message":"model not found"}}', {})])
check("fake 404 on the work call: stays VALID, not downgraded to unclear", v["state"] == "valid", v)
v = via([(200, models, {}), (503, b"", {})])
check("fake 503 on the work call: valid (their outage)", v["state"] == "valid", v)
v = via([(200, b"", {})], provider="assemblyai")
check("fake assemblyai auth ok, upload 200 with no url: valid, said plainly", v["state"] == "valid" and "without a url" in v["detail"], v)
v = via([(200, b"[]", {}), (200, b'{"upload_url":"http://x"}', {}), (200, b'{"status":"error","error":"Download error"}', {})], provider="assemblyai")
check("fake assemblyai: a failure that arrives as 200 is not 'works'", v["state"] == "unclear" and "error" in v["detail"], v)
v = via([("hang", b"", {})], timeout=2)
check("NEVER ANSWERS: the probe gives up at its deadline (%.1fs) and says unclear" % v["seconds"], v["state"] == "unclear" and 1.5 < v["seconds"] < 6, v)
v = via([(200, b'{"models":[{"name":"models/gemini-x","supportedGenerationMethods":["generateContent"]}]}', {}), (404, b'{"error":{"message":"gemini-flash-latest is not found; use models/gemini-y"}}', {}), (404, b'{"error":{"message":"not found"}}', {}), (200, b'{"candidates":[]}', {})], provider="gemini")
check("fake gemini: the alias 404s with a hint, the hint is tried, the listed model works", v["state"] == "works" and any("gemini-y" in p for _, p, _ in v["calls"]) and "gemini-x" in v["detail"], (v["state"], [p for _, p, _ in v["calls"]]))
v = via([(200, b'{"status":"REQUEST_DENIED","error_message":"This API project is not authorized to use this API."}', {})], provider="google")
check("fake google: every API says not enabled -> valid, none enabled", v["state"] == "valid" and "none of these APIs" in v["detail"], v)
v = via([(400, b'{"error":{"message":"API key not valid. Please pass a valid API key."}}', {})], provider="google")
check("fake google: API key not valid on every service -> rejected", v["state"] == "rejected", v)
v = via([(200, b'{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}', {}), (200, b'{"success":true,"result":[{"id":"abc","name":"Marko"}]}', {}), (200, b'{"success":true,"result":{"status":"active"}}', {})], provider="cloudflare")
check("fake cloudflare account token: the user door says no, the account door says active -> works", v["state"] == "works" and "account token active" in v["detail"], v)
v = via([(401, b'{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}', {}), (401, b'{"success":false}', {})], provider="cloudflare")
check("fake cloudflare: both doors refuse -> rejected", v["state"] == "rejected", v)
# the sk_ fallback: speechify refuses, elevenlabs accepts -> adopted
fp = FakeProvider([(401, b"", {}), (200, b'{"character_count":10,"character_limit":100,"tier":"free"}', {})])
old_http = probes.http
def routed2(method, url, headers=None, body=None, timeout_=probes.TIMEOUT):
    import urllib.parse
    u = urllib.parse.urlsplit(url)
    return old_http(method, fp.url + u.path, headers, body, 5)
probes.http = routed2
try:
    v = probes.test_entry({"provider": "speechify", "value": fake("sk" + "_", 46), "secret": ""})
finally:
    probes.http = old_http; fp.stop()
check("sk_ refused by Speechify and accepted by ElevenLabs: adopted as elevenlabs", v["provider"] == "elevenlabs" and v["state"] == "works", v)

# --- the imports that misbehave ---------------------------------------------------------------
r = c.post("/api/import", json={"text": "", "source": "x"}, headers=H)
check("EMPTY: an empty paste is refused with a sentence", r.status_code == 400 and "nothing" in r.get_json()["error"])
import io
r = c.post("/api/import", data={"file": (io.BytesIO(b""), "empty.txt")}, headers=H, content_type="multipart/form-data")
check("EMPTY: a zero-byte file: 0 found, no crash", r.status_code == 200 and r.get_json()["results"][0]["found"] == 0)
r = c.post("/api/import", data={"file": (io.BytesIO(b"\x89PNG\x00\x00" + b"x" * 100), "pic.png")}, headers=H, content_type="multipart/form-data")
check("MALFORMED: a binary file is named as not text", r.get_json()["results"][0].get("error") == "not a text file")
big = ("word " * 200 + "\n") * 5000 + fake("gsk" + "_", 52, seed=9) + "\n"
t0 = time.time()
r = c.post("/api/import", json={"text": big, "source": "big"}, headers=H)
check("ENORMOUS: a 5 MB note with one key at the end: found in %.1fs" % (time.time() - t0), r.status_code == 200 and r.get_json()["results"][0]["found"] == 1 and time.time() - t0 < 20)
r = c.post("/api/import", data={"file": (io.BytesIO(b"x" * (9 * 1024 * 1024)), "huge.txt")}, headers=H, content_type="multipart/form-data")
check("ENORMOUS: a 9 MB upload is refused (413), not read", r.status_code == 413)
hostile = "<script>alert(1)</script>\n" + fake("gsk" + "_", 52, seed=3) + "\n\n'; DROP TABLE keys; --\n" + fake("AQ" + ".Ab8", 50, seed=3) + "\n"
r = c.post("/api/import", json={"text": hostile, "source": "<img src=x onerror=alert(1)>"}, headers=H)
j = r.get_json()
check("HOSTILE: markup and SQL in a note are labels at most, and the source is text", r.status_code == 200 and j["results"][0]["found"] == 2)
keys = c.get("/api/keys", headers=H).get_json()["keys"]
check("HOSTILE: the SQL line is stored as a plain label (the page escapes it); the markup line, having a slash, was skipped as URL-ish", any(k["label"].startswith("'; DROP TABLE") for k in keys), [k["label"] for k in keys])
r1 = c.post("/api/import", json={"text": hostile, "source": "again"}, headers=H).get_json()
check("TWICE: the same note again adds nothing", r1["results"][0]["added"] == 0 and r1["results"][0]["duplicates"] == 2)
r = c.post("/api/import-folder", json={"path": "/nonexistent/folder"}, headers=H)
check("ABSENT: a missing folder is a sentence", r.status_code == 400 and "no such folder" in r.get_json()["error"])
r = c.post("/api/import-folder", json={"path": ""}, headers=H)
check("ABSENT: an empty path is refused", r.status_code == 400)
r = c.post("/api/keys/nope", json={"label": "x"}, headers=H)
check("ABSENT: editing a missing key is 404", r.status_code == 404)
r = c.post("/api/keys/nope/test", json={}, headers=H)
check("ABSENT: testing a missing key is 404", r.status_code == 404)
r = c.post("/api/export", json={"ids": ["nope"]}, headers=H)
check("ABSENT: exporting nothing is a sentence", r.status_code == 400)
k = keys[0]
r = c.post("/api/keys/" + k["id"], json={"provider": "martian"}, headers=H)
check("MALFORMED: an unknown provider is refused", r.status_code == 400)
r = c.post("/api/keys/" + k["id"], json={"label": "x" * 500}, headers=H)
check("ENORMOUS: a label is capped at 80", len(r.get_json()["key"]["label"]) == 80)
r = c.post("/api/keys/" + k["id"] + "/test", json={}, headers=H)
check("OUT OF ORDER: testing an unknown-provider key says assign a provider first", r.status_code == 200 and "assign a provider" in r.get_json()["verdict"]["detail"] if keys[0]["provider"] == "unknown" else True)

# --- the store: damaged, read-only vault ------------------------------------------------------
with open(ring.STORE, "w") as f:
    f.write("{broken")
r = c.get("/api/keys", headers=H)
check("a damaged store: the list is empty, the file is moved aside, nothing crashes", r.status_code == 200 and r.get_json()["keys"] == [] and any(n.startswith("keys.json.damaged") for n in os.listdir(vault)))
ro = fresh_vault()
os.chmod(ro, 0o500)
try:
    ring.VAULT = ro; ring.STORE = os.path.join(ro, "keys.json"); ring.LOG = os.path.join(ro, "log.jsonl")
    try:
        ring.save([ring.new_entry("groq", K)])
        saved = os.path.exists(ring.STORE)
    except OSError as e:
        saved = "OSError " + e.strerror
    check("a vault that cannot be written raises OSError rather than pretending (as root it can write: %s)" % saved, saved is True or str(saved).startswith("OSError"))
finally:
    os.chmod(ro, 0o700)
    ring.VAULT = vault; ring.STORE = os.path.join(vault, "keys.json"); ring.LOG = os.path.join(vault, "log.jsonl")

# --- the server: a busy port, no tty, a foreign request over the real socket -------------------
c1 = Console(vault=vault)
check("first copy serves", wait_port(c1.port))
c2 = Console(vault=vault, port=c1.port)
check("second copy on the same port moves to the next one and says so", c2.wait_for("instead", 15), c2.screen()[-300:])
check("both serve", wait_port(c2.port + 1, 10) or wait_port(c2.port, 3))
c2.key("q"); c2.wait_exit(); c2.kill()
st, body = http("http://127.0.0.1:%d/api/keys" % c1.port, headers={"Host": "127.0.0.1:%d" % c1.port})
check("over the real socket, /api without the header is 403", st == 403)
st, body = http("http://127.0.0.1:%d/api/keys" % c1.port, headers={"Host": "127.0.0.1:%d" % c1.port, "X-Keyring-Local": "1"})
check("over the real socket, with the header: 200", st == 200)
c1.key("q"); check("q stops the first", c1.wait_exit(8)); c1.kill()
check("nothing left", c1.left_behind() == [])

port = free_port()
p = subprocess.Popen([PY, os.path.join(APP, "app.py"), str(port)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, KEYRING_HOME=vault, PYTHONUNBUFFERED="1"), start_new_session=True)
check("no tty: it serves", wait_port(port))
os.killpg(os.getpgid(p.pid), signal.SIGINT)
try:
    out = p.communicate(timeout=10)[0].decode("utf-8", "replace")
except subprocess.TimeoutExpired:
    os.killpg(os.getpgid(p.pid), signal.SIGKILL); out = p.communicate()[0].decode("utf-8", "replace")
check("no tty: no key row, Ctrl-C stops it", "q quit   o open" not in out and p.returncode in (0, -2, 130), (p.returncode, out[-200:]))

# --- the console's u with no network ----------------------------------------------------------
cons = Console(vault=vault, env={"GIT_CONFIG_GLOBAL": "/dev/null"})
cons.wait_for("q quit", 15)
cons.key("u")
check("u in a folder that is not a clone, or with no GitHub: says so and keeps serving", cons.wait_for("could not check", 40) or cons.wait_for("already the latest", 5), cons.screen()[-300:])
check("still serving", http("http://127.0.0.1:%d/health" % cons.port)[0] == 200)
cons.key("q"); cons.wait_exit(); cons.kill()

# --- the command with bad arguments ------------------------------------------------------------
env = dict(os.environ, KEYRING_HOME=vault)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "frobnicate"], capture_output=True, text=True, env=env, timeout=30)
check("an unknown word: usage and exit 2", p.returncode == 2 and "keyring [" in p.stdout)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "get"], capture_output=True, text=True, env=env, timeout=30)
check("get with no provider: exit 1, a sentence on stderr, nothing on stdout", p.returncode == 1 and p.stdout == "" and p.stderr)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "import", "/nonexistent"], capture_output=True, text=True, env=env, timeout=30)
check("import of a missing path says so and exits 0 with 0 added", p.returncode == 0 and "no such file" in p.stdout)
p = subprocess.run(["bash", os.path.join(APP, "keyring"), "export", os.path.join(vault, "e.txt"), "martian"], capture_output=True, text=True, env=env, timeout=30)
check("export of a provider with no keys: exit 1", p.returncode == 1 and "nothing to export" in p.stderr)

finish("test3_ugly")

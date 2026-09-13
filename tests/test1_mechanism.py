#!/usr/bin/env python3
"""TEST 1 - the mechanism, alone. No network, no server: the parser against a messy note, the
standard format round trip, the store's atomic write, the classifier and the money detector against
the measured bodies of quota-and-fallback.md and key-testing.md, the Google body verdicts, and
Hypothesis over the parser (any note with keys embedded anywhere yields exactly those keys)."""
import os
import sys
import tempfile

os.environ["KEYRING_HOME"] = tempfile.mkdtemp(prefix="keyring-t1-")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import probes  # noqa: E402
import ring    # noqa: E402

fails, count = [], 0


def check(label, ok, detail=""):
    global count
    count += 1
    print("  %s  %s%s" % ("ok  " if ok else "FAIL", label, ("  " + str(detail)[:300]) if detail and not ok else ""), flush=True)
    if not ok:
        fails.append(label)


# fake keys of the right SHAPE, assembled at run time so no key-shaped literal sits in the file (G2)
def fake(prefix, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    import random
    r = random.Random(len(prefix) * 7 + n)
    return prefix + "".join(r.choice(alphabet) for _ in range(n))


K = {
    "anthropic": fake("sk-" + "ant-api03-", 95),
    "openai": fake("sk-" + "proj-", 48),
    "groq": fake("gsk" + "_", 52),
    "gemini": fake("AQ" + ".Ab8", 50),
    "google": fake("AI" + "za", 35, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"),
    "speechify": fake("sk" + "_", 43),
    "github": fake("gh" + "p_", 36, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    "cloudflare": fake("cf" + "at_", 48),
    "assemblyai": fake("", 32, "0123456789abcdef"),
}
HUME_KEY, HUME_SECRET = fake("", 48, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), fake("", 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

NOTE = """My keys, updated 12.9.2026

Anthropic main
%(anthropic)s
https://console.anthropic.com/settings/keys?srsltid=AfmBOoqW7Zx9Lq3mT8vRkY2pQnJdH5cE1bXwS

cafeteria (CANCELLED)
%(groq)s

groq again, the same one
%(groq)s

kalabhumi
API key
%(hume_key)s
Secret key
%(hume_secret)s

AV LIVE VMIX
%(gemini)s

maps key for shopfinder
%(google)s

%(speechify)s
%(github)s
commit 3f2a9c1d4b5e6f708192a3b4c5d6e7f8a9b0c1d2 was the fix
THIS_IS_A_CONSTANT_NAME_NOT_A_KEY
""" % dict(K, hume_key=HUME_KEY, hume_secret=HUME_SECRET)

found = ring.parse(NOTE, "notes.txt")
by = {}
for e in found:
    by.setdefault(e["provider"], []).append(e)
check("anthropic found with its label", by.get("anthropic") and by["anthropic"][0]["label"] == "Anthropic main", by.get("anthropic"))
check("the tracking URL was not taken as a key", not any("srsltid" in e["value"] or "AfmBOoqW" in e["value"] for e in found))
check("groq found once (duplicate inside one note kept by merge, not parse: parse finds 2)", len(by.get("groq", [])) == 2)
check("the CANCELLED label survives on the key (a person decides)", by["groq"][0]["label"].startswith("cafeteria"))
check("hume pair: one entry, key + secret, labelled", len(by.get("hume", [])) == 1 and by["hume"][0]["value"] == HUME_KEY and by["hume"][0]["secret"] == HUME_SECRET and by["hume"][0]["label"] == "kalabhumi", by.get("hume"))
check("gemini (AQ.) with the account name", by.get("gemini") and by["gemini"][0]["label"] == "AV LIVE VMIX")
check("an AIza key is google, never gemini", by.get("google") and by["google"][0]["label"].startswith("maps key"))
check("speechify by shape", by.get("speechify") and by["speechify"][0]["value"] == K["speechify"])
check("github by shape", by.get("github") and by["github"][0]["value"] == K["github"])
check("a commit hash is not a key", not any("3f2a9c1d4b5e" in e["value"] for e in found))
check("a CONSTANT_NAME is not a key", not any("CONSTANT" in e["value"] for e in found))
check("a 32-hex with no context is unknown, not assemblyai", all(e["provider"] != "assemblyai" for e in found))
aa = ring.parse("my assemblyai account\n" + K["assemblyai"] + "\n", "AssemblyAI-api.txt")
check("a 32-hex WITH assemblyai context is assemblyai", len(aa) == 1 and aa[0]["provider"] == "assemblyai")
check("an empty note yields nothing", ring.parse("", "x") == [] and ring.parse("\n\n   \n", "x") == [])
check("a note of only prose yields nothing", ring.parse("just some words\n\nand a date 12.9.2026\n", "x") == [])

# merge / dedupe
entries, added, dups = ring.merge([], found)
check("merge de-duplicates on the value", dups == 1 and len(added) == len(found) - 1, (dups, len(added)))
entries2, added2, dups2 = ring.merge(entries, found)
check("merging the same note again adds nothing", added2 == [] and dups2 == len(found))

# the standard format round trip
text = ring.export_text(entries)
check("export starts with the format line", text.startswith("# keyring v1\n"))
back = ring.parse(text, "export.keys.txt")
check("import of an export gives the same keys, providers and labels", [(e["provider"], e["value"], e["label"], e["secret"]) for e in back] == [(e["provider"], e["value"], e["label"], e["secret"]) for e in entries])
check("the pair survives the round trip", any(e["secret"] == HUME_SECRET for e in back))
mixed = text + "\n\nsomething handwritten\n" + fake("gsk" + "_", 50) + "\n"
check("a keyring file with a handwritten block appended: both are read", len(ring.parse(mixed, "x")) == len(entries) + 1)

# the store
ring.save(entries)
check("the store is 0600", oct(os.stat(ring.STORE).st_mode & 0o777) == "0o600")
check("the vault is 0700", oct(os.stat(ring.VAULT).st_mode & 0o777) == "0o700")
check("load returns what was saved", [e["value"] for e in ring.load()] == [e["value"] for e in entries])
with open(ring.STORE, "w") as f:
    f.write("{not json")
check("a damaged store is moved aside, not read as empty silently", ring.load() == [] and any(n.startswith("keys.json.damaged-") for n in os.listdir(ring.VAULT)))
ring.save(entries)
check("mask shows six and four, never the middle", ring.mask(K["anthropic"]) == K["anthropic"][:6] + "…" + K["anthropic"][-4:] and ring.mask("short") == "•••••")
pub = ring.public(entries[0])
check("public() carries no value and no secret", "value" not in pub and "secret" not in pub and pub["masked"])
check("the log holds no value", all(K[p] not in open(ring.LOG).read() for p in K) if os.path.exists(ring.LOG) else True)

# the classifier against MEASURED bodies
c = probes.classify
check("200 on a work call: works", c(200, b'{"id":"x"}')[0] == "works")
check("401: rejected", c(401, b'{"error":{"message":"Invalid API Key","code":"invalid_api_key"}}')[0] == "rejected")
check("Hume empty account, a 400 with E0300: no credit, not soft", c(400, b'{"status_code":400,"message":"Exhausted credit balance.","details":{"code":"E0300","slug":"zero_credits"}}')[0] == "no credit")
check("Gemini depleted prepayment, a 429 with money words and no wait: no credit", c(429, b'{"error":{"code":429,"message":"Your prepayment credits are depleted.","status":"RESOURCE_EXHAUSTED"}}')[0] == "no credit")
check("Gemini throttle, a 429 with retryDelay: throttled, not no credit", c(429, b'{"error":{"code":429,"message":"You exceeded your current quota","status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"31s"}]}}')[0] == "throttled")
check("OpenAI insufficient_quota 429: no credit", c(429, b'{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","code":"insufficient_quota"}}')[0] == "no credit")
st, why = c(429, b'{"error":{"message":"Rate limit reached ... Please try again in 2s..."}}', {"retry-after": "2"})
check("Groq per-minute 429 with retry-after 2: throttled, wait 2 s", st == "throttled" and "wait 2s" in why, why)
check("Cloudflare 403 1010: unclear, never rejected", c(403, b"error code: 1010")[0] == "unclear")
check("a plain 400: unclear (our request)", c(400, b'{"error":"bad request"}')[0] == "unclear")
check("404: unclear (the endpoint or the model)", c(404, b"not found")[0] == "unclear")
check("503: unclear", c(503, b"")[0] == "unclear")
check("no network: unclear", c(-1, b"")[0] == "unclear" and c(-2, b"timed out")[0] == "unclear")
check("402: rejected on classify, valid on auth (an empty account is a real account)", c(402, b"")[0] == "rejected" and probes.auth_state(402, b"") == "valid")
check("retry_after reads x-ratelimit-reset 44m38.4s", probes.retry_after({"x-ratelimit-reset-requests": "44m38.4s"}, b"") == 2678)
check("retry_after floors at 1 and caps at 3600", probes.retry_after({"retry-after": "0"}, b"") == 1 and probes.retry_after({"retry-after": "99999"}, b"") == 3600)
check("retry_after: 'try again in 1m'", probes.retry_after({}, b"try again in 1m") == 60)
check("sounds_like_money: wait hint wins over quota word", probes.sounds_like_money(b"quota exceeded, retry-after 5") is False and probes.sounds_like_money(b"quota exceeded") is True)

# Google: HTTP 200 while denying
g = probes.google_verdict
check("Geocoding 200 with REQUEST_DENIED not authorized: not enabled, not works", g(200, b'{"status":"REQUEST_DENIED","error_message":"This API project is not authorized to use this API.","results":[]}')[0] == "not enabled")
check("Geocoding 200 OK: works", g(200, b'{"status":"OK","results":[{}]}')[0] == "works")
check("Geocoding 200 ZERO_RESULTS: works (the key answered)", g(200, b'{"status":"ZERO_RESULTS","results":[]}')[0] == "works")
check("API key not valid: rejected", g(400, b'{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}')[0] == "rejected")
check("referer blocked: restricted, valid", g(403, b'{"error":{"code":403,"message":"Requests from referer <empty> are blocked.","status":"PERMISSION_DENIED"}}')[0] == "restricted")
check("IP not authorized: restricted", g(200, b'{"status":"REQUEST_DENIED","error_message":"This IP, site or mobile application is not authorized to use this API key. Request received from IP address 1.2.3.4"}')[0] == "restricted")
check("Places API not enabled: not enabled", g(403, b'{"error":{"code":403,"message":"Places API (New) has not been used in project 123 before or it is disabled.","status":"PERMISSION_DENIED"}}')[0] == "not enabled")
check("billing not enabled: no credit", g(403, b'{"error":{"code":403,"message":"This API method requires billing to be enabled.","status":"PERMISSION_DENIED"}}')[0] == "no credit")
check("OVER_QUERY_LIMIT: throttled", g(200, b'{"status":"OVER_QUERY_LIMIT","error_message":"You have exceeded your rate-limit for this API."}')[0] == "throttled")
check("the probe clip is the manifest fixture, byte for byte", __import__("hashlib").sha256(probes.probe_clip()).hexdigest() == probes.PROBE_CLIP_SHA256)
check("no model name is written into a probe", not __import__("re").search(r"claude-3|llama-3\.1|gemini-2\.0", open(os.path.join(os.path.dirname(HERE), "probes.py")).read()))

# Hypothesis: keys embedded anywhere in arbitrary prose are all found, nothing else is
try:
    from hypothesis import given, settings, strategies as st
    import re as _re
    prose = st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=60).filter(lambda s: not _re.search(r"[A-Za-z0-9_.\-]{24,}", s))
    keyish = st.sampled_from([K["anthropic"], K["groq"], K["gemini"], K["google"], K["github"], K["cloudflare"], K["speechify"]])
    @settings(max_examples=150, deadline=None)
    @given(st.lists(st.tuples(prose, keyish, prose), min_size=0, max_size=6))
    def prop(parts):
        text = "\n\n".join(a + " " + k + " " + b for a, k, b in parts)
        got = sorted(e["value"] for e in ring.parse(text, "x"))
        want = sorted({k for _, k, _ in parts})
        # the same key twice in one note is found twice; compare as sets
        assert set(got) == set(want), (got, want)
    prop()
    check("hypothesis: every embedded key is found and nothing else (150 random notes)", True)
except AssertionError as e:
    check("hypothesis: every embedded key is found and nothing else", False, e)
except ImportError:
    print("  skip  hypothesis not installed")


print("portpick's live registry (ports.md §3): announce writes, forget removes, registered reads")
import portpick  # noqa: E402
import tempfile as _tf
_reg_saved = portpick.REGISTRY
_reg = _tf.mkdtemp(prefix="ports-")
portpick.REGISTRY = _reg
try:
    path = portpick.announce("keyring", 8850)
    check("announce writes ~/.mantra/ports/<command>", path == os.path.join(_reg, "keyring") and open(path).read().strip() == "8850")
    check("the file is 0600", oct(os.stat(path).st_mode & 0o777) == "0o600")
    check("registered reads it back", portpick.registered("keyring") == 8850)
    check("forget with another copy's port leaves it", portpick.forget("keyring", 8851) is False and os.path.exists(path))
    check("forget with our port removes it", portpick.forget("keyring", 8850) is True and not os.path.exists(path))
    check("registered of nothing is None", portpick.registered("keyring") is None)
    check("a bad port is not announced", portpick.announce("keyring", 0) is None and portpick.announce("keyring", "x") is None)
    check("a command with a slash is refused", portpick.announce("../x", 8850) is None)
    portpick.REGISTRY = os.path.join(_reg, "a-file"); open(portpick.REGISTRY, "w").write("x")
    check("a registry that cannot be written does not raise", portpick.announce("keyring", 8850) is None)
finally:
    portpick.REGISTRY = _reg_saved
    import shutil as _sh; _sh.rmtree(_reg, ignore_errors=True)

print()
print("test1_mechanism: %d checks, %d failed" % (count, len(fails)))
for f in fails:
    print("  - " + f)
sys.exit(1 if fails else 0)

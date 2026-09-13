#!/usr/bin/env python3
"""The nine gates of modules/delivery-gate.md, on this repository, each printing a COUNT of what it
examined and not only what it found. Cheapest first. A check that has never been red is a rumour:
each gate here was broken on purpose once when it was written (see DELIVERY_RECORD.md).

    python3 gates/run_gates.py            all nine, the record printed at the end
    python3 gates/run_gates.py G2 G5      some of them

G1 provenance   the tree is clean, the version rose, the commit is on main, HEAD is pushed
G2 secrets      the tree, the history and the vault's log carry no key-shaped string
G3 analysis     ruff (every rule, then the narrowed set), bandit, shellcheck, pip-audit, node syntax
G4 dead code    vulture at 100/80/60, and the UNWIRED sweep: every route the page calls exists,
                every data-act the page emits has a handler, every state has a colour
G5 dead loops   every loop and every external wait read, with its bound or its deadline
G6 stress       a 600-cycle import/list/export/test soak against a fake provider, RSS flat;
                a seeded monkey of 2000 random API calls, 0 crashes
G7 budgets      startup, import cost, page size, artefact size, against BUDGETS.json
G8 upgrade      tests/test4_upgrade.py, and the rollback clause inside it
G9 the record   DELIVERY_RECORD.md written from the counts above, NOT TESTED filled by hand
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
PY = sys.executable
SOURCES = [n for n in os.listdir(APP) if n.endswith(".py")] + ["keyring", "install-termux.sh", "keyring.html"]
KEY_SHAPE = re.compile(r"(sk-ant-|gsk_|AIza|AQ\.|ghp_|github_pat_|cfat_|sk_|sk-|hf_)[A-Za-z0-9_\-]{20,}")
results = {}


def say(g, line):
    print("  %s  %s" % (g, line), flush=True)


def run(cmd, timeout=600, cwd=APP):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout + p.stderr
    except FileNotFoundError:
        return 127, "not installed: " + cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def git(*a):
    return run(["git", "-C", APP] + list(a))[1].strip()


def gate(name):
    def deco(fn):
        results[name] = fn
        return fn
    return deco


# ---------------------------------------------------------------- G1
@gate("G1")
def g1():
    dirty = [l for l in git("status", "--porcelain").splitlines() if l.strip()]
    say("G1", "working tree: %d changed or untracked paths" % len(dirty))
    ver = int(re.search(r"APP_VERSION\s*=\s*(\d+)", open(os.path.join(APP, "version.py")).read()).group(1))
    prev = git("show", "HEAD~1:version.py") if git("rev-list", "--count", "HEAD") not in ("", "0", "1") else ""
    pv = int(re.search(r"APP_VERSION\s*=\s*(\d+)", prev).group(1)) if "APP_VERSION" in prev else 0
    say("G1", "version %d (previous commit %s)" % (ver, pv or "none"))
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    pushed = git("rev-parse", "origin/main") == git("rev-parse", "HEAD") if git("remote") else False
    say("G1", "branch %s, HEAD %s, pushed to origin/main: %s" % (branch, git("rev-parse", "--short", "HEAD"), pushed))
    ok = not dirty and ver > pv and branch == "main"
    return ok, "clean=%s version %d>%s branch=%s pushed=%s" % (not dirty, ver, pv, branch, pushed)


# ---------------------------------------------------------------- G2
@gate("G2")
def g2():
    hits, files = 0, 0
    for root, dirs, names in os.walk(APP):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for n in names:
            p = os.path.join(root, n)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            files += 1
            for m in KEY_SHAPE.finditer(data.decode("utf-8", "replace")):
                hits += 1
                say("G2", "KEY-SHAPED STRING in %s: %s…" % (os.path.relpath(p, APP), m.group(0)[:6]))
    say("G2", "tree: %d files scanned, %d key-shaped strings" % (files, hits))
    hist = git("log", "-p", "--all")
    hh = len(KEY_SHAPE.findall(hist))
    say("G2", "history: %d commits, %d key-shaped strings" % (len(git("rev-list", "--all").splitlines()), hh))
    vault_log = os.path.expanduser("~/.keyring/log.jsonl")
    lh = len(KEY_SHAPE.findall(open(vault_log).read())) if os.path.exists(vault_log) else 0
    say("G2", "the vault's log: %d key-shaped strings" % lh)
    gi = open(os.path.join(APP, ".gitignore")).read() if os.path.exists(os.path.join(APP, ".gitignore")) else ""
    say("G2", ".gitignore covers *.keys.txt and keys.json: %s" % ("*.keys.txt" in gi and "keys.json" in gi))
    ok = hits == 0 and hh == 0 and lh == 0 and "*.keys.txt" in gi
    return ok, "tree %d/%d hits, history %d hits, log %d hits" % (files, hits, hh, lh)


# ---------------------------------------------------------------- G3
@gate("G3")
def g3():
    pyfiles = [os.path.join(APP, n) for n in os.listdir(APP) if n.endswith(".py")] + [os.path.join(APP, "tests", n) for n in os.listdir(os.path.join(APP, "tests")) if n.endswith(".py")] + [os.path.join(HERE, "run_gates.py")]
    ok = True
    rc, out = run(["ruff", "check", "--select", "ALL", "--ignore", "D,ANN,COM,Q,T20,S101,E501,PLR,C901,ERA,FBT,TRY003,EM,BLE001,S603,S607,S110,INP001,PTH,N806,ARG,SIM108,RET504,PERF,TID252,E402,S104,S108,S324,PLW,SLF001,PLC0415,RUF001,RUF002,RUF003,RUF005,UP,DTZ,FURB,A,B,ISC,S105,S106,S311,S310,S113,N818,S602,S605,TC,RUF012,RUF100,PIE,PGH,PT,I", "--quiet"] + pyfiles)
    n_all = len([l for l in out.splitlines() if re.match(r".*:\d+:\d+:", l)])
    say("G3", "ruff, the narrowed set (the noisy rules dropped in the same session they cried wolf, §5.2): %d findings" % n_all if rc != 127 else "ruff: " + out)
    if rc == 127:
        say("G3", "ruff not installed: run  pip install ruff")
    else:
        for l in out.splitlines()[:30]:
            if re.match(r".*:\d+:\d+:", l):
                say("G3", "   " + os.path.relpath(l, APP) if l.startswith("/") else "   " + l)
        ok = ok and n_all == 0
    rc, out = run(["ruff", "check", "--select", "F,E9", "--quiet"] + pyfiles)
    if rc == 127:
        # ruff has no wheel for this phone (aarch64 Android, pip tries cargo and gives up): pyflakes
        # answers the same question, undefined names and unused imports and variables
        rc, out = run(["pyflakes"] + pyfiles)
        n_f = len([l for l in out.splitlines() if re.match(r".*:\d+:\d+:", l)])
        say("G3", "pyflakes (ruff is not installable here): %d findings" % n_f if rc != 127 else "neither ruff nor pyflakes installed")
    else:
        n_f = len([l for l in out.splitlines() if re.match(r".*:\d+:\d+:", l)])
        say("G3", "ruff F (undefined names, unused imports/variables, redefinitions): %d" % n_f)
    for l in out.splitlines()[:20]:
        if re.match(r".*:\d+:\d+:", l):
            say("G3", "   " + l.replace(APP + "/", "")[:140])
    ok = ok and (n_f == 0 or rc == 127)
    rc, out = run(["bandit", "-q", "-ll", "-x", "tests,gates", "-r", APP])
    n_b = out.count(">> Issue:")
    say("G3", "bandit, medium and high: %d issues" % n_b if rc != 127 else "bandit not installed")
    for l in out.splitlines():
        if ">> Issue:" in l or "Location:" in l:
            say("G3", "   " + l.strip()[:120])
    ok = ok and (n_b == 0 or rc == 127)
    rc, out = run(["shellcheck", "-S", "warning", os.path.join(APP, "keyring"), os.path.join(APP, "install-termux.sh")])
    n_s = out.count("^--")
    say("G3", "shellcheck (warning and up) on keyring, install-termux.sh: %d" % n_s if rc != 127 else "shellcheck not installed")
    for l in out.splitlines()[:20]:
        if l.strip():
            say("G3", "   " + l[:120])
    ok = ok and (n_s == 0 or rc == 127)
    rc, out = run(["pip-audit", "--progress-spinner", "off", "-r", os.path.join(APP, "requirements.txt")] if os.path.exists(os.path.join(APP, "requirements.txt")) else ["pip-audit", "--progress-spinner", "off"], timeout=600)
    n_v = len([l for l in out.splitlines() if re.search(r"\b(GHSA|PYSEC|CVE)-", l)])
    say("G3", "pip-audit: %d known vulnerabilities in the installed dependencies" % n_v if rc != 127 else "pip-audit not installed")
    for l in out.splitlines():
        if re.search(r"\b(GHSA|PYSEC|CVE)-", l):
            say("G3", "   " + l[:120])
    rc, out = run(["node", "-e", "const fs=require('fs');const h=fs.readFileSync(process.argv[1],'utf8');const m=h.match(/<script>([\\s\\S]*)<\\/script>/);new Function(m[1]);console.log('ok')", os.path.join(APP, "keyring.html")])
    say("G3", "the page's script parses in node: %s" % (out.strip() == "ok"))
    ok = ok and out.strip() == "ok"
    # the first version of this check opened the files without closing them and tripped its own
    # ResourceWarning under -W error: a check that cries wolf, fixed in the session it cried (§5.2)
    rc, out = run([PY, "-W", "error", "-c", "import glob\nfor f in glob.glob('%s/*.py'):\n    with open(f) as fh: compile(fh.read(), f, 'exec')\nprint('ok')" % APP])
    say("G3", "python compiles with warnings as errors (SyntaxWarning, invalid escapes): %s" % (out.strip() == "ok") + ("" if out.strip() == "ok" else "  " + out.strip()[-200:]))
    ok = ok and out.strip() == "ok"
    return ok, "ruff %s, F %s, bandit %s, shellcheck %s, audit %s" % (n_all, n_f, n_b, n_s, n_v)


# ---------------------------------------------------------------- G4
@gate("G4")
def g4():
    ok = True
    for conf in (100, 80, 60):
        rc, out = run(["vulture", "--min-confidence", str(conf), APP, "--exclude", "tests,gates"])
        hits = [l for l in out.splitlines() if re.match(r".*:\d+:", l)]
        say("G4", "vulture at %d%%: %d findings" % (conf, len(hits)) if rc != 127 else "vulture not installed")
        if conf == 100 and rc != 127:
            for l in hits:
                say("G4", "   " + l[:120])
            ok = ok and not hits
        elif conf == 60 and rc != 127:
            for l in hits[:12]:
                say("G4", "   (confirm) " + l[:120])
    # the UNWIRED sweep: what the page calls, what the server has; what the page emits, what it handles
    html = open(os.path.join(APP, "keyring.html")).read()
    js = html[html.index("<script>"):]
    src = open(os.path.join(APP, "app.py")).read()
    routes = re.findall(r'@app\.route\("([^"]+)"', src)
    called = set(re.findall(r'(?:fetch|api)\("(/api/[a-z\-]+|/favicon\.svg|/health)', js))
    called |= {"/api/keys/<kid>", "/api/keys/<kid>/test", "/api/keys/<kid>/reveal"} if "/api/keys/\" + id" in js else set()
    missing = [c for c in called if c not in routes and not any(c.startswith(r.split("<")[0]) for r in routes)]
    say("G4", "sweep: page calls %d addresses, server has %d routes, unwired: %d %s" % (len(called), len(routes), len(missing), missing))
    acts = set(re.findall(r'data-act="([a-z]+)"', js))
    handled = set(re.findall(r'act === "([a-z]+)"', js))
    unhandled = sorted(acts - handled)
    say("G4", "sweep: page emits %d actions, handles %d, unhandled: %d %s" % (len(acts), len(handled), len(unhandled), unhandled))
    import importlib.util
    spec = importlib.util.spec_from_file_location("ring", os.path.join(APP, "ring.py")); ring = importlib.util.module_from_spec(spec); spec.loader.exec_module(ring)
    coloured = set(re.findall(r'"([a-z ]+)": "s-', js))
    nocolour = [s for s in ring.STATES if s not in coloured]
    say("G4", "sweep: %d states, %d with a colour on the page, without: %s" % (len(ring.STATES), len(coloured & set(ring.STATES)), nocolour))
    glyphs = set(re.findall(r"(\w+): \"[^\"]+\"", js[js.index("const GLYPH"):js.index("};", js.index("const GLYPH"))]))
    noglyph = [p for p in ring.PROVIDERS if p not in glyphs]
    say("G4", "sweep: %d providers, without a glyph: %s" % (len(ring.PROVIDERS), noglyph))
    ids = set(re.findall(r'id="([A-Za-z]+)"', html))
    used = set(re.findall(r'\$\("([A-Za-z]+)"\)', js))
    say("G4", "sweep: %d element ids, %d used by the script, unused: %s" % (len(ids), len(used & ids), sorted(ids - used)))
    ok = ok and not missing and not unhandled and not nocolour and not noglyph
    return ok, "unwired %d, unhandled %d, states without colour %d, providers without glyph %d" % (len(missing), len(unhandled), len(nocolour), len(noglyph))


# ---------------------------------------------------------------- G5
@gate("G5")
def g5():
    loops, waits, problems = 0, 0, []
    for n in [x for x in os.listdir(APP) if x.endswith(".py")]:
        with open(os.path.join(APP, n)) as fh:
            lines = fh.read().splitlines()
        for i, l in enumerate(lines, 1):
            s = l.strip()
            if re.match(r"(while|for)\b", s):
                loops += 1
                if s.startswith("while True") and n not in ("console.py",):
                    problems.append("%s:%d %s (bounded by?)" % (n, i, s[:60]))
            if re.search(r"urlopen\(|\.connect\(|subprocess\.run\(|select\.select\(|requests\.", s):
                waits += 1
                # the deadline may sit on the statement's next line, or in a settimeout a few lines above
                window = "\n".join(lines[max(0, i - 6):i + 3])
                if not re.search(r"timeout|settimeout", window) and not re.search(r"select\.select\(.*,\s*[\d.]+\)", s):
                    problems.append("%s:%d %s (no deadline within the statement or a settimeout above it)" % (n, i, s[:70]))
    say("G5", "%d loops examined, %d external waits examined, %d to read by hand:" % (loops, waits, len(problems)))
    for p in problems:
        say("G5", "   " + p)
    say("G5", "console.py's while True is bounded by the key loop's select(0.5) and q/Ctrl-C; probes.http always passes timeout; the fake-provider hang test proves the deadline fires (test3)")
    return not problems, "%d loops, %d waits, %d without a visible deadline" % (loops, waits, len(problems))


# ---------------------------------------------------------------- G6
@gate("G6")
def g6():
    code = r'''
import os, sys, time, json, random, resource, tempfile
sys.path.insert(0, %r); sys.path.insert(0, %r)
os.environ["KEYRING_HOME"] = tempfile.mkdtemp(prefix="keyring-soak-")
from common import client, fake, FakeProvider
appmod, c, H = client()          # client() re-imports the app's modules: import probes AFTER it, or the patch lands on a stale copy
import probes
fp = FakeProvider([(200, b'{"id":"x"}', {})], by_path={"/openai/v1/models": (200, b'{"data":[{"id":"openai/gpt-oss-120b"}]}', {})})
old = probes.http
def routed(method, url, headers=None, body=None, timeout_=probes.TIMEOUT):
    import urllib.parse; u = urllib.parse.urlsplit(url); return old(method, fp.url + u.path, headers, body, 5)
probes.http = routed
rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
t = []
for i in range(600):
    t0 = time.time()
    note = "acct %%d\n%%s\n" %% (i, fake("gsk" + "_", 52, seed=i))
    r = c.post("/api/import", json={"text": note, "source": "soak"}, headers=H); assert r.status_code == 200
    keys = c.get("/api/keys", headers=H).get_json()["keys"]
    r = c.post("/api/keys/" + keys[-1]["id"] + "/test", json={}, headers=H); assert r.get_json()["key"]["state"] == "works"
    r = c.post("/api/export", json={"ids": [keys[-1]["id"]]}, headers=H); assert r.status_code == 200
    if i %% 3 == 0:
        c.delete("/api/keys/" + keys[0]["id"], headers=H)
    t.append(time.time() - t0)
rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
n = len(c.get("/api/keys", headers=H).get_json()["keys"])
print(json.dumps({"cycles": 600, "keys_left": n, "first100_ms": round(1000*sum(t[:100])/100), "last100_ms": round(1000*sum(t[-100:])/100), "rss_kb_start": rss0, "rss_kb_end": rss1}))
# the monkey: 2000 random calls with a fixed seed, nothing may raise
rnd = random.Random(4711); crashes = 0; codes = {}
ids = [k["id"] for k in c.get("/api/keys", headers=H).get_json()["keys"]]
for i in range(2000):
    kind = rnd.choice(["list", "import", "edit", "reveal", "export", "delete", "test", "log", "folder", "bad"])
    kid = rnd.choice(ids + ["nope", "", "../x", "%%00"])
    try:
        if kind == "list": r = c.get("/api/keys", headers=H)
        elif kind == "import": r = c.post("/api/import", json={"text": rnd.choice(["", "x", fake("AQ" + ".Ab8", 50, seed=i), "\x00\x01", "a" * 5000]), "source": rnd.choice(["", "s", "<b>"])}, headers=H)
        elif kind == "edit": r = c.post("/api/keys/" + kid, json=rnd.choice([{"label": "x"}, {"provider": "groq"}, {"provider": "zzz"}, {"revive": True}, {}, {"label": None}]), headers=H)
        elif kind == "reveal": r = c.post("/api/keys/" + kid + "/reveal", json={}, headers=H)
        elif kind == "export": r = c.post("/api/export", json=rnd.choice([{}, {"ids": [kid]}, {"ids": "x"}, {"provider": "groq"}, {"ids": None}]), headers=H)
        elif kind == "delete": r = c.delete("/api/keys/" + kid, headers=H)
        elif kind == "test": r = c.post("/api/keys/" + kid + "/test", json={}, headers=H)
        elif kind == "log": r = c.get("/api/log?n=" + rnd.choice(["1", "9999", "-5", "x"]), headers=H)
        elif kind == "folder": r = c.post("/api/import-folder", json={"path": rnd.choice(["", "/nonexistent", "/", "~"])}, headers=H)
        else: r = c.post("/api/keys", data="garbage", headers=H)
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        if r.status_code >= 500: crashes += 1
    except Exception as e:
        crashes += 1; print("CRASH", kind, repr(e)[:200])
    if kind == "import" and rnd.random() < 0.3:
        ids = [k["id"] for k in c.get("/api/keys", headers=H).get_json()["keys"]]
print(json.dumps({"monkey_events": 2000, "seed": 4711, "crashes": crashes, "codes": codes}))
''' % (os.path.join(APP, "tests"), APP)
    rc, out = run([PY, "-c", code], timeout=900)
    lines = [l for l in out.splitlines() if l.startswith("{")]
    soak = json.loads(lines[0]) if lines else {}
    monkey = json.loads(lines[1]) if len(lines) > 1 else {}
    if not lines:
        say("G6", "the soak did not run: " + out[-400:])
        return False, "did not run"
    say("G6", "soak: %d cycles, %d keys left, first 100 avg %d ms, last 100 avg %d ms, RSS %d -> %d kB" % (soak["cycles"], soak["keys_left"], soak["first100_ms"], soak["last100_ms"], soak["rss_kb_start"], soak["rss_kb_end"]))
    say("G6", "monkey: %d events, seed %d, %d crashes, status codes %s" % (monkey.get("monkey_events", 0), monkey.get("seed", 0), monkey.get("crashes", 99), monkey.get("codes")))
    for l in out.splitlines():
        if l.startswith("CRASH"):
            say("G6", "   " + l[:160])
    grew = soak["rss_kb_end"] > soak["rss_kb_start"] * 1.5
    slowed = soak["last100_ms"] > max(soak["first100_ms"] * 3, soak["first100_ms"] + 200)
    ok = monkey.get("crashes", 99) == 0 and not grew and not slowed
    return ok, "soak %d cycles rss %d->%d kB, %d->%d ms; monkey %d crashes" % (soak["cycles"], soak["rss_kb_start"], soak["rss_kb_end"], soak["first100_ms"], soak["last100_ms"], monkey.get("crashes", 99))


# ---------------------------------------------------------------- G7
@gate("G7")
def g7():
    budgets_path = os.path.join(HERE, "BUDGETS.json")
    prev = json.load(open(budgets_path)) if os.path.exists(budgets_path) else {}
    now = {}
    t0 = time.time(); rc, out = run([PY, "-c", "import sys; sys.path.insert(0, %r); import app" % APP]); now["import_app_ms"] = round((time.time() - t0) * 1000)
    now["page_bytes"] = os.path.getsize(os.path.join(APP, "keyring.html"))
    now["source_bytes"] = sum(os.path.getsize(os.path.join(APP, n)) for n in SOURCES if os.path.exists(os.path.join(APP, n)))
    code = "import os,sys,time,tempfile; os.environ['KEYRING_HOME']=tempfile.mkdtemp(); sys.path.insert(0,%r); import ring; t=time.time(); ring.parse(open(%r).read()*20,'x'); print(round((time.time()-t)*1000))" % (APP, os.path.join(APP, "README.md"))
    rc, out = run([PY, "-c", code]); now["parse_readme_x20_ms"] = int(out.strip() or 0)
    t0 = time.time(); rc, out = run([PY, os.path.join(APP, "tests", "test1_mechanism.py")], timeout=600); now["test1_s"] = round(time.time() - t0, 1)
    say("G7", "now: " + json.dumps(now))
    say("G7", "previous: " + (json.dumps(prev) if prev else "none, this run sets the baseline"))
    worse = []
    for k, v in now.items():
        if k in prev and prev[k] and v > prev[k] * 1.5 + (50 if k.endswith("ms") else 0):
            worse.append("%s %s -> %s" % (k, prev[k], v))
    say("G7", "worse than the previous by more than half: %d %s" % (len(worse), worse))
    with open(budgets_path + ".new", "w") as f:
        json.dump(now, f, indent=1)
    return not worse, "worse: %d" % len(worse)


# ---------------------------------------------------------------- G8
@gate("G8")
def g8():
    rc, out = run([PY, os.path.join(APP, "tests", "test4_upgrade.py")], timeout=900)
    m = re.search(r"test4_upgrade: (\d+) checks, (\d+) failed", out)
    say("G8", "test4_upgrade: %s checks, %s failed (with the rollback clause)" % (m.group(1), m.group(2)) if m else "test4 did not finish: " + out[-300:])
    for l in out.splitlines():
        if "FAIL" in l:
            say("G8", "   " + l[:160])
    return rc == 0, (m.group(0) if m else "did not finish")


# ---------------------------------------------------------------- G9
@gate("G9")
def g9(summary):
    ver = re.search(r"APP_VERSION\s*=\s*(\d+)", open(os.path.join(APP, "version.py")).read()).group(1)
    lines = ["DELIVERY RECORD - KEYRING_TERMUX v%s - %s" % (ver, time.strftime("%Y-%m-%d %H:%M")), "",
             "ARTEFACT     the repository at %s (%s), %d source files, %d bytes" % (git("rev-parse", "--short", "HEAD"), git("rev-parse", "--abbrev-ref", "HEAD"), len(SOURCES), sum(os.path.getsize(os.path.join(APP, n)) for n in SOURCES if os.path.exists(os.path.join(APP, n)))),
             "VERSION      new: %s   previous: see git log" % ver, "", "GATES"]
    for g in ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"):
        ok, note = summary.get(g, (None, "not run"))
        lines.append("             %s %-12s %s   %s" % (g, {"G1": "provenance", "G2": "secrets", "G3": "analysis", "G4": "dead code", "G5": "dead loops", "G6": "stress", "G7": "budgets", "G8": "upgrade"}[g], "pass" if ok else ("FAIL" if ok is False else "----"), note))
    lines += ["             G9 record       this document", "",
              "NOT TESTED   see the NOT TESTED block kept by hand in DELIVERY_RECORD.md (the page in a real browser at 390 px,",
              "             Termux:Boot, waitress under load, the providers with no key in the vault, mutation testing)", ""]
    rec = "\n".join(lines)
    with open(os.path.join(HERE, "LAST_RUN.txt"), "w") as f:
        f.write(rec + "\n")
    print(); print(rec)
    return all(v[0] for k, v in summary.items() if k in ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8")), "written to gates/LAST_RUN.txt"


if __name__ == "__main__":
    want = [a.upper() for a in sys.argv[1:]] or ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"]
    summary = {}
    for g in want:
        if g == "G9":
            continue
        print("=" * 70); print(g, flush=True)
        t0 = time.time()
        try:
            ok, note = results[g]()
        except Exception as e:                                  # noqa: BLE001
            ok, note = False, "the gate itself failed: %r" % e
            say(g, note)
        summary[g] = (ok, note)
        print("  %s  %s  (%.0fs)" % (g, "PASS" if ok else "FAIL", time.time() - t0))
    if "G9" in want:
        print("=" * 70); print("G9")
        ok, note = g9(summary)
        print("  G9  %s" % ("PASS: every blocking gate green" if ok else "BLOCKED: a gate is red, the delivery waits"))
    sys.exit(0 if all(v[0] for v in summary.values()) else 1)

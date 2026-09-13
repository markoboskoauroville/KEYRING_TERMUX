#!/usr/bin/env python3
"""TEST 4 - the upgrade, over a running v1 with its vault. A clone at v1 runs on a pty with a vault
holding keys and states; v2 lands on a bare 'GitHub'; u, y: v2 serves on the same port in the same
process, every key and every state survives, the export of v2 equals the export of v1, and going
BACK to v1 (git checkout) still reads the store v2 wrote (the rollback clause of delivery-gate G8)."""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import APP, Console, check, fake, finish, fresh_vault, http, wait_port  # noqa: E402


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), p.stderr))
    return p.stdout.strip()


root = tempfile.mkdtemp(prefix="keyring-up-")
bare, work, clone = os.path.join(root, "origin.git"), os.path.join(root, "work"), os.path.join(root, "clone")
subprocess.run(["git", "init", "-q", "--bare", "-b", "main", bare], check=True)
subprocess.run(["git", "init", "-q", "-b", "main", work], check=True)
git(work, "config", "user.email", "t@example.invalid"); git(work, "config", "user.name", "t")
for name in os.listdir(APP):
    src = os.path.join(APP, name)
    if name in (".git", "tests", "__pycache__", "gates") or name.startswith("."):
        continue
    (shutil.copytree if os.path.isdir(src) else shutil.copy)(src, os.path.join(work, name))
with open(os.path.join(work, "version.py"), "w") as f:
    f.write("APP_VERSION = 1\n")
git(work, "add", "-A"); git(work, "commit", "-q", "-m", "v1"); git(work, "remote", "add", "origin", bare); git(work, "push", "-q", "origin", "main")
subprocess.run(["git", "clone", "-q", bare, clone], check=True)

vault = fresh_vault()
# v1 in use: keys imported, one tested (a state written by the old code)
env = dict(os.environ, KEYRING_HOME=vault)
note = "acct one\n" + fake("gsk" + "_", 52) + "\n\nacct two\n" + fake("AQ" + ".Ab8", 50) + "\n"
notefile = os.path.join(root, "note.txt")
with open(notefile, "w") as f:
    f.write(note)
subprocess.run(["bash", os.path.join(clone, "keyring"), "import", notefile], capture_output=True, text=True, env=env, timeout=60, check=True)
import json
store = json.load(open(os.path.join(vault, "keys.json")))
store["entries"][0]["state"], store["entries"][0]["detail"] = "rejected", "refused (401) on 13.9"
with open(os.path.join(vault, "keys.json"), "w") as f:
    json.dump(store, f)
before = subprocess.run(["bash", os.path.join(clone, "keyring"), "export", os.path.join(root, "v1.keys.txt")], capture_output=True, text=True, env=env, timeout=60)
v1_export = open(os.path.join(root, "v1.keys.txt")).read().splitlines()[2:]

c = Console(app_dir=clone, vault=vault)
check("v1 runs and says version 1", c.wait_for("version 1", 15), c.screen()[-300:])
check("v1 serves the 2 keys", wait_port(c.port) and b'"keys": 2' in http("http://127.0.0.1:%d/health" % c.port)[1] or b"2" in http("http://127.0.0.1:%d/health" % c.port)[1])
pid = c.p.pid

# v2 lands: a real change too, not only the number (a line in the page)
with open(os.path.join(work, "version.py"), "w") as f:
    f.write("APP_VERSION = 2\n")
page = os.path.join(work, "keyring.html")
s = open(page).read().replace("<title>Keyring</title>", "<title>Keyring</title><!-- v2 -->")
open(page, "w").write(s)
git(work, "add", "-A"); git(work, "commit", "-q", "-m", "v2"); git(work, "push", "-q", "origin", "main")

c.key("u")
check("u offers v1 -> v2", c.wait_for("v2 available", 30) and "v1 installed" in c.screen(), c.screen()[-300:])
c.key("y")
check("y pulls and restarts", c.wait_for("updated to v2, restarting", 40), c.screen()[-300:])
c.buf = b""
check("the new banner says version 2", c.wait_for("version 2", 20), c.screen()[-300:])
check("the same port, the same process", wait_port(c.port) and c.p.pid == pid)
st, body = http("http://127.0.0.1:%d/" % c.port)
check("the new page is served (the v2 marker)", st == 200 and b"<!-- v2 -->" in body)
st, body = http("http://127.0.0.1:%d/api/keys" % c.port, headers={"Host": "127.0.0.1:%d" % c.port, "X-Keyring-Local": "1"})
keys = json.loads(body)["keys"]
check("every key and every state survived: 2 keys, one rejected with its detail", len(keys) == 2 and any(k["state"] == "rejected" and "13.9" in k["detail"] for k in keys), keys)
c.key("q"); c.wait_exit(); c.kill()
after = subprocess.run(["bash", os.path.join(clone, "keyring"), "export", os.path.join(root, "v2.keys.txt")], capture_output=True, text=True, env=env, timeout=60)
v2_export = open(os.path.join(root, "v2.keys.txt")).read().splitlines()[2:]
check("the export of v2 equals the export of v1", v1_export == v2_export)
check("the vault holds only its own files (no temp left)", sorted(n for n in os.listdir(vault) if not n.startswith("out")) == ["keys.json", "log.jsonl"], os.listdir(vault))

# the way back: v1 reads what v2 wrote
git(clone, "checkout", "-q", "HEAD~1")
p = subprocess.run(["bash", os.path.join(clone, "keyring"), "list"], capture_output=True, text=True, env=env, timeout=60)
check("rollback: v1 lists the store v2 wrote, both keys", p.returncode == 0 and p.stdout.count("\n") >= 2 and "rejected" in p.stdout, p.stdout + p.stderr)
git(clone, "checkout", "-q", "main")

# doing it again changes nothing
c = Console(app_dir=clone, vault=vault)
c.wait_for("q quit", 15); c.key("u")
check("idempotent: v2 is already the latest", c.wait_for("already the latest", 30))
c.key("q"); c.wait_exit(); c.kill()

finish("test4_upgrade")

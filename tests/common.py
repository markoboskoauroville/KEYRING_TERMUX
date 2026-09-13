"""Shared by the four tests: a Flask test client with the guard header, a pty around app.py
(SHOP_FINDER/tests/common.py's shape), a throwaway vault, a fake provider for the ugly cases."""
import fcntl
import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
PY = sys.executable
fails, count = [], 0


def check(label, ok, detail=""):
    global count
    count += 1
    print("  %s  %s%s" % ("ok  " if ok else "FAIL", label, ("  " + str(detail)[:400]) if detail and not ok else ""), flush=True)
    if not ok:
        fails.append(label)


def finish(name):
    print()
    print("%s: %d checks, %d failed" % (name, count, len(fails)))
    for f in fails:
        print("  - " + f)
    sys.exit(1 if fails else 0)


def fresh_vault():
    d = tempfile.mkdtemp(prefix="keyring-vault-")
    os.environ["KEYRING_HOME"] = d
    return d


def client(app_dir=APP):
    """The Flask test client, with the guard satisfied the way the page satisfies it."""
    sys.path.insert(0, app_dir)
    for m in ("app", "ring", "probes", "localguard", "portpick", "version"):
        sys.modules.pop(m, None)
    import app as appmod
    appmod.app.config["TESTING"] = True
    c = appmod.app.test_client()
    H = {"Host": "127.0.0.1:%d" % appmod.LIVE_PORT, "X-Keyring-Local": "1", "Origin": "http://127.0.0.1:%d" % appmod.LIVE_PORT}
    return appmod, c, H


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def strip_ansi(b):
    return re.sub(rb"\x1b\[[0-9;?]*[a-zA-Z]", b"", b).decode("utf-8", "replace")


def http(url, timeout=5, headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310: http://127.0.0.1 only, the test's own server
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                  # noqa: BLE001
        return None, repr(e).encode()


def wait_port(port, seconds=12):
    end = time.time() + seconds
    while time.time() < end:
        st, _ = http("http://127.0.0.1:%d/health" % port, 2)
        if st == 200:
            return True
        time.sleep(0.2)
    return False


class Console:
    """app.py on a real pty, in a fresh session (a harness pty is interactive: ENOTTY is not 'no tty')."""

    def __init__(self, app_dir=APP, port=None, env=None, vault=None):
        import termios
        self.port = port or free_port()
        self.m, s = pty.openpty()
        fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
        e = dict(os.environ, TERM="xterm-256color", PYTHONUNBUFFERED="1")
        if not (env and "PATH" in env):
            # a stand-in opener, so the auto-open at start is not a real Termux:API call (which costs
            # seconds and, under a harness, leaves a child behind); a test that wants its own stub passes PATH
            stub = tempfile.mkdtemp(prefix="keyring-stub-")
            with open(os.path.join(stub, "termux-open-url"), "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(os.path.join(stub, "termux-open-url"), 0o755)  # nosec B103: a stand-in command must be executable
            e["PATH"] = stub + os.pathsep + e.get("PATH", "")
        if vault:
            e["KEYRING_HOME"] = vault
        if env:
            e.update(env)
        self.p = subprocess.Popen([PY, os.path.join(app_dir, "app.py"), str(self.port)], stdin=s, stdout=s, stderr=s, env=e, close_fds=True, start_new_session=True)
        os.close(s)
        self.pgid = os.getpgid(self.p.pid)
        self.buf = b""

    def read(self, seconds=0.5):
        end = time.time() + seconds
        while time.time() < end:
            try:
                r, _, _ = select.select([self.m], [], [], 0.1)
            except (OSError, ValueError):
                break
            if r:
                try:
                    chunk = os.read(self.m, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf += chunk
        return strip_ansi(self.buf)

    def wait_for(self, text, seconds=12):
        end = time.time() + seconds
        while time.time() < end:
            if text in self.read(0.3):
                return True
        return False

    def key(self, ch):
        os.write(self.m, ch.encode())

    def screen(self):
        return strip_ansi(self.buf)

    def alive(self):
        return self.p.poll() is None

    def wait_exit(self, seconds=8):
        end = time.time() + seconds
        while time.time() < end and self.p.poll() is None:
            self.read(0.2)
        return self.p.poll() is not None

    def kill(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if self.p.poll() is None:
                try:
                    os.killpg(self.pgid, sig)
                except OSError:
                    pass
                time.sleep(0.5)
        self.p.poll()
        try:
            os.close(self.m)
        except OSError:
            pass

    def left_behind(self):
        left = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/stat" % pid) as f:
                    st = f.read()
                pgrp = int(st[st.rindex(")") + 2:].split()[2])
            except (OSError, ValueError, IndexError):
                continue
            if pgrp == self.pgid and int(pid) != os.getpid():
                left.append(int(pid))
        return left


class FakeProvider:
    """A local HTTP server that answers what it is told: the ugly cases without spending anything.
    script: a list of (status, body bytes, headers dict) answered in order; the last repeats.
    'hang' as a status accepts the connection and never answers (NEVER ANSWERS)."""

    def __init__(self, script, by_path=None):
        import http.server
        import threading
        self.script = list(script)
        self.by_path = dict(by_path or {})        # path -> answer, before the scripted sequence
        self.calls = []
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                n = min(len(fake.calls), len(fake.script) - 1)
                fake.calls.append((self.command, self.path, dict(self.headers)))
                status, body, headers = fake.by_path.get(self.path.split("?")[0], fake.script[n])
                if status == "hang":
                    time.sleep(60)
                    return
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _serve

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.httpd.shutdown()


def fake(prefix, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789", seed=0):
    import random
    r = random.Random(len(prefix) * 7 + n + seed)
    return prefix + "".join(r.choice(alphabet) for _ in range(n))


def real_key(provider):
    """One real key of that provider from the REAL vault, for Test 2 only; None when there is none."""
    real = os.path.join(os.path.expanduser("~"), ".keyring", "keys.json")
    try:
        with open(real, encoding="utf-8") as f:
            for e in json.load(f).get("entries", []):
                if e.get("provider") == provider and e.get("state") not in ("rejected",):
                    return e
    except (OSError, ValueError):
        pass
    return None

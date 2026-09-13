# HANDOVER: KEYRING_TERMUX (13.9.2026)

## What it is

The key repository on Marko's phone: every API key in one vault (`~/.keyring`), found by shape in
his handwritten notes, tested for real (a list call proves a key is real; only the smallest piece
of work proves the account has credit), exported in one format, and read by every other app and by
Claude Code with `keyring get <provider>`. Built 13.9.2026 in one session with SHOP_FINDER v2 (the
settings gear there uses this app's probes) and three new manifest modules.

## Where it runs

    keyring                     ~/KEYRING_TERMUX/app.py through the launcher ~/KEYRING_TERMUX/keyring,
                                on the PATH as $PREFIX/bin/keyring and ~/.local/bin/keyring (wrappers,
                                written by  keyring install)
    http://127.0.0.1:8842       the page (8842-8857, then any: portpick.py). Loopback only, the
                                guard's three checks on every /api call (localguard.py)
    ~/.keyring/keys.json        the vault, 0600 in a 0700 folder; log.jsonl beside it, fingerprints only
    the shape                   MAHA_TRANSCRIBE_TERMUX_TERMINAL: console.py, portpick.py, localguard.py,
                                selfupdate.py copied verbatim and adapted in their first lines

## Decisions of 13.9.2026

- **A repository of its own, public, no key in it** (`KEYRING_TERMUX`; the name `KEYRING` on GitHub
  redirects to PASSWORD_KEYRING, the Android app). The command is `keyring`; the vault is outside
  the repository, always.
- **Keys by reference.** `keyring get <provider>` prints one value and nothing else, exit 1 with a
  sentence on stderr when there is none, so `$(keyring get groq)` is the key or empty. SHOP_FINDER's
  serve.py and update_pools.py ask it after the environment and their own 0600 file.
- **Six states, not four**: `valid` was added to the manifest's five (works, no credit, rejected,
  throttled, unclear) because a retired model or an outage on the work call must not downgrade an
  authenticated key (key-testing.md §6).
- **The keyring v1 format** (ring.py's docstring): `provider:` / `label:` / `key:` / `secret:` lines,
  blank line between entries. Readable, greppable, and the block parser of every other app reads it.
- **Two false verdicts fixed and measured** against Marko's own keys: the Maps key restricted to
  Places (a Geocoding probe says REQUEST_DENIED at HTTP 200) and the Cloudflare account token
  (`/user/tokens/verify` says invalid). Both recorded in key-testing.md §6b and apis/cloudflare.md.
- **The Google probe asks four APIs** and says per API which answered; Places first because
  SHOP_FINDER uses it. Each is a billable call of the smallest size; four calls per test.
- **Hume pairs** are read from the `API key` / `Secret key` labels (Key_Tester's way) and from a
  48 + 64 alnum pair in one block; the pair is one entry, exported together.
- **The vault on the phone, measured**: 91 keys from 15 notes; Hume 21 pairs all working, Speechify
  21 working, Gemini 25 working, AssemblyAI 5 working, Anthropic, Google, GitHub, Cloudflare working;
  **all five Groq keys in the notes are revoked** (401 from Groq itself, confirmed with curl); the
  Groq key SHOP_FINDER's machine uses came from the Mac and is not in the phone's notes.

## What the tests found while being written (and fixed)

- The Hume pair parser produced two `unknown` entries: the labels were not read. Fixed, test 1.
- A 40-hex commit hash was taken as a key. Fixed: pure hex of 40 or 64 is never a key.
- `google_verdict` ordered "not authorized to use this API" before the IP/referrer check, so a
  restricted key read as "not enabled". Reordered.
- The u key's restart landed on the NEXT port: TIME_WAIT read as taken. portpick.is_free now
  connects after a failed bind (ports.md).
- The auto-open at start left a real termux-open-url child behind under the harness. The tests
  put a stand-in on the PATH.
- `/api/log?n=x` answered 500: found by the seeded monkey (G6). Fixed.
- The gate runner itself was wrong twice: its compile check tripped its own ResourceWarning, and
  its soak patched a stale module (imported before the harness re-imported the app). Both fixed
  and recorded in termux-proot-working.md.

## NOT tested

- **The page in a real browser** (390 px, the file picker dialog, the clipboard copy, the export
  download): the four tests drive the API and the console; the page's script is parsed by node and
  its wiring is checked by the G4 sweep. Marko's exploratory half hour is the test: import the Api
  folder from the page, test a Hume pair, export all, paste the export into a second phone.
- **Termux:Boot**, and the page opening on a phone without Termux:API.
- **Providers with no key in the vault**: OpenAI, OpenRouter, ElevenLabs, Hugging Face, Deepgram;
  their probes are exercised against the fake provider only (test 3).
- **Mutation testing** (mutmut does not install on the phone's Python); Hypothesis runs (150 random
  notes) since the ANDROID_API_LEVEL fix.
- **waitress under load**: the soak runs through Flask's test client, not the socket.

## Still to do

- The live port registry for launchers (ports.md §3): `~/.mantra/ports/keyring`.
- OpenAI / OpenRouter / ElevenLabs probes against a real key, the day one is in the vault.
- A Spotify pair from two blocks (the note keeps the id and the secret in separate blocks): the
  parser pairs only inside one block; the two arrive as two entries and are paired by hand.

## 13.9.2026, the afternoon: the live port registry, and Chrome

- **`portpick.announce("keyring", LIVE_PORT)`** right after `pick()`: the port actually bound is written
  to `~/.mantra/ports/keyring` (0600) and removed at exit, so the launcher (mamc) opens the page where
  the app IS, not where its source says it would like to be (ports.md §3). A line left by a kill is
  ignored by the reader unless the port answers. The tests cover announce, forget and registered.
- **The page opens in Chrome**, whatever the default browser: `termux-open-url URL com.android.chrome`
  after a cached `pm list packages` check, bounded by `timeout -k 5 30` (termux-app.md §5). Marko's
  rule of the day for every app on the phone.
- portpick.py and the opener were pulled level with the source in MAHA_TRANSCRIBE_TERMUX_TERMINAL
  (the TIME_WAIT fix and the timeout bound had lived only in copies). Version 2.

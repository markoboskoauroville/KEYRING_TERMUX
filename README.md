# KEYRING_TERMUX, the key repository

**One place on the phone for every API key, tested for real, exported in one format, read by
every app and by Claude Code.** Marko, 13.9.2026: *"a central database of all my API keys, so I
don't need to go to all these text files, and you can also access this database for developing
applications locally in this Termux environment."*

    keyring                      the server on 127.0.0.1:8842 and the page; q quits it
    keyring get groq             one value on stdout, for a script:  $(keyring get groq)
    keyring secret hume          the secret half of a two-part credential
    keyring list [provider]      every key, masked, with its state; never a value
    keyring import <file|dir>    keys by shape from notes, or a keyring v1 file
    keyring export out.txt [p]   the keyring v1 format, every key or one provider's
    keyring test <provider|all>  the probes, one line per key
    keyring update               pull the newest version and exit (the u key does it live)

Install, once: `curl -fsSL https://raw.githubusercontent.com/markoboskoauroville/KEYRING_TERMUX/main/install-termux.sh | bash`,
then `keyring import ~/storage/downloads/Api` brings every note in.

## What the page does

1. **Bring keys in**: a file picker (the rule), a folder on the phone, or a pasted note. Keys are
   found by **shape** inside notes (account names, URLs, dates and CANCELLED lines are left alone),
   de-duplicated on the value, and a Hume account arrives as one entry with its secret.
2. **The keys**: one row per key with its provider's glyph, its label, the masked value (six and
   four, never the middle), its state and the date the state was learned. Filter by provider and
   state; select any number; **test**, **copy** (to the clipboard, the one moment a value leaves
   the vault), **export**, **edit** (label, provider), **revive**, **delete**.
3. **The standard file, keyring v1**: what export writes and import reads first.
4. **What happened**: the log, fingerprints and counts only.

## The six states, and what testing means

A list call proves a key is real; only the smallest piece of work proves the account can do
anything (`modules/key-testing.md`). Every provider that sells something is asked for one token,
one word of speech, or one second of audio; the answer is one of:

| state | meaning | do |
|---|---|---|
| **works** | valid and has credit | use it |
| **valid** | authenticated; the work call gave no real answer (a retired model, an outage) | use it |
| **no credit** | valid, the account is empty | top up, or delete on purpose |
| **rejected** | 401 / 402 / 403 | delete, or revive after fixing it at the provider |
| **throttled** | 429 with a wait | wait; never delete |
| **unclear** | no network, Cloudflare 1010, our request: says nothing about the key | try again |

Two false verdicts that other testers give, fixed here and measured 13.9.2026:

- **A Google Maps key restricted to the Places API**: a Geocoding-only tester says dead. The
  google probe asks Places (New), Map Tiles, Geocoding and Gemini, reads the body (Google answers
  HTTP 200 while denying) and reports per API: `works for Places: Places ✓ · Tiles not enabled ·
  Geocoding ✗ · Gemini not enabled`.
- **A Cloudflare account-owned token** (`cfat_…`): `/user/tokens/verify` says *Invalid API Token*
  while wrangler deploys with it every day. The probe then lists `/accounts` and verifies at that
  account's own `/tokens/verify`: *account token active*.

## The vault

`~/.keyring/` (0700): `keys.json` (0600) and `log.jsonl` (0600). Outside every repository. The
store is written beside itself and renamed over, never truncated. A damaged store is moved aside,
never read as empty. `KEYRING_HOME` moves the vault (the tests use throwaway ones).

## The files

    app.py            Flask, 127.0.0.1 only, the guard's three checks on every /api call
    keyring.html      the page, AGY tokens, nothing appears or disappears
    ring.py           the store, the parser, the keyring v1 format
    probes.py         the validity and work probes per provider, the classifier, the money detector
    cli.py            the command's words (get, list, import, export, test, secret, where)
    keyring           the launcher (run, update, install) and the platform
    console.py, localguard.py, portpick.py, selfupdate.py   copied from MAHA_TRANSCRIBE_TERMUX_TERMINAL
    version.py        APP_VERSION, one whole number
    tests/            the four tests (python3 tests/run_all.py)
    gates/            the nine gates (python3 gates/run_gates.py), BUDGETS.json, the last record
    HANDOVER.md       where it runs, what was decided, what is not tested
    DELIVERY_RECORD.md  the record of the last delivery, gate by gate

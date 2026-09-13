# DELIVERY RECORD, KEYRING_TERMUX

The nine gates (modules/delivery-gate.md), run on the phone with `python3 gates/run_gates.py`.
The last run's counts are in `gates/LAST_RUN.txt` (ignored by git) and pasted below at each
delivery. **The NOT TESTED block is written by hand and is the most valuable part.**

## v1, 13.9.2026

The final run, on commit 5279405 (v1), all nine green:

NOT TESTED   the page in a real browser at 390 px; the clipboard copy and the export download in a
             browser; Termux:Boot; OpenAI, OpenRouter, ElevenLabs, Hugging Face, Deepgram against
             a real key (none in the vault); mutation testing (mutmut has no build for this phone);
             waitress under load (the soak uses Flask's test client)

ACCEPTED     G1's "built by CI" is not met: there is no CI on this repository; the artefact is the
             repository at a commit, built on nothing. The middle band of delivery-gate.md §12.

KNOWN        a Spotify id + secret written in two separate blocks of a note arrive as two entries

```
DELIVERY RECORD - KEYRING_TERMUX v1 - 2026-09-13 10:27

ARTEFACT     the repository at 5279405 (main), 12 source files, 116131 bytes
VERSION      new: 1   previous: see git log

GATES
             G1 provenance   pass   clean=True version 1>0 branch=main pushed=True
             G2 secrets      pass   tree 25/0 hits, history 0 hits, log 0 hits
             G3 analysis     pass   ruff 0, F 0, bandit 0, shellcheck 0, audit 0
             G4 dead code    pass   unwired 0, unhandled 0, states without colour 0, providers without glyph 0
             G5 dead loops   pass   32 loops, 5 waits, 0 without a visible deadline
             G6 stress       pass   soak 600 cycles rss 41812->47912 kB, 63->87 ms; monkey 0 crashes
             G7 budgets      pass   worse: 0
             G8 upgrade      pass   test4_upgrade: 12 checks, 0 failed
             G9 record       this document

NOT TESTED   see the NOT TESTED block kept by hand in DELIVERY_RECORD.md (the page in a real browser at 390 px,
             Termux:Boot, waitress under load, the providers with no key in the vault, mutation testing)

```

The four tests on the same commit: test1 57 checks (Hypothesis on), test2 41, test3 50, test4 12; all green.

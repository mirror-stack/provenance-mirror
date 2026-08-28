# Changelog

All notable changes to Provenance Mirror are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.3.0] — 2026-08-28

### Fixed
- **`_get_last_seal` no longer parses the whole ledger on every append.** It read the file
  forward from the start to find the last line, making each append O(n): measured
  2026-08-26 on a 4.6 MB / 5,676-entry ledger, **55.24 ms** per lookup against **0.079 ms**
  reading from the end — and the old cost grew with every entry ever written, so the ledger
  got slower precisely because it was being used. Ported from action-mirror. Answers are
  unchanged on all 94 ledgers checked, including CRLF/CR/LF endings, unsealed or
  unparseable trailing lines, and a ledger with no sealed entry at all. The empty-ledger
  answer stays `GENESIS` — it is hashed into the head of every existing chain.
- **An append no longer dies partway on a line that is not a JSON object.** The previous
  reader called `.get()` on whatever the line parsed to, so a bare number — which real
  ledgers contain — raised `AttributeError` *from inside the append*, after the caller
  believed the record was being written. Such lines are now skipped like any other
  unsealed line.
- **A line whose `seal` is `null` is no longer handed out as the chain head.** A census of
  92 ledgers found zero such lines, so nothing in flight depended on the old answer — but
  the old reader could write a `null` `prev_seal` into a live chain.

### Added
- **CI** (`#4`) — 3.10–3.12 test matrix plus a package job that installs only the built
  wheel and import-smokes it. Until then this mirror shipped on every push with no
  automated verification.
- **`synthesize` is documented** (`#5`) — the verdict priority *is* the honesty policy, so
  it belongs in the docs rather than only in the code.

### Note on this entry
`#4` and `#5` landed before `#6` and were never written up here; they are recorded now
from their commits rather than left out, because a changelog that skips what shipped is
the same defect this project exists to name.

---

## [0.2.0] — 2026-07-21

### Security
- **Ledger seal width: 16-hex (64-bit) truncation → full 64-hex SHA-256** —
  closes the dishonest-sealer birthday-collision gap (~2^32): a sealer could
  search two entries sharing one truncated seal and swap them after sealing.
  New entries seal with the full digest; legacy 16-hex seals keep verifying
  via prefix match (`_seal_matches`). No ledger migration needed. Stack-
  consistency follow-up to the same fix in measure-mirror (0.27.0) and
  action-mirror (0.2.0). (`tracing.py` watermark hashes are a clean/marked
  comparison, not an adversarial commitment — left as-is by design.)

## [0.1.0] — 2026-06-12

First proof-of-concept. The **frame** is real and tested; the heavy crypto/ML
signals are explicitly marked as stubs (see README "Honest limitations").

### Added — content authenticity verifier (`provmirror.pm`)
- **5 signal probes** (each returns a `Signal` pointing AUTHENTIC / SYNTHETIC /
  TAMPERED / NONE):
  - ① `c2pa_manifest_check` — C2PA / Content Credentials manifest present?
    (AI-origin assertion inside flips it to SYNTHETIC)
  - ② `generator_meta_check` — known AI-generator fingerprint in metadata
  - ③ `ai_watermark_check` — declared AI watermark / training assertion
  - ④ `tamper_anchor_check` — same bytes previously sealed under a different
    origin (re-attribution / laundering signal)
  - ⑤ `format_integrity_check` — container structure intact? double-compression hint
- **`verify(file_path, *, ledger_path, origin, seal)`** — single entry point:
  runs all probes, synthesizes a verdict, seals it into a chain-hashed ledger.
- **Verdict synthesis** (honesty-first): `TAMPERED` > `SYNTHETIC` >
  `CONFLICTING` > `AUTHENTIC-SIGNED` > `UNVERIFIED`. The default `UNVERIFIED`
  means "unknown", never "fake" — refusing to brand the innocent is the value.
- **`badge(result, *, fmt)`** — verdict-colored markdown / SVG badge.

### Added — leak tracing (`provmirror.tracing`)
- **`fingerprint_text(text, recipient)`** / **`read_fingerprint(text)`** —
  invisible per-recipient zero-width-character mark (U+200B/U+200C, U+200D
  framing). Visually identical, survives copy/paste, decodes to the recipient id.
- **`distribute(text, *, recipient, doc_id, ledger_path)`** — fingerprint a copy
  and seal the distribution record.
- **`trace(leaked_text, *, ledger_path)`** — attribute a surfaced copy:
  `CONFIRMED` / `FINGERPRINT-ONLY` / `HASH-MATCH` / `DOC-KNOWN` / `UNTRACEABLE`.

### Added — tooling
- **CLI `pm`** (`pip install -e .`): `verify`, `distribute`, `trace`.
  Ledger default from `$PM_LEDGER`.
- Chain-hashed ledger ported from measure-mirror (`_seal`, `verify_chain` semantics).
- 33 tests (22 verifier + 11 tracing), all passing. Zero dependencies.

### Design
- **Verifier, not detector** — never claims "fake" from pixels; checks
  deterministic provenance/integrity signals only. Avoids the detector arms race.
- Same DNA as measure-mirror: zero-training, deterministic, sealed ledger,
  two-sided, honest about uncertainty.

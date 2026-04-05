`wilderness` is a terminal-native perimeter for hostile artifact intake.

> “The art of surviving interactions with text, and other artifacts, from the outside world.”

That line is the project contract. This is not generic security theater. It is survival at the boundary where outside artifacts meet inside systems.

## Trust States

- `quarantine`: raw outside material, not trusted, not for downstream use
- `shelter`: unpacked and normalized in a controlled workspace, still untrusted
- `safe_camp`: inspected and explicitly promoted for constrained downstream use
- `discard`: blocked as unsafe, malformed, deceptive, or operationally useless

## v1 Scope

The first build is structural-first:

- safe intake into quarantine
- safe unpacking into shelter
- policy checks for size, count, depth, names, and file types
- provenance capture and append-only inspection history
- advisory suspicious-text heuristics for prompt-poison and exfiltration-shaped text
- machine-readable inspection artifacts
- explicit promotion to safe camp
- terminal-native downstream verification with `wilderness verify`

Broad prompt-poison heuristics are still out of scope. This pass adds a narrow advisory heuristic layer, not broad prompt-policing or semantic classification.

## CLI Workflow

```bash
wilderness inspect bundle.zip
wilderness inspect bundle.zip --out shelter-copy/
wilderness report .wilderness/reports/<inspection-id>.json
wilderness promote .wilderness/reports/<inspection-id>.json
wilderness verify .wilderness/reports/<inspection-id>.json
wilderness source .wilderness/reports/<inspection-id>.json
wilderness suspicious-text-check suspicious.txt
wilderness manifest-check bundle.zip
```

Each inspection writes:

- a human-readable terminal summary
- a JSON inspection artifact with status, findings, provenance, policy, and promotion eligibility
- an append-only JSONL history ledger at `.wilderness/history/<inspection-id>.jsonl`

When policy enables forensic retention for blocked artifacts, `inspect` also copies the raw quarantined input into `.wilderness/discard/<inspection-id>/raw/` and records that path in the inspection artifact.

Inspection artifacts now also carry a top-level `suspicious_text` section with normalization metadata, built-in rule counts, loaded pack provenance, and any local suspicious-text promotion-gating policy.

Inspection artifacts also carry a top-level `manifest` section with manifest presence, discovered paths, schema validation status, normalized claims, and any manifest-free fallback decision used for promotion gating.

Inspection artifacts now also carry a top-level `redaction` section with whether redaction was enabled, required, applied, and materialized as a parallel derivative.

The inspection artifact is immutable after `inspect`. Live trust state is derived from the history ledger, not by rewriting the original report.

Promotion is never implicit. `inspect` can leave a bundle in `shelter` or `discard`, but only `promote` can move material into `safe_camp`.

When redaction is enabled and actually changes content, `inspect` now materializes a full derivative under `.wilderness/redacted/<inspection-id>/` while leaving the original shelter output untouched. `promote` uses that derivative only when policy requires redaction.

By default, promotion requires a supported manifest. A local policy may allow a narrow manifest-free fallback for a single text or JSON file that otherwise passes structural checks. Directories and archives remain outside that fallback scope.

Supported manifests now use an explicit v1 schema. Required fields are:

- `schema_version = 1`
- `source_name`
- `raw_sha256`

Optional fields are:

- `raw_size_bytes`
- `source_kind`

Only one supported manifest may appear in an inspected artifact. Parse failures, missing required fields, invalid hash format, unknown schema versions, or multiple supported manifests block promotion.

For embedded manifests, `raw_sha256` is checked against the bundle payload the manifest describes, excluding the manifest file itself so the digest is not self-referential.

`wilderness verify` is the downstream gate. It exits `0` only when a report is still promotable or already promoted. `--require-promoted` insists on a live `safe_camp` copy.

`wilderness source` resolves the exact downstream-ready tree the system would use. By default it prefers a live promoted `safe_camp` copy when one exists, otherwise it falls back to the effective report-derived source: required redacted derivative first, normalized shelter output otherwise. `--mode` can force `promoted`, `redacted`, or `shelter`, `--json` makes the result machine-readable, and `--out` copies the resolved tree to a chosen destination.

Suspicious-text findings are advisory by default. A local policy may also turn all suspicious-text findings, or selected suspicious-text `rule_id` values, into promotion blockers without changing the detector itself.

Suspicious-text scanning now supports adjacent-line windows, normalization for evasive text forms, and additive local TOML rule packs. Built-in rules remain on by default, and pack rules layer on top of them.

Supported v1 manifest file names are fixed to:

- `manifest.json`
- `manifest.toml`
- `provenance.json`

The human report output is an operator contract and is snapshot-tested. Escape handling and severity summaries should stay stable unless the contract is changed deliberately.

Supported suspicious-text policy controls are:

- `suspicious_text_enabled`
- `suspicious_text_max_bytes`
- `suspicious_text_max_findings_per_file`
- `suspicious_text_snippet_chars`
- `suspicious_text_window_lines`
- `suspicious_text_rule_packs`
- `suspicious_text_block_all`
- `suspicious_text_block_rule_ids`

Manifest promotion policy controls are:

- `manifest_required_for_promotion`
- `manifest_free_fallback_enabled`
- `manifest_free_fallback_scope`

`wilderness suspicious-text-check` explains active rules for a single text file, reports normalized-only matches, and surfaces exclude-pattern suppressions for pack debugging.

Rule packs are local TOML files referenced from policy. Relative pack paths resolve from the policy file directory.

```toml
schema_version = 1

[[rules]]
id = "audit_log_leak"
pattern = "leak the audit log"
description = "custom advisory phrase"
exclude_pattern = "example|never"
window_lines = 1
```

Discard-retention policy controls are:

- `discard_retention_enabled`
- `discard_copy_mode`

## Exit Codes

- `wilderness inspect`: `0` promotable, `10` completed but review-needed, `20` discard or blocked
- `wilderness promote`: `0` promoted, `20` blocked or stale
- `wilderness verify`: `0` promotable or promoted, `20` blocked, stale, or not yet promoted when `--require-promoted` is set
- `wilderness source`: `0` resolved and optionally exported, `20` missing, stale, or unavailable requested source
- `wilderness suspicious-text-check`: `0` successful check or rule listing, `20` invalid input, non-text input, or invalid policy/rule pack
- `wilderness manifest-check`: `0` valid supported manifests, `20` invalid or missing supported manifests
- `wilderness report`: `0` on successful render

## Layout

```text
.wilderness/
  quarantine/
  shelter/
  redacted/
  reports/
  history/
  discard/
  safe-camp/
src/wilderness/
tests/
data/
  benign/
  hostile/
```

## Development

Requires Python 3.11+.

```bash
python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m wilderness.cli inspect data/benign/sample.json
```

The repository-level operating rules live in [AGENTS.md](AGENTS.md). Keep it aligned with [SPEC.md](SPEC.md), [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), and this file whenever the contract changes.

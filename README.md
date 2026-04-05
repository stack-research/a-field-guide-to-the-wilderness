# wilderness

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
wilderness manifest-check bundle.zip
```

Each inspection writes:

- a human-readable terminal summary
- a JSON inspection artifact with status, findings, provenance, policy, and promotion eligibility
- an append-only JSONL history ledger at `.wilderness/history/<inspection-id>.jsonl`

The inspection artifact is immutable after `inspect`. Live trust state is derived from the history ledger, not by rewriting the original report.

Promotion is never implicit. `inspect` can leave a bundle in `shelter` or `discard`, but only `promote` can move material into `safe_camp`.

`wilderness verify` is the downstream gate. It exits `0` only when a report is still promotable or already promoted. `--require-promoted` insists on a live `safe_camp` copy.

Suspicious-text findings are advisory in v1. They appear in the inspection artifact and human report, but they do not block promotion by default.

Suspicious-text scanning now supports adjacent-line windows and additive local TOML rule packs. Built-in rules remain on by default, and pack rules layer on top of them.

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

## Exit Codes

- `wilderness inspect`: `0` promotable, `10` completed but review-needed, `20` discard or blocked
- `wilderness promote`: `0` promoted, `20` blocked or stale
- `wilderness verify`: `0` promotable or promoted, `20` blocked, stale, or not yet promoted when `--require-promoted` is set
- `wilderness manifest-check`: `0` valid supported manifests, `20` invalid or missing supported manifests
- `wilderness report`: `0` on successful render

## Layout

```text
.wilderness/
  quarantine/
  shelter/
  reports/
  history/
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

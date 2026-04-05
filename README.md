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
- provenance capture and inspection history
- advisory suspicious-text heuristics for prompt-poison and exfiltration-shaped text
- machine-readable inspection artifacts
- explicit promotion to safe camp

Broad prompt-poison heuristics are still out of scope. This pass adds a narrow advisory heuristic layer, not broad prompt-policing or semantic classification.

## CLI Workflow

```bash
wilderness inspect bundle.zip
wilderness inspect bundle.zip --out shelter-copy/
wilderness report .wilderness/reports/<inspection-id>.json
wilderness promote .wilderness/reports/<inspection-id>.json
wilderness manifest-check bundle.zip
```

Each inspection writes:

- a human-readable terminal summary
- a JSON inspection artifact with status, findings, provenance, policy, and promotion eligibility

Promotion is never implicit. `inspect` can leave a bundle in `shelter` or `discard`, but only `promote` can move material into `safe_camp`.

Suspicious-text findings are advisory in v1. They appear in the inspection artifact and human report, but they do not block promotion by default.

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

## Exit Codes

- `wilderness inspect`: `0` promotable, `10` completed but review-needed, `20` discard or blocked
- `wilderness promote`: `0` promoted, `20` blocked or stale
- `wilderness manifest-check`: `0` valid supported manifests, `20` invalid or missing supported manifests
- `wilderness report`: `0` on successful render

## Layout

```text
.wilderness/
  quarantine/
  shelter/
  reports/
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

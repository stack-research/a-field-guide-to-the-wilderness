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
- machine-readable inspection artifacts
- explicit promotion to safe camp

Broad prompt-poison heuristics are out of scope for this pass. The perimeter comes first.

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
python3 -m wilderness.cli inspect data/benign/sample.json
```

The repository-level operating rules live in [AGENTS.md](/Users/macos-user/.projects/stack-research/a-field-guide-to-the-wilderness/AGENTS.md). Keep it aligned with [SPEC.md](/Users/macos-user/.projects/stack-research/a-field-guide-to-the-wilderness/SPEC.md), [IMPLEMENTATION_PLAN.md](/Users/macos-user/.projects/stack-research/a-field-guide-to-the-wilderness/IMPLEMENTATION_PLAN.md), and this file whenever the contract changes.

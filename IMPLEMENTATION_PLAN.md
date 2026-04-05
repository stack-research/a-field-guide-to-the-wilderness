# Implementation Plan

This checklist feeds the first implementation sprints for `wilderness`.

## Docs And Operating Contract

- [x] Draft [AGENTS.md](AGENTS.md)
- [x] Draft [README.md](README.md)
- [x] Lock `wilderness` as the working CLI name
- [x] Add a maintenance rule to keep docs aligned with CLI, policy, and report changes

## Core CLI Skeleton

- [x] Create `pyproject.toml` with a `wilderness` console entry point
- [x] Scaffold `src/wilderness/`
- [x] Add `inspect`, `report`, `promote`, `verify`, and `manifest-check` commands
- [x] Create a local state root at `.wilderness/`

## Intake, Shelter, And Inspection

- [x] Land raw material in quarantine before inspection
- [x] Support files, directories, `.zip`, `.tar`, `.tar.gz`, and `.tgz`
- [x] Probe archive types by content, not extension alone
- [x] Normalize unpacked paths into shelter
- [x] Block traversal, absolute paths, symlink escapes, and duplicate normalized names
- [x] Enforce raw-size, expanded-size, file-count, nested-archive-depth, and line-length limits
- [x] Surface control characters in filenames and content as findings
- [x] Detect likely binary payloads in nominally textual bundles
- [x] Emit machine-readable inspection artifacts with stable top-level fields

## Policy, Provenance, And Promotion

- [x] Load local policy from `policy.toml` with stdlib `tomllib`
- [x] Include the effective policy in each inspection artifact
- [x] Capture raw, normalized, and optional redacted hashes
- [x] Record manifest presence and simple manifest mismatches
- [x] Make promotion a separate command
- [x] Re-check eligibility and shelter integrity before copying into safe camp

## Tests And Corpus

- [x] Add `tests/`
- [x] Add `data/benign/`
- [x] Add `data/hostile/`
- [x] Cover traversal blocking, control-sequence handling, promotion gating, and benign promotion
- [x] Expand the hostile corpus with more forged provenance, decompression edge cases, and duplicate-name collisions
- [x] Add XML-specific malformed fixture coverage
- [x] Add redaction-focused fixture coverage beyond inline synthetic test data

## Next Sprints

- [x] Tighten suspicious-text heuristics after the structural boundary is stable
- [x] Add richer manifest policy and provenance schema validation
- [x] Add shell-friendly exit codes for blocked and promotable states
- [x] Add snapshot tests for the human report output

## Trust Ledger And Downstream Gate

- [x] Add a per-inspection append-only history ledger under `.wilderness/history/`
- [x] Record `received`, `inspected`, `promotion_blocked`, and `promoted` events
- [x] Keep inspection artifacts immutable after `inspect`
- [x] Derive current safe-camp state from history instead of rewriting the report
- [x] Add `verify` as the downstream CLI gate for promotable and promoted artifacts

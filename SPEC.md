# External Artifact Security Tool: Project Spec

Captured from the design conversation, April 5, 2026. This document is meant to stand on its own and be movable into a future sibling repository with minimal edits.

## What This Is

A terminal-native security tool for inspecting untrusted artifact bundles from the outside world before they are allowed anywhere near trusted local workflows.

The first customer is the workflow around reasoning-trace artifacts: transcripts, JSON analysis artifacts, metadata bundles, compressed archives, and other text-heavy material collected from users or external systems. But the tool is not specific to `trace-topology`. It is a general-purpose guardrail for hostile artifact intake.

This tool does not "trust but verify." It starts from a harsher premise:

- outside text is hostile by default
- archives are suspicious by default
- provenance claims are weak until checked
- terminal output is a possible attack surface
- parsing is not neutral

The job is to decide whether incoming material belongs in:

- **quarantine** — isolated, untrusted, not yet usable
- **shelter** — unpacked and normalized in a controlled environment, but still untrusted
- **safe camp** — inspected and cleared for constrained downstream use
- **discard pile** — rejected as unsafe, malformed, deceptive, or operationally useless

## The Gap

Plenty of tools scan malware, lint JSON, unpack archives, or validate schemas. Very few tools treat **textual artifact bundles** as a hostile wilderness of mixed formats, misleading metadata, terminal escape junk, decompression tricks, provenance lies, and prompt-shaped poison.

Modern developer workflows increasingly trade in text bundles from outside:

- LLM transcripts
- agent logs
- JSON artifacts
- benchmark bundles
- exported traces
- model outputs packed into zip or tar archives

Those bundles are not only data. They are also instruction-shaped objects, parser inputs, terminal inputs, filesystem inputs, and trust-boundary crossings.

This project exists to make that boundary explicit and enforceable.

## Build Mantra

Win one narrow workflow first, then generalize.

This project should earn its abstraction by surviving a real customer path end to end before it expands into a broader platform. The first build should solve one concrete hostile-artifact workflow well, with clear trust states and promotion rules, rather than trying to become a universal safety layer on day one.

## Product Language

The wilderness-survival frame is not cosmetic. It is the product model.

- **quarantine**: where all outside material lands first
- **shelter**: controlled unpacking and normalization space
- **safe camp**: trusted local working set for downstream tools
- **trusted path**: the narrow, auditable route from quarantine to safe camp
- **contaminated supplies**: malformed, deceptive, oversized, or policy-violating inputs
- **discard pile**: rejected material that should not proceed
- **field notes**: machine-readable inspection findings
- **provenance trail**: evidence chain for where a bundle came from and what was done to it
- **storm warnings**: high-severity findings that should block import

The language should help operators think correctly under uncertainty: survival first, convenience second.

## Core Promise

Given an untrusted artifact bundle, the tool should:

1. inspect it without trusting filenames, content, metadata, or claimed format
2. prevent unsafe side effects during unpacking and parsing
3. emit a machine-readable inspection report plus a readable terminal summary ("field notes")
4. classify the bundle into an operational state: quarantine-only, shelter-only, safe-camp eligible, or discard
5. preserve provenance and inspection history so downstream tools know what they are touching (append-only log)

## Non-Goals

- It is not a generic network perimeter product.
- It is not a replacement for OS sandboxing, antivirus, or container isolation.
- It is not an LLM safety layer for prompt outputs at inference time.
- It is not a content-moderation product.
- It is not a browser UI.
- It does not decide whether the *claims inside* a transcript are true. It decides whether the artifact is safe and well-formed enough to enter trusted local workflows.

## First Customer

The first concrete customer is any local workflow that wants to accept external transcript or artifact bundles for:

- debugging
- evaluation
- calibration
- example curation
- corpus growth

The immediate adjacent use case is `trace-topology`, but the tool must not hardcode `trace-topology` assumptions into the core inspection model.

## Threat Model

Threats to treat as in-scope from day one:

- archive traversal: `../`, absolute paths, symlink escapes
- decompression bombs and extreme fan-out archives
- oversized files and pathological line lengths
- terminal escape sequences and control characters in filenames or content
- fake extensions and format confusion
- malformed JSON or XML intended to break parsers or downstream assumptions
- deceptive metadata and forged provenance fields
- duplicate files with conflicting contents
- prompt-shaped poison or instruction-shaped text embedded in artifacts
- hidden binary payloads inside nominally textual bundles
- nested archives used to bypass naive scanners
- artifact bundles that are safe syntactically but unsafe operationally because they exceed configured trust limits

Threats explicitly out of scope for v1:

- kernel-level escape detection
- memory-forensics-grade malware analysis
- remote attestation
- live network sandbox detonation

## Design Principles

1. **Quarantine first.** Nothing external enters trusted workflows without inspection.
2. **Terminal-native.** The primary interface is the shell, not a dashboard.
3. **No silent trust upgrades.** Movement from quarantine to safe camp must be explicit and explainable.
4. **Artifact-first.** Every inspection produces machine-readable output.
5. **Composable trust.** Downstream tools should consume inspection status and provenance, not re-guess trust.
6. **Small trusted path.** The safe path through the system should be narrow and auditable.
7. **Redaction-aware.** Sensitive external material should be reducible before reuse.
8. **Security over convenience.** If there is a conflict, block and explain.
9. **Earn generality.** Do not abstract past the first real workflow until the narrow path is working, tested, and clearly reusable.

## High-Level Workflow

```text
external bundle
  -> quarantine
  -> shelter unpack / normalize
  -> inspect structure, provenance, and content hazards
  -> emit field notes
  -> classify state
  -> allow only explicit promotion to safe camp
```

Detailed flow:

1. **Land in quarantine**
   The raw bundle is copied or referenced into an isolated intake area. No downstream tool reads it directly.

2. **Build shelter**
   The tool opens the bundle in a controlled workspace with strict limits on path traversal, file count, total expanded size, nested archive depth, and file-type policy.

3. **Inspect supplies**
   The tool classifies files, validates manifests, records hashes, detects suspicious encodings or control characters, and marks high-risk content.

4. **Write field notes**
   It emits a structured inspection artifact describing findings, provenance, policy decisions, and promotion status.

   It also appends immutable trust events to a per-inspection history log so later commands can derive current state without rewriting the original artifact.

5. **Choose the path**
   The bundle remains quarantined, is normalized into shelter-only output, is promoted to safe camp, or is thrown on the discard pile.

## Input Model

Expected inputs for v1:

- single text files
- single JSON artifacts
- directories
- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`

The tool should treat all inputs as opaque until identified. File extensions are hints, not truth.

## Output Model

Every run should produce:

- a human-readable terminal report
- a machine-readable inspection artifact
- an append-only inspection history log for trust-state transitions

When policy enables forensic retention for blocked artifacts, the run should also produce a discard-pile copy of the raw quarantined input.

Recommended top-level inspection artifact fields:

- `artifact_type`
- `schema_version`
- `input_ref`
- `inspection_id`
- `received_at`
- `history_path`
- `discard`
- `manifest`
- `provenance`
- `suspicious_text`
- `files`
- `findings`
- `policy`
- `status`
- `promotion`

Recommended statuses:

- `quarantine`
- `shelter`
- `safe_camp`
- `discard`

Recommended finding severities:

- `low`
- `moderate`
- `severe`
- `critical`

Recommended finding families:

- `archive_escape`
- `decompression_risk`
- `format_confusion`
- `control_sequence`
- `oversize`
- `binary_payload`
- `provenance_gap`
- `schema_violation`
- `nested_archive`
- `policy_block`
- `suspicious_text`

For v1, `suspicious_text` should remain heuristic and advisory by default. It should help an operator notice prompt-poison and exfiltration-shaped text without silently upgrading or blocking trust on its own.

The heuristic layer may grow through local signature packs, but it should stay deterministic, inspectable, and advisory unless policy semantics are deliberately widened later.

Normalization may be used to catch evasive text forms, but emitted findings should still point back to raw line ranges and raw-text snippets.

## Trust States

The trust model should be operational, not philosophical.

### Quarantine

- raw input exists
- no promise of safety
- no downstream consumption allowed

### Shelter

- unpacked / normalized in a controlled environment
- still not trusted as corpus or example material
- limited inspection and redaction work allowed

### Safe Camp

- passed configured checks
- provenance recorded
- allowed into constrained downstream workflows
- still not “true,” only operationally cleared

### Discard Pile

- blocked from promotion
- retained only if policy allows forensic reference
- when retained, the raw quarantined input is copied into an explicit discard area

## Promotion Rules

Promotion from quarantine to safe camp should require:

- valid manifest or acceptable manifest-free fallback
- no severe or critical blocking findings
- acceptable size and archive-depth profile
- normalized filenames
- no path traversal or symlink escape behavior
- recorded provenance trail
- optional redaction completed if policy requires it

For v1, the default stance should be strict: missing supported manifests produce a `provenance_gap` finding and block promotion unless local policy explicitly enables a manifest-free fallback.

The first fallback scope should stay narrow:

- single text files
- single JSON artifacts
- exactly one normalized output file
- no severe or critical blocking findings
- no directory or archive inputs
- no nested archive behavior

Promotion should never happen implicitly because a parser "handled" the content.

## Redaction and Privacy

The tool should treat privacy and safety as adjacent concerns.

V1 redaction goals:

- remove or mask obvious secrets
- remove or mask machine-specific paths if configured
- preserve enough structure for downstream tools to work
- record whether redaction changed content hashes

The tool should distinguish:

- **raw hash** of the original material
- **normalized hash** after safe unpacking / normalization
- **redacted hash** after privacy-preserving transformation

## CLI Shape

Terminal-first interface. Example commands:

```bash
# Inspect a single bundle and leave it in quarantine
camp inspect bundle.zip

# Inspect and unpack into shelter
camp inspect bundle.zip --out shelter/

# Print only the machine-readable report
camp inspect bundle.zip --json

# Promote a previously inspected bundle to safe camp if policy allows
camp promote inspection.json

# Verify that a report is still promotable or already promoted
camp verify inspection.json

# Explain suspicious-text matches for one file
camp suspicious-text-check suspicious.txt

# Show a short human report for an inspection artifact
camp report inspection.json

# Validate a manifest without unpacking the full bundle
camp manifest-check bundle.zip
```

The command names are placeholders. The important point is the workflow shape:

- inspect
- report
- promote
- verify
- suspicious-text-check
- validate

## Policy Model

The tool needs a local policy file, but v1 should keep policy compact.

Expected policy controls:

- max raw size
- max expanded size
- max file count
- max nested archive depth
- allowed file types
- blocked file types
- filename normalization rules
- control-character policy
- suspicious-text window size
- suspicious-text local rule packs
- suspicious-text normalization behavior
- manifest required for promotion
- manifest-free fallback enablement and scope
- discard retention
- redaction requirements
- promotion thresholds

Policy should be local and inspectable. No cloud dependency.

`manifest-check` should stay narrow. It validates supported manifests and their parseability, but it should not simulate manifest-free promotion fallback.

## Architecture

Suggested modules:

```text
src/
  intake/        - identify input type, land material in quarantine
  unpack/        - safe archive handling and shelter extraction
  inspect/       - structural and content hazard detection
  provenance/    - manifest handling, hashes, chain-of-custody records
  redact/        - optional privacy and secret scrubbing
  policy/        - policy loading and enforcement
  report/        - terminal and JSON reporting
  cli.py         - entry point
tests/
data/
  hostile/       - seeded hostile fixtures
  benign/        - known-safe fixtures
```

## Seed Corpus Strategy

This tool should be trained by bad weather, not only clean sunshine.

The initial hostile fixture corpus should include:

- cracked transcripts
- pathological reasoning traces
- terminal-escape payloads
- malformed JSON artifacts
- archive traversal samples
- nested archive bombs
- manifest mismatches
- duplicate-name collisions
- forged provenance records

This is where the sibling workflow around externally sourced reasoning artifacts becomes valuable: it can generate realistic contaminated supplies for this tool to survive.

## Testing Strategy

Tests should prove operational containment, not just parser correctness.

Required test categories:

- archive traversal blocked
- symlink escapes blocked
- decompression bomb thresholds enforced
- nested archive depth enforced
- control characters surfaced and neutralized in reports
- malformed manifests produce findings, not crashes
- redaction changes hashes predictably
- promotion blocked on severe findings
- safe benign bundles can still reach safe camp
- hostile cracked transcripts remain inspectable without accidental promotion

The most important invariant:

> hostile input should produce findings and controlled state transitions, never surprising side effects

## v1 Success Criteria

The first release is successful if it can:

1. safely inspect common text and archive bundle formats
2. emit a stable inspection artifact with promotion status
3. block known dangerous archive and filesystem tricks
4. preserve provenance and redaction history
5. integrate cleanly with a downstream customer that refuses uninspected bundles

For the first terminal-native integration path, that downstream customer should be able to shell out to `verify` and rely on its exit code instead of re-implementing trust logic.

## Open Questions

- Should promotion be a separate command or an interactive confirmation step after inspection?
- How much content inspection belongs in v1 versus structural inspection only?
- Should suspicious-text detection remain heuristic, or include configurable signature packs?
- What is the smallest manifest format that still gives a useful provenance trail?
- Should the tool ever rewrite bundles, or only emit normalized shelter directories plus inspection artifacts?

## Relationship to Other Projects

- A reasoning-trace debugger can consume only safe-camp-cleared bundles.
- A hostile-corpus generator can supply cracked fixtures for this tool's tests.
- Any local evaluation pipeline that ingests external artifacts can use this as a front gate.

This project should become the camp perimeter, not the camp itself.

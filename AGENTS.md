# AGENTS.md

This repository builds `wilderness`, a terminal-native intake perimeter for hostile artifact bundles.

## Project Rules

- Use `wilderness` as the working CLI, package, and documentation name until there is an explicit rename.
- Keep [SPEC.md](SPEC.md), [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), and [README.md](README.md) in sync whenever commands, trust states, report fields, or policy semantics change.
- Preserve the trust path: quarantine first, shelter second, promotion only by explicit command, no silent trust upgrades.
- Prefer Python 3.11+ and the standard library unless an added dependency clearly reduces risk or materially improves containment.
- Treat terminal output as an attack surface. Escape hostile filenames and content in reports and tests.
- Treat CLI exit codes and the human report format as operator contracts. Change them only with matching doc and test updates.
- Keep the first build structural-first. Suspicious-text heuristics should stay narrow, advisory, and line-oriented unless the policy model is deliberately widened.

## Maintenance Directive

When you add or change:

- CLI commands or flags
- inspection artifact schema
- trust-state transitions
- promotion rules
- policy fields

update the following files in the same change:

- [SPEC.md](SPEC.md) if the product contract changed
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) if sprint checklists or sequencing changed
- [README.md](README.md) if operator-facing behavior changed

## Working Style

- Favor small trusted paths over clever abstraction.
- Add hostile fixtures before widening supported formats.
- A downstream tool should be able to trust the inspection status and provenance trail without re-guessing them.

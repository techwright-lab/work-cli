# Agent workflow

Before changing code, read `skills/work-cli/SKILL.md`. Use the operator-selected
Work authority for new managed tasks. Keep an explicitly supplied isolated
feature worktree as the workspace; do not nest allocation inside it. Ask for
configuration before initializing a new authority or changing capacity.

Run verification in disposable owned fixtures through
`tools/qualification/container.sh`; use `WORK_QUALIFICATION_GIT_VERSION=2.56.0`
for the second supported Git fixture. Run the complete locked workspace tests,
formatting, strict all-target Clippy, Python helper tests, packaging and artifact
smoke before reporting release readiness. Follow `docs/distribution.md` for exact
commands and publication gates.

Keep real repositories and credentials out of qualification containers. Preserve
payload, authority history and quota on unknown outcomes. Keep release publication
and confirmed checkout removal behind their explicit operator authorization.

## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for techwright-lab/work-cli.
Before tracker operations, read `docs/agents/issue-tracker.md`.

### Triage labels

Before triage, read `docs/agents/triage-labels.md` for the five canonical labels.

### Domain docs

Before domain exploration, read `docs/agents/domain.md` for the single-context
layout and glossary/ADR consumer rules.

# Changelog

All notable changes to Isoklo are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.1 · 2026-11-20

Documentation only; no code changes.
- A fuller README: quick start, the GitHub setup in full, each check with examples, how to accept an intentional
  change, what leaves your machine, limits and FAQ.
- A live demo: four agent pull requests on [isoklo/isoklo-demo](https://github.com/isoklo/isoklo-demo), with
  screenshots of a blocked pull request and of a finding on the exact lines.
- Corrected: brand-new packages are flagged for review, not blocked.

## 0.1.0 · 2026-11-20

First public release.

### `isoklo check`
- **Weakened tests.** Blocks deleted test files, removed assertions that were not added back, assertions that can never
  fail, and skipped or focused tests. Moved or reformatted assertions cancel out. A reasoned
  `isoklo: allow-test-change <reason>` comment turns a block into a review.
- **Unknown packages.** Looks up new dependencies in `package.json`, `requirements*.txt` and `pyproject.toml` on the npm
  and PyPI registries. Blocks names that don't exist and flags packages first published in the last 30 days. Private
  scopes from `.npmrc` are never sent to the public registry. `--offline` skips the lookups.
- **Agent and CI configuration.** Flags changes to MCP servers, agent permissions and hooks, instruction files, code
  owners and CI workflows. Blocks the risky ones (new or changed MCP servers, wide permissions, removed deny rules,
  bypassed permission prompts, new hooks, risky workflow changes, Isoklo removed from CI) unless
  `--allow-config-change <reason>` is given. Secret values are redacted from messages and evidence.
- Output for people, `--json` for machines, and inside GitHub Actions: annotations on the changed lines plus a job
  summary.
- Exit codes: 0 passed, 1 blocked, 2 could not run (fails closed).

### `isoklo doctor`
- Shows which agent reads which instruction file: Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, Antigravity
  CLI and Devin Desktop (formerly Windsurf). Every fact was checked against the vendor's docs on 2026-11-20, and the
  source is in `src/doctor/knowledge.ts`.
- Finds a shadowed `AGENTS.md`, duplicates, empty or oversized files, and legacy `.cursorrules`.

### GitHub
- Composite action (`isoklo/isoklo@v0`) and a copyable workflow in `examples/github/isoklo.yml`.

# Changelog

All notable changes to Isoklo are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.2.0 · 2026-11-22 (Isoklo v2)

Every 0.1 rule, flag, exit code and JSON field still works the same way. New checks can block changes that 0.1 passed,
so read the rule table before upgrading a required gate.

### Zero setup
- **`npx isoklo`** with no arguments scans the repository as it is: no config, no account. `npx isoklo <folder>` too.
- **`isoklo init`** detects GitHub or GitLab, the package manager and the hook manager (git, Husky, lefthook), and
  installs a `pre-push` hook, the CI workflow (GitHub Actions or a GitLab merge-request job) and an
  `isoklo.config.json` whose baseline accepts today's findings. Idempotent; `--dry-run`; `--require` makes the check
  required on the default branch through the GitHub CLI.
- **The GitHub App** (`apps/github-app`, Cloudflare Workers and Hono): check runs with line annotations, one summary
  comment updated in place, signed webhooks, merge-base policy, organisation policy, Stripe and GitHub Marketplace
  billing, a one-click registration script and a local simulator.

### 32 new rules (62 in all), each with a canonical id, a severity and a version
- **Agent and MCP:** `agent/hidden-unicode` (decodes Unicode tag smuggling), `agent/prompt-injection`,
  `agent/approvals-disabled`; static `agent/permission-wide`, `agent/permission-mode`, `agent/mcp-all-enabled`;
  `mcp/unpinned-server`, `mcp/plaintext-secret`, `mcp/dangerous-server`. `mcp.json` and
  `claude_desktop_config.json` are now read as MCP configs.
- **Reward hacking:** `tamper/check-disabled-file`, `tamper/suppression-added`, `tamper/security-suppression`,
  `tamper/type-check-weakened`, `tamper/lint-config-weakened`, `tamper/coverage-lowered`,
  `tamper/test-script-weakened`, `tamper/gitignore-weakened`, `tamper/isoklo-config-changed`.
- **Supply chain:** `deps/install-script` (from npm's own install metadata), `deps/typosquat` (offline),
  `deps/lockfile-untrusted-source`, `deps/lifecycle-script`, `deps/registry-changed`.
- **Secrets and exfiltration:** `sec/secret-leaked` (provider keys, Supabase service_role JWTs, private keys,
  credentials in URLs), `sec/env-file-committed`, `sec/remote-code-exec`, `sec/env-exfiltration`,
  `sec/exfil-endpoint`, `sec/prt-head-checkout`, `sec/workflow-injection`.
- **Scope:** `scope/out-of-scope` (`--scope`, `isoklo-scope:` in the pull request body, or policy, intersected),
  `scope/forbidden-path`, `scope/too-many-files`, `scope/sensitive-zone`, `scope/lockfile-without-manifest`.

### Evidence, reports and policy
- **Evidence receipts:** canonical JSON (RFC 8785) with a SHA-256 digest, HMAC signing with `ISOKLO_RECEIPT_KEY`,
  and `isoklo verify`.
- **`isoklo report`:** a standalone executive audit report (HTML, prints to PDF) with an A to F posture grade.
- **`isoklo doctor`** now grades the repository's AI-agent security posture (merge gate, hook, workflow permissions,
  lockfile, `.env`, code owners) alongside the instruction-file analysis; `--min-grade` makes it a gate.
- **`--sarif`** for GitHub Code Scanning, **`--receipt`**, **`--html`**, **`--staged`**, **`--diff`**, **`--brief`**,
  and `isoklo rules`.
- **Policy** (`isoklo.config.json`, with a JSON Schema): scope, per-rule levels, ignore paths, baseline, trusted
  registries and MCP publishers. Read from the base commit in `check`, so a change cannot loosen its own gate; a
  policy that cannot be parsed fails closed.
- **The engine** (`isoklo/engine`) has no Node-only imports, so the GitHub App runs exactly the CLI's rules.

### Fixed
- The diff parser read a removed line beginning with `-- ` (an SQL comment, for example) as a file header. Hunks are
  now read by their line counts, and context lines (as in GitHub's API patches) are understood.

## 0.1.2 · 2026-11-21

- **GitHub Action:** runs on `actions/setup-node@v7` (Node.js 24). GitHub now warns that v4 actions run on the
  deprecated Node.js 20. Package caching is turned off in the action: Isoklo installs nothing from your repository,
  and caching on untrusted pull requests is a cache-poisoning risk.
- **Recommended workflow:** `actions/checkout@v7`.
- **README:** a note for people arriving from the GitHub Marketplace, whose one-line snippet leaves out the full
  history Isoklo needs.

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

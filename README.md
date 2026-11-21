<p align="center">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/readme-banner.png" alt="isoklo · Proof before merge." width="100%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-passed.svg" alt="isoklo: passed">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-review.svg" alt="isoklo: review">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-blocked.svg" alt="isoklo: blocked">
</p>

# Isoklo

**Proof before merge.** Isoklo is a merge gate for AI coding agents. It checks every pull request before a person spends
time on it, and blocks it, with the exact line as evidence, when the change:

- **weakens tests:** deletes them, removes assertions, skips them, or swaps in assertions that can never fail;
- **adds a package that doesn't exist:** a name the agent invented, which anyone could register with malicious code;
- **widens what agents and CI may do:** new MCP servers, wider permissions, hooks, or a workflow that switches the gate
  off.

```console
$ npx isoklo check
isoklo check · main...HEAD · 2 files changed, 1 test file, 1 new package, 0 config files

✕ blocked  Test disabled: test/cart.test.js:1 skips a test.
             test/cart.test.js:1  test.skip("total", () => {
           fix: remove the skip or focus marker, or fix the test so it can run.

✕ blocked  Package does not exist: expres-json-validatorz is not on npm (checked 2026-11-20 15:47 UTC).
             package.json:4  "expres-json-validatorz": "^1.0.0",
           fix: check the name; an agent may have invented it, and someone could register it with malicious code.

blocked · 2 problems must be fixed before merge.
```

No model is asked for an opinion. Every check is a fixed rule, so the same change always gets the same verdict, and it
runs in seconds.

## Live demo
Four agent pull requests on [isoklo/isoklo-demo](https://github.com/isoklo/isoklo-demo), left open as exhibits. Every
one passes its unit tests; Isoklo blocks three of them.

| Pull request | What the agent did | Unit Tests | Isoklo |
|---|---|:---:|:---:|
| [#1](https://github.com/isoklo/isoklo-demo/pull/1) | Deleted the assertions that caught its bug, and added `test.skip` | ✅ | ❌ blocked |
| [#2](https://github.com/isoklo/isoklo-demo/pull/2) | Added an invented npm package, `invoice-pdf-renderer-lite` | ✅ | ❌ blocked |
| [#3](https://github.com/isoklo/isoklo-demo/pull/3) | Quietly gave itself `Bash(*)` and `WebFetch(domain:*)` in `.claude/settings.json` | ✅ | ❌ blocked |
| [#4](https://github.com/isoklo/isoklo-demo/pull/4) | Fixed a real bug, with regression tests | ✅ | ✅ passed |

Pull request #1 cannot be merged, although its unit tests pass:

![Pull request #1: the isoklo check is failing and required, so the merge button is disabled](https://raw.githubusercontent.com/isoklo/isoklo/main/docs/pr-blocked.png)

The finding sits on the exact lines, in the pull request's diff:

![Isoklo's annotation in the diff: 2 assertions removed, 1 added in their place, 1 check fewer](https://raw.githubusercontent.com/isoklo/isoklo/main/docs/pr-inline.png)

## Contents
[Live demo](#live-demo) · [Quick start](#quick-start) · [Add it to GitHub](#add-it-to-github) · [What it checks](#what-it-checks) ·
[When a change is intentional](#when-a-change-is-intentional) · [isoklo doctor](#isoklo-doctor) ·
[What leaves your machine](#what-leaves-your-machine) · [Reference](#reference) · [Limits](#limits) · [FAQ](#faq) ·
[Licence](#licence)

## Quick start
You need Node.js 22 or later and git. Run it inside a repository, on the branch you want to check:

```console
npx isoklo check            # compare this branch with main (or master)
npx isoklo check --base dev # compare with another branch
npx isoklo doctor           # see which agent reads which instruction file
```

Nothing to install or configure. `check` exits `0` when the change passes and `1` when it is blocked, so it works in any
CI system or git hook as it is.

## Add it to GitHub
Two steps, about two minutes.

**1. Add the workflow.** Save this as `.github/workflows/isoklo.yml`. (Coming from the GitHub Marketplace? Its snippet
is only the `uses:` line. Use this complete workflow instead: Isoklo needs the full history, `fetch-depth: 0`, to
compare a pull request with its base, and it only ever needs read access.)

```yaml
name: isoklo

on:
  pull_request: # never pull_request_target: the gate reads untrusted code, so it gets no secrets

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # full history: Isoklo compares the pull request with where it left the base branch
          persist-credentials: false

      - uses: isoklo/isoklo@v0
        with:
          # Optional: a maintainer adds the "isoklo-allow-config" label to accept a deliberate config change.
          allow-config-change: ${{ contains(github.event.pull_request.labels.*.name, 'isoklo-allow-config') && 'label isoklo-allow-config applied by a maintainer' || '' }}
```

**2. Make it required.** In your repository, open **Settings → Rules → Rulesets** (or **Settings → Branches** for older
branch protection), protect your main branch, turn on **Require status checks to pass**, and add the check named
**check** (pull requests show it as *isoklo / check*). It appears in the list after the workflow has run once. GitHub
will then refuse to merge a pull request until Isoklo passes.

Findings appear as notes on the changed lines of the pull request, and as a full table on its **Checks** page.

<details>
<summary>Action inputs</summary>

| Input | Default | What it does |
|---|---|---|
| `version` | *(empty)* | Run this version from npm, for example `0.1.0`. Empty runs the copy inside the action. |
| `base` | *(empty)* | Branch or commit to compare against. Empty uses the pull request's base branch. |
| `offline` | `false` | `true` skips the package registry lookups. |
| `allow-config-change` | *(empty)* | A reason that turns blocked configuration changes into review. Set it only from something agents cannot control, such as a label only maintainers can apply. |

For the strongest guarantee, pin the action to a full commit SHA instead of `@v0`, because tags can be moved.
</details>

## What it checks
Every finding has a level:

| | Level | Meaning |
|---|---|---|
| ✕ | **blocked** | Must be fixed before merge. The check fails (exit 1). |
| ! | **review** | Worth a person's look. The check still passes. |
| · | **info** | For the record. The check passes. |

### 1. Weakened tests
Agents under pressure to make a build pass tend to make the tests easier instead of the code correct.

| Blocked | Example |
|---|---|
| A test file with assertions is deleted, and they did not move elsewhere | `git rm test/auth.test.js` |
| More assertions removed than added back | 3 `expect(...)` lines gone, 1 added |
| A test is skipped or focused | `test.skip(`, `it.only(`, `xit(`, `@pytest.mark.skip`, `t.Skip()`, `@Disabled` |
| An assertion that can never fail replaces a real one | `expect(true).toBe(true)`, `assert True` |

**Fair by design.** Moving an assertion to another test file, reformatting it, or changing a test while keeping as many
checks is not a weakened test, and passes. Test files and assertions are recognised for JavaScript and TypeScript
(Jest, Vitest, Mocha with Chai, node:test, AVA), Python (pytest, unittest), Go (testing, testify), Java and Kotlin
(JUnit, AssertJ), C# (xUnit, NUnit) and Ruby (RSpec).

### 2. Packages that don't exist
When an agent adds a dependency to `package.json`, `requirements*.txt` or `pyproject.toml`, Isoklo looks it up on npm or
PyPI.

| Finding | Level |
|---|---|
| The package does not exist on the public registry | **blocked** |
| It does not exist publicly, but it may be private (a scoped npm name, a custom registry, or a private Python index) | review |
| It was first published less than 30 days ago | review |
| The registry did not answer | review: never a silent pass, never a false block |
| `--offline` was used, so nothing was looked up | info |

Invented package names are a known attack ("slopsquatting"): attackers register the names agents tend to make up.

### 3. Agent and CI configuration
The files that decide what an agent may run, and what CI trusts, are rarely read in review, and a prompt injection can
talk an agent into widening its own power.

**Blocked:**
- a new MCP server, or a change to what an existing one runs or connects to;
- Claude Code permissions that allow everything (`*`, `Bash`, `Bash(*)`, `mcp__*`, `WebFetch(domain:*)`) or risky
  commands (`curl`, `rm`, `sudo`, `git push`, `npm publish`, `docker` and similar);
- in Claude Code settings: removed deny rules, `defaultMode: bypassPermissions`, `enableAllProjectMcpServers`, or new
  or changed hooks;
- a workflow that uses `pull_request_target` or `permissions: write-all`;
- any change that removes Isoklo from CI. A change cannot switch off the gate that checks it.

**Review:** narrower permission changes, MCP environment changes (variable names only, never values), workflow write
permissions, `continue-on-error`, new secrets in workflows, other CI systems, agent instruction files, `CODEOWNERS`, and
other agents' settings.

MCP files checked: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
`.agents/mcp_config.json`, `.devin/mcp_config.json`, `.devin/mcp_config.local.json` and `.roo/mcp.json`.

Secret values that appear in configuration are replaced with `***` before anything is printed.

## When a change is intentional
Sometimes a person really did mean to remove a test or add a server. Isoklo never hides that; it asks for a reason that
reviewers can see.

**Tests.** Add a comment to each test file you changed on purpose. The finding drops from blocked to review, and shows
your reason:

```js
// isoklo: allow-test-change total([]) is now covered in test/empty.test.js
```

```console
! review   Tests weakened: 1 assertion removed, 0 added in their place, 1 check fewer.
             test/cart.test.js:3  expect(total([])).toBe(0);
           allowed: total([]) is now covered in test/empty.test.js
```

A marker without a reason does not count. Because the marker is part of the diff, reviewers see it too.

**Configuration.** Pass a reason from somewhere an agent cannot write to:

```console
npx isoklo check --allow-config-change "MCP server approved in #12"
```

In GitHub, the workflow above does this when a maintainer adds the `isoklo-allow-config` label. Limit who can apply
labels (triage access) if you rely on it.

**Packages.** There is no override for a package that does not exist: fix the name. For private npm scopes, declare the
scope's registry in `.npmrc` and Isoklo will leave those packages alone.

## isoklo doctor
Most repositories now carry instructions for several agents, and each agent reads different files. `doctor` shows which
agent reads which, and what is being ignored:

```console
$ npx isoklo doctor
isoklo doctor · /home/you/shop

Instruction files
  CLAUDE.md       ~5 tokens   read by Claude Code, GitHub Copilot
  AGENTS.md       ~5 tokens   read by Codex, Cursor, GitHub Copilot, Antigravity CLI, Devin Desktop (the cross-agent standard)

Findings
  ! review  Claude Code ignores AGENTS.md here: CLAUDE.md exists and does not import it.
            fix: add the line `@AGENTS.md` to CLAUDE.md, or make CLAUDE.md a symlink to AGENTS.md.

1 finding to review. Estimated total: ~10 tokens of instructions. Doctor is advisory and never blocks a merge.
```

It covers Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, Antigravity CLI and Devin Desktop (formerly Windsurf),
and also finds identical copies that will drift apart, empty files, files too long to be followed reliably, and Cursor's
legacy `.cursorrules`. Which agent reads which file changes often; every fact was checked against the vendor's own
documentation on 2026-11-20, and the sources are listed in
[`src/doctor/knowledge.ts`](https://github.com/isoklo/isoklo/blob/main/src/doctor/knowledge.ts).

`doctor` always exits `0`. Add `--strict` to exit `1` when there is something to review.

## What leaves your machine
Only the **names of newly added packages**, sent to the public registries to check that they exist:
`registry.npmjs.org`, `api.npmjs.org` and `pypi.org`.

- No source code, diffs, file names or repository names are ever sent.
- Packages in private npm scopes listed in `.npmrc` are never looked up.
- No telemetry, no account, no API key.
- `--offline` turns off the lookups completely.

Isoklo has no runtime dependencies: the npm package is its own code and nothing else.

## Reference

### Commands and options
| | |
|---|---|
| `isoklo check [path]` | Check the current branch against its base. |
| `--base <ref>` | The branch or commit to compare against. Default: the pull request's base in GitHub Actions, then `main` or `master`. |
| `--head <ref>` | The commit to check. Default: `HEAD`. |
| `--offline` | Don't contact package registries. |
| `--allow-config-change <reason>` | Accept blocked configuration changes as reviewed. |
| `isoklo doctor [path]` | Check agent instruction files. |
| `--strict` | `doctor`: exit 1 when there are findings to review. |
| `--json` | Print a machine-readable report (both commands). |
| `-h`, `--help` · `-v`, `--version` | Help and version. |

### Exit codes
| Code | Meaning |
|---|---|
| `0` | Passed (findings to review do not fail the check). |
| `1` | Blocked. |
| `2` | Could not run, for example the base branch is missing. The check **fails closed**: nothing is approved. |

### JSON output
`--json` prints one object with the verdict and every finding, for scripts and dashboards:

```json
{
  "tool": "isoklo",
  "command": "check",
  "version": "0.1.2",
  "verdict": "passed",
  "base": "main",
  "head": "HEAD",
  "filesChanged": 1,
  "results": [
    {
      "rule": "weakened-tests",
      "findings": [
        {
          "id": "assertions-removed",
          "level": "review",
          "message": "Tests weakened: 1 assertion removed, 0 added in their place, 1 check fewer.",
          "evidence": [{ "path": "test/cart.test.js", "line": 3, "text": "expect(total([])).toBe(0);" }],
          "allowedBecause": "total([]) is now covered in test/empty.test.js"
        }
      ]
    }
  ]
}
```

*(Shortened. Each finding also carries `rule` and `fix`; each result carries `passes` and `stats`.)*

Colour turns off automatically outside a terminal, and whenever `NO_COLOR` is set.

## Limits
Isoklo is deliberately narrow. Knowing what it does not do is part of trusting it.

- **It does not judge code quality** or find bugs in your logic. It catches specific, provable ways a change can make a
  repository less safe.
- **Its patterns are heuristics.** An unusual test style can be missed. Misses are far more likely than false blocks,
  and every block shows its evidence, so you can check it.
- **Packages:** npm and PyPI only, from `package.json`, `requirements*.txt` and `pyproject.toml`. Lockfiles and other
  ecosystems are not checked yet.
- **CI integration** is built for GitHub Actions. Elsewhere, use the exit code and `--json`.

## Roadmap
- **Scope:** block changes that stray outside the issue they claim to fix.
- **Rule proving** (`isoklo rules prove`): replay your own merged pull requests with and without each agent rule, to show
  which rules actually help.
- More package ecosystems.

See the [changelog](https://github.com/isoklo/isoklo/blob/main/CHANGELOG.md) for what has shipped.

## FAQ
**Does it use AI?** No. Every verdict comes from fixed rules, so it is fast, free to run, and cannot be talked out of a
block.

**Does it only check pull requests written by agents?** It checks every pull request. The rules target the mistakes
agents make most, but a person who deletes a test gets the same verdict.

**Will it slow down CI?** A check takes seconds. The only network calls are the package lookups, and each request
gives up after 8 seconds.

**What if it blocks something it shouldn't?** Use the escape hatch for that rule (see
[When a change is intentional](#when-a-change-is-intentional)), and please
[open an issue](https://github.com/isoklo/isoklo/issues) with the example, so the rule can improve.

## Why the name
*iso* (Greek ἴσος, "equal"). Euclid's *Elements* I.5, the isosceles theorem, was nicknamed the *pons asinorum*, the bridge
every student had to cross to show they could follow a proof. Isoklo is that bridge for agent code. The symbol is a point
and a line with one tail at each end; turn it half a turn and it lands on itself, equal both ways.

## Licence
Isoklo is released under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md)
(`FSL-1.1-ALv2`). You may use, copy, modify and redistribute it for any purpose except offering a competing product or
service. Two years after each version is released, that version also becomes available under the Apache License 2.0.

The licence does not grant rights to the Isoklo name or logo. The logo and launch assets in
[`brand/`](https://github.com/isoklo/isoklo/tree/main/brand) are provided so you can link to and describe the project.

Bug reports and ideas are welcome in [issues](https://github.com/isoklo/isoklo/issues).

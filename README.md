<p align="center">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/readme-banner.png" alt="isoklo · Proof before merge." width="100%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-passed.svg" alt="isoklo: passed">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-review.svg" alt="isoklo: review">
  <img src="https://raw.githubusercontent.com/isoklo/isoklo/main/brand/launch-kit/badge-blocked.svg" alt="isoklo: blocked">
</p>

# Isoklo

**Proof before merge.** Isoklo is a merge gate for AI coding agents. It checks every agent-written pull request before a
person spends time on it, and blocks it, with the exact line as evidence, when the agent:
- weakened or deleted tests;
- added a package that doesn't exist or appeared in the last 30 days;
- quietly changed agent, MCP or CI configuration.

The same change always gets the same verdict: every rule is deterministic, and no model is asked for an opinion.

```console
$ npx isoklo check
isoklo check · main...HEAD · 2 files changed, 1 test file, 1 new package, 0 config files

✕ blocked  Tests weakened: 2 assertions removed, 0 added in their place, 2 checks fewer.
             tests/auth.test.ts:3  expect(b).toBe(2);
             tests/auth.test.ts:4  expect(c).toBe(3);
           fix: restore the removed assertions, or replace each one with an assertion that checks the same behaviour.

blocked · 1 problem must be fixed before merge.
```

Requires Node.js 22 or later, and git.

## Commands
| | |
|---|---|
| `isoklo check [path]` | Check the current branch against its base (`--base`, `--head`, `--offline`, `--json`, `--allow-config-change <reason>`). |
| `isoklo doctor [path]` | See which agent reads which instruction file (Claude Code, Codex, Cursor, GitHub Copilot, Gemini and Antigravity CLI, Devin Desktop), and find shadowed, duplicated, empty or oversized ones (`--json`, `--strict`). |

Exit codes: `0` passed · `1` blocked · `2` could not run (the check fails closed).

## Use it in GitHub
Copy [`examples/github/isoklo.yml`](https://github.com/isoklo/isoklo/blob/main/examples/github/isoklo.yml) to
`.github/workflows/isoklo.yml`. Then require the **isoklo / check** status check in your branch protection rules, so
GitHub will not merge a pull request until Isoklo passes. Findings appear on the changed lines of the pull request, and
in a summary on its checks page.

## Status
Version 0.1. Coming next: checking that a change stays inside its issue's scope, and proving whether your agent rules
help by replaying your own merged pull requests with and without each rule. See the
[changelog](https://github.com/isoklo/isoklo/blob/main/CHANGELOG.md).

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

/**
 * Every rule Isoklo can report, as data: canonical id, suite, default severity, version, and the plain explanation of
 * the attack it stops. Reports, SARIF, receipts, `isoklo rules` and the README table all read from here, and a test
 * fails if any rule reports a finding that is not listed. Bump a rule's `version` whenever its behaviour changes, so
 * evidence receipts record exactly which logic produced a verdict.
 */
import type { Finding, Level, Severity, Suite } from "../check/types.js";

export type Mode = "check" | "scan";

export interface RuleMeta {
  /** `suite/name`, stable forever: configs, baselines and receipts refer to it. */
  id: string;
  suite: Suite;
  /** Severity when the rule blocks. Review-level findings drop to `reviewSeverity` (default medium). */
  severity: Severity;
  reviewSeverity?: Severity;
  version: number;
  /** Short title for tables. */
  title: string;
  /** The exploit or failure this rule stops, in two or three plain sentences. */
  why: string;
  /** check: runs on a change (pull request, branch, staged files). scan: runs on the files as they are. */
  modes: Mode[];
  /** True for rules that shipped in v1 (0.1.x). */
  v1?: boolean;
}

const both: Mode[] = ["check", "scan"];
const check: Mode[] = ["check"];

export const RULES: readonly RuleMeta[] = [
  // ------------------------------------------------------------------ agent
  {
    id: "agent/hidden-unicode", suite: "agent", severity: "critical", version: 1, modes: both,
    title: "Hidden Unicode in agent-facing text or code",
    why: "Zero-width, bidirectional and Unicode tag characters are invisible in editors and in code review, but models and compilers read them. Attackers use them to hide instructions in rules files (the Rules File Backdoor) or to make code run differently from how it reads (Trojan Source, CVE-2021-42574).",
  },
  {
    id: "agent/prompt-injection", suite: "agent", severity: "high", version: 1, modes: both,
    title: "Prompt-override text in agent instructions",
    why: "Instruction files are loaded into every agent session with full trust. Text that tells the agent to ignore its instructions, hide what it does from the user, or send data elsewhere turns the repository itself into the attacker.",
  },
  {
    id: "agent/approvals-disabled", suite: "agent", severity: "critical", version: 1, modes: both,
    title: "Agent approvals or sandbox turned off",
    why: "Claude Code's dangerously-skip-permissions flag, Codex's danger-full-access sandbox mode and similar switches let an agent run any command, edit any file and reach the network with nobody approving. One prompt injection is then enough to take over the machine or the CI runner.",
  },
  {
    id: "agent/permission-wide", suite: "agent", severity: "critical", version: 1, modes: both, v1: true,
    title: "Agent permissions allow everything or risky commands",
    why: "Wildcard allow rules (*, Bash, Bash(*), mcp__*, WebFetch(domain:*)) and risky commands (curl, rm, sudo, git push) are pre-approved, so the agent never asks before acting. An injected instruction runs with your credentials.",
  },
  {
    id: "agent/permission-added", suite: "agent", severity: "medium", version: 1, modes: check, v1: true,
    title: "New agent permission",
    why: "Each pre-approved command is one less moment where a person sees what the agent is about to do.",
  },
  {
    id: "agent/deny-removed", suite: "agent", severity: "high", version: 1, modes: check, v1: true,
    title: "Agent deny rules removed",
    why: "Deny rules are the last line between an agent and commands the team decided it must never run. An agent removing them is widening its own power.",
  },
  {
    id: "agent/permission-mode", suite: "agent", severity: "critical", version: 1, modes: both, v1: true,
    title: "Agent permission prompts bypassed",
    why: "defaultMode: bypassPermissions turns every permission prompt off for everyone who opens the repository with an older Claude Code.",
  },
  {
    id: "agent/mcp-all-enabled", suite: "agent", severity: "high", version: 1, modes: both, v1: true,
    title: "Every project MCP server auto-enabled",
    why: "enableAllProjectMcpServers trusts every MCP server in the repository, including ones a later pull request adds, without anyone approving them.",
  },
  {
    id: "agent/hook-added", suite: "agent", severity: "high", version: 1, modes: check, v1: true,
    title: "Agent hooks added or changed",
    why: "Hooks run shell commands automatically on agent events, on every developer machine that opens the repository.",
  },
  {
    id: "agent/hook-removed", suite: "agent", severity: "medium", version: 1, modes: check, v1: true,
    title: "Agent hooks removed",
    why: "Hooks often run formatters, tests or safety checks; removing them can switch a guardrail off quietly.",
  },
  {
    id: "agent/instructions-changed", suite: "agent", severity: "medium", version: 1, modes: check, v1: true,
    title: "Agent instructions changed",
    why: "Text in these files steers every future agent run, so it deserves the same review as code.",
  },
  {
    id: "agent/settings-changed", suite: "agent", severity: "medium", version: 1, modes: check, v1: true,
    title: "Other agent settings changed",
    why: "Agent settings files decide what an agent may run and read.",
  },
  {
    id: "agent/config-unreadable", suite: "agent", severity: "medium", version: 1, modes: check, v1: true,
    title: "Agent configuration could not be parsed",
    why: "A file Isoklo cannot parse cannot be compared, so it must be read by a person.",
  },
  // ------------------------------------------------------------------ mcp
  {
    id: "mcp/server-added", suite: "mcp", severity: "high", version: 1, modes: check, v1: true,
    title: "New MCP server",
    why: "An MCP server is a program or remote service the agent can call with the developer's access. A prompt injection can ask an agent to add one that exfiltrates code or secrets.",
  },
  {
    id: "mcp/server-changed", suite: "mcp", severity: "high", version: 1, modes: check, v1: true,
    title: "MCP server now runs something else",
    why: "Changing a trusted server's command or address keeps its name, and its approval, while swapping what actually runs.",
  },
  {
    id: "mcp/server-env-changed", suite: "mcp", severity: "medium", version: 1, modes: check, v1: true,
    title: "MCP server settings changed",
    why: "A changed token or endpoint can route the agent's tool calls, and their data, somewhere else.",
  },
  {
    id: "mcp/server-removed", suite: "mcp", severity: "info", version: 1, modes: check, v1: true,
    title: "MCP server removed",
    why: "Recorded for completeness; removing a server reduces what agents can do.",
  },
  {
    id: "mcp/unpinned-server", suite: "mcp", severity: "high", reviewSeverity: "medium", version: 1, modes: both,
    title: "MCP server runs an unpinned package",
    why: "npx -y, uvx and docker pull the newest version on every start. If the package is hijacked or typo-squatted, every developer's agent runs the attacker's code with their credentials, with no change in the repository to review.",
  },
  {
    id: "mcp/plaintext-secret", suite: "mcp", severity: "critical", version: 1, modes: both,
    title: "Plaintext secret in MCP configuration",
    why: "MCP configs are committed and copied around. A key written into env, headers or args is readable by everyone with the repository, and by every agent and log that touches it.",
  },
  {
    id: "mcp/dangerous-server", suite: "mcp", severity: "high", version: 1, modes: both,
    title: "MCP server with dangerous reach",
    why: "Inline shell payloads, a filesystem server rooted at / or the home folder, unencrypted remote servers and Docker host mounts give an agent far more than the task needs.",
  },
  // ------------------------------------------------------------------ tamper
  {
    id: "tamper/test-file-deleted", suite: "tamper", severity: "high", version: 1, modes: check, v1: true,
    title: "Test file deleted",
    why: "Agents rewarded for a green build can delete the test that catches their bug instead of fixing the code.",
  },
  {
    id: "tamper/assertions-removed", suite: "tamper", severity: "high", version: 1, modes: check, v1: true,
    title: "Assertions removed",
    why: "Fewer assertions means less behaviour is checked; the build turns green because it checks less, not because the code is right.",
  },
  {
    id: "tamper/tautology", suite: "tamper", severity: "high", version: 1, modes: check, v1: true,
    title: "Assertion that can never fail",
    why: "expect(true).toBe(true) adds a line and no coverage. It is the most common shape of reward hacking in agent pull requests.",
  },
  {
    id: "tamper/test-disabled", suite: "tamper", severity: "high", version: 1, modes: check, v1: true,
    title: "Test skipped or focused",
    why: ".skip silences a failing test; .only silently stops every other test from running.",
  },
  {
    id: "tamper/check-disabled-file", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Type-checking or linting turned off for a whole file",
    why: "File-wide markers (TypeScript's nocheck, a bare ESLint disable, Pylint's skip-file and the like) make every error in the file disappear, including the one the agent was asked to fix.",
  },
  {
    id: "tamper/suppression-added", suite: "tamper", severity: "medium", version: 1, modes: check,
    title: "Lint or type error suppressed",
    why: "TypeScript ignore comments, ESLint disable-next-line comments, and Python type-ignore and noqa markers hide one error each. An agent adding them is often hiding a real bug to get the build green.",
  },
  {
    id: "tamper/security-suppression", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Security scanner silenced",
    why: "Bandit's nosec, Semgrep's nosemgrep, SonarQube's NOSONAR and Gitleaks' allow markers tell a security scanner to look away. Without a written reason there is no way to tell a false positive from a hidden vulnerability.",
  },
  {
    id: "tamper/type-check-weakened", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Type-checking weakened",
    why: "Turning off strict, noImplicitAny or strictNullChecks (or mypy's checks) makes whole classes of bugs invisible to CI across the codebase, not just in the agent's change.",
  },
  {
    id: "tamper/lint-config-weakened", suite: "tamper", severity: "medium", version: 1, modes: check,
    title: "Linter rules turned off",
    why: "A rule switched off in the linter config disappears for everyone, everywhere, and is rarely noticed in review.",
  },
  {
    id: "tamper/coverage-lowered", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Coverage threshold lowered",
    why: "Lowering the coverage bar is the quickest way to make a failing build pass without writing a test.",
  },
  {
    id: "tamper/test-script-weakened", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Test command can no longer fail",
    why: "Appending || true, --passWithNoTests or exit 0 to a test, lint or type-check command makes CI report success whatever happens.",
  },
  {
    id: "tamper/gitignore-weakened", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Secrets no longer ignored by git",
    why: "Removing .env or key files from .gitignore, or adding a negation rule that un-ignores them, makes the next git add commit them.",
  },
  {
    id: "tamper/isoklo-config-changed", suite: "tamper", severity: "high", version: 1, modes: check,
    title: "Merge-gate policy changed in the change it gates",
    why: "A pull request must not be able to loosen the policy that judges it. Isoklo reads policy from the base branch; this change edits it for the future.",
  },
  {
    id: "tamper/isoklo-removed-from-ci", suite: "tamper", severity: "critical", version: 1, modes: check, v1: true,
    title: "Merge gate removed from CI",
    why: "A change that switches off the gate that checks it would pass every future check.",
  },
  {
    id: "tamper/workflow-changed", suite: "tamper", severity: "medium", version: 1, modes: check, v1: true,
    title: "CI workflow changed",
    why: "Workflows run with the repository's credentials and decide what CI enforces.",
  },
  {
    id: "tamper/ci-changed", suite: "tamper", severity: "medium", version: 1, modes: check, v1: true,
    title: "Other CI configuration changed",
    why: "CI configuration runs with the repository's credentials and decides what CI enforces.",
  },
  {
    id: "tamper/codeowners-changed", suite: "tamper", severity: "medium", version: 1, modes: check, v1: true,
    title: "Code owners changed",
    why: "CODEOWNERS decides who must approve what; editing it can remove the reviewer who would have caught the change.",
  },
  // ------------------------------------------------------------------ deps
  {
    id: "deps/package-does-not-exist", suite: "deps", severity: "critical", version: 1, modes: check, v1: true,
    title: "Package does not exist (hallucinated)",
    why: "Agents invent plausible package names. Attackers register those names with malware (slopsquatting), so the next install runs their code.",
  },
  {
    id: "deps/package-maybe-private", suite: "deps", severity: "medium", version: 1, modes: check, v1: true,
    title: "Package not public; may be private",
    why: "A name missing from the public registry is either private or invented; a person must confirm which.",
  },
  {
    id: "deps/package-brand-new", suite: "deps", severity: "medium", version: 1, modes: check, v1: true,
    title: "Package first published under 30 days ago",
    why: "Most malicious packages are caught and removed within days. A brand-new dependency has had no time to be vetted.",
  },
  {
    id: "deps/package-unverified", suite: "deps", severity: "medium", version: 1, modes: check, v1: true,
    title: "Registry did not answer",
    why: "Isoklo never passes a package it could not verify; it asks for review instead.",
  },
  {
    id: "deps/packages-not-verified", suite: "deps", severity: "info", version: 1, modes: check, v1: true,
    title: "Packages not checked (offline)",
    why: "Recorded so an offline run never looks like a verified one.",
  },
  {
    id: "deps/manifest-unreadable", suite: "deps", severity: "medium", version: 1, modes: check, v1: true,
    title: "Dependency manifest could not be parsed",
    why: "New packages in an unparseable manifest cannot be checked.",
  },
  {
    id: "deps/install-script", suite: "deps", severity: "critical", reviewSeverity: "medium", version: 1, modes: check,
    title: "New package runs an install script",
    why: "preinstall and postinstall scripts run with the developer's or CI's full access on npm install. Nearly every npm malware campaign uses them; a new or little-used package with one is the classic shape.",
  },
  {
    id: "deps/typosquat", suite: "deps", severity: "high", version: 1, modes: check,
    title: "Name one typo away from a popular package",
    why: "Typo-squatted names (expresss, reqeusts) are registered specifically to catch mistakes by people and by agents.",
  },
  {
    id: "deps/lockfile-untrusted-source", suite: "deps", severity: "high", version: 1, modes: both,
    title: "Lockfile installs from an untrusted source",
    why: "Nobody reads lockfiles in review. A resolved URL pointing at a plain-http or unknown host makes every install fetch the attacker's tarball while package.json looks unchanged.",
  },
  {
    id: "deps/lifecycle-script", suite: "deps", severity: "critical", reviewSeverity: "medium", version: 1, modes: check,
    title: "Install-time script added to this project",
    why: "preinstall, postinstall and prepare in the project's own package.json run on every developer's machine and every CI job at install time.",
  },
  {
    id: "deps/registry-changed", suite: "deps", severity: "high", version: 1, modes: check,
    title: "Package registry or index changed",
    why: "Pointing npm or pip at another registry, adding an extra index, or turning TLS checks off enables dependency confusion and man-in-the-middle installs.",
  },
  // ------------------------------------------------------------------ sec
  {
    id: "sec/secret-leaked", suite: "sec", severity: "critical", reviewSeverity: "high", version: 1, modes: both,
    title: "Secret or private key in the code",
    why: "A committed key is readable by everyone with the repository, stays in git history after deletion, and is scraped from public repositories within minutes. Revoke it; deleting the line is not enough.",
  },
  {
    id: "sec/env-file-committed", suite: "sec", severity: "critical", version: 1, modes: both,
    title: ".env file committed",
    why: ".env files hold the real credentials for databases, payment providers and AI APIs. Committing one shares all of them at once.",
  },
  {
    id: "sec/remote-code-exec", suite: "sec", severity: "high", reviewSeverity: "medium", version: 1, modes: both,
    title: "Downloads and runs remote code",
    why: "Piping a downloaded script straight into a shell runs whatever the server returns at that moment, with no integrity check. Agents copy these one-liners from the web, and attackers plant them in instructions.",
  },
  {
    id: "sec/env-exfiltration", suite: "sec", severity: "critical", reviewSeverity: "high", version: 1, modes: both,
    title: "Environment or secrets sent out",
    why: "Serialising the whole process environment, or a workflow's entire secrets context, and sending it over the network is how compromised packages and injected agents steal every credential at once.",
  },
  {
    id: "sec/exfil-endpoint", suite: "sec", severity: "high", reviewSeverity: "medium", version: 1, modes: both,
    title: "Known data-collection endpoint",
    why: "Request bins, webhook catchers and out-of-band testing domains exist to receive data from somewhere it should not leave. Production code has no reason to call them.",
  },
  {
    id: "sec/prt-head-checkout", suite: "sec", severity: "critical", version: 1, modes: both,
    title: "pull_request_target checks out pull request code",
    why: "pull_request_target runs with write access and secrets. Checking out the pull request's head then runs a stranger's code with those secrets: the pwn-request pattern behind many supply-chain breaches.",
  },
  {
    id: "sec/workflow-injection", suite: "sec", severity: "high", version: 1, modes: both,
    title: "Untrusted input injected into a workflow script",
    why: "${{ github.event.pull_request.title }} and similar values are pasted into the shell before it runs. A crafted title becomes a command running with the workflow's token.",
  },
  {
    id: "sec/workflow-risk", suite: "sec", severity: "high", version: 1, modes: both, v1: true,
    title: "Workflow trust widened",
    why: "pull_request_target, write-all and new write permissions give pull request code more power than a check needs.",
  },
  {
    id: "sec/workflow-secrets", suite: "sec", severity: "medium", version: 1, modes: check, v1: true,
    title: "Workflow uses new secrets",
    why: "Each secret a workflow can read is one a malicious step could print or send out.",
  },
  // ------------------------------------------------------------------ scope
  {
    id: "scope/out-of-scope", suite: "scope", severity: "high", version: 1, modes: check,
    title: "File changed outside the declared scope",
    why: "Agents drift: asked to fix one thing, they refactor another. Edits outside the task's declared files are where unreviewed behaviour changes hide.",
  },
  {
    id: "scope/forbidden-path", suite: "scope", severity: "high", version: 1, modes: check,
    title: "File changed in a forbidden area",
    why: "Some areas (billing, auth, infrastructure) must only change in pull requests written for them. The policy lists them; this change touches one.",
  },
  {
    id: "scope/too-many-files", suite: "scope", severity: "medium", version: 1, modes: check,
    title: "Change larger than the policy allows",
    why: "Very large agent changes cannot be reviewed line by line; the policy caps them.",
  },
  {
    id: "scope/sensitive-zone", suite: "scope", severity: "medium", version: 1, modes: check,
    title: "Sensitive area changed alongside unrelated work",
    why: "Auth, billing, infrastructure and migrations changed as a side effect of an unrelated task are the edits reviewers miss.",
  },
  {
    id: "scope/lockfile-without-manifest", suite: "scope", severity: "medium", version: 1, modes: check,
    title: "Lockfile changed without a manifest change",
    why: "A lockfile edit with no package.json change can swap a dependency's version or source invisibly.",
  },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

/** v1 finding ids (rule group + local id) to their canonical v2 rule ids. */
const LEGACY: Record<string, string> = {
  "weakened-tests:test-file-deleted": "tamper/test-file-deleted",
  "weakened-tests:assertions-removed": "tamper/assertions-removed",
  "weakened-tests:tautology": "tamper/tautology",
  "weakened-tests:test-disabled": "tamper/test-disabled",
  "unknown-packages:manifest-unreadable": "deps/manifest-unreadable",
  "unknown-packages:packages-not-verified": "deps/packages-not-verified",
  "unknown-packages:package-not-found-maybe-private": "deps/package-maybe-private",
  "unknown-packages:package-does-not-exist": "deps/package-does-not-exist",
  "unknown-packages:package-unverified": "deps/package-unverified",
  "unknown-packages:package-brand-new": "deps/package-brand-new",
  "unknown-packages:install-script": "deps/install-script",
  "unknown-packages:typosquat": "deps/typosquat",
  "agent-config:config-unreadable": "agent/config-unreadable",
  "agent-config:mcp-server-added": "mcp/server-added",
  "agent-config:mcp-server-changed": "mcp/server-changed",
  "agent-config:mcp-server-env-changed": "mcp/server-env-changed",
  "agent-config:mcp-server-removed": "mcp/server-removed",
  "agent-config:permission-wide": "agent/permission-wide",
  "agent-config:permission-added": "agent/permission-added",
  "agent-config:deny-removed": "agent/deny-removed",
  "agent-config:permission-mode": "agent/permission-mode",
  "agent-config:mcp-all-enabled": "agent/mcp-all-enabled",
  "agent-config:hook-added": "agent/hook-added",
  "agent-config:hook-removed": "agent/hook-removed",
  "agent-config:isoklo-removed-from-ci": "tamper/isoklo-removed-from-ci",
  "agent-config:workflow-risk": "sec/workflow-risk",
  "agent-config:workflow-secrets": "sec/workflow-secrets",
  "agent-config:workflow-changed": "tamper/workflow-changed",
  "agent-config:agent-settings-changed": "agent/settings-changed",
  "agent-config:ci-changed": "tamper/ci-changed",
  "agent-config:instructions-changed": "agent/instructions-changed",
  "agent-config:codeowners-changed": "tamper/codeowners-changed",
};

/** The canonical id of a finding, or null when no rule is registered for it (a bug the tests catch). */
export function canonicalId(f: Pick<Finding, "rule" | "id">): string | null {
  const legacy = LEGACY[`${f.rule}:${f.id}`];
  if (legacy !== undefined) return legacy;
  const native = `${f.rule}/${f.id}`;
  return BY_ID.has(native) ? native : null;
}

export const ruleMeta = (id: string): RuleMeta | undefined => BY_ID.get(id);

/** Severity of a finding: explicit if the rule set one, otherwise derived from the registry and the level. */
export function severityOf(meta: RuleMeta, level: Level, downgraded: boolean): Severity {
  if (downgraded) return meta.severity === "info" ? "info" : meta.reviewSeverity ?? meta.severity;
  if (level === "blocked") return meta.severity;
  if (level === "review") return meta.reviewSeverity ?? (meta.severity === "info" ? "info" : "medium");
  return "info";
}

/**
 * v2 rules about deliberate configuration that a maintainer's --allow-config-change reason may accept (v1 rules apply
 * it themselves). Leaked secrets, hidden text, injected instructions, exfiltration and invented packages are never
 * accepted this way: a reason does not make them safe.
 */
export const CONFIG_CHANGE_RULES: ReadonlySet<string> = new Set([
  "mcp/unpinned-server", "mcp/dangerous-server", "agent/approvals-disabled", "tamper/isoklo-config-changed",
  "tamper/type-check-weakened", "tamper/lint-config-weakened", "tamper/coverage-lowered", "tamper/test-script-weakened",
  "tamper/gitignore-weakened", "tamper/check-disabled-file", "deps/registry-changed", "deps/lifecycle-script",
  "deps/lockfile-untrusted-source", "sec/prt-head-checkout", "sec/workflow-injection", "scope/forbidden-path",
  "scope/out-of-scope", "scope/too-many-files",
]);

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "info"];
export const severityRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);

/** Rules that run in a mode, for receipts ("which logic produced this verdict"). */
export const rulesFor = (mode: Mode) => RULES.filter((r) => r.modes.includes(mode)).map((r) => ({ id: r.id, version: r.version }));

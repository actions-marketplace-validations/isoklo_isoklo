/**
 * Posture checks (input/output): the safeguards around agent changes that are not in any single file's content.
 *   merge gate in CI · pre-push hook · workflow token permissions · lockfile · .env ignored · code owners for agent config
 * Combined with `isoklo scan` findings into an A to F grade by grade.ts.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { git } from "../check/git.js";
import type { ScanFile } from "../engine/scan.js";
import type { PostureCheck } from "./grade.js";

const read = async (path: string) => {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
};
const exists = async (path: string) => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

async function hooksDir(root: string): Promise<string | null> {
  try {
    const p = (await git(root, ["rev-parse", "--path-format=absolute", "--git-path", "hooks"])).trim();
    return p === "" ? null : p;
  } catch {
    return null;
  }
}

export async function postureChecks(root: string, files: ScanFile[]): Promise<PostureCheck[]> {
  const checks: PostureCheck[] = [];
  const byPath = new Map(files.map((f) => [f.path, f.text]));
  const workflows = files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path));
  const otherCi = files.filter((f) => /^(\.gitlab-ci\.yml|\.circleci\/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml|Jenkinsfile)$/.test(f.path));
  const gateFiles = [...workflows, ...otherCi].filter((f) => /isoklo/i.test(f.text.replace(/^\s*#.*$/gm, "")));

  // 1. A deterministic merge gate in CI.
  checks.push(gateFiles.length > 0
    ? { id: "merge-gate-ci", title: "Merge gate in CI", status: "pass", severity: "high", detail: `${gateFiles.map((f) => f.path).join(", ")} runs Isoklo on every change.` }
    : {
      id: "merge-gate-ci", title: "Merge gate in CI", status: "fail", severity: "high",
      detail: "No CI workflow runs Isoklo, so agent pull requests can merge without a deterministic check. (The Isoklo GitHub App also counts; it cannot be seen from here.)",
      fix: "run `npx isoklo init --ci`, or install the Isoklo GitHub App on the repository.",
    });

  // 2. A local pre-push hook (optional when CI gates; worth having when it does not).
  const hooks = await hooksDir(root);
  const hookTexts = [
    hooks === null ? null : await read(join(hooks, "pre-push")),
    byPath.get(".husky/pre-push") ?? null,
    byPath.get("lefthook.yml") ?? byPath.get("lefthook.yaml") ?? null,
  ];
  const hasHook = hookTexts.some((t) => t !== null && /isoklo/i.test(t));
  checks.push(hasHook
    ? { id: "pre-push-hook", title: "Pre-push hook", status: "pass", severity: "medium", detail: "A pre-push hook runs Isoklo before changes leave the machine." }
    : {
      id: "pre-push-hook", title: "Pre-push hook", status: gateFiles.length > 0 ? "pass" : "warn", severity: gateFiles.length > 0 ? "info" : "medium",
      detail: gateFiles.length > 0 ? "No pre-push hook; CI gates every change, so this is optional." : "No pre-push hook: problems are found only after a push, if at all.",
      fix: "run `npx isoklo init --hook`.",
    });

  // 3. Workflow token permissions declared.
  const noPerms = workflows.filter((f) => !/^permissions\s*:/m.test(f.text));
  checks.push(workflows.length === 0
    ? { id: "workflow-permissions", title: "Workflow token permissions", status: "pass", severity: "medium", detail: "No GitHub Actions workflows." }
    : noPerms.length === 0
      ? { id: "workflow-permissions", title: "Workflow token permissions", status: "pass", severity: "medium", detail: `All ${workflows.length} workflows declare their token permissions.` }
      : {
        id: "workflow-permissions", title: "Workflow token permissions", status: "warn", severity: "medium",
        detail: `${noPerms.length} of ${workflows.length} workflows do not declare permissions, so they get the repository's default token, which can be read-write: ${noPerms.map((f) => f.path).join(", ")}.`,
        fix: "add `permissions: { contents: read }` at the top of each workflow and widen per job only where needed.",
      });

  // 4. Lockfile present and unambiguous.
  if (byPath.has("package.json")) {
    const locks = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"].filter((l) => byPath.has(l) || files.some((f) => f.path === l));
    const lockExists = locks.length > 0 || (await exists(join(root, "bun.lockb")));
    checks.push(!lockExists
      ? { id: "lockfile", title: "Dependency lockfile", status: "warn", severity: "medium", detail: "package.json has no committed lockfile, so every install can resolve different (possibly hijacked) versions.", fix: "commit the lockfile your package manager writes." }
      : locks.length > 1
        ? { id: "lockfile", title: "Dependency lockfile", status: "warn", severity: "medium", detail: `${locks.length} lockfiles (${locks.join(", ")}): different machines may install different trees.`, fix: "keep the lockfile of the package manager you use and delete the others." }
        : { id: "lockfile", title: "Dependency lockfile", status: "pass", severity: "medium", detail: `${locks[0] ?? "bun.lockb"} pins every installed version.` });
  }

  // 5. .env ignored by git.
  let envIgnored: boolean;
  try {
    await git(root, ["check-ignore", "-q", "--no-index", ".env"]);
    envIgnored = true;
  } catch {
    const gi = byPath.get(".gitignore") ?? (await read(join(root, ".gitignore"))) ?? "";
    envIgnored = /^\s*\/?\.env(\*|\.\*|\s|$)/m.test(gi);
  }
  checks.push(envIgnored
    ? { id: "env-ignored", title: ".env ignored", status: "pass", severity: "medium", detail: ".env files are ignored by git." }
    : { id: "env-ignored", title: ".env ignored", status: "warn", severity: "medium", detail: ".gitignore does not cover .env, so the next `git add .` can commit real credentials.", fix: "add `.env*` to .gitignore, and commit a .env.example with placeholders for anyone setting up." });

  // 6. Code owners for agent and CI configuration.
  const owners = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"].map((p) => byPath.get(p)).find((t) => t !== undefined);
  const covers = owners !== undefined && /^\s*(\*|\/?\.github\/|\/?\.claude\/|\/?\.mcp\.json|\/?AGENTS\.md|\/?CLAUDE\.md|\/?isoklo\.config\.json)/m.test(owners);
  checks.push(covers
    ? { id: "config-owners", title: "Owners for agent and CI config", status: "pass", severity: "medium", detail: "CODEOWNERS assigns reviewers to agent and CI configuration." }
    : {
      id: "config-owners", title: "Owners for agent and CI config", status: "warn", severity: "medium",
      detail: owners === undefined ? "No CODEOWNERS file: nobody is required to review changes to agent or CI configuration." : "CODEOWNERS does not cover .github/, .claude/, .mcp.json or AGENTS.md.",
      fix: "add lines such as `/.github/ @your-team`, `/.claude/ @your-team`, `/.mcp.json @your-team`, `/AGENTS.md @your-team` to .github/CODEOWNERS.",
    });

  // 7. Agent configuration present at all (informational).
  try {
    const top = await readdir(root);
    const agentDirs = top.filter((n) => [".claude", ".cursor", ".codex", ".gemini", ".devin", ".agents", ".vscode"].includes(n));
    if (agentDirs.length > 0 || byPath.has("AGENTS.md") || byPath.has("CLAUDE.md")) {
      checks.push({ id: "agent-config-present", title: "Agent configuration found", status: "pass", severity: "info", detail: `Agent configuration in this repository: ${[...agentDirs, ...["AGENTS.md", "CLAUDE.md"].filter((p) => byPath.has(p))].join(", ")}. Isoklo scanned it.` });
    }
  } catch {
    // unreadable root: nothing to add
  }
  return checks;
}

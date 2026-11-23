/**
 * `isoklo init`: set Isoklo up in one command, with nothing to copy by hand.
 *   --hook    a git pre-push hook (plain git hooks, Husky, or core.hooksPath)
 *   --ci      a CI workflow for the detected host (GitHub Actions or GitLab CI)
 *   --config  isoklo.config.json, with today's findings recorded as the baseline
 *   --require make the check required on the default branch (GitHub ruleset, through the gh CLI)
 * Every step is idempotent: running init twice changes nothing the second time, and files that exist are never
 * overwritten without --force.
 */
import { execFile } from "node:child_process";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { git } from "../check/git.js";
import { SCHEMA_URL } from "../engine/config.js";

export type Host = "github" | "gitlab" | "bitbucket" | "other" | "none";
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export interface Detected {
  root: string;
  host: Host;
  /** owner/name on the host, when the remote says. Credentials in the remote URL are never kept. */
  repo: string | null;
  packageManager: PackageManager | null;
  hookManager: "husky" | "lefthook" | "git";
  /** Where the pre-push hook goes. */
  hookPath: string;
  hasGithubDir: boolean;
}

export interface Step {
  what: string;
  path: string | null;
  status: "created" | "updated" | "unchanged" | "skipped" | "would create" | "would update" | "failed";
  note?: string;
}

const exists = async (p: string) => {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
};
const readOr = async (p: string) => {
  try {
    return await readFile(p, "utf8");
  } catch {
    return null;
  }
};
const toPosix = (p: string) => p.split(sep).join("/");

/** owner/name from a remote URL; userinfo (tokens) is dropped. */
export function parseRemote(url: string): { host: Host; repo: string | null } {
  const m = /^(?:[a-z+]+:\/\/)?(?:[^@/]+@)?([^/:]+)[:/]+(.+?)(?:\.git)?\/?$/i.exec(url.trim());
  if (m === null) return { host: "other", repo: null };
  const hostname = (m[1] ?? "").toLowerCase();
  const host: Host = hostname.endsWith("github.com") ? "github" : hostname.includes("gitlab") ? "gitlab" : hostname.includes("bitbucket") ? "bitbucket" : "other";
  return { host, repo: m[2] ?? null };
}

export async function detect(root: string): Promise<Detected> {
  let remote: string;
  try {
    remote = (await git(root, ["remote", "get-url", "origin"])).trim();
  } catch {
    remote = "";
  }
  const parsed = remote === "" ? { host: "none" as Host, repo: null } : parseRemote(remote);
  const pkgText = await readOr(join(root, "package.json"));
  let packageManager: PackageManager | null = null;
  if (pkgText !== null) {
    const field = /"packageManager"\s*:\s*"(npm|pnpm|yarn|bun)@/.exec(pkgText)?.[1] as PackageManager | undefined;
    packageManager = field
      ?? ((await exists(join(root, "pnpm-lock.yaml"))) ? "pnpm"
        : (await exists(join(root, "yarn.lock"))) ? "yarn"
          : (await exists(join(root, "bun.lockb"))) || (await exists(join(root, "bun.lock"))) ? "bun" : "npm");
  }
  let host = parsed.host;
  if (host === "none" && (await exists(join(root, ".gitlab-ci.yml")))) host = "gitlab";
  const hasGithubDir = await exists(join(root, ".github"));
  if (host === "none" && hasGithubDir) host = "github";

  const husky = await exists(join(root, ".husky"));
  const lefthook = (await exists(join(root, "lefthook.yml"))) || (await exists(join(root, "lefthook.yaml")));
  let hookPath: string;
  if (husky) hookPath = join(root, ".husky", "pre-push");
  else {
    const hooks = (await git(root, ["rev-parse", "--path-format=absolute", "--git-path", "hooks"])).trim();
    hookPath = join(hooks, "pre-push");
  }
  return { root, host, repo: parsed.repo, packageManager, hookManager: husky ? "husky" : lefthook ? "lefthook" : "git", hookPath, hasGithubDir };
}

// ---------------------------------------------------------------- file contents
export const HOOK_MARKER = "# isoklo pre-push hook";

export function hookScript(version: string, withShebang = true): string {
  return `${withShebang ? "#!/bin/sh\n" : ""}${HOOK_MARKER}: proof before merge. Added by \`npx isoklo init\`.
# Checks this branch against its base before every push. Skip once with: git push --no-verify
if [ -x ./node_modules/.bin/isoklo ]; then
  ./node_modules/.bin/isoklo check
elif command -v npx >/dev/null 2>&1; then
  npx --yes isoklo@${version} check
else
  echo "isoklo: npx is not installed, so the pre-push check did not run." >&2
  true
fi
isoklo_status=$?
if [ "$isoklo_status" -eq 1 ]; then
  echo "isoklo: push stopped. Fix the problems above, or push anyway with git push --no-verify." >&2
  exit 1
fi
if [ "$isoklo_status" -eq 2 ]; then
  echo "isoklo: the check could not run (see above), so this push was not checked." >&2
fi
`;
}

export function githubWorkflow(version: string): string {
  return `# Isoklo: proof before merge. Added by \`npx isoklo init\`.
# Blocks pull requests that weaken tests, add invented packages, leak secrets or widen what agents and CI may do.
name: isoklo
on: pull_request # never pull_request_target: the gate reads untrusted code, so it gets no secrets
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: isoklo/isoklo@v0
        with: { version: "${version}" }
`;
}

export function gitlabJob(version: string): string {
  return `# Isoklo: proof before merge. Added by \`npx isoklo init\`.
isoklo:
  stage: .pre
  image: node:22
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"
  script:
    - git fetch --quiet origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - npx --yes isoklo@${version} check --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
`;
}

export function configFile(version: string, baseline: string[]): string {
  return JSON.stringify({
    $schema: SCHEMA_URL.replace("unpkg.com/isoklo/", `unpkg.com/isoklo@${version}/`),
    scope: { allow: [], deny: [] },
    rules: {},
    ignorePaths: [],
    baseline,
  }, null, 2) + "\n";
}

// ---------------------------------------------------------------- steps
export interface ApplyOptions {
  version: string;
  force: boolean;
  dryRun: boolean;
  /** Fingerprints of today's findings, for the config baseline. */
  baseline: string[];
}

async function put(path: string, content: string, o: ApplyOptions, what: string, root: string, mode?: number): Promise<Step> {
  const rel = toPosix(relative(root, path)) || path;
  const current = await readOr(path);
  if (current === content) return { what, path: rel, status: "unchanged" };
  if (current !== null && !o.force) return { what, path: rel, status: "skipped", note: "the file exists; pass --force to replace it" };
  if (o.dryRun) return { what, path: rel, status: current === null ? "would create" : "would update" };
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content);
  if (mode !== undefined) await chmod(path, mode).catch(() => undefined);
  return { what, path: rel, status: current === null ? "created" : "updated" };
}

export async function installHook(d: Detected, o: ApplyOptions): Promise<Step> {
  const what = d.hookManager === "husky" ? "pre-push hook (Husky)" : "pre-push hook";
  const rel = toPosix(relative(d.root, d.hookPath));
  if (d.hookManager === "lefthook") {
    return { what, path: "lefthook.yml", status: "skipped", note: "lefthook manages hooks here; add a pre-push command: `npx --yes isoklo check`" };
  }
  const current = await readOr(d.hookPath);
  if (current !== null && current.includes(HOOK_MARKER)) return { what, path: rel, status: "unchanged" };
  if (current !== null && !o.force) {
    // An existing hook that is not ours: add Isoklo after it rather than replace it.
    if (/\bexit\s+0\s*$/.test(current.trim()) || /\bexec\s/.test(current)) {
      return { what, path: rel, status: "skipped", note: "an existing pre-push hook ends with exit or exec; add `npx --yes isoklo check || exit 1` to it, or pass --force" };
    }
    if (o.dryRun) return { what, path: rel, status: "would update" };
    await writeFile(d.hookPath, `${current.replace(/\s*$/, "\n")}\n${hookScript(o.version, false)}`);
    await chmod(d.hookPath, 0o755).catch(() => undefined);
    return { what, path: rel, status: "updated", note: "added after the existing hook" };
  }
  return put(d.hookPath, hookScript(o.version, d.hookManager !== "husky"), o, what, d.root, 0o755);
}

export async function installCi(d: Detected, o: ApplyOptions): Promise<Step> {
  if (d.host === "github" || (d.host !== "gitlab" && d.hasGithubDir)) {
    return put(join(d.root, ".github", "workflows", "isoklo.yml"), githubWorkflow(o.version), o, "GitHub Actions workflow", d.root);
  }
  if (d.host === "gitlab") {
    const main = join(d.root, ".gitlab-ci.yml");
    const current = await readOr(main);
    if (current === null) return put(main, gitlabJob(o.version), o, "GitLab CI job", d.root);
    if (current.includes("isoklo")) return { what: "GitLab CI job", path: ".gitlab-ci.yml", status: "unchanged" };
    const included = join(d.root, ".gitlab", "isoklo.gitlab-ci.yml");
    const step = await put(included, gitlabJob(o.version), o, "GitLab CI job", d.root);
    if (/^include\s*:/m.test(current)) {
      return { ...step, note: "add `- local: .gitlab/isoklo.gitlab-ci.yml` to the include list in .gitlab-ci.yml" };
    }
    if (!o.dryRun && step.status !== "skipped") await writeFile(main, `${current.replace(/\s*$/, "\n")}\ninclude:\n  - local: .gitlab/isoklo.gitlab-ci.yml\n`);
    return { ...step, note: "included from .gitlab-ci.yml" };
  }
  return { what: "CI workflow", path: null, status: "skipped", note: "no GitHub or GitLab remote found; run `npx isoklo check` in your CI, or use the pre-push hook" };
}

export async function installConfig(d: Detected, o: ApplyOptions): Promise<Step> {
  const path = join(d.root, "isoklo.config.json");
  const current = await readOr(path);
  if (current !== null && o.force) {
    // Refresh the baseline but keep the maintainer's other settings.
    try {
      const doc = JSON.parse(current) as Record<string, unknown>;
      doc["baseline"] = o.baseline;
      return put(path, JSON.stringify(doc, null, 2) + "\n", o, "isoklo.config.json (baseline refreshed)", d.root);
    } catch {
      // not JSON: fall through and replace it
    }
  }
  return put(path, configFile(o.version, o.baseline), o, "isoklo.config.json", d.root);
}

/** Make the Isoklo check required on the default branch, with a repository ruleset created through the gh CLI. */
export function rulesetPayload(context = "check"): string {
  return JSON.stringify({
    name: "isoklo: proof before merge",
    target: "branch",
    enforcement: "active",
    conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } },
    rules: [{ type: "required_status_checks", parameters: { strict_required_status_checks_policy: false, required_status_checks: [{ context }] } }],
  });
}

export function requireCheck(d: Detected, o: ApplyOptions): Promise<Step> {
  const what = "required check on the default branch";
  if (d.host !== "github" || d.repo === null) return Promise.resolve({ what, path: null, status: "skipped", note: "only GitHub repositories with an origin remote are supported" });
  if (o.dryRun) return Promise.resolve({ what, path: null, status: "would create", note: `ruleset on ${d.repo} requiring the "check" status` });
  return new Promise((resolve) => {
    const child = execFile("gh", ["api", "--method", "POST", `repos/${d.repo}/rulesets`, "--input", "-"], { windowsHide: true }, (error, _stdout, stderr) => {
      if (error) {
        const code = (error as NodeJS.ErrnoException).code;
        resolve({
          what, path: null, status: "failed",
          note: code === "ENOENT"
            ? "the GitHub CLI (gh) is not installed; add the rule in Settings → Rules → Rulesets, requiring the check named \"check\""
            : `gh could not create the ruleset (${String(stderr).trim().split("\n")[0] ?? "unknown error"}); you need admin access to ${d.repo}`,
        });
        return;
      }
      resolve({ what, path: null, status: "created", note: `ruleset on ${d.repo}: pull requests need "check" to pass` });
    });
    child.stdin?.end(rulesetPayload());
  });
}

/**
 * Git, run safely: execFile with an argument array (never a shell string), no prompts, no colour, bounded output.
 * Anything that stops Isoklo from reading the change is a GitError, which the CLI turns into exit 2 ("could not run"),
 * never into a pass.
 */
import { execFile } from "node:child_process";

export class GitError extends Error {}

const MAX_OUTPUT = 64 * 1024 * 1024;

export function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      ["-c", "core.quotePath=false", "-c", "color.ui=false", ...args],
      {
        cwd,
        maxBuffer: MAX_OUTPUT,
        windowsHide: true,
        encoding: "utf8",
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_PAGER: "cat", LC_ALL: "C" },
      },
      (error, stdout, stderr) => {
        if (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code === "ENOENT") return reject(new GitError("git is not installed or not on PATH."));
          if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
            return reject(new GitError("the change is too large to read (over 64 MB of diff)."));
          }
          const first = String(stderr).trim().split("\n")[0] ?? error.message;
          return reject(new GitError(first.replace(/^fatal:\s*/, "")));
        }
        resolve(stdout);
      },
    );
  });
}

/** Succeeds only inside a git work tree; returns its top folder. */
export async function repoRoot(cwd: string): Promise<string> {
  try {
    return (await git(cwd, ["rev-parse", "--show-toplevel"])).trim();
  } catch (error) {
    if (error instanceof GitError && /not a git repository/i.test(error.message)) {
      throw new GitError(`"${cwd}" is not inside a git repository.`);
    }
    throw error;
  }
}

async function commitOf(cwd: string, ref: string): Promise<string | null> {
  try {
    return (await git(cwd, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`])).trim() || null;
  } catch {
    return null;
  }
}

/**
 * Pick the base to compare against. An explicit --base wins. Otherwise, in GitHub Actions use the pull request's base
 * branch, then the remote's default branch, then the usual names. Returns the ref and every candidate tried.
 */
export async function resolveBase(cwd: string, explicit: string | undefined): Promise<{ ref: string; tried: string[] }> {
  const candidates: string[] = [];
  if (explicit !== undefined) {
    candidates.push(explicit);
  } else {
    const prBase = process.env["GITHUB_BASE_REF"];
    if (prBase) candidates.push(`origin/${prBase}`);
    try {
      const head = (await git(cwd, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"])).trim();
      if (head) candidates.push(head.replace(/^refs\/remotes\//, ""));
    } catch {
      // no remote default; fall through to the usual names
    }
    candidates.push("origin/main", "main", "origin/master", "master");
  }
  for (const ref of candidates) {
    if ((await commitOf(cwd, ref)) !== null) return { ref, tried: candidates };
  }
  const list = [...new Set(candidates)].join(", ");
  throw new GitError(
    explicit !== undefined
      ? `base "${explicit}" is not a commit in this repository.`
      : `could not find a base branch to compare against (tried ${list}). Pass one with --base.`,
  );
}

export async function headCommit(cwd: string, head: string): Promise<string> {
  const sha = await commitOf(cwd, head);
  if (sha === null) throw new GitError(`head "${head}" is not a commit in this repository.`);
  return sha;
}

/**
 * The pull request's own changes: base...head (three dots) diffs head against the point where it left base,
 * so commits that landed on base afterwards are not mistaken for the agent's work.
 */
export function diffPullRequest(cwd: string, base: string, head: string): Promise<string> {
  return git(cwd, ["diff", "--no-ext-diff", "--unified=0", "--find-renames", `${base}...${head}`]);
}

/** The commit where head left base: the "before" side of the pull request. */
export async function mergeBase(cwd: string, base: string, head: string): Promise<string> {
  return (await git(cwd, ["merge-base", base, head])).trim();
}

/** A file's content at a commit, or null if it does not exist there. */
export async function showFile(cwd: string, rev: string, path: string): Promise<string | null> {
  try {
    return await git(cwd, ["show", `${rev}:${path}`]);
  } catch (error) {
    if (error instanceof GitError && /(does not exist|exists on disk, but not in|bad revision|invalid object name)/i.test(error.message)) {
      return null;
    }
    throw error;
  }
}

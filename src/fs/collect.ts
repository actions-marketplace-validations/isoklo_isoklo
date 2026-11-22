/**
 * Read a repository's files for scan mode (input/output only). Inside git: tracked files plus untracked files that are
 * not ignored (`git add .` would commit them). Outside git: a walk that skips dependency and build folders. Large and
 * binary files are skipped; symlinks are never followed out of the folder.
 */
import { lstat, readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { git, GitError } from "../check/git.js";
import type { ScanFile } from "../engine/scan.js";

export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_FILES = 25_000;

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "out", "coverage", ".next", ".nuxt", ".turbo", ".cache", "target", "__pycache__", ".venv", "venv", "vendor", ".terraform", ".svelte-kit", ".parcel-cache"]);
const toPosix = (p: string) => p.split(sep).join("/");

export interface Collected {
  files: ScanFile[];
  /** Files that were listed but not read (too large, unreadable, or past the file limit). */
  skipped: number;
  inGit: boolean;
}

async function gitList(root: string): Promise<{ tracked: string[]; untracked: string[] } | null> {
  try {
    const tracked = (await git(root, ["ls-files", "-z", "--cached"])).split("\0").filter(Boolean);
    const untracked = (await git(root, ["ls-files", "-z", "--others", "--exclude-standard"])).split("\0").filter(Boolean);
    return { tracked, untracked };
  } catch (error) {
    if (error instanceof GitError) return null;
    throw error;
  }
}

async function walk(root: string, dir: string, out: string[]): Promise<void> {
  if (out.length >= MAX_FILES) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isSymbolicLink()) continue;
    const abs = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(root, abs, out);
    } else if (e.isFile()) {
      out.push(toPosix(relative(root, abs)));
      if (out.length >= MAX_FILES) return;
    }
  }
}

export async function collect(root: string): Promise<Collected> {
  const listed = await gitList(root);
  const paths: { path: string; tracked: boolean }[] = [];
  if (listed !== null) {
    for (const p of listed.tracked) paths.push({ path: p, tracked: true });
    for (const p of listed.untracked) paths.push({ path: p, tracked: false });
  } else {
    const all: string[] = [];
    await walk(root, root, all);
    for (const p of all) paths.push({ path: p, tracked: true });
  }
  const files: ScanFile[] = [];
  let skipped = 0;
  for (const { path, tracked } of paths.slice(0, MAX_FILES)) {
    if (path.split("/").some((part) => part === "node_modules")) continue;
    const abs = join(root, path);
    try {
      const info = await lstat(abs);
      if (!info.isFile() || info.size > MAX_FILE_BYTES) { skipped++; continue; }
      files.push({ path, text: await readFile(abs, "utf8"), tracked });
    } catch {
      skipped++;
    }
  }
  skipped += Math.max(0, paths.length - MAX_FILES);
  return { files, skipped, inGit: listed !== null };
}

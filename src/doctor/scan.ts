/**
 * Scan (input/output only): find the instruction files a repo contains and read them.
 * No judgement happens here; analyze.ts decides what the files mean.
 */
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";
import { FILE_SPECS, type FileSpec } from "./knowledge.js";

/** Never read a single instruction file larger than this; anything bigger is reported but not loaded. */
export const MAX_READ_BYTES = 2 * 1024 * 1024;

export interface ScannedFile {
  specId: string;
  /** Path relative to the repo root, always with forward slashes so reports look the same on every OS. */
  path: string;
  bytes: number;
  /** Text content, or null when the file was too large or unreadable. */
  text: string | null;
  /** Hash of the content, used to spot copies that will drift apart. */
  sha256: string | null;
  /** Set when the file is a symlink: where it points, relative to the repo (null if it points outside the repo). */
  symlinkTo?: string | null;
}

export class ScanError extends Error {}

const toPosix = (p: string) => p.split(sep).join("/");

/**
 * Windows and macOS file systems ignore case, so "claude.md" would answer to "CLAUDE.md". Agents on Linux CI do not
 * ignore case, so only report a file when its exact spelling exists.
 */
async function existsExactCase(root: string, rel: string): Promise<boolean> {
  const parts = rel.split(/[\\/]/);
  let dir = root;
  for (const part of parts) {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      return false;
    }
    if (!names.includes(part)) return false;
    dir = join(dir, part);
  }
  return true;
}

async function readOne(root: string, rootReal: string, spec: FileSpec, rel: string): Promise<ScannedFile | null> {
  const abs = join(root, rel);
  if (!(await existsExactCase(root, rel))) return null;
  let info;
  try {
    info = await lstat(abs);
  } catch {
    return null; // does not exist
  }
  const file: ScannedFile = { specId: spec.id, path: toPosix(rel), bytes: 0, text: null, sha256: null };

  if (info.isSymbolicLink()) {
    // Follow a symlink only if it stays inside the repo: never read files the repo doesn't own.
    let target: string;
    try {
      target = await realpath(abs);
    } catch {
      file.symlinkTo = null;
      return file; // broken link
    }
    const inside = target === rootReal || target.startsWith(rootReal + sep);
    file.symlinkTo = inside ? toPosix(relative(rootReal, target)) : null;
    if (!inside) return file;
    info = await stat(target);
  }
  if (!info.isFile()) return null;

  file.bytes = info.size;
  if (info.size <= MAX_READ_BYTES) {
    const buf = await readFile(abs);
    file.text = buf.toString("utf8");
    file.sha256 = createHash("sha256").update(buf).digest("hex");
  }
  return file;
}

export async function scan(root: string): Promise<ScannedFile[]> {
  let rootInfo;
  try {
    rootInfo = await stat(root);
  } catch {
    throw new ScanError(`cannot read "${root}": no such folder.`);
  }
  if (!rootInfo.isDirectory()) throw new ScanError(`"${root}" is a file, not a folder.`);
  const rootReal = await realpath(root);

  const found: ScannedFile[] = [];
  for (const spec of FILE_SPECS) {
    if (spec.extension === undefined) {
      const f = await readOne(root, rootReal, spec, spec.path);
      if (f) found.push(f);
      continue;
    }
    // Rule folder: direct children, or the whole tree when the vendor reads subfolders; sorted so output is stable
    // on every OS.
    let names: string[];
    try {
      names = (await readdir(join(root, spec.path), { recursive: spec.recursive === true })).map(toPosix).sort();
    } catch {
      continue; // folder does not exist
    }
    for (const name of names) {
      if (!name.toLowerCase().endsWith(spec.extension)) continue;
      const f = await readOne(root, rootReal, spec, join(spec.path, name));
      if (f) found.push(f);
    }
  }
  return found;
}

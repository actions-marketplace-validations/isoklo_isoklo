/**
 * Analyze (pure): turn scanned files into facts and findings. No file system, no printing, so every rule is easy to test.
 */
import { CLAUDE_PRIMARY_IDS, FILE_SPECS, LARGE_FILE_TOKENS, type Agent } from "./knowledge.js";
import type { ScannedFile } from "./scan.js";

export type Level = "review" | "info";

export interface Finding {
  id: string;
  level: Level;
  /** Verdict first, in the examiner voice. */
  message: string;
  /** What to do about it. */
  fix?: string;
  paths: string[];
}

export interface FileReport {
  path: string;
  specId: string;
  /** Estimated tokens (characters ÷ 4, rounded up). An estimate, never exact. */
  tokens: number | null;
  readBy: Agent[];
  note?: string;
}

export interface DoctorReport {
  files: FileReport[];
  findings: Finding[];
  totalTokens: number;
}

export const estimateTokens = (text: string) => Math.ceil(text.length / 4);

/** True when CLAUDE.md-style text pulls AGENTS.md in with Claude Code's import syntax, e.g. "@AGENTS.md" or "@./AGENTS.md". */
export const importsAgentsMd = (text: string) => /(^|\s)@(\.\/)?AGENTS\.md\b/m.test(text);

export function analyze(scanned: ScannedFile[]): DoctorReport {
  const specOf = (id: string) => FILE_SPECS.find((s) => s.id === id);
  const byId = (id: string) => scanned.filter((f) => f.specId === id);
  const findings: Finding[] = [];

  const agentsMd = byId("agents-md")[0];
  const claudePrimary = scanned.filter((f) => (CLAUDE_PRIMARY_IDS as readonly string[]).includes(f.specId));
  const claudeImportsAgents = claudePrimary.some(
    (f) => (f.text !== null && importsAgentsMd(f.text)) || f.symlinkTo === "AGENTS.md",
  );
  // Claude Code falls back to AGENTS.md only when no CLAUDE.md-family file exists.
  const claudeReadsAgentsMd = agentsMd !== undefined && (claudePrimary.length === 0 || claudeImportsAgents);

  const files: FileReport[] = scanned.map((f) => {
    const spec = specOf(f.specId);
    const readBy: Agent[] = [...(spec?.agents ?? [])];
    if (f.specId === "agents-md" && claudeReadsAgentsMd) readBy.unshift("Claude Code");
    const report: FileReport = {
      path: f.path, specId: f.specId, readBy,
      tokens: f.text === null ? null : estimateTokens(f.text),
    };
    if (spec?.note !== undefined) report.note = spec.note;
    return report;
  });

  // 1. AGENTS.md silently ignored by Claude Code.
  if (agentsMd !== undefined && claudePrimary.length > 0 && !claudeImportsAgents) {
    const names = claudePrimary.map((f) => f.path);
    findings.push({
      id: "agents-md-shadowed",
      level: "review",
      message: `Claude Code ignores AGENTS.md here: ${names.join(" and ")} ${names.length > 1 ? "exist" : "exists"} and ${
        names.length > 1 ? "do" : "does"} not import it.`,
      fix: "add the line `@AGENTS.md` to CLAUDE.md, or make CLAUDE.md a symlink to AGENTS.md.",
      paths: ["AGENTS.md", ...names],
    });
  }

  // 2. Identical copies that will drift apart.
  const groups = new Map<string, ScannedFile[]>();
  for (const f of scanned) {
    if (f.sha256 === null || f.symlinkTo !== undefined || (f.text ?? "").trim() === "") continue;
    groups.set(f.sha256, [...(groups.get(f.sha256) ?? []), f]);
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    const paths = group.map((f) => f.path);
    findings.push({
      id: "duplicate-content",
      level: "review",
      message: `${paths.join(" and ")} are identical copies; they will drift apart the first time one is edited.`,
      fix: "keep one file and import or symlink it from the others.",
      paths,
    });
  }

  for (const f of scanned) {
    // 3. Symlinks that point outside the repo or nowhere.
    if (f.symlinkTo === null) {
      findings.push({
        id: "symlink-outside", level: "review",
        message: `${f.path} is a symlink that points outside this repo or to nothing; agents may not see it, and Isoklo did not read it.`,
        fix: "point it at a file inside the repo, or replace it with a real file.",
        paths: [f.path],
      });
      continue;
    }
    if (f.text === null) {
      findings.push({
        id: "too-large-to-read", level: "review",
        message: `${f.path} is ${f.bytes.toLocaleString("en-US")} bytes; Isoklo did not read it.`,
        fix: "instruction files this large are rarely followed; split or trim it.",
        paths: [f.path],
      });
      continue;
    }
    // 4. Empty files.
    if (f.text.trim() === "") {
      findings.push({
        id: "empty-file", level: "review",
        message: `${f.path} is empty, so it gives agents nothing.`,
        fix: "add instructions or delete the file.",
        paths: [f.path],
      });
      continue;
    }
    // 5. Large files.
    const tokens = estimateTokens(f.text);
    if (tokens > LARGE_FILE_TOKENS) {
      findings.push({
        id: "large-file", level: "review",
        message: `${f.path} is about ${tokens.toLocaleString("en-US")} tokens (estimate). Every agent task pays for it, and long files are followed less reliably.`,
        fix: `trim it below ${LARGE_FILE_TOKENS.toLocaleString("en-US")} tokens; keep only what an agent cannot work out from the code.`,
        paths: [f.path],
      });
    }
  }

  // 6. Legacy Cursor rules next to the current format.
  if (byId("cursorrules").length > 0) {
    const both = byId("cursor-rules").length > 0;
    findings.push({
      id: "cursorrules-legacy", level: both ? "review" : "info",
      message: both
        ? ".cursorrules (legacy) and .cursor/rules both exist; the two can disagree."
        : ".cursorrules is Cursor's legacy format.",
      fix: "move its rules into .cursor/rules, or into AGENTS.md so every agent shares them.",
      paths: [".cursorrules"],
    });
  }

  // 7. Nothing found.
  if (scanned.length === 0) {
    findings.push({
      id: "no-instructions", level: "info",
      message: "No agent instruction files found. Agents will work from the code alone.",
      fix: "that is fine. If you add one, start with AGENTS.md: most agents read it.",
      paths: [],
    });
  }

  const totalTokens = files.reduce((n, f) => n + (f.tokens ?? 0), 0);
  return { files, findings, totalTokens };
}

/**
 * agent/hidden-unicode, agent/prompt-injection, agent/approvals-disabled: the text an agent reads, and the switches
 * that stop a person from approving what it does.
 *
 * Note for maintainers: trigger strings are written with a character class (permission[s]) so these rule files do not
 * match themselves when Isoklo checks its own pull requests.
 */
import type { Finding } from "../../check/types.js";
import { clip, isDocPath } from "../../engine/text.js";
import { decodeTags, visible } from "../../engine/visible.js";
import { findingFrom, type ContentUnit, type Hit } from "../content.js";
import { isAgentFile, isAgentInstructions } from "../paths.js";

// ---------------------------------------------------------------- hidden Unicode
const TAGS = /[\u{E0000}-\u{E007F}]+/gu;
const HAS_BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const HAS_VARIATION_SUPPLEMENT = /[\u{E0100}-\u{E01EF}]/u;
const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060-\u2064\u180E\uFEFF\u00AD]/g;

/** Show invisible characters as visible tokens, so the evidence line reads the way a model reads it. */
export const revealInvisible = visible;

/** Data and prose files (translations, docs) use bidi controls legitimately; code does not. */
const isCodePath = (path: string) => /\.(m?[jt]sx?|cjs|cts|py|rb|go|rs|java|kt|kts|scala|cs|fs|swift|c|cc|cpp|h|hpp|php|sh|bash|zsh|ps1|lua|dart|ex|exs|sql|vue|svelte|astro)$/i.test(path);

/** Zero-width joiners inside emoji sequences and non-joiners inside Persian or Indic words are text, not tricks. */
function legitimateZeroWidth(line: string, index: number): boolean {
  const c = line[index];
  const before = [...line.slice(Math.max(0, index - 2), index)].pop() ?? "";
  const after = [...line.slice(index + 1, index + 3)][0] ?? "";
  if (c === "\u200D" && /\p{Extended_Pictographic}|\p{Emoji_Modifier}|\uFE0F/u.test(before) && /\p{Extended_Pictographic}/u.test(after)) return true;
  if ((c === "\u200C" || c === "\u200D") && /[^\p{ASCII}]/u.test(before) && /\p{L}|\p{M}/u.test(before) && /\p{L}|\p{M}/u.test(after) && /[^\p{ASCII}]/u.test(after)) return true;
  return false;
}

export function hiddenUnicode(u: ContentUnit): Finding | null {
  const agent = isAgentFile(u.path);
  // Bidi controls are Trojan Source in code; in translations, data and docs they are usually real right-to-left text.
  const data = !agent && !isCodePath(u.path);
  const hits: Hit[] = [];
  for (const l of u.lines) {
    const found: string[] = [];
    let severity: Hit["severity"] = "high";
    let level: Hit["level"] = "blocked";
    const tags = l.text.match(TAGS);
    if (tags) { found.push(`Unicode tag characters that spell "${clip(decodeTags(tags.join("")), 60)}"`); severity = "critical"; }
    if (HAS_VARIATION_SUPPLEMENT.test(l.text)) { found.push("hidden variation-selector data"); severity = "critical"; }
    if (HAS_BIDI.test(l.text)) {
      found.push("bidirectional control characters (Trojan Source)");
      if (agent) severity = "critical";
      else if (data && found.length === 1) { level = "review"; severity = "medium"; }
    }
    if (agent) {
      const zw = [...l.text.matchAll(ZERO_WIDTH)].filter((m) => !(m[0] === "\uFEFF" && l.line === 1 && m.index === 0) && !legitimateZeroWidth(l.text, m.index));
      if (zw.length > 0) { found.push(`${zw.length} zero-width character${zw.length === 1 ? "" : "s"}`); severity = "critical"; }
    }
    if (found.length > 0) hits.push({ line: l.line, text: clip(revealInvisible(l.text)), level, severity, what: found.join(" and ") });
  }
  return findingFrom("agent", "hidden-unicode", u.path, hits,
    (whats) => `Hidden characters in ${agent ? "agent-facing file " : ""}${u.path}: ${whats.join("; ")}. People reviewing the file cannot see them; ${agent ? "the agent reads them as instructions" : "compilers and models read them"}.`,
    "delete the invisible characters (the evidence shows where they are), then check where the text came from.");
}

// ---------------------------------------------------------------- prompt injection
interface InjectionPattern {
  re: RegExp;
  level: Hit["level"];
  severity: Hit["severity"];
  what: string;
  /** Skip when a negation sits just before the match ("never ignore previous instructions"). */
  negatable?: boolean;
  /**
   * Skip when the sentence before the match is negated ("Do not push to main without asking the user"). Only for
   * review-level patterns: a whole-sentence window would let an attacker open with "Never mind," to dodge a block.
   */
  sentenceNegatable?: boolean;
}

const INJECTION: readonly InjectionPattern[] = [
  {
    re: /\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|every\s+)?(of\s+)?(the\s+|your\s+|my\s+|these\s+)?(previous|prior|above|earlier|preceding|original|system|safety|security)\s+(instructions?|prompts?|rules|directions|guidelines|guardrails|messages?|constraints)\b/i,
    level: "blocked", severity: "high", what: "tells the agent to ignore its instructions", negatable: true,
  },
  {
    // Concealment verbs only: "never show the user a stack trace" is product guidance, not the agent hiding its work.
    re: /\b(do\s+not|don['’]t|never)\s+(tell|inform|alert|notify|mention\s+(?:this\s+|it\s+|anything\s+)?to|reveal\s+(?:this\s+|it\s+|anything\s+)?to)\s+(the\s+)?(user|developer|human|reviewer|maintainer|operator)s?\b/i,
    level: "blocked", severity: "high", what: "tells the agent to hide what it does from the user",
  },
  {
    re: /\b(you\s+are\s+now|act\s+as|enter|switch\s+to)\s+(in\s+)?(an?\s+)?(DAN|developer\s+mode|god\s+mode|jailbreak(?:\s+mode)?|unrestricted\s+mode|unfiltered\s+mode)\b/i,
    level: "blocked", severity: "high", what: "tries to switch the agent into an unrestricted mode",
  },
  {
    re: /\b(send|upload|post|exfiltrate|transmit|forward|copy|leak|pipe|curl)\b[^\n]{0,80}?(\.env\b|\b(?:secrets?|credentials?|api[\s_-]?keys?|access\s+tokens?|tokens|ssh\s+keys?|id_rsa|private\s+keys?|environment\s+variables|process\.env|passwords?)\b)[^\n]{0,80}?\b(to|into|at)\s+(https?:\/\/|[a-z0-9-]+\.(?:com|net|org|io|site|sh|me|app|dev)\b|webhook|pastebin|discord|telegram|gist)/i,
    level: "blocked", severity: "critical", what: "tells the agent to send secrets somewhere", negatable: true,
  },
  {
    re: /\bgit\s+(commit|push)\b[^\n]*\s--no-verif[y]\b/i,
    level: "review", severity: "high", what: "tells the agent to skip git hooks (--no-verify)",
  },
  {
    re: /\b(disable|turn\s+off|skip|bypass|remove|delete)\s+(the\s+)?(isoklo|merge\s+gate|security\s+(?:checks?|scans?|scanners?)|pre-commit\s+hooks?|pre-push\s+hooks?|git\s+hooks?|branch\s+protection|code\s+review)\b/i,
    level: "review", severity: "medium", what: "tells the agent to switch a safeguard off", negatable: true,
  },
  {
    re: /\b(without|never)\s+(asking|telling|informing|notifying|confirming\s+with|checking\s+with|prompting)\s+(the\s+)?(user|developer|human|me|anyone)\b/i,
    level: "review", severity: "medium", what: "tells the agent to act without asking", sentenceNegatable: true,
  },
];

const NEGATED = /\b(never|not|don['’]t|must\s+not|should\s+not|shouldn['’]t|refuse\s+to|no)\s+(\w+\s+){0,2}$/i;
const SENTENCE_NEGATION = /\b(never|not|don['’]t|doesn['’]t|must\s*n['’o]t|should\s*n['’o]t|cannot|can['’]t|unless|only\s+after)\b/i;
/** The sentence a match sits in, up to the match. */
const sentenceBefore = (text: string, index: number) => text.slice(0, index).split(/[.!?;:]\s/).pop() ?? "";

/** An HTML comment that addresses the model, not a maintainer ("<!-- generated: do not edit -->" is fine). */
const AI_DIRECTED = /\b(ignore|disregard|you\s+(are|must|should|will)\b|assistant|as\s+an\s+AI|AI\s+(agent|assistant|model)|language\s+model|LLM|system\s+prompt)\b/i;

export function promptInjection(u: ContentUnit): Finding | null {
  if (!isAgentInstructions(u.path)) return null;
  const hits: Hit[] = [];
  let inComment = false;
  let prevLine = -1;
  for (const l of u.lines) {
    // Lines must be consecutive for a comment to carry over (check mode reads only added lines).
    if (l.line !== prevLine + 1) inComment = false;
    prevLine = l.line;
    for (const p of INJECTION) {
      const m = p.re.exec(l.text);
      if (m === null) continue;
      if (p.negatable === true && NEGATED.test(l.text.slice(0, m.index))) continue;
      if (p.sentenceNegatable === true && SENTENCE_NEGATION.test(sentenceBefore(l.text, m.index))) continue;
      hits.push({ line: l.line, text: clip(l.text), level: p.level, severity: p.severity, what: p.what });
      break;
    }
    // Hidden HTML comments: invisible when the Markdown is rendered, read in full by the agent.
    const opens = l.text.includes("<!--");
    const commentText = opens ? l.text.slice(l.text.indexOf("<!--")) : inComment ? l.text : "";
    if (commentText !== "" && AI_DIRECTED.test(commentText) && !hits.some((h) => h.line === l.line)) {
      hits.push({ line: l.line, text: clip(l.text), level: "review", severity: "medium", what: "hides instructions for the agent in an HTML comment that rendered Markdown does not show" });
    }
    if (opens) inComment = !l.text.slice(l.text.lastIndexOf("<!--")).includes("-->");
    else if (inComment && l.text.includes("-->")) inComment = false;
  }
  return findingFrom("agent", "prompt-injection", u.path, hits,
    (whats) => `Agent instructions in ${u.path} ${whats.join("; ")}.`,
    "remove the text; if it arrived in a pull request, treat the source as untrusted and check what else it changed.");
}

// ---------------------------------------------------------------- approvals and sandbox switched off
interface Switch { re: RegExp; severity: Hit["severity"]; what: string }

const SWITCHES: readonly Switch[] = [
  { re: /--dangerously-skip-permission[s]\b/, severity: "critical", what: "runs Claude Code with every permission check off" },
  { re: /--dangerously-bypass-approvals-and-sandbo[x]\b/, severity: "critical", what: "runs Codex with approvals and the sandbox off" },
  { re: /--permission-mode[=\s]+["']?bypassPermission[s]\b/, severity: "critical", what: "runs Claude Code in bypassPermissions mode" },
  { re: /--allow-all-tool[s]\b/, severity: "critical", what: "pre-approves every tool for the GitHub Copilot CLI" },
  { re: /--approval-mode[=\s]+["']?yol[o]\b|\b(gemini|qwen|codex|cursor-agent|opencode)\b[^\n]*\s--yol[o]\b/, severity: "critical", what: "runs the agent with every action auto-approved (yolo)" },
  { re: /\bsandbox_mode\s*=\s*["']danger-full-acces[s]["']/, severity: "critical", what: "gives Codex full disk and network access (danger-full-access)" },
  { re: /\bapproval_policy\s*=\s*["']neve[r]["']/, severity: "high", what: "sets Codex to never ask for approval" },
  { re: /["']chat\.tools\.(global\.)?autoApprov[e]["']\s*:\s*true/, severity: "high", what: "auto-approves every tool call in VS Code agent mode" },
];

export function approvalsDisabled(u: ContentUnit): Finding | null {
  const agent = isAgentFile(u.path);
  // Prose about these flags (READMEs, docs) is not a setting; agent instruction files are, since the agent obeys them.
  if (!agent && isDocPath(u.path)) return null;
  const hits: Hit[] = [];
  for (const l of u.lines) {
    for (const s of SWITCHES) {
      if (s.re.test(l.text)) { hits.push({ line: l.line, text: clip(l.text), level: "blocked", severity: s.severity, what: s.what }); break; }
    }
  }
  return findingFrom("agent", "approvals-disabled", u.path, hits,
    (whats) => `Agent safety switched off in ${u.path}: it ${whats.join("; ")}.`,
    "remove the flag or setting; if an agent must run unattended, run it in a disposable sandbox with no secrets and an allowlist of commands.");
}

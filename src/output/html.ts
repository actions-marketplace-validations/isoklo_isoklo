/**
 * The executive audit report: one self-contained HTML file (no scripts, no network requests) that prints cleanly to
 * PDF. Euklo's visual language: ink and paper, one brass mark (the evidence seal), Jost for display, Atkinson
 * Hyperlegible for text and code. Every value from the repository is HTML-escaped: evidence is untrusted input.
 */
import type { CheckSummary } from "../check/report.js";
import { countBySeverity, findingsOf, verdictOf } from "../check/report.js";
import type { Finding, Severity, Suite } from "../check/types.js";
import type { DoctorReport } from "../doctor/analyze.js";
import { GRADE_MEANING, type Posture } from "../doctor/grade.js";
import type { Receipt } from "../engine/receipt.js";
import { ruleMeta } from "../engine/registry.js";
import { FONT_FACES } from "./fonts.js";
import { visible } from "../engine/visible.js";

export interface AuditInput {
  repository: string;
  generatedAt: Date;
  version: string;
  preparedFor?: string;
  preparedBy?: string;
  scan: CheckSummary;
  /** Optional: a change checked against its base (`report --diff main...HEAD`). */
  check?: CheckSummary;
  posture: Posture;
  instructions?: DoctorReport;
  receipt: Receipt;
  commit?: string | null;
}

/**
 * Every value that reaches the page goes through here: invisible and control characters become visible tokens (no
 * bidi reordering of the evidence), then HTML is escaped for both text and attribute contexts.
 */
export const esc = (s: unknown) =>
  visible(String(s ?? "")).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/`/g, "&#96;");
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const cap = (s: string) => (s === "" ? s : s[0]?.toUpperCase() + s.slice(1));
const date = (d: Date) => d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

const SUITE_NAME: Record<Suite, string> = {
  agent: "Agent instructions and permissions",
  mcp: "MCP servers",
  tamper: "Guardrail tampering",
  deps: "Supply chain",
  sec: "Secrets, exfiltration and CI",
  scope: "Scope",
};
const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", info: "Info" };

const SYMBOL = (cls: string) =>
  `<svg class="${cls}" viewBox="9 9 102 102" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="16"><path d="M47.26 43.54A12.74 12.74 0 0 1 60 56.28L60 90.26A12.74 12.74 0 0 0 72.74 103"/><path d="M60 20.19h0" stroke-width="22"/></g></svg>`;

/** The one brass mark on the page: the evidence seal, around the receipt. */
function seal(digest: string): string {
  // One ring of text, stretched to the circle exactly (2πr for r = 74), so it closes on itself at every font size.
  const ring = "ISOKLO · EVIDENCE RECEIPT · SEALED · DETERMINISTIC · ";
  return `<svg class="seal" viewBox="0 0 200 200" role="img" aria-label="Isoklo evidence seal">
  <defs><path id="sealpath" d="M100,100 m-74,0 a74,74 0 1,1 148,0 a74,74 0 1,1 -148,0"/></defs>
  <circle cx="100" cy="100" r="96" fill="none" stroke="currentColor" stroke-width="2.5"/>
  <circle cx="100" cy="100" r="88" fill="none" stroke="currentColor" stroke-width="1"/>
  <circle cx="100" cy="100" r="60" fill="none" stroke="currentColor" stroke-width="1"/>
  <text font-size="11" fill="currentColor" font-family="var(--font-display)"><textPath href="#sealpath" textLength="462" lengthAdjust="spacing">${ring}</textPath></text>
  <g transform="translate(70 56) scale(0.6)" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="13"><path d="M38.26 34.54A12.74 12.74 0 0 1 51 47.28L51 81.26A12.74 12.74 0 0 0 63.74 94"/><path d="M51 11.19h0" stroke-width="19"/></g>
  <text x="100" y="138" text-anchor="middle" font-size="7.5" letter-spacing="0.6" fill="currentColor" font-family="var(--font-mono)">${esc(digest.slice(0, 16))}</text>
</svg>`;
}

function executiveSummary(i: AuditInput, findings: Finding[]): string {
  const blocked = findings.filter((f) => f.level === "blocked");
  const crit = blocked.filter((f) => f.severity === "critical").length;
  const p = i.posture;
  const gaps = p.checks.filter((c) => c.status !== "pass");
  const sentences: string[] = [];
  sentences.push(
    `Isoklo read ${plural(i.scan.filesChanged, "file")} in <strong>${esc(i.repository)}</strong> on ${esc(date(i.generatedAt))}, with ${plural(i.scan.rulesRun?.length ?? 0, "deterministic rule")}` +
      (i.check ? ` and checked the change ${esc(`${i.check.base}...${i.check.head}`)} (${plural(i.check.filesChanged, "file")}) with ${plural(i.check.rulesRun?.length ?? 0, "more")}` : "") + ".",
  );
  sentences.push(blocked.length === 0
    ? "It found nothing that should stop a merge."
    : `It found <strong>${plural(blocked.length, "problem")} that should stop a merge</strong>${crit > 0 ? `, ${crit} of them critical` : ""}.`);
  sentences.push(`The repository's AI-agent security posture grades <strong>${p.grade}</strong> (${p.score} out of 100): ${esc(GRADE_MEANING[p.grade])}`);
  if (gaps.length > 0) sentences.push(`Safeguards to add: ${gaps.map((c) => esc(c.title.toLowerCase())).join(", ")}.`);
  const top = findings.filter((f) => f.level !== "info").slice(0, 3);
  const topList = top.length === 0 ? "" : `<h3>Fix first</h3><ol class="top">${top.map((f) => {
    const meta = f.ruleId ? ruleMeta(f.ruleId) : undefined;
    const at = f.evidence[0];
    return `<li><span class="sev sev-${f.severity}">${SEV_LABEL[f.severity ?? "info"]}</span> <strong>${esc(meta?.title ?? f.id)}</strong>${at ? ` in <code>${esc(at.path)}:${at.line}</code>` : ""}. ${esc(cap(f.fix))}</li>`;
  }).join("")}</ol>`;
  return `<p class="lede">${sentences.join(" ")}</p>${topList}`;
}

function matrix(findings: Finding[]): string {
  const suites: Suite[] = ["agent", "mcp", "tamper", "deps", "sec", "scope"];
  const sevs: Severity[] = ["critical", "high", "medium", "info"];
  const count = (s: Suite, v: Severity) => findings.filter((f) => (f.ruleId ?? "").startsWith(`${s}/`) && f.severity === v && (f.level !== "info" || v === "info")).length;
  const rows = suites.map((s) => {
    const cells = sevs.map((v) => {
      const n = count(s, v);
      return `<td class="${n > 0 ? `hot sev-${v}-cell` : "zero"}">${n}</td>`;
    }).join("");
    return `<tr><th scope="row">${esc(SUITE_NAME[s])}</th>${cells}</tr>`;
  }).join("");
  return `<table class="matrix"><thead><tr><th></th>${sevs.map((v) => `<th scope="col">${SEV_LABEL[v]}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>`;
}

function postureList(p: Posture): string {
  return `<ul class="checks">${p.checks.map((c) => `<li class="check check-${c.status}"><span class="mark" aria-label="${c.status}">${c.status === "pass" ? "✓" : c.status === "fail" ? "✕" : "△"}</span><div><strong>${esc(c.title)}</strong><span class="detail">${esc(c.detail)}</span>${c.status !== "pass" && c.fix ? `<span class="fix">Fix: ${esc(c.fix)}</span>` : ""}</div></li>`).join("")}</ul>`;
}

function findingCard(f: Finding, n: number, source: string): string {
  const meta = f.ruleId ? ruleMeta(f.ruleId) : undefined;
  const evidence = f.evidence.slice(0, 12).map((e) => `<tr><td class="loc"><code>${esc(e.path)}:${e.line}</code></td><td><code class="snippet">${esc(e.text) || "<span class=\"muted\">(whole file)</span>"}</code></td></tr>`).join("");
  return `<article class="finding sev-border-${f.severity}" id="f${n}">
  <header><span class="num">${String(n).padStart(2, "0")}</span><span class="sev sev-${f.severity}">${SEV_LABEL[f.severity ?? "info"]}</span><span class="verdict verdict-${f.level}">${f.level === "blocked" ? "Blocks merge" : f.level === "review" ? "Review" : "Note"}</span><code class="rule">${esc(f.ruleId ?? f.id)}</code><span class="source">${esc(source)}</span></header>
  <h3>${esc(meta?.title ?? f.id)}</h3>
  <p class="msg">${esc(f.message)}</p>
  ${evidence ? `<table class="evidence"><tbody>${evidence}</tbody></table>${f.evidence.length > 12 ? `<p class="muted small">and ${f.evidence.length - 12} more locations</p>` : ""}` : ""}
  ${meta ? `<p class="why"><span class="label">Why it matters</span>${esc(meta.why)}</p>` : ""}
  <p class="fixline"><span class="label">${f.allowedBecause !== undefined ? "Accepted" : "Fix"}</span>${esc(cap(f.allowedBecause ?? f.fix))}</p>
</article>`;
}

export function toHtml(i: AuditInput): string {
  const scanFindings = findingsOf(i.scan).map((f) => ({ f, source: "Repository files" }));
  const checkFindings = i.check ? findingsOf(i.check).map((f) => ({ f, source: `Change ${i.check?.base}...${i.check?.head}` })) : [];
  const seen = new Set<string>();
  const all = [...checkFindings, ...scanFindings].filter(({ f }) => {
    const key = f.fingerprint ?? `${f.ruleId}:${f.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const rank = { blocked: 0, review: 1, info: 2 } as const;
  const sevRank = { critical: 0, high: 1, medium: 2, info: 3 } as const;
  all.sort((a, b) => rank[a.f.level] - rank[b.f.level] || sevRank[a.f.severity ?? "info"] - sevRank[b.f.severity ?? "info"]);
  const findings = all.map((x) => x.f);
  const actionable = all.filter(({ f }) => f.level !== "info");
  const notes = all.filter(({ f }) => f.level === "info");
  const counts = countBySeverity(findings);
  const verdict = i.check ? verdictOf(i.check) === "blocked" || verdictOf(i.scan) === "blocked" ? "blocked" : "passed" : verdictOf(i.scan);
  const blockedCount = findings.filter((f) => f.level === "blocked").length;
  const r = i.receipt;
  const title = `Isoklo audit: ${i.repository}`;

  const checklist = actionable.map(({ f }, k) => {
    const at = f.evidence[0];
    return `<li><label><input type="checkbox"><span class="box" aria-hidden="true"></span><span><span class="sev sev-${f.severity}">${SEV_LABEL[f.severity ?? "info"]}</span> ${esc(cap(f.fix))}${at ? ` <code>${esc(at.path)}:${at.line}</code>` : ""} <a href="#f${k + 1}" class="ref">${esc(f.ruleId ?? f.id)}</a></span></label></li>`;
  }).join("");

  const instructions = i.instructions && i.instructions.files.length > 0
    ? `<h3>Agent instruction files</h3><table class="plain"><thead><tr><th>File</th><th>Read by</th><th class="num">Tokens (est.)</th></tr></thead><tbody>${i.instructions.files.map((f) => `<tr><td><code>${esc(f.path)}</code></td><td>${esc(f.readBy.join(", ") || "no agent")}</td><td class="num">${f.tokens ?? "–"}</td></tr>`).join("")}</tbody></table>${i.instructions.findings.length > 0 ? `<ul class="notes">${i.instructions.findings.map((f) => `<li>${esc(f.message)}${f.fix ? ` <span class="muted">Fix: ${esc(f.fix)}</span>` : ""}</li>`).join("")}</ul>` : ""}`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="isoklo ${esc(i.version)}">
<meta name="color-scheme" content="light">
<title>${esc(title)}</title>
<style>
${FONT_FACES}
:root {
  --ink: #11100E; --paper: #F7F6F3; --white: #FFFFFF;
  --stone-100: #EFEEEB; --stone-200: #E2E0DD; --stone-300: #CECDCA; --stone-400: #AAA9A6; --stone-500: #878683;
  --stone-600: #6B6A68; --stone-700: #4F4E4C; --stone-800: #343330; --stone-900: #1F1E1C;
  --brass: #B39F77; --brass-deep: #75603C;
  --critical: #AF302B; --critical-tint: #FFEEEC; --high: #B5483A; --medium: #8D561E; --medium-tint: #FDF2DD;
  --success: #2F7145; --success-tint: #E7F8EA; --info: #6B6A68;
  --font-display: 'Jost', 'Futura', 'Century Gothic', 'Avenir Next', system-ui, sans-serif;
  --font-text: 'Atkinson Hyperlegible Next', 'Atkinson Hyperlegible', 'Segoe UI', system-ui, -apple-system, sans-serif;
  --font-mono: 'Atkinson Hyperlegible Mono', ui-monospace, 'SFMono-Regular', 'Cascadia Mono', Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 15px/1.6 var(--font-text); -webkit-print-color-adjust: exact; print-color-adjust: exact; }
code, .mono { font-family: var(--font-mono); font-size: .86em; }
a { color: inherit; }
.wrap { max-width: 920px; margin: 0 auto; padding: 0 40px; }
/* Cover: ink */
.cover { background: var(--ink); color: var(--paper); padding: 40px 0 44px; }
.brandrow { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.wordmark { display: flex; align-items: center; gap: 10px; font: 500 22px/1 var(--font-display); letter-spacing: .01em; }
.wordmark .sym { width: 26px; height: 26px; color: var(--paper); }
.byline { font: 500 11px/1 var(--font-display); letter-spacing: .18em; text-transform: uppercase; color: var(--stone-300); }
.eyebrow { margin: 56px 0 10px; font: 500 12px/1 var(--font-display); letter-spacing: .2em; text-transform: uppercase; color: var(--stone-400); }
.cover h1 { margin: 0; font: 500 44px/1.06 var(--font-display); letter-spacing: -.02em; word-break: break-word; }
.meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px 24px; margin: 28px 0 0; padding: 18px 0 0; border-top: 1px solid var(--stone-800); }
.meta dt { font: 500 10.5px/1.2 var(--font-display); letter-spacing: .16em; text-transform: uppercase; color: var(--stone-400); }
.meta dd { margin: 4px 0 0; font-size: 13.5px; color: var(--paper); word-break: break-word; }
.verdictband { display: grid; grid-template-columns: auto 1fr; gap: 28px; align-items: center; margin-top: 36px; padding: 24px; border: 1px solid var(--stone-800); border-radius: 4px; background: var(--stone-900); }
.grade { width: 108px; height: 108px; display: grid; place-items: center; border: 2px solid var(--paper); border-radius: 50%; font: 500 60px/1 var(--font-display); }
.grade-A, .grade-B { border-color: #7ECA93; color: #7ECA93; }
.grade-C { border-color: #E6B764; color: #E6B764; }
.grade-D, .grade-F { border-color: #F18C81; color: #F18C81; }
.vtitle { font: 500 24px/1.2 var(--font-display); margin: 0 0 4px; }
.vsub { margin: 0 0 14px; color: var(--stone-300); font-size: 14px; }
.strip { display: flex; flex-wrap: wrap; gap: 8px; }
.pill { display: inline-flex; align-items: baseline; gap: 6px; padding: 5px 11px; border-radius: 999px; border: 1px solid var(--stone-700); font-size: 12.5px; color: var(--stone-200); }
.pill b { font: 500 15px/1 var(--font-display); color: var(--paper); }
.pill.c b { color: #F18C81; } .pill.h b { color: #F5A38F; } .pill.m b { color: #E6B764; }
/* Body */
main { padding: 8px 0 40px; }
section { padding: 34px 0 6px; border-bottom: 1px solid var(--stone-200); counter-increment: section; }
section:last-of-type { border-bottom: 0; }
h2 { font: 500 26px/1.15 var(--font-display); letter-spacing: -.01em; margin: 0 0 16px; }
h2::before { content: counter(section, decimal-leading-zero); display: block; font: 500 11px/1 var(--font-display); letter-spacing: .2em; color: var(--stone-500); margin-bottom: 10px; }
h3 { font: 500 17px/1.3 var(--font-display); margin: 22px 0 10px; }
.lede { font-size: 17px; line-height: 1.65; margin: 0; max-width: 68ch; }
ol.top { margin: 0; padding-left: 22px; } ol.top li { margin: 6px 0; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 3px; font: 500 10.5px/1.7 var(--font-display); letter-spacing: .1em; text-transform: uppercase; vertical-align: 1px; white-space: nowrap; }
.sev-critical { background: var(--critical); color: var(--white); }
.sev-high { background: var(--critical-tint); color: var(--critical); box-shadow: inset 0 0 0 1px #E8B4AF; }
.sev-medium { background: var(--medium-tint); color: var(--medium); box-shadow: inset 0 0 0 1px #E9CF9F; }
.sev-info { background: var(--stone-100); color: var(--stone-600); }
.grid2 { display: grid; grid-template-columns: 1.1fr 1fr; gap: 28px; align-items: start; }
table { border-collapse: collapse; width: 100%; }
.matrix th, .matrix td { padding: 9px 10px; border-bottom: 1px solid var(--stone-200); text-align: center; font-size: 13.5px; }
.matrix th[scope=row] { text-align: left; font-weight: 400; }
.matrix thead th { font: 500 10.5px/1 var(--font-display); letter-spacing: .14em; text-transform: uppercase; color: var(--stone-600); }
.matrix td.zero { color: var(--stone-300); }
.matrix td.hot { font: 500 15px/1 var(--font-display); }
.sev-critical-cell { color: var(--critical); } .sev-high-cell { color: var(--high); } .sev-medium-cell { color: var(--medium); } .sev-info-cell { color: var(--info); }
.checks { list-style: none; margin: 0; padding: 0; }
.check { display: grid; grid-template-columns: 22px 1fr; gap: 8px; padding: 9px 0; border-bottom: 1px solid var(--stone-200); font-size: 13.5px; }
.check .mark { font: 500 14px/1.5 var(--font-display); }
.check-pass .mark { color: var(--success); } .check-fail .mark { color: var(--critical); } .check-warn .mark { color: var(--medium); }
.check .detail { display: block; color: var(--stone-700); }
.check .fix { display: block; color: var(--stone-600); font-size: 12.5px; margin-top: 2px; }
.deductions { font-size: 12.5px; color: var(--stone-600); margin-top: 10px; }
/* Findings */
.finding { background: var(--white); border: 1px solid var(--stone-200); border-left: 4px solid var(--stone-300); border-radius: 4px; padding: 18px 20px 14px; margin: 0 0 16px; break-inside: avoid; }
.sev-border-critical { border-left-color: var(--critical); } .sev-border-high { border-left-color: var(--high); } .sev-border-medium { border-left-color: #C99A4E; }
.finding header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-size: 12px; color: var(--stone-600); }
.finding .num { font: 500 12px/1 var(--font-mono); color: var(--stone-500); }
.finding .verdict { font: 500 10.5px/1.7 var(--font-display); letter-spacing: .1em; text-transform: uppercase; }
.verdict-blocked { color: var(--critical); } .verdict-review { color: var(--medium); } .verdict-info { color: var(--stone-500); }
.finding .rule { margin-left: auto; color: var(--stone-700); }
.finding .source { color: var(--stone-500); }
.finding h3 { margin: 10px 0 4px; font-size: 18px; }
.msg { margin: 0 0 12px; }
.evidence { margin: 0 0 12px; border: 1px solid var(--stone-200); border-radius: 3px; background: var(--paper); }
.evidence td { padding: 6px 10px; vertical-align: top; border-bottom: 1px solid var(--stone-200); font-size: 12.5px; }
.evidence tr:last-child td { border-bottom: 0; }
.evidence .loc { white-space: nowrap; width: 1%; color: var(--stone-700); }
.snippet { white-space: pre-wrap; word-break: break-word; color: var(--ink); }
.label { display: block; font: 500 10.5px/1.4 var(--font-display); letter-spacing: .14em; text-transform: uppercase; color: var(--stone-500); margin-bottom: 2px; }
.why, .fixline { margin: 8px 0 0; font-size: 13.5px; }
.why { color: var(--stone-700); }
.muted { color: var(--stone-500); } .small { font-size: 12.5px; }
/* Checklist */
.checklist { list-style: none; margin: 0; padding: 0; counter-reset: item; }
.checklist li { padding: 8px 0; border-bottom: 1px solid var(--stone-200); font-size: 13.5px; }
.checklist label { display: grid; grid-template-columns: 22px 1fr; gap: 10px; cursor: pointer; }
.checklist input { position: absolute; opacity: 0; }
.checklist .box { width: 16px; height: 16px; margin-top: 3px; border: 1.5px solid var(--stone-600); border-radius: 2px; }
.checklist input:checked + .box { background: var(--ink); box-shadow: inset 0 0 0 3px var(--white); }
.checklist input:focus-visible + .box { outline: 2px solid var(--ink); outline-offset: 2px; }
.ref { color: var(--stone-500); font-family: var(--font-mono); font-size: 11.5px; text-decoration: none; }
/* Receipt and seal: the only brass on the page */
.receipt { display: grid; grid-template-columns: 170px 1fr; gap: 28px; align-items: center; }
.seal { width: 170px; height: 170px; color: var(--brass-deep); }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; font-size: 13px; }
.kv dt { color: var(--stone-600); } .kv dd { margin: 0; word-break: break-all; }
pre.cmd { background: var(--ink); color: var(--paper); padding: 10px 14px; border-radius: 3px; font: 12.5px/1.5 var(--font-mono); overflow-x: auto; }
.plain th, .plain td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--stone-200); font-size: 13px; }
.plain th { font: 500 10.5px/1.4 var(--font-display); letter-spacing: .14em; text-transform: uppercase; color: var(--stone-600); }
td.num, th.num { text-align: right; }
.notes { font-size: 13px; color: var(--stone-700); }
footer.page { border-top: 1px solid var(--stone-200); padding: 18px 0 40px; font-size: 12px; color: var(--stone-600); display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
footer.page .sym { width: 14px; height: 14px; vertical-align: -2px; color: var(--ink); }
@media (max-width: 720px) {
  .wrap { padding: 0 16px; }
  .cover h1 { font-size: 32px; }
  .meta { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .verdictband, .grid2, .receipt { grid-template-columns: 1fr; }
  .finding .rule { margin-left: 0; }
}
@page { size: A4; margin: 14mm 14mm 16mm; }
@media print {
  body { font-size: 10.5pt; background: var(--white); }
  .wrap { max-width: none; padding: 0; }
  .cover { margin: -14mm -14mm 0; padding: 14mm 14mm 12mm; break-after: page; min-height: 100vh; }
  section { break-inside: auto; }
  h2, h3 { break-after: avoid; }
  .finding, .check, .checklist li, .receipt, table.matrix { break-inside: avoid; }
  .finding { background: var(--white); }
  a { text-decoration: none; }
}
</style>
</head>
<body>
<header class="cover">
  <div class="wrap">
    <div class="brandrow"><div class="wordmark">${SYMBOL("sym")}<span>isoklo</span></div><div class="byline">by Euklo</div></div>
    <p class="eyebrow">AI-agent security audit</p>
    <h1>${esc(i.repository)}</h1>
    <dl class="meta">
      <div><dt>Prepared for</dt><dd>${esc(i.preparedFor ?? i.repository)}</dd></div>
      <div><dt>Prepared by</dt><dd>${esc(i.preparedBy ?? "Isoklo")}</dd></div>
      <div><dt>Date</dt><dd>${esc(date(i.generatedAt))}</dd></div>
      <div><dt>Commit</dt><dd class="mono">${esc(i.commit ? i.commit.slice(0, 12) : "working tree")}</dd></div>
    </dl>
    <div class="verdictband">
      <div class="grade grade-${i.posture.grade}" aria-label="Grade ${i.posture.grade}">${i.posture.grade}</div>
      <div>
        <p class="vtitle">${verdict === "blocked" ? `Merge blocked: ${plural(blockedCount, "problem")} to fix` : "No problems that block a merge"}</p>
        <p class="vsub">Posture ${i.posture.score}/100. ${esc(GRADE_MEANING[i.posture.grade])}</p>
        <div class="strip">
          <span class="pill c"><b>${counts.critical}</b> critical</span>
          <span class="pill h"><b>${counts.high}</b> high</span>
          <span class="pill m"><b>${counts.medium}</b> medium</span>
          <span class="pill"><b>${notes.length}</b> notes</span>
        </div>
      </div>
    </div>
  </div>
</header>
<main class="wrap">
  <section>
    <h2>Executive summary</h2>
    ${executiveSummary(i, findings)}
  </section>
  <section>
    <h2>Risk overview</h2>
    <div class="grid2">
      <div><h3>Findings by area and severity</h3>${matrix(findings)}</div>
      <div><h3>Safeguards</h3>${postureList(i.posture)}
        ${i.posture.deductions.length > 0 ? `<p class="deductions">Grade arithmetic: 100 ${i.posture.deductions.map((d) => `− ${d.points} (${esc(d.source)})`).join(" ")} = ${i.posture.score}.</p>` : ""}
      </div>
    </div>
    ${instructions}
  </section>
  <section>
    <h2>Findings</h2>
    ${actionable.length === 0 ? `<p class="lede">No findings that need action. Every rule passed.</p>` : actionable.map(({ f, source }, k) => findingCard(f, k + 1, source)).join("\n")}
    ${notes.length > 0 ? `<h3>Notes for the record</h3><ul class="notes">${notes.map(({ f }) => `<li><code>${esc(f.ruleId ?? f.id)}</code> ${esc(f.message)}${f.allowedBecause ? ` <span class="muted">(${esc(f.allowedBecause)})</span>` : ""}</li>`).join("")}</ul>` : ""}
  </section>
  <section>
    <h2>Remediation checklist</h2>
    ${actionable.length === 0 ? `<p>Nothing to fix. To keep it that way, gate every pull request: <code>npx isoklo init</code>, or install the Isoklo GitHub App.</p>` : `<ul class="checklist">${checklist}</ul>`}
    ${i.posture.checks.filter((c) => c.status !== "pass" && c.fix).length > 0 ? `<h3>Safeguards to add</h3><ul class="checklist">${i.posture.checks.filter((c) => c.status !== "pass" && c.fix).map((c) => `<li><label><input type="checkbox"><span class="box" aria-hidden="true"></span><span><strong>${esc(c.title)}.</strong> ${esc(cap(c.fix ?? ""))}</span></label></li>`).join("")}</ul>` : ""}
  </section>
  <section>
    <h2>Evidence receipt</h2>
    <div class="receipt">
      ${seal(r.integrity.digest)}
      <div>
        <p>This report is backed by a canonical JSON receipt of the run. Its SHA-256 digest changes if a single finding, rule version or timestamp is altered.</p>
        <dl class="kv">
          <dt>Digest</dt><dd class="mono">sha256:${esc(r.integrity.digest)}</dd>
          <dt>Signature</dt><dd>${r.integrity.signature ? `HMAC-SHA256, key ${esc(r.integrity.signature.keyId)}` : "unsigned"}</dd>
          <dt>Engine</dt><dd>isoklo ${esc(r.engineVersion)} · ${plural(r.rules.length, "rule")} · ${esc(r.mode)}</dd>
          <dt>Issued</dt><dd>${esc(r.createdAt)}</dd>
          <dt>Verdict</dt><dd>${esc(r.verdict)} · ${r.counts.byLevel.blocked} blocked, ${r.counts.byLevel.review} to review</dd>
        </dl>
        <pre class="cmd">npx isoklo verify isoklo-receipt.json</pre>
      </div>
    </div>
  </section>
  <section>
    <h2>Method and limits</h2>
    <p>Isoklo applies fixed rules: no model is asked for an opinion, so the same repository and change always get the same result. It reads agent instructions and settings, MCP server configurations, CI workflows, dependency manifests and lockfiles, and every text file for secrets, hidden Unicode and remote code execution. When a change is checked, it also compares tests, type-checking, linting and coverage settings before and after, and looks up new packages on npm and PyPI. Secret values are masked to their first four characters in this report.</p>
    <p class="muted">It does not judge code quality or find logic bugs, and its patterns can miss unusual styles; misses are far more likely than false alarms, and every finding above shows its evidence so it can be checked. Rules run: ${esc((r.rules ?? []).map((x) => `${x.id}@${x.version}`).join(", "))}.</p>
  </section>
</main>
<footer class="page wrap"><span>${SYMBOL("sym")} isoklo ${esc(i.version)} · proof before merge</span><span>Generated ${esc(i.generatedAt.toISOString().slice(0, 16).replace("T", " "))} UTC · by Euklo</span></footer>
</body>
</html>
`;
}

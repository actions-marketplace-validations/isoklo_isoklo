/**
 * Rule 1: weakened tests. Pure: parsed diff in, findings out.
 *
 * Blocks when a change:
 *   - deletes a test file that had assertions (and they did not move elsewhere),
 *   - removes more assertions than it adds back,
 *   - replaces assertions with ones that can never fail,
 *   - skips a test, or focuses one so the others stop running.
 * Fairness: moved or reformatted assertions cancel out across all test files; a reviewable
 * `isoklo: allow-test-change <reason>` comment in a file turns that file's blocks into "review".
 */
import type { FileDiff } from "./diff.js";
import { ALLOW_MARKER, disables, isAssertion, isTautology, isTestPath, normalize } from "./patterns.js";
import type { Evidence, Finding, RuleResult } from "./types.js";


interface Tagged extends Evidence {
  norm: string;
  deletedFile: boolean;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Remove pairs that are the same line on both sides: moved or reformatted, not changed. */
function cancel(removed: Tagged[], added: Tagged[]): { removed: Tagged[]; added: Tagged[] } {
  const addCount = new Map<string, number>();
  for (const a of added) addCount.set(a.norm, (addCount.get(a.norm) ?? 0) + 1);
  const remCount = new Map<string, number>();
  for (const r of removed) remCount.set(r.norm, (remCount.get(r.norm) ?? 0) + 1);

  const keptRemoved = removed.filter((r) => {
    const n = addCount.get(r.norm) ?? 0;
    if (n > 0) { addCount.set(r.norm, n - 1); return false; }
    return true;
  });
  const keptAdded = added.filter((a) => {
    const n = remCount.get(a.norm) ?? 0;
    if (n > 0) { remCount.set(a.norm, n - 1); return false; }
    return true;
  });
  return { removed: keptRemoved, added: keptAdded };
}

export function weakenedTests(files: FileDiff[]): RuleResult {
  const tests = files.filter((f) => !f.binary && isTestPath(f.newPath ?? f.oldPath ?? "") );
  const pathOf = (f: FileDiff) => f.newPath ?? f.oldPath ?? "";

  // Collect assertion and disable lines on both sides, plus allow markers.
  const remAsserts: Tagged[] = [];
  const addAsserts: Tagged[] = [];
  const remDisables: Tagged[] = [];
  const addDisables: (Tagged & { what: string })[] = [];
  const allow = new Map<string, string>(); // path -> reason ("" if missing)

  for (const f of tests) {
    const deleted = f.status === "deleted";
    const oldP = f.oldPath ?? pathOf(f);
    const newP = pathOf(f);
    for (const l of f.removed) {
      const t: Tagged = { path: oldP, line: l.line, text: l.text.trim(), norm: normalize(l.text), deletedFile: deleted };
      if (!deleted && l.newAt !== undefined) t.anchor = { path: newP, line: l.newAt };
      if (isAssertion(l.text)) remAsserts.push(t);
      if (disables(l.text) !== null) remDisables.push(t);
    }
    for (const l of f.added) {
      const m = ALLOW_MARKER.exec(l.text);
      if (m) allow.set(newP, (m[1] ?? "").trim());
      const t: Tagged = { path: newP, line: l.line, text: l.text.trim(), norm: normalize(l.text), deletedFile: false };
      if (isAssertion(l.text)) addAsserts.push(t);
      const what = disables(l.text);
      if (what !== null) addDisables.push({ ...t, what });
    }
  }

  const asserts = cancel(remAsserts, addAsserts);
  const dis = cancel(remDisables, addDisables);
  const newDisables = addDisables.filter((d) => dis.added.includes(d));

  const findings: Finding[] = [];
  const ev = ({ path, line, text, anchor }: Tagged): Evidence => (anchor ? { path, line, text, anchor } : { path, line, text });

  // Deleted test files whose assertions did not move elsewhere.
  const byDeletedFile = new Map<string, Tagged[]>();
  for (const r of asserts.removed.filter((x) => x.deletedFile)) {
    byDeletedFile.set(r.path, [...(byDeletedFile.get(r.path) ?? []), r]);
  }
  for (const [path, lost] of byDeletedFile) {
    findings.push({
      rule: "weakened-tests", id: "test-file-deleted", level: "blocked",
      message: `Test file deleted: ${path} had ${plural(lost.length, "assertion")}, and none of them moved to another test.`,
      fix: "restore the file, or move its assertions into another test file.",
      evidence: lost.map(ev),
    });
  }

  // Assertions removed from files that still exist, against real (non-tautological) assertions added.
  const removedLive = asserts.removed.filter((x) => !x.deletedFile);
  const addedReal = asserts.added.filter((x) => !isTautology(x.text));
  const addedTaut = asserts.added.filter((x) => isTautology(x.text));
  if (removedLive.length > addedReal.length) {
    const net = removedLive.length - addedReal.length;
    findings.push({
      rule: "weakened-tests", id: "assertions-removed", level: "blocked",
      message: `Tests weakened: ${plural(removedLive.length, "assertion")} removed, ${addedReal.length} added in their place, ${plural(net, "check")} fewer.`,
      fix: "restore the removed assertions, or replace each one with an assertion that checks the same behaviour.",
      evidence: removedLive.map(ev),
    });
  }

  // Assertions that can never fail.
  if (addedTaut.length > 0) {
    findings.push({
      rule: "weakened-tests", id: "tautology",
      level: removedLive.length > 0 || byDeletedFile.size > 0 ? "blocked" : "review",
      message: `${plural(addedTaut.length, "assertion")} added that can never fail.`,
      fix: "assert on the real result of the code under test.",
      evidence: addedTaut.map(ev),
    });
  }

  // Tests switched off or focused.
  for (const d of newDisables) {
    findings.push({
      rule: "weakened-tests", id: "test-disabled", level: "blocked",
      message: `Test disabled: ${d.path}:${d.line} ${d.what}.`,
      fix: "remove the skip or focus marker, or fix the test so it can run.",
      evidence: [ev(d)],
    });
  }

  // Escape hatch: every file a finding points at carries a reasoned allow marker -> review, not blocked.
  for (const f of findings) {
    const paths = [...new Set(f.evidence.map((e) => e.path))];
    const reasons = paths.map((p) => allow.get(p));
    if (reasons.every((r) => r !== undefined && r !== "")) {
      f.level = "review";
      f.allowedBecause = [...new Set(reasons as string[])].join("; ");
    } else if (reasons.some((r) => r === "")) {
      f.fix += " The isoklo: allow-test-change marker needs a reason after it.";
    }
  }

  const passes: string[] = [];
  if (tests.length === 0) passes.push("No test files changed.");
  else {
    if (!findings.some((f) => f.id === "test-file-deleted")) passes.push("No test files deleted.");
    if (!findings.some((f) => f.id === "assertions-removed")) {
      passes.push(removedLive.length > 0
        ? `${plural(removedLive.length, "assertion")} changed, and at least as many added back.`
        : "No assertions removed.");
    }
    if (!findings.some((f) => f.id === "test-disabled")) passes.push("No tests skipped or focused.");
  }

  return {
    rule: "weakened-tests",
    findings,
    passes,
    stats: { testFiles: tests.length, assertionsRemoved: remAsserts.length, assertionsAdded: addAsserts.length },
  };
}

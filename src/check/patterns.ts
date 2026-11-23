/**
 * What counts as a test file, an assertion, a disabled test and an empty assertion, across common languages.
 * Patterns are heuristics: they will miss unusual styles (false negatives) far more often than they misfire.
 * Keep them here, as data, so they can grow with real-world examples and tests.
 */

const TEST_PATH: readonly RegExp[] = [
  /(^|\/)(__tests__|tests?|spec|specs|e2e)\//i,
  /\.(test|spec|e2e|cy|it|integration)\.[cm]?[jt]sx?$/i, // also Playwright *.e2e.ts and Cypress *.cy.ts
  /(^|\/)test_[^/]+\.py$/i,
  /_test\.(py|go|rb|exs?)$/i,
  /(^|\/)[^/]*Tests?\.(java|kt|cs|swift)$/,
  /_spec\.rb$/i,
];

export const isTestPath = (path: string) => TEST_PATH.some((re) => re.test(path));

/** A line that checks something. */
const ASSERTION: readonly RegExp[] = [
  /\bexpect\s*\(/, // jest, vitest, chai, rspec-style
  /\bassert(\.\w+)?\s*\(/, // node:assert, chai assert, python assert(...)
  /^\s*assert\s/, // python, swift, elixir
  /\bself\.assert\w*\s*\(/, // unittest
  /\bpytest\.raises\s*\(/,
  /\b(Assert|Assertions)\.\w+\s*\(/, // NUnit, xUnit, JUnit 5
  /\bassert(That|Equals|True|False|Null|NotNull|Throws)\s*\(/, // JUnit / AssertJ static imports
  /\bt\.(Error|Errorf|Fatal|Fatalf|Fail|FailNow)\b/, // Go testing
  /\b(require|assert)\.\w+\s*\(\s*t\b/, // Go testify
  /\.should(\.|\s*\()/, // chai should
  /\bt\.(is|not|deepEqual|true|false|throws|truthy|falsy)\s*\(/, // ava, node:test t.*
];

export const isAssertion = (line: string) => {
  const code = line.replace(/^\s*(\/\/|#).*$/, ""); // a commented-out line is not an assertion
  return code.trim() !== "" && ASSERTION.some((re) => re.test(code));
};

/** A line that switches tests off, or focuses one so the others stop running. */
const DISABLE: readonly { re: RegExp; what: string }[] = [
  { re: /\b(it|test|describe|context|suite)\.(skip|todo)\s*\(/, what: "skips a test" },
  { re: /\b(it|test|describe|context|suite)\.only\s*\(/, what: "focuses one test, so the others stop running" },
  { re: /\b(xit|xdescribe|xtest|fit|fdescribe)\s*\(/, what: "skips or focuses a test" },
  { re: /@pytest\.mark\.(skip|skipif|xfail)\b/, what: "skips a test" },
  { re: /@unittest\.(skip|skipIf|skipUnless|expectedFailure)\b/, what: "skips a test" },
  { re: /\bpytest\.skip\s*\(/, what: "skips a test" },
  { re: /\bt\.(Skip|Skipf|SkipNow)\s*\(/, what: "skips a test" },
  { re: /@(Disabled|Ignore)\b/, what: "skips a test" },
  { re: /\[(Ignore|Skip)\b/, what: "skips a test" },
];

export function disables(line: string): string | null {
  const code = line.replace(/^\s*(\/\/|#).*$/, "");
  for (const { re, what } of DISABLE) if (re.test(code)) return what;
  return null;
}

/** Assertions that can never fail: they add a line but no coverage. */
const TAUTOLOGY: readonly RegExp[] = [
  /\bexpect\s*\(\s*(true|false|null|undefined|\d+|'[^']*'|"[^"]*")\s*\)\s*\.\s*(toBe|toEqual|toStrictEqual)\s*\(\s*\1\s*\)/,
  /\bexpect\s*\(\s*true\s*\)\s*\.\s*toBeTruthy\s*\(\s*\)/,
  /\bassert(\.ok)?\s*\(\s*(true|1)\s*\)/,
  /^\s*assert\s+(True|1)\s*$/,
  /^\s*assert\s+(\d+)\s*==\s*\1\s*$/,
  /\bself\.assertTrue\s*\(\s*True\s*\)/,
  /\bassertTrue\s*\(\s*true\s*\)/,
];

export const isTautology = (line: string) => TAUTOLOGY.some((re) => re.test(line));

/** The reviewable escape hatch: a comment in the changed test file saying why the change is intentional. */
export const ALLOW_MARKER = /isoklo:\s*allow-test-change\b\s*[:-]?\s*(.*)$/;

/** Two lines are "the same" if they differ only in whitespace or a trailing ; or , (reformatting, not a change). */
export const normalize = (line: string) => line.trim().replace(/\s+/g, " ").replace(/[;,]\s*$/, "");

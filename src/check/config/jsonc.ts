/**
 * Parse JSON that may contain comments and trailing commas (VS Code and some agents allow them). Zero dependencies.
 * Returns undefined when the text is not valid even after that.
 */
export function parseJsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    const next = text[i + 1];
    if (inString) {
      out += c;
      if (c === "\\") { out += next ?? ""; i++; continue; }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === "/" && next === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; continue; }
    if (c === "/" && next === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; continue; }
    out += c;
  }
  const noTrailing = out.replace(/,(\s*[}\]])/g, "$1");
  try {
    return JSON.parse(noTrailing);
  } catch {
    return undefined;
  }
}

export const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** First line (1-based) where `"key"` appears as a JSON key, for evidence. */
export function keyLine(text: string, key: string): { line: number; text: string } {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const lines = text.split(/\r?\n/);
  const i = lines.findIndex((l) => new RegExp(`"${escaped}"\\s*:`).test(l));
  return i < 0 ? { line: 1, text: "" } : { line: i + 1, text: (lines[i] ?? "").trim() };
}

/** First line containing a JSON string value, for evidence on array entries. */
export function valueLine(text: string, value: string): { line: number; text: string } {
  const lines = text.split(/\r?\n/);
  const needle = JSON.stringify(value);
  const i = lines.findIndex((l) => l.includes(needle));
  return i < 0 ? { line: 1, text: "" } : { line: i + 1, text: (lines[i] ?? "").trim() };
}

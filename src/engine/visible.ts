/**
 * Make text safe to show: every character a reader cannot see, or that changes how the text around it is drawn,
 * becomes a visible token. Applied to every message and evidence line Isoklo prints, writes or posts, so a hostile
 * file cannot clear a terminal or fake a "passed" line (ANSI escapes), reorder a report (bidi controls), or hide text.
 */
import { clip } from "./text.js";

const TAGS = /[\u{E0000}-\u{E007F}]+/gu;
const VARIATION_SUPPLEMENT = /[\u{E0100}-\u{E01EF}]+/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;
const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060-\u2064\u180E\uFEFF\u00AD]/g;
/** C0 controls (except tab), DEL and C1 controls: terminal escape sequences start here. */
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

const hex = (c: string) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;

/** Unicode tag characters mirror ASCII (U+E0041 is "A"): decode them to show what is hidden. */
export const decodeTags = (run: string) =>
  [...run].map((c) => {
    const cp = (c.codePointAt(0) ?? 0) - 0xe0000;
    return cp >= 0x20 && cp <= 0x7e ? String.fromCharCode(cp) : "";
  }).join("");

/** Show invisible and control characters as visible tokens, so text reads the way a model or terminal reads it. */
export function visible(text: string): string {
  return text
    .replace(TAGS, (run) => `⟨hidden text: "${clip(decodeTags(run), 80)}"⟩`)
    .replace(VARIATION_SUPPLEMENT, (run) => `⟨${[...run].length} hidden variation selectors⟩`)
    .replace(BIDI, (c) => `⟨${hex(c)}⟩`)
    .replace(ZERO_WIDTH, (c) => `⟨${hex(c)}⟩`)
    .replace(CONTROL, (c) => `⟨${hex(c)}⟩`)
    .replace(/\r?\n/g, " ");
}

/**
 * sec/secret-leaked, sec/env-file-committed, sec/remote-code-exec, sec/env-exfiltration, sec/exfil-endpoint.
 */
import type { Finding } from "../../check/types.js";
import { basename, clip, entropy, isDocPath, isGeneratedPath, isLockfile, plural } from "../../engine/text.js";
import { findingFrom, type ContentUnit, type Hit } from "../content.js";
import { isAgentFile } from "../paths.js";
import { findSecrets, maskSecrets, maskValue } from "./secrets.js";

// ---------------------------------------------------------------- secrets
export function secretLeaked(u: ContentUnit): Finding | null {
  if (/\.(min\.js|map)$/.test(u.path)) return null;
  const hits: Hit[] = [];
  for (const l of u.lines) {
    if (l.text.length > 4000) continue; // minified or data lines
    const found = findSecrets(l.text).filter((s) => !(isLockfile(u.path) && s.kind.startsWith("possible secret")));
    if (found.length === 0) continue;
    const worst = found.find((s) => s.level === "blocked") ?? (found[0] as (typeof found)[number]);
    hits.push({ line: l.line, text: clip(maskSecrets(l.text)), level: worst.level, severity: worst.severity, what: found.map((s) => `${s.kind} (${maskValue(s.value)})`).join(", ") });
  }
  return findingFrom("sec", "secret-leaked", u.path, hits,
    (whats, all) => `${all.some((h) => h.level === "blocked") ? "Secret" : "Possible secret"} in ${u.path}: ${whats.join("; ")}.`,
    "revoke and rotate the key first (it is in git history now), then load it from an environment variable or secret manager. If it is a test value, move it to a path listed in ignorePaths.");
}

// ---------------------------------------------------------------- .env files
const ENV_FILE = /^(\.env(\.[\w.-]+)?|[\w.-]+\.env)$/;
const ENV_TEMPLATE = /\.(example|sample|template|tmpl|tpl|dist|defaults?|schema|enc|vault|keep)$|example|sample|template/i;
const ENV_ALWAYS_SECRET = /^\.env(\.(local|prod|production|staging|development\.local|production\.local))?$|(^|\.)prod(uction)?\.env$/;

export const isEnvFile = (path: string) => {
  const b = basename(path);
  return ENV_FILE.test(b) && !ENV_TEMPLATE.test(b) && b !== ".envrc";
};

export function envFileCommitted(u: ContentUnit): Finding | null {
  if (!isEnvFile(u.path) || u.status === "deleted") return null;
  const b = basename(u.path);
  const hits: Hit[] = [];
  for (const l of u.lines) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(l.text);
    if (!m) continue;
    const value = (m[2] ?? "").trim().replace(/^["']|["']$/g, "");
    if (value === "" || /^(changeme|todo|xxx+|<.*>|\$\{.*\}|your[_-].*|example.*|placeholder|true|false|\d{1,6}|localhost.*|127\.0\.0\.1.*|development|production|test)$/i.test(value)) continue;
    const secretLooking = findSecrets(l.text).length > 0 || (value.length >= 16 && entropy(value) >= 3.5) || /(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL)/i.test(m[1] ?? "");
    if (!secretLooking && !ENV_ALWAYS_SECRET.test(b)) continue;
    hits.push({ line: l.line, text: clip(`${m[1]}=${maskValue(value)}`), level: "blocked", severity: "critical", what: m[1] ?? "" });
  }
  if (hits.length === 0) return null;
  const where = u.mode === "scan" && u.tracked === false ? "is not ignored by git, so the next git add commits it" : "is committed";
  return findingFrom("sec", "env-file-committed", u.path, hits,
    () => `Environment file ${u.path} ${where}, with ${plural(hits.length, "value")} that look${hits.length === 1 ? "s" : ""} real: ${hits.slice(0, 6).map((h) => h.what).join(", ")}${hits.length > 6 ? ", …" : ""}.`,
    `remove it from git (git rm --cached ${u.path}), add it to .gitignore, rotate the values, and commit a ${b}.example with placeholders instead.`);
}

// ---------------------------------------------------------------- downloading and running remote code
// Command names are spelled with a character class (ie[x]) so these patterns do not match their own source line.
// An interpreter only counts when it reads its program from the pipe (`| python3`, `| node -`), not when it formats
// data (`| python3 -m json.tool`). `[^\s=]+=` keeps the env-assignment loop unambiguous, so long lines stay fast.
const PIPE_TO_SHELL =
  /\b(curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+([^\s=]+=\S*\s+)*)?(ba|z|da|k|fi)?sh\b|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)(\s*$|\s*[;&|)#]|\s+-(\s|$))|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(ie[x]|Invoke-Expressio[n])\b|\b(ie[x]|Invoke-Expressio[n])\b\s*\(?\s*\(?\s*(New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebReques[t]|Invoke-RestMetho[d])/i;
const PROCESS_SUBSTITUTION = /\b(ba|z)?sh\s+(-c\s+)?["']?<\(\s*(curl|wget)\b|\beval\s+["']?\$\(\s*(curl|wget)\b|\bsource\s+<\(\s*(curl|wget)\b/i;
const DECODE_AND_RUN = /\bbase64\s+(-d|--decode|-D)\b[^\n|]*\|\s*(ba|z)?sh\b|\becho\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64\s+(-d|--decode)/i;
const EVAL_FETCHED = /\b(exec|eval)\s*\(\s*(requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s*\(|\beval\s*\(\s*(await\s+)?\(?\s*(await\s+)?fetch\s*\(|new\s+Function\s*\(\s*await\s+\(?\s*(await\s+)?fetch\s*\(/;

/** Official installers that are conventionally piped to a shell; still worth a look, not a block. */
const KNOWN_INSTALLERS = [
  "sh.rustup.rs", "get.docker.com", "deno.land", "bun.sh", "astral.sh", "install.python-poetry.org", "get.pnpm.io",
  "raw.githubusercontent.com/nvm-sh/", "raw.githubusercontent.com/Homebrew/", "sdk.cloud.google.com", "get.helm.sh",
  "install.determinate.systems", "nixos.org", "fnm.vercel.app", "deb.nodesource.com", "rpm.nodesource.com", "aka.ms",
  "claude.ai/install", "cli.github.com", "starship.rs", "get.sdkman.io", "foundry.paradigm.xyz", "dot.net/v1",
  "packages.microsoft.com", "pyenv.run", "rye.astral.sh", "volta.sh", "mise.run", "get.jenkins.io", "golang.org",
];

const urlOf = (line: string) => /https?:\/\/[^\s"'`|)<>]+/.exec(line)?.[0] ?? null;

/** An official installer only by exact host (and path prefix where given): sh.rustup.rs.evil.dev is not sh.rustup.rs. */
export function isKnownInstaller(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const host = u.hostname.toLowerCase();
  return KNOWN_INSTALLERS.some((k) => {
    const [kh, ...kp] = k.split("/");
    return host === kh && (kp.length === 0 || kp.join("/") === "" || u.pathname.startsWith(`/${kp.join("/")}`));
  });
}

export function remoteCodeExec(u: ContentUnit): Finding | null {
  const agent = isAgentFile(u.path);
  if (!agent && isDocPath(u.path)) return null;
  const hits: Hit[] = [];
  for (const l of u.lines) {
    let what: string | null = null;
    let critical = false;
    if (DECODE_AND_RUN.test(l.text)) { what = "decodes hidden base64 and runs it in a shell"; critical = true; }
    else if (EVAL_FETCHED.test(l.text)) { what = "evaluates code downloaded at run time"; critical = true; }
    else if (PIPE_TO_SHELL.test(l.text) || PROCESS_SUBSTITUTION.test(l.text)) what = "downloads a script and runs it in a shell";
    if (what === null) continue;
    const url = urlOf(l.text);
    const known = url !== null && isKnownInstaller(url);
    const level = agent || critical || !known ? "blocked" : "review";
    const severity = agent || critical ? "critical" : known ? "medium" : "high";
    hits.push({ line: l.line, text: clip(maskSecrets(l.text)), level, severity, what: known ? `${what} (from ${url})` : url ? `${what} from ${url}` : what });
  }
  return findingFrom("sec", "remote-code-exec", u.path, hits,
    (whats) => `${agent ? `Agent instructions in ${u.path} tell the agent to run remote code` : `${u.path} runs remote code`}: it ${whats.join("; ")}.`,
    "download the file, pin it by version and checksum (or use a package manager), and run the checked copy.");
}

// ---------------------------------------------------------------- exfiltration
const WHOLE_ENV =
  /JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|values)\(\s*process\.env\s*\)|json\.dumps\(\s*(dict\(\s*)?os\.environ|dict\(\s*os\.environ\s*\)|str\(\s*os\.environ\s*\)|\bprintenv\b[^\n]*\||\benv\s*\|\s*(curl|nc|ncat|base64|gzip)\b|Deno\.env\.toObject\(\)|\bos\.Environ\(\)/;
const ALL_SECRETS = /toJSON\(\s*secrets\s*\)/;
const NETWORK = /\b(fetch|axios|got|superagent|request|http\.request|https\.request|XMLHttpRequest|sendBeacon|WebSocket|requests\.(get|post|put)|urllib|urlopen|httpx|curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod)\b|https?:\/\//;

const STRONG_EXFIL = /\b(webhook\.site|requestbin\.net|burpcollaborator\.net|oastify\.com|interact\.sh|interactsh\.com|oast\.(fun|me|live|site|online|pro)|canarytokens\.com|dnslog\.cn|ceye\.io|requestcatcher\.com|beeceptor\.com|postb\.in|ptsv[23]\.com|hookbin\.com|transfer\.sh|0x0\.st|file\.io|pastebin\.com\/api|paste\.ee|hastebin\.com|termbin\.com)\b/i;
// Tunnels are only worth a look when the code actually calls one (a URL), not when a dev-server setting allows them
// (Next.js allowedDevOrigins: ["*.ngrok-free.app"]).
const WEAK_EXFIL = /https?:\/\/[\w.-]*\b(ngrok(-free)?\.(io|app|dev)|pipedream\.net|trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run)\b/i;

export function envExfiltration(u: ContentUnit): Finding | null {
  if (isDocPath(u.path) && !isAgentFile(u.path)) return null;
  const hits: Hit[] = [];
  const byLine = new Map(u.lines.map((l) => [l.line, l.text]));
  const near = (n: number) => {
    for (let i = n - 5; i <= n + 5; i++) {
      const t = byLine.get(i);
      if (t !== undefined && (NETWORK.test(t) || STRONG_EXFIL.test(t) || WEAK_EXFIL.test(t))) return true;
    }
    return false;
  };
  for (const l of u.lines) {
    if (ALL_SECRETS.test(l.text)) {
      hits.push({ line: l.line, text: clip(l.text), level: "blocked", severity: "critical", what: "serialises every repository secret at once" });
    } else if (WHOLE_ENV.test(l.text)) {
      const sent = near(l.line);
      hits.push({
        line: l.line, text: clip(l.text), level: sent ? "blocked" : "review", severity: sent ? "critical" : "high",
        what: sent ? "serialises the whole environment next to a network call" : "serialises the whole environment",
      });
    }
  }
  return findingFrom("sec", "env-exfiltration", u.path, hits,
    (whats) => `${u.path} ${whats.join("; ")}. Every credential in the environment goes with it.`,
    "read only the variables the code needs, by name, and never send the environment or secrets object anywhere.");
}

export function exfilEndpoint(u: ContentUnit): Finding | null {
  const agent = isAgentFile(u.path);
  if ((isDocPath(u.path) && !agent) || isGeneratedPath(u.path)) return null;
  const hits: Hit[] = [];
  for (const l of u.lines) {
    const strong = STRONG_EXFIL.exec(l.text);
    const weak = strong === null ? WEAK_EXFIL.exec(l.text) : null;
    const m = strong ?? weak;
    if (m === null) continue;
    hits.push({
      line: l.line, text: clip(maskSecrets(l.text)),
      level: strong !== null || agent ? "blocked" : "review",
      severity: agent ? "critical" : strong !== null ? "high" : "medium",
      what: m[0],
    });
  }
  return findingFrom("sec", "exfil-endpoint", u.path, hits,
    (whats) => `${u.path} talks to ${whats.join(", ")}, a service built to collect data from elsewhere or to tunnel into a local machine.`,
    "remove the call; production code and agent instructions have no reason to send anything there.");
}

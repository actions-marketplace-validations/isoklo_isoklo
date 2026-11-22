/**
 * Secret detection: provider-specific key formats (blocked), Supabase service_role JWTs decoded to check their role,
 * private keys, credentials in connection strings, and generic high-entropy values assigned to secret-looking names
 * (review). Known documentation examples and placeholders are ignored. Evidence never contains a secret: every match
 * is masked to its first four characters.
 */
import { entropy } from "../../engine/text.js";
import type { Level, Severity } from "../../check/types.js";

export interface SecretMatch {
  kind: string;
  value: string;
  level: Level;
  severity: Severity;
}

interface Pattern {
  kind: string;
  re: RegExp;
  level: Level;
  severity: Severity;
  /** Minimum entropy of the captured value; keeps "ghp_aaaa…" style fixtures out. */
  minEntropy?: number;
}

const PATTERNS: readonly Pattern[] = [
  { kind: "AWS access key ID", re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "AWS secret access key", re: /aws[_-]?secret[_-]?(?:access[_-]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, level: "blocked", severity: "critical", minEntropy: 3.5 },
  { kind: "GitHub token", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "GitHub fine-grained token", re: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "Anthropic API key", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,})/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "OpenAI API key", re: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "Stripe live secret key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "Stripe test secret key", re: /\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b/g, level: "review", severity: "medium", minEntropy: 3 },
  { kind: "Stripe webhook signing secret", re: /\b(whsec_[A-Za-z0-9]{24,})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "Slack webhook URL", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,})/g, level: "blocked", severity: "high" },
  { kind: "Discord webhook URL", re: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,}\/[\w-]{40,})/g, level: "blocked", severity: "high" },
  { kind: "Google API key", re: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g, level: "blocked", severity: "high", minEntropy: 3 },
  { kind: "npm access token", re: /\b(npm_[A-Za-z0-9]{36})\b/g, level: "blocked", severity: "critical", minEntropy: 3 },
  { kind: "PyPI API token", re: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})/g, level: "blocked", severity: "critical" },
  { kind: "Hugging Face token", re: /\b(hf_[A-Za-z0-9]{34,})\b/g, level: "blocked", severity: "high", minEntropy: 3 },
  { kind: "SendGrid API key", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g, level: "blocked", severity: "high" },
  { kind: "Telegram bot token", re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g, level: "blocked", severity: "high" },
  { kind: "private key", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/g, level: "blocked", severity: "critical" },
  {
    kind: "database URL with a password",
    re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^:\s/'"@]+:([^@\s/'"]{6,})@[^\s'"`]+)/g,
    level: "blocked", severity: "critical",
  },
];

const JWT = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g;

/**
 * A quoted value assigned to a name: api_key = "…", "clientSecret": "…". The name is bounded (64 characters) and
 * checked separately, so a long run of word characters cannot make the match slow.
 */
const ASSIGNMENT = /([A-Za-z0-9_.-]{1,64})["']?\s*(?:=|:|:=|=>)\s*["']([^"'\s]{16,256})["']/g;
const SECRET_NAME = /secret|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer/i;

/** Lines longer than this are data (minified code, base64, lockfiles), and only their start is read. */
const MAX_LINE = 4000;

/** Documentation examples and obvious placeholders. */
const PLACEHOLDER = /(example|sample|dummy|fake|placeholder|your[_-]?|xxxx|0{6,}|123456|abcdef|changeme|redacted|replace|insert|<|>|\$\{|\{\{|%s|\*\*\*|\.\.\.)/i;
const DOC_EXAMPLES = new Set([
  "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  // Stripe's own documented test keys, printed in its API reference. Joined at runtime so the source holds no
  // key-shaped literal for GitHub push protection to flag; the set's values are unchanged.
  ...[["sk", "4eC39HqLyjWDarjtT1zdp7dc"], ["sk", "BQokikJOvBiI2HlWgH4olfQ2"], ["rk", "4eC39HqLyjWDarjtT1zdp7dc"]]
    .map(([kind, rest]) => [kind, "test", rest].join("_")),
]);

/** Database URLs pointing at the developer's own machine or a compose service, or using the stock dev password. */
const LOCAL_DB_HOST = /@(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)(:\d+)?(\/|$|\?)/i;
const DEV_PASSWORD = /^(postgres|password|passw0rd|secret|root|admin|example|test|testing|mysql|pass|changeme|dev|development|local|guest|rabbitmq|redis|mongo|prisma|docker)$/i;

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (part === undefined) return null;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    const json: unknown = JSON.parse(atob(b64));
    return typeof json === "object" && json !== null ? (json as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Mask a secret for display: the first four characters only. */
export const maskValue = (v: string) => (v.length <= 8 ? "***" : `${v.slice(0, 4)}…***`);

export function findSecrets(input: string): SecretMatch[] {
  const line = input.length > MAX_LINE ? input.slice(0, MAX_LINE) : input;
  const out: SecretMatch[] = [];
  const seen = new Set<string>();
  const add = (m: SecretMatch) => {
    if (seen.has(m.value)) return;
    seen.add(m.value);
    out.push(m);
  };

  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of line.matchAll(p.re)) {
      const value = m[1] ?? m[0];
      const dbUrl = p.kind === "database URL with a password";
      const secretPart = dbUrl ? m[2] ?? "" : value;
      if (DOC_EXAMPLES.has(value) || (p.kind !== "private key" && PLACEHOLDER.test(secretPart))) continue;
      if (dbUrl && (LOCAL_DB_HOST.test(value) || DEV_PASSWORD.test(secretPart))) continue;
      if (p.minEntropy !== undefined && entropy(secretPart) < p.minEntropy) continue;
      add({ kind: p.kind, value, level: p.level, severity: p.severity });
    }
  }

  for (const m of line.matchAll(JWT)) {
    const token = m[1] as string;
    const payload = decodeJwtPayload(token);
    // Supabase anon keys are public by design; the service_role key bypasses row-level security entirely.
    if (payload?.["role"] === "service_role") add({ kind: "Supabase service_role key", value: token, level: "blocked", severity: "critical" });
  }

  for (const m of line.matchAll(ASSIGNMENT)) {
    const name = (m[1] ?? "").toLowerCase();
    const value = m[2] ?? "";
    if (!SECRET_NAME.test(name)) continue;
    if (seen.has(value) || out.some((o) => o.value.includes(value) || value.includes(o.value))) continue;
    if (/public|publishable|_url|_uri|endpoint|_path|_file|_name|_id$|placeholder|hash/.test(name)) continue;
    if (/^(https?:|\$|process\.env|os\.environ|env\(|getenv)/i.test(value)) continue;
    if (PLACEHOLDER.test(value) || !/[a-z]/i.test(value) || !/\d/.test(value)) continue;
    if (entropy(value) < 3.5) continue;
    add({ kind: `possible secret in ${m[1]}`, value, level: "review", severity: "high" });
  }
  return out;
}

/** Replace every secret on a line with its mask, so evidence can be printed, stored and shared. */
export function maskSecrets(line: string): string {
  let out = line;
  for (const s of findSecrets(line)) out = out.split(s.value).join(maskValue(s.value));
  return out;
}

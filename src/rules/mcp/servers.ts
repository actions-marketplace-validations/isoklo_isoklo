/**
 * mcp/unpinned-server, mcp/plaintext-secret, mcp/dangerous-server: what each MCP server in a config actually runs.
 * In `check` mode only servers that are new or changed are judged (v1's mcp/server-added already blocks new ones; these
 * rules say what is wrong with them). In `scan` mode every server is judged.
 */
import { isObject, keyLine, parseJsonc } from "../../check/config/jsonc.js";
import type { Finding, Level, Severity } from "../../check/types.js";
import { canonicalJson } from "../../engine/crypto.js";
import type { Mode } from "../../engine/registry.js";
import { clip, entropy } from "../../engine/text.js";
import { findSecrets, maskValue } from "../sec/secrets.js";

export interface McpServer {
  name: string;
  command: string | null;
  args: string[];
  env: Record<string, string>;
  headers: Record<string, string>;
  url: string | null;
  /** Canonical JSON of the server entry, to tell changed servers from unchanged ones. */
  fingerprint: string;
}

export function readMcpServers(text: string | null): McpServer[] | null {
  if (text === null) return [];
  const doc = parseJsonc(text);
  if (!isObject(doc)) return null;
  const table = isObject(doc["mcpServers"]) ? doc["mcpServers"] : isObject(doc["servers"]) ? doc["servers"] : {};
  const strMap = (v: unknown) => (isObject(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, typeof x === "string" ? x : JSON.stringify(x)])) : {});
  return Object.entries(table).filter(([, raw]) => isObject(raw)).map(([name, raw]) => {
    const r = raw as Record<string, unknown>;
    const url = ["url", "httpUrl", "serverUrl"].map((k) => r[k]).find((v): v is string => typeof v === "string") ?? null;
    return {
      name,
      command: typeof r["command"] === "string" ? r["command"] : null,
      args: Array.isArray(r["args"]) ? r["args"].map(String) : [],
      env: strMap(r["env"]),
      headers: strMap(r["headers"]),
      url,
      fingerprint: canonicalJson(r),
    };
  });
}

/** Publishers whose npm scopes, PyPI names or container namespaces belong to the vendor itself. */
const VERIFIED_PREFIXES = [
  "@modelcontextprotocol/", "@anthropic-ai/", "@playwright/", "@microsoft/", "@azure/", "@cloudflare/", "@sentry/",
  "@stripe/", "@supabase/", "@upstash/", "@notionhq/", "@vercel/", "@browserbasehq/", "@hubspot/", "@heroku/",
  "@neondatabase/", "@shopify/", "@paypal/", "@figma/", "@atlassian/", "@gitlab/", "@google-cloud/", "@googleapis/",
  "@aws/", "@awslabs/", "@elastic/", "@mongodb-js/", "@pinecone-database/", "@redis/", "@twilio-alpha/",
  "ghcr.io/github/", "mcp/", "docker.io/mcp/", "mcr.microsoft.com/",
  "awslabs.", "mcp-server-git", "mcp-server-fetch", "mcp-server-time", "mcp-server-sqlite",
];

const EXACT_VERSION = /^v?\d+\.\d+\.\d+([-+][\w.-]+)?$/;

interface Launch { tool: string; pkg: string; pinned: boolean }

/** The package or image a server installs at start-up, and whether it is pinned to an exact version. */
/**
 * Windows MCP configs wrap commands in a shell (`cmd /c npx -y pkg`), as do some others (`bash -c "uvx pkg"`). When
 * the wrapped part is one plain command (no pipes, redirects or substitutions), judge that command instead.
 */
export function unwrapShell(s: McpServer): McpServer | null {
  if (s.command === null) return null;
  const tool = (s.command.split(/[\\/]/).pop() ?? "").replace(/\.exe$/i, "").toLowerCase();
  const flag = s.args[0] ?? "";
  const isWrapper = (tool === "cmd" && /^\/[ck]$/i.test(flag)) || (/^(bash|sh|zsh|dash)$/.test(tool) && /^-l?c$/.test(flag));
  if (!isWrapper || s.args.length < 2) return null;
  const words = s.args.length === 2 ? (s.args[1] ?? "").trim().split(/\s+/) : s.args.slice(1);
  if (words.length === 0 || words.some((w) => /[|&;<>$`()]/.test(w))) return null;
  return { ...s, command: words[0] ?? null, args: words.slice(1) };
}

export function launchOf(server: McpServer): Launch | null {
  const s = unwrapShell(server) ?? server;
  if (s.command === null) return null;
  const tool = (s.command.split(/[\\/]/).pop() ?? "").replace(/\.(cmd|exe)$/i, "").toLowerCase();
  const args = [...s.args];
  let rest: string[] | null = null;
  if (tool === "npx" || tool === "bunx" || tool === "pnpx") rest = args;
  else if ((tool === "pnpm" || tool === "yarn") && args[0] === "dlx") rest = args.slice(1);
  else if (tool === "npm" && args[0] === "exec") rest = args.slice(1);
  else if (tool === "uvx" || tool === "pipx") rest = tool === "pipx" && args[0] === "run" ? args.slice(1) : args;
  else if (tool === "uv" && args[0] === "tool" && args[1] === "run") rest = args.slice(2);
  if (rest !== null) {
    // An explicit package flag wins: npx -p pkg@1.2.3 cmd, uvx --from pkg==1.2.3 cmd.
    const flag = rest.findIndex((a) => a === "-p" || a === "--package" || a === "--from");
    const eq = rest.find((a) => /^--(package|from)=/.test(a));
    const pkg = eq?.split("=").slice(1).join("=") ?? (flag >= 0 ? rest[flag + 1] : rest.find((a) => !a.startsWith("-")));
    if (pkg === undefined) return null;
    const npmStyle = tool !== "uvx" && tool !== "pipx" && tool !== "uv";
    let pinned: boolean;
    if (npmStyle) {
      const at = pkg.lastIndexOf("@");
      pinned = at > 0 && EXACT_VERSION.test(pkg.slice(at + 1));
    } else {
      pinned = /==\s*v?\d+\.\d+(\.\d+)?/.test(pkg) || (/@/.test(pkg) && EXACT_VERSION.test(pkg.split("@").pop() ?? ""));
    }
    return { tool, pkg, pinned };
  }
  if (tool === "docker" || tool === "podman") {
    const i = args.indexOf("run");
    if (i < 0) return null;
    const VALUE_FLAGS = new Set(["-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "-w", "--workdir", "--mount", "-u", "--user", "--entrypoint", "--platform", "--env-file", "-l", "--label", "--add-host", "--cpus", "-m", "--memory", "--pull"]);
    for (let j = i + 1; j < args.length; j++) {
      const a = args[j] as string;
      if (a.startsWith("-")) { if (VALUE_FLAGS.has(a)) j++; continue; }
      const digest = a.includes("@sha256:");
      const tag = /:[\w][\w.-]*$/.exec(a.replace(/^[^/]*:\d+\//, ""))?.[0];
      return { tool, pkg: a, pinned: digest || (tag !== undefined && tag !== ":latest") };
    }
  }
  return null;
}

const isVerified = (pkg: string, extra: readonly string[]) =>
  [...VERIFIED_PREFIXES, ...extra].some((p) => pkg.startsWith(p) || pkg.replace(/^docker\.io\//, "").startsWith(p));

/** A value that refers to a secret elsewhere instead of holding it: ${VAR}, ${env:VAR}, ${input:id}, $VAR, {{ }}. */
const REFERENCE = /^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]+\}\}|<[^>]+>|%[A-Z_]+%)\s*$|^(Bearer|Basic|token)\s+(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*)$/i;
const SENSITIVE_KEY = /(token|secret|password|passwd|api[_-]?key|apikey|auth|bearer|credential|private[_-]?key|access[_-]?key|cookie)/i;

function plaintextSecrets(s: McpServer): string[] {
  const out: string[] = [];
  const check = (where: string, key: string, value: string) => {
    if (value.trim() === "" || REFERENCE.test(value)) return;
    const raw = value.replace(/^(Bearer|Basic|token)\s+/i, "");
    const known = findSecrets(`${key}="${raw}"`).filter((x) => x.level === "blocked" || SENSITIVE_KEY.test(key));
    const generic = SENSITIVE_KEY.test(key) && raw.length >= 12 && entropy(raw) >= 3 && !/^(true|false|null|\d+)$/i.test(raw) && !/(example|placeholder|your[_-]|xxx|changeme|<)/i.test(raw);
    if (known.length > 0 || generic) out.push(`${where} ${key} = ${maskValue(raw)}`);
  };
  for (const [k, v] of Object.entries(s.env)) check("env", k, v);
  for (const [k, v] of Object.entries(s.headers)) check("header", k, v);
  for (let i = 0; i < s.args.length; i++) {
    const a = s.args[i] as string;
    const inline = /^--?([\w-]*(?:token|secret|password|api[_-]?key|key|auth)[\w-]*)=(.+)$/i.exec(a);
    if (inline) check("arg", `--${inline[1]}`, inline[2] ?? "");
    else if (/^--?[\w-]*(token|secret|password|api[_-]?key|auth)[\w-]*$/i.test(a) && s.args[i + 1] !== undefined) check("arg", a, s.args[i + 1] as string);
    else if (findSecrets(a).some((x) => x.level === "blocked")) out.push(`arg ${maskValue(a)}`);
  }
  if (s.url !== null && (/[?&](api[_-]?key|token|key|secret|access_token)=[^&\s${]{8,}/i.test(s.url) || /^https?:\/\/[^/\s:@]+:[^/\s@]+@/.test(s.url))) {
    out.push(`url ${s.url.replace(/([?&][^=]+=)[^&]+/g, "$1***").replace(/\/\/[^/@]+@/, "//***@")}`);
  }
  return out;
}

const SHELLS = /^(bash|sh|zsh|dash|fish|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|pwsh\.exe)$/i;
const FETCH_AND_RUN = /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expressio[n]|ie[x]|base64|eval|nc|ncat)\b/i;
const WHOLE_DISK = /^(\/|~|~\/|\$HOME|\$\{HOME\}|%USERPROFILE%|[A-Za-z]:[\\/]?|\/Users\/?|\/home\/?|\/root\/?)$/;

function dangers(s: McpServer): { what: string; severity: Severity; level: Level }[] {
  const out: { what: string; severity: Severity; level: Level }[] = [];
  const tool = (s.command ?? "").split(/[\\/]/).pop() ?? "";
  if (SHELLS.test(tool) && unwrapShell(s) === null) {
    const script = s.args.join(" ");
    if (FETCH_AND_RUN.test(script)) out.push({ what: `runs an inline shell script that downloads or decodes code (${clip(script, 80)})`, severity: "critical", level: "blocked" });
    else if (s.args.some((a) => /^(-c|\/c|-Command|-EncodedCommand|-enc)$/i.test(a))) out.push({ what: "runs an inline shell script instead of a server program", severity: "medium", level: "review" });
  }
  if (s.args.some((a) => /server-filesystem|mcp-filesystem|filesystem-server/.test(a))) {
    const roots = s.args.filter((a) => WHOLE_DISK.test(a.trim()));
    if (roots.length > 0) out.push({ what: `gives the agent the whole disk or home folder (${roots.join(", ")})`, severity: "high", level: "blocked" });
  }
  if (s.url !== null && /^http:\/\//i.test(s.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:|\/|$)/i.test(s.url)) {
    out.push({ what: `connects over unencrypted http (${s.url.replace(/([?&][^=]+=)[^&]+/g, "$1***")})`, severity: "high", level: "blocked" });
  }
  if (/^(docker|podman)$/.test(tool)) {
    if (s.args.includes("--privileged")) out.push({ what: "runs a privileged container", severity: "high", level: "blocked" });
    const mounts = s.args.filter((a) => /^(\/|\/var\/run\/docker\.sock|\$HOME|~|[A-Za-z]:\\?):/.test(a) || /source=\/(,|$)|docker\.sock/.test(a));
    if (mounts.length > 0) out.push({ what: `mounts the host into the container (${mounts.join(", ")})`, severity: "high", level: "blocked" });
  }
  if (s.args.some((a) => /^--(no-sandbox|disable-sandbox|unsafe|allow-all|dangerously[\w-]*|disable-security)$/i.test(a))) {
    out.push({ what: `turns safety off (${s.args.filter((a) => /^--(no-sandbox|disable-sandbox|unsafe|allow-all|dangerously[\w-]*|disable-security)$/i.test(a)).join(" ")})`, severity: "high", level: "blocked" });
  }
  return out;
}

export function mcpServerFindings(path: string, after: string | null, before: string | null, mode: Mode, trusted: readonly string[]): Finding[] {
  const now = readMcpServers(after);
  if (now === null) return []; // v1 reports unparseable MCP configs as agent/config-unreadable
  const prev = mode === "check" ? new Map((readMcpServers(before) ?? []).map((s) => [s.name, s.fingerprint])) : new Map<string, string>();
  const text = after ?? "";
  const out: Finding[] = [];
  for (const s of now) {
    if (mode === "check" && prev.get(s.name) === s.fingerprint) continue;
    const where = keyLine(text, s.name);
    const evidence = [{ path, ...where }];

    const launch = launchOf(s);
    if (launch !== null && !launch.pinned) {
      const verified = isVerified(launch.pkg, trusted);
      out.push({
        rule: "mcp", id: "unpinned-server", level: verified ? "review" : "blocked", severity: verified ? "medium" : "high",
        message: `MCP server "${s.name}" runs ${launch.tool} ${launch.pkg} without a pinned version${verified ? "" : ", from a publisher Isoklo cannot verify"}. Each start fetches whatever that name points to then.`,
        fix: launch.tool === "docker" || launch.tool === "podman"
          ? `pin the image by digest (${launch.pkg.replace(/:[\w.-]+$/, "")}@sha256:…), and use a publisher you trust.`
          : `pin an exact version (${launch.tool === "uvx" || launch.tool === "pipx" || launch.tool === "uv" ? `${launch.pkg.split(/[=@]/)[0]}==1.2.3` : `${launch.pkg.replace(/@[^@/]*$/, "")}@1.2.3`}) that you have reviewed, or add the publisher to trustedMcpPackages.`,
        evidence,
      });
    }

    const secrets = plaintextSecrets(s);
    if (secrets.length > 0) {
      out.push({
        rule: "mcp", id: "plaintext-secret", level: "blocked", severity: "critical",
        message: `MCP server "${s.name}" has ${secrets.length === 1 ? "a secret" : `${secrets.length} secrets`} written into ${path}: ${secrets.join("; ")}.`,
        fix: "rotate the key, then reference it instead of writing it: \"env\": { \"API_KEY\": \"${API_KEY}\" } (or ${input:…} in VS Code), with the value kept outside the repository.",
        evidence: evidence.map((e) => ({ ...e, text: e.text.replace(/:\s*\{.*$/, ": { … }") })),
      });
    }

    for (const d of dangers(s)) {
      out.push({
        rule: "mcp", id: "dangerous-server", level: d.level, severity: d.severity,
        message: `MCP server "${s.name}" ${d.what}.`,
        fix: "limit the server to what the task needs: a project folder, an https endpoint, a published server program, no host mounts.",
        evidence,
      });
    }
  }
  return out;
}

/**
 * Supply-chain signals in files people rarely read:
 *   deps/lockfile-untrusted-source  lockfile entries resolved from plain http or an unknown host
 *   deps/lifecycle-script           install-time scripts added to the project's own package.json
 *   deps/registry-changed           npm/yarn/pip pointed at another registry or index, or TLS checks off
 */
import { isObject, parseJsonc } from "../../check/config/jsonc.js";
import type { Evidence, Finding } from "../../check/types.js";
import { basename, clip } from "../../engine/text.js";
import type { FileChange } from "../change.js";
import { findingFrom, type ContentUnit, type Hit } from "../content.js";

// ---------------------------------------------------------------- lockfiles
export const DEFAULT_REGISTRY_HOSTS = [
  "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "npm.pkg.github.com", "pkgs.dev.azure.com",
  "codeload.github.com", "files.pythonhosted.org", "pypi.org", "repo.yarnpkg.com",
];

const isNpmLock = (path: string) => /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/.test(path);
const isPyLock = (path: string) => /(^|\/)(poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock)$/.test(path);
export const isTextLockfile = (path: string) => isNpmLock(path) || isPyLock(path);

/** The lines in each lockfile format that say where a package is downloaded from (not funding or homepage links). */
function sourceLine(path: string): RegExp {
  const b = basename(path);
  if (b === "package-lock.json" || b === "npm-shrinkwrap.json") return /"resolved"\s*:/;
  if (b === "yarn.lock") return /^\s*(resolved\s|resolution:)/;
  if (b === "pnpm-lock.yaml") return /tarball:|resolution:/;
  if (b === "poetry.lock") return /^\s*url\s*=/;
  if (b === "uv.lock") return /\burl\s*=|registry\s*=/;
  if (b === "Pipfile.lock") return /"url"\s*:/;
  return /"(https?|git\+[\w+]+):\/\//; // bun.lock: a custom registry URL appears in the entry itself
}

const URL_IN_LINE = /((?:https?|git\+[\w+]+|git|ssh):\/\/[^"'\s,}\]]+)/;

export function lockfileSources(u: ContentUnit, trustedHosts: readonly string[]): Finding | null {
  if (!isTextLockfile(u.path)) return null;
  const hosts = new Set([...DEFAULT_REGISTRY_HOSTS, ...trustedHosts.map((h) => h.toLowerCase())]);
  const wanted = sourceLine(u.path);
  const hits: Hit[] = [];
  for (const l of u.lines) {
    if (!wanted.test(l.text)) continue;
    const url = URL_IN_LINE.exec(l.text)?.[1];
    if (url === undefined) continue;
    let host: string;
    try {
      host = new URL(url.replace(/^git\+/, "")).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (/^http:\/\//i.test(url) && !/^(localhost|127\.0\.0\.1)$/.test(host)) {
      hits.push({ line: l.line, text: clip(l.text), level: "blocked", severity: "critical", what: `installs over unencrypted http from ${host}` });
    } else if (/^git(\+[\w+]+)?:/i.test(url) || host === "codeload.github.com" || host === "github.com") {
      hits.push({ line: l.line, text: clip(l.text), level: "review", severity: "medium", what: `installs straight from a git repository (${host})` });
    } else if (!hosts.has(host) && ![...hosts].some((h) => host.endsWith(`.${h}`))) {
      hits.push({ line: l.line, text: clip(l.text), level: "blocked", severity: "high", what: `installs from ${host}, which is not a known registry` });
    }
  }
  return findingFrom("deps", "lockfile-untrusted-source", u.path, hits,
    (whats) => `Lockfile ${u.path} ${[...new Set(whats)].slice(0, 4).join("; ")}. package.json can look unchanged while the install fetches something else.`,
    "regenerate the lockfile from the public registry (delete it and run a clean install); if the host is your private registry, add it to trustedRegistries in isoklo.config.json or to .npmrc.");
}

// ---------------------------------------------------------------- install-time scripts in this project
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepack"];
const FETCHES = /\b(curl|wget|fetch\(|https?:\/\/|node\s+-e|python3?\s+-c|base64|eval|powershell|iwr|Invoke-WebRequest|nc\s|bash\s+-c|sh\s+-c)/i;

function scriptsOf(text: string | null): Record<string, string> {
  const doc = text === null ? null : parseJsonc(text);
  if (!isObject(doc) || !isObject(doc["scripts"])) return {};
  return Object.fromEntries(Object.entries(doc["scripts"]).filter((e): e is [string, string] => typeof e[1] === "string"));
}

export function lifecycleScripts(c: FileChange): Finding | null {
  if (basename(c.path) !== "package.json" || c.status === "deleted" || /(^|\/)node_modules\//.test(c.path)) return null;
  const before = scriptsOf(c.before);
  const after = scriptsOf(c.after);
  const changed = LIFECYCLE.filter((k) => after[k] !== undefined && after[k] !== before[k]);
  if (changed.length === 0) return null;
  const lines = (c.after ?? "").split(/\r?\n/);
  const evidence: Evidence[] = changed.map((k) => {
    const i = lines.findIndex((l) => new RegExp(`"${k}"\\s*:`).test(l));
    return { path: c.path, line: i < 0 ? 1 : i + 1, text: clip(i < 0 ? `"${k}": ${after[k]}` : (lines[i] ?? "").trim()) };
  });
  const dangerous = changed.filter((k) => FETCHES.test(after[k] ?? ""));
  return {
    rule: "deps", id: "lifecycle-script", level: dangerous.length > 0 ? "blocked" : "review",
    severity: dangerous.length > 0 ? "critical" : "medium",
    message: dangerous.length > 0
      ? `Install-time script in ${c.path} downloads or evaluates code: ${dangerous.map((k) => `${k}: ${clip(after[k] ?? "", 80)}`).join("; ")}. It runs on every npm install, on every machine and CI job.`
      : `Install-time script ${before[changed[0] as string] === undefined ? "added" : "changed"} in ${c.path}: ${changed.map((k) => `${k}: ${clip(after[k] ?? "", 80)}`).join("; ")}. It runs on every npm install.`,
    fix: "move one-off setup into a script people run on purpose (npm run setup); install-time scripts should only build the project's own code.",
    evidence,
  };
}

// ---------------------------------------------------------------- registries and indexes
const REGISTRY_FILE = /(^|\/)(\.npmrc|\.yarnrc|\.yarnrc\.yml|bunfig\.toml|pip\.conf|pip\.ini|\.pypirc|requirements[^/]*\.txt|constraints[^/]*\.txt|pyproject\.toml|uv\.toml|poetry\.toml)$/;
const REGISTRY_LINE = /^\s*(registry|@[\w.-]+:registry|npmRegistryServer|npmScopes|registry\s*=|index-url|extra-index-url|--index-url|--extra-index-url|-i\s|--trusted-host|trusted-host|url\s*=\s*"https?:|\[\[tool\.(uv\.index|poetry\.source)\]\])/i;
const TLS_OFF = /^\s*(strict-ssl\s*=\s*false|enableStrictSsl\s*:\s*false|ssl_verify\s*=\s*false|--trusted-host|trusted-host)/i;

export function registryChanged(u: ContentUnit): Finding | null {
  if (u.mode !== "check" || !REGISTRY_FILE.test(u.path)) return null;
  const hits: Hit[] = [];
  for (const l of u.lines) {
    const t = l.text;
    if (/^\s*[#;]/.test(t)) continue;
    if (TLS_OFF.test(t)) hits.push({ line: l.line, text: clip(t), level: "blocked", severity: "high", what: "turns TLS certificate checks off" });
    else if (REGISTRY_LINE.test(t)) {
      const insecure = /http:\/\/(?!localhost|127\.0\.0\.1)/i.test(t);
      hits.push({
        line: l.line, text: clip(t.replace(/(_authToken|_auth|password|token)\s*=\s*\S+/gi, "$1=***")),
        level: insecure ? "blocked" : "review", severity: insecure ? "critical" : "high",
        what: insecure ? "points package installs at an unencrypted registry" : "points package installs at another registry or index",
      });
    }
  }
  return findingFrom("deps", "registry-changed", u.path, hits,
    (whats) => `Package source changed in ${u.path}: ${[...new Set(whats)].join("; ")}.`,
    "confirm the registry belongs to your organisation and uses https; an extra index lets a public package with the same name as a private one win (dependency confusion).");
}

/**
 * isoklo.config.json: optional policy. Isoklo needs no configuration; everything here only tunes it.
 *
 * Security rule: when checking a change, the policy is read from the BASE commit, never from the change itself, so a
 * pull request cannot loosen the gate that judges it (and editing the policy is its own finding,
 * tamper/isoklo-config-changed). The GitHub App does the same, and paid plans can add an organisation-wide policy
 * from the org's `.github` repository that repositories cannot override.
 */
import { parseJsonc, isObject } from "../check/config/jsonc.js";
import type { Level } from "../check/types.js";
import { ruleMeta } from "./registry.js";

export type RuleSetting = Level | "off";

export interface ScopePolicy {
  /** Every changed file must match one of these globs (empty: no restriction). */
  allow: string[];
  /** No changed file may match these globs. */
  deny: string[];
  /** Sensitive areas by name; null keeps the built-in defaults, an empty object turns the check off. */
  sensitive: Record<string, string[]> | null;
  /** Most files a single change may touch (null: no limit). */
  maxFiles: number | null;
}

export interface IsokloConfig {
  scope: ScopePolicy;
  /** Per-rule level: "blocked", "review", "info", or "off". */
  rules: Record<string, RuleSetting>;
  /** Files the content rules (secrets, hidden Unicode, remote code, suppressions) skip, for fixtures and samples. */
  ignorePaths: string[];
  /** Look new packages up on npm and PyPI (default true; --offline wins). */
  online: boolean;
  /** Fingerprints of accepted findings, written by `isoklo init --config`; they report as info, not blocked. */
  baseline: string[];
  /** Extra package hosts lockfiles may install from (a private registry, for example). */
  trustedRegistries: string[];
  /** Extra MCP server packages or images to treat as from a verified publisher. */
  trustedMcpPackages: string[];
  /**
   * GitHub App waivers. allowAuthor: may the pull request's own author waive its findings? Off by default, because an
   * agent often opens pull requests with its owner's account; turn it on for repositories with a single maintainer.
   * null means "not set here" (so an organisation policy can decide).
   */
  waivers: { allowAuthor: boolean | null };
}

export const CONFIG_FILES = ["isoklo.config.json", ".isoklo.json", ".github/isoklo.config.json"] as const;

export const SCHEMA_URL = "https://unpkg.com/isoklo/schema/isoklo.config.schema.json";

export const defaultConfig = (): IsokloConfig => ({
  scope: { allow: [], deny: [], sensitive: null, maxFiles: null },
  rules: {},
  ignorePaths: [],
  online: true,
  baseline: [],
  trustedRegistries: [],
  trustedMcpPackages: [],
  waivers: { allowAuthor: null },
});

export class ConfigError extends Error {}

const KNOWN_KEYS = new Set(["$schema", "scope", "rules", "ignorePaths", "online", "baseline", "trustedRegistries", "trustedMcpPackages", "waivers"]);
const SETTINGS = new Set<RuleSetting>(["blocked", "review", "info", "off"]);

const strings = (v: unknown, where: string, problems: string[]): string[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    problems.push(`${where} must be a list of strings; it was ignored.`);
    return [];
  }
  return v as string[];
};

/**
 * Parse a policy file. Throws ConfigError when the file is not valid JSON (the gate fails closed rather than run with a
 * policy it cannot read). Unknown keys and wrong types become warnings, and the default stays in force for them.
 */
export function parseConfig(text: string | null, source = "isoklo.config.json"): { config: IsokloConfig; warnings: string[] } {
  const config = defaultConfig();
  const warnings: string[] = [];
  if (text === null || text.trim() === "") return { config, warnings };
  const doc = parseJsonc(text);
  if (!isObject(doc)) throw new ConfigError(`${source} is not a valid JSON object, so the policy could not be read.`);

  for (const key of Object.keys(doc)) if (!KNOWN_KEYS.has(key)) warnings.push(`${source}: unknown setting "${key}" was ignored.`);

  const scope = doc["scope"];
  if (scope !== undefined) {
    if (!isObject(scope)) warnings.push(`${source}: scope must be an object; it was ignored.`);
    else {
      config.scope.allow = strings(scope["allow"], `${source}: scope.allow`, warnings);
      config.scope.deny = strings(scope["deny"], `${source}: scope.deny`, warnings);
      const max = scope["maxFiles"];
      if (max !== undefined) {
        if (typeof max === "number" && Number.isInteger(max) && max > 0) config.scope.maxFiles = max;
        else warnings.push(`${source}: scope.maxFiles must be a whole number above 0; it was ignored.`);
      }
      const sensitive = scope["sensitive"];
      if (sensitive === false) config.scope.sensitive = {};
      else if (isObject(sensitive)) {
        config.scope.sensitive = {};
        for (const [zone, globs] of Object.entries(sensitive)) {
          config.scope.sensitive[zone] = strings(globs, `${source}: scope.sensitive.${zone}`, warnings);
        }
      } else if (sensitive !== undefined) warnings.push(`${source}: scope.sensitive must be an object or false; it was ignored.`);
    }
  }

  const rules = doc["rules"];
  if (rules !== undefined) {
    if (!isObject(rules)) warnings.push(`${source}: rules must be an object; it was ignored.`);
    else {
      for (const [id, setting] of Object.entries(rules)) {
        if (ruleMeta(id) === undefined) { warnings.push(`${source}: no rule is called "${id}"; run \`isoklo rules\` for the list.`); continue; }
        if (typeof setting !== "string" || !SETTINGS.has(setting as RuleSetting)) {
          warnings.push(`${source}: rules["${id}"] must be "blocked", "review", "info" or "off".`);
          continue;
        }
        config.rules[id] = setting as RuleSetting;
      }
    }
  }

  config.ignorePaths = strings(doc["ignorePaths"], `${source}: ignorePaths`, warnings);
  config.baseline = strings(doc["baseline"], `${source}: baseline`, warnings);
  config.trustedRegistries = strings(doc["trustedRegistries"], `${source}: trustedRegistries`, warnings).map((h) => h.toLowerCase());
  config.trustedMcpPackages = strings(doc["trustedMcpPackages"], `${source}: trustedMcpPackages`, warnings);
  if (doc["online"] !== undefined) {
    if (typeof doc["online"] === "boolean") config.online = doc["online"];
    else warnings.push(`${source}: online must be true or false; it was ignored.`);
  }
  const waivers = doc["waivers"];
  if (waivers !== undefined) {
    if (!isObject(waivers)) warnings.push(`${source}: waivers must be an object; it was ignored.`);
    else {
      for (const key of Object.keys(waivers)) if (key !== "allowAuthor") warnings.push(`${source}: unknown setting "waivers.${key}" was ignored.`);
      const allow = waivers["allowAuthor"];
      if (typeof allow === "boolean") config.waivers.allowAuthor = allow;
      else if (allow !== undefined) warnings.push(`${source}: waivers.allowAuthor must be true or false; it was ignored.`);
    }
  }
  return { config, warnings };
}

/**
 * An organisation policy (paid plans, from the org's .github repository) layered under a repository's policy. The
 * organisation wins wherever it speaks: its rule settings override the repository's, its forbidden paths are added to
 * the repository's, and the repository cannot switch on a setting the organisation left off.
 */
export function mergeOrgPolicy(org: IsokloConfig, repo: IsokloConfig): IsokloConfig {
  return {
    scope: {
      allow: repo.scope.allow.length > 0 ? repo.scope.allow : org.scope.allow,
      deny: [...new Set([...org.scope.deny, ...repo.scope.deny])],
      sensitive: org.scope.sensitive ?? repo.scope.sensitive,
      maxFiles: org.scope.maxFiles === null ? repo.scope.maxFiles
        : repo.scope.maxFiles === null ? org.scope.maxFiles : Math.min(org.scope.maxFiles, repo.scope.maxFiles),
    },
    rules: { ...repo.rules, ...org.rules },
    ignorePaths: [...new Set([...org.ignorePaths, ...repo.ignorePaths])],
    online: org.online && repo.online,
    baseline: repo.baseline,
    trustedRegistries: [...new Set([...org.trustedRegistries, ...repo.trustedRegistries])],
    trustedMcpPackages: [...new Set([...org.trustedMcpPackages, ...repo.trustedMcpPackages])],
    waivers: { allowAuthor: org.waivers.allowAuthor ?? repo.waivers.allowAuthor },
  };
}

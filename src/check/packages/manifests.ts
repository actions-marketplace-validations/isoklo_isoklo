/**
 * Read dependency manifests and work out which packages a change ADDS. Pure: text in, names out.
 * A version bump of an existing dependency is not a new package. Non-registry sources (git, file, workspace, URLs)
 * are skipped: there is no registry to ask about them.
 */

export type Ecosystem = "npm" | "pypi";

export interface DeclaredPackage {
  ecosystem: Ecosystem;
  /** The name to look up in the registry (npm alias targets resolved; PyPI names normalised). */
  name: string;
  /** The line in the new manifest that declares it (1-based), for evidence. */
  line: number;
  text: string;
  /** npm: the declared version when it is exact (1.2.3), so the registry answer is about that version. */
  exactVersion?: string;
}

export interface ManifestFacts {
  packages: Map<string, DeclaredPackage>;
  /** PyPI: the manifest points at a private or extra index, so a missing name may be private. */
  privateIndex: boolean;
}

export const manifestKind = (path: string): "package.json" | "requirements" | "pyproject" | null => {
  if (/(^|\/)node_modules\//.test(path)) return null;
  const base = path.split("/").pop() ?? "";
  if (base === "package.json") return "package.json";
  if (/^requirements.*\.txt$/i.test(base)) return "requirements";
  if (base === "pyproject.toml") return "pyproject";
  return null;
};

/** PEP 503: case-insensitive, and runs of - _ . are the same. */
export const normalizePypi = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

const lineOf = (text: string, re: RegExp) => {
  const lines = text.split(/\r?\n/);
  const i = lines.findIndex((l) => re.test(l));
  return i < 0 ? { line: 1, text: "" } : { line: i + 1, text: (lines[i] ?? "").trim() };
};

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---------------------------------------------------------------- npm
const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const NON_REGISTRY = /^(file:|link:|workspace:|portal:|patch:|git\+|git:|github:|gitlab:|bitbucket:|https?:|\.{0,2}\/|~\/)/;
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

export function npmPackages(text: string): ManifestFacts | null {
  let pkg: unknown;
  try {
    pkg = JSON.parse(text);
  } catch {
    return null;
  }
  const packages = new Map<string, DeclaredPackage>();
  if (typeof pkg !== "object" || pkg === null) return { packages, privateIndex: false };
  for (const section of NPM_SECTIONS) {
    const deps = (pkg as Record<string, unknown>)[section];
    if (typeof deps !== "object" || deps === null) continue;
    for (const [key, specRaw] of Object.entries(deps as Record<string, unknown>)) {
      const spec = typeof specRaw === "string" ? specRaw.trim() : "";
      if (NON_REGISTRY.test(spec) || GITHUB_SHORTHAND.test(spec)) continue;
      // "alias": "npm:real-name@^1.0.0" installs real-name.
      const alias = /^npm:((?:@[^/@\s]+\/)?[^@\s]+)(?:@(.*))?/.exec(spec);
      const name = alias?.[1] ?? key;
      const where = lineOf(text, new RegExp(`"${escapeRe(key)}"\\s*:`));
      const version = (alias ? alias[2] ?? "" : spec).replace(/^=/, "");
      const declared: DeclaredPackage = { ecosystem: "npm", name, ...where };
      if (/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) declared.exactVersion = version;
      packages.set(name, declared);
    }
  }
  return { packages, privateIndex: false };
}

// ---------------------------------------------------------------- PyPI
const PEP508_NAME = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/;

/** A PEP 508 requirement string, or null when it is not a registry package (URLs, paths, direct references). */
function requirementName(req: string): string | null {
  const r = req.trim();
  if (r === "" || r.startsWith("-") || r.includes("://") || /^[./~]/.test(r)) return null;
  if (/^\S+\s*@\s*\S/.test(r)) return null; // name @ https://... is a direct reference
  const m = PEP508_NAME.exec(r);
  return m?.[1] ? normalizePypi(m[1]) : null;
}

export function requirementsPackages(text: string): ManifestFacts {
  const packages = new Map<string, DeclaredPackage>();
  let privateIndex = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (/^(--index-url|--extra-index-url|-i)\b/.test(line)) privateIndex = true;
    const name = requirementName(line);
    if (name !== null && !packages.has(name)) packages.set(name, { ecosystem: "pypi", name, line: i + 1, text: raw.trim() });
  });
  return { packages, privateIndex };
}

/**
 * pyproject.toml without a TOML library (Isoklo has no dependencies): a careful line reader for the standard places
 * dependencies live. [project] dependencies, [project.optional-dependencies], and Poetry's dependency tables.
 */
export function pyprojectPackages(text: string): ManifestFacts {
  const packages = new Map<string, DeclaredPackage>();
  let table = "";
  let inArray = false;
  const add = (name: string | null, i: number, raw: string) => {
    if (name !== null && name !== "python" && !packages.has(name)) {
      packages.set(name, { ecosystem: "pypi", name, line: i + 1, text: raw.trim() });
    }
  };
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, "").trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      table = (header[1] ?? "").trim();
      inArray = false;
      return;
    }
    const arrayTable = table === "project" || table === "project.optional-dependencies";
    if (arrayTable) {
      const start = table === "project" ? /^dependencies\s*=\s*\[(.*)$/ : /^[\w.-]+\s*=\s*\[(.*)$/;
      const m = start.exec(line);
      let rest: string | null = null;
      if (m) { inArray = true; rest = m[1] ?? ""; } else if (inArray) rest = line;
      if (rest !== null) {
        for (const q of rest.matchAll(/"([^"]*)"|'([^']*)'/g)) add(requirementName(q[1] ?? q[2] ?? ""), i, raw);
        if (rest.includes("]")) inArray = false;
      }
      return;
    }
    if (/^tool\.poetry(\.group\.[\w.-]+)?\.(dev-)?dependencies$/.test(table)) {
      const m = /^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/.exec(line);
      if (m?.[1]) {
        const isPath = /\b(path|git|url)\s*=/.test(line);
        if (!isPath) add(normalizePypi(m[1]), i, raw);
      }
    }
  });
  return { packages, privateIndex: /\[\[tool\.poetry\.source\]\]|\[\[tool\.uv\.index\]\]/.test(text) };
}

export function readManifest(kind: NonNullable<ReturnType<typeof manifestKind>>, text: string): ManifestFacts | null {
  if (kind === "package.json") return npmPackages(text);
  if (kind === "requirements") return requirementsPackages(text);
  return pyprojectPackages(text);
}

/** Packages declared in `after` that `before` did not declare at all (version changes are not new packages). */
export function addedPackages(before: ManifestFacts | null, after: ManifestFacts): DeclaredPackage[] {
  return [...after.packages.values()].filter((p) => !before?.packages.has(p.name));
}

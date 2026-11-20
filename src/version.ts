import { readFileSync } from "node:fs";

/**
 * Reads the version from package.json at runtime, so the version lives in exactly one place.
 * dist/version.js sits one folder below package.json, both in the repo and inside the published npm package.
 */
export function readVersion(): string {
  const url = new URL("../package.json", import.meta.url);
  const pkg: unknown = JSON.parse(readFileSync(url, "utf8"));
  if (typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string") {
    return pkg.version;
  }
  return "unknown";
}

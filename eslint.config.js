// Lint for the CLI, the engine, the GitHub App and the tests. Type safety comes from `tsc --strict`; this catches the
// rest (unused code, unsafe patterns, accidental any).
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import { defineConfig } from "eslint/config";

const runtimeGlobals = Object.fromEntries(
  [
    "process", "console", "Buffer", "URL", "URLSearchParams", "setTimeout", "clearTimeout", "Response", "Request", "Headers",
    "fetch", "crypto", "performance", "TextEncoder", "TextDecoder", "atob", "btoa", "AbortSignal", "structuredClone",
  ].map((g) => [g, "readonly"]),
);

export default defineConfig(
  {
    ignores: [
      "dist/**", "node_modules/**", "brand/**", "tools/**", "docs/**",
      "apps/github-app/dist/**", "apps/github-app/node_modules/**", "apps/github-app/.wrangler/**",
    ],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    languageOptions: { globals: runtimeGlobals },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "no-control-regex": "off", // rules match control and invisible characters on purpose
      "no-misleading-character-class": "off",
      eqeqeq: ["error", "always", { null: "ignore" }],
      "prefer-const": "error",
    },
  },
  {
    files: ["test/**/*.js", "apps/github-app/test/**/*.js", "apps/github-app/scripts/**/*.mjs", "eslint.config.js"],
    rules: { "@typescript-eslint/consistent-type-imports": "off" },
  },
);

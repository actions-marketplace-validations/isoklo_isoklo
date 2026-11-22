// Register the Isoklo GitHub App in one click, with GitHub's app-manifest flow:
//   1. this script opens a local page that posts app-manifest.json to GitHub;
//   2. you click "Create GitHub App" on github.com (signed in as yourself; nothing is automated there);
//   3. GitHub redirects back here with a one-time code, which this script exchanges for the app's id, private key
//      and webhook secret, and writes them to .dev.vars and .secrets/ (both ignored by git).
//
//   npm run register -- --webhook https://isoklo-github-app.<you>.workers.dev/webhooks/github [--org your-org]
import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { execFile } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const appDir = join(here, "..");
const { values } = parseArgs({ options: { webhook: { type: "string" }, org: { type: "string" }, name: { type: "string" }, port: { type: "string" } } });
const port = Number(values.port ?? 3999);
if (!values.webhook || !/^https:\/\//.test(values.webhook)) {
  console.error("isoklo register: pass --webhook https://<your worker>/webhooks/github (deploy the worker first: npm run deploy).");
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(join(appDir, "app-manifest.json"), "utf8"));
manifest.hook_attributes.url = values.webhook;
manifest.redirect_url = `http://localhost:${port}/callback`;
if (values.name) manifest.name = values.name;
const target = values.org
  ? `https://github.com/organizations/${encodeURIComponent(values.org)}/settings/apps/new`
  : "https://github.com/settings/apps/new";
const state = crypto.randomUUID();
const esc = (s) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

const page = `<!doctype html><meta charset="utf-8"><title>Register Isoklo</title>
<body style="font:16px system-ui;max-width:40em;margin:4em auto">
<h1>Register the Isoklo GitHub App</h1>
<p>This sends the app's settings to GitHub. You will review them and click <b>Create GitHub App</b> there.</p>
<form method="post" action="${esc(target)}?state=${state}">
<input type="hidden" name="manifest" value="${esc(JSON.stringify(manifest))}">
<button style="font:inherit;padding:.6em 1.2em">Continue to GitHub</button></form></body>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);
  if (url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(page);
    return;
  }
  if (url.pathname !== "/callback") {
    res.writeHead(404).end();
    return;
  }
  const code = url.searchParams.get("code");
  if (!code || url.searchParams.get("state") !== state) {
    res.writeHead(400).end("Missing code or wrong state; start again with npm run register.");
    return;
  }
  const r = await fetch(`https://api.github.com/app-manifests/${encodeURIComponent(code)}/conversions`, {
    method: "POST", headers: { accept: "application/vnd.github+json", "user-agent": "isoklo-register" },
  });
  if (!r.ok) {
    res.writeHead(502).end(`GitHub refused the conversion (${r.status}).`);
    console.error(`isoklo register: GitHub answered ${r.status}: ${await r.text()}`);
    server.close();
    return;
  }
  const app = await r.json();
  mkdirSync(join(appDir, ".secrets"), { recursive: true });
  writeFileSync(join(appDir, ".secrets", "github-app.pem"), app.pem, { mode: 0o600 });
  writeFileSync(join(appDir, ".secrets", "webhook-secret.txt"), app.webhook_secret, { mode: 0o600 });
  writeFileSync(
    join(appDir, ".dev.vars"),
    `GITHUB_APP_ID="${app.id}"\nGITHUB_WEBHOOK_SECRET="${app.webhook_secret}"\nGITHUB_APP_PRIVATE_KEY="${app.pem.replace(/\n/g, "\\n")}"\n`,
    { mode: 0o600 },
  );
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(
    `<body style="font:16px system-ui;max-width:40em;margin:4em auto"><h1>Isoklo is registered</h1><p>App id ${app.id} (${esc(app.slug)}). Return to the terminal for the last two steps.</p><p><a href="${esc(app.html_url)}">Open the app's settings</a></p></body>`,
  );
  console.log(`\nRegistered ${app.slug} (app id ${app.id}): ${app.html_url}
Saved .dev.vars and .secrets/ (ignored by git). Next:

  1. Set the app id in wrangler.toml:  GITHUB_APP_ID = "${app.id}"
  2. Store the secrets in Cloudflare:
       bash/zsh:    npx wrangler secret put GITHUB_APP_PRIVATE_KEY < .secrets/github-app.pem
                    npx wrangler secret put GITHUB_WEBHOOK_SECRET < .secrets/webhook-secret.txt
       PowerShell:  Get-Content -Raw .secrets/github-app.pem | npx wrangler secret put GITHUB_APP_PRIVATE_KEY
                    Get-Content -Raw .secrets/webhook-secret.txt | npx wrangler secret put GITHUB_WEBHOOK_SECRET
  3. npm run deploy, then install the app: ${app.html_url}/installations/new
`);
  server.close();
});

server.listen(port, () => {
  const url = `http://localhost:${port}/`;
  console.log(`Open ${url} to register the Isoklo GitHub App${values.org ? ` for ${values.org}` : ""}.`);
  const opener = process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  execFile(opener[0], opener[1], () => undefined);
});

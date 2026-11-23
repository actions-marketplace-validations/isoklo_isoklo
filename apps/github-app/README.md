# Isoklo GitHub App

Install once on a repository or an organisation; every pull request gets the Isoklo merge gate with **no workflow
file and no YAML**. It runs the exact engine the CLI runs (`isoklo/engine`), on Cloudflare Workers.

What a pull request gets:

- an **`isoklo` check run**: `success`, or `action_required` with **one annotation per file, line and rule** and a
  **Re-run Isoklo** button (re-runs from GitHub's own "Re-run" also work);
- **one summary comment**, updated in place on every push, posted only when there is something to say
  (`COMMENT_ON_PASS = "true"` to always post);
- an **evidence receipt** in the check and the comment: SHA-256 over canonical JSON, signed with Ed25519 when
  `RECEIPT_SIGNING_JWK` is set (anyone can check it with `npx isoklo verify`), or HMAC with `RECEIPT_SIGNING_KEY`;
- **maintainer waivers**: `/isoklo waive <rule-id or fingerprint> <reason>` in a pull request comment.

Safety properties:

- every webhook's `X-Hub-Signature-256` is verified (HMAC-SHA256, constant-time compare) before anything is read;
- redeliveries are de-duplicated by `X-GitHub-Delivery`;
- the policy is read from the pull request's **merge base**, never from the pull request (and on Team, the org policy
  from `<org>/.github/isoklo.config.json` wins over the repository's);
- any failure completes the check as `failure` ("could not run"): the gate fails closed;
- a waiver counts only from a person (never a bot) with write or admin access, checked with GitHub's API, who is not
  the pull request's author (unless the base branch's policy sets `waivers.allowAuthor`); comments that are not
  `/isoklo` commands are dropped before any API call;
- the app asks only for `checks: write`, `contents: read`, `pull_requests: write`, `issues: read` (to receive
  `/isoklo` comments) and `metadata: read`.

## Try it locally (no accounts)

```console
npm ci && npm run simulate
```

`scripts/simulate.mjs` sends a signed `pull_request` webhook for a realistic agent pull request into the app, with a
fake GitHub API that checks the app's JWT the way GitHub does, and prints the check run, its annotations and the
comment. `npm test` runs the full suite (signatures, plans, Stripe, Marketplace, org policy, re-runs, fail-closed).
`npm run check:bundle` builds the Worker bundle with wrangler without deploying.

## Deploy and register (about 10 minutes)

Prerequisites: a Cloudflare account, `npx wrangler login`, and the root package built (`npm run build` in the repo root).

1. **Create the KV namespace** and paste its id into `wrangler.toml`:
   ```console
   npx wrangler kv namespace create ISOKLO_KV
   ```
2. **Deploy** once to get the Worker's URL (`https://isoklo-github-app.<you>.workers.dev`):
   ```console
   npm run deploy
   ```
3. **Register the GitHub App in one click** with GitHub's app-manifest flow:
   ```console
   npm run register -- --webhook https://isoklo-github-app.<you>.workers.dev/webhooks/github
   ```
   Add `--org <your-org>` to own the app as an organisation. The script opens a local page, you click
   **Create GitHub App** on github.com, and it saves the app id, private key and webhook secret to `.dev.vars` and
   `.secrets/` (both ignored by git). It prints the next commands. (To register by hand instead: GitHub →
   Settings → Developer settings → GitHub Apps → New, with the permissions and events in `app-manifest.json`.)
4. **Store the secrets** in Cloudflare and set the app id:
   ```console
   npx wrangler secret put GITHUB_APP_PRIVATE_KEY < .secrets/github-app.pem
   npx wrangler secret put GITHUB_WEBHOOK_SECRET < .secrets/webhook-secret.txt
   npx wrangler secret put RECEIPT_SIGNING_KEY        # optional: any long random string, for HMAC-signed receipts
   ```
   PowerShell: `Get-Content -Raw .secrets/github-app.pem | npx wrangler secret put GITHUB_APP_PRIVATE_KEY`.
   Then set `GITHUB_APP_ID` in `wrangler.toml` and `npm run deploy` again.
5. **Sign receipts with Ed25519** (recommended: anyone can verify them). Make a key and store only the private half,
   straight from one command into the other; the public half is then served at `/.well-known/isoklo-receipt-keys.json`:
   ```console
   npx isoklo@latest keygen 2>/dev/null | npx wrangler secret put RECEIPT_SIGNING_JWK
   ```
   PowerShell: `npx isoklo@latest keygen 2>$null | npx wrangler secret put RECEIPT_SIGNING_JWK`. When it is set it is
   used instead of `RECEIPT_SIGNING_KEY`. The CLI's `isoklo verify` trusts the key published by the official App's
   Worker; a self-hosted App publishes its own, which users pass with `--jwks https://<worker>/.well-known/isoklo-receipt-keys.json`.
6. **Install** the app from its page (`https://github.com/apps/<slug>/installations/new`) on a repository or a whole
   organisation. Open a pull request: the `isoklo` check appears within seconds.
7. **Make it required** (optional): Settings → Rules → Rulesets → require the status check **isoklo**.

Upgrading an existing App to 0.3: in the App's settings, add **Repository permissions → Issues: Read-only** and
subscribe to **Issue comment** events, then deploy. Each installation's owner is asked to accept the new permission;
until they do, everything else keeps working and `/isoklo waive` comments simply do not arrive.

## The App's public page

`github.com/apps/isoklo` shows the App's name, logo, description and homepage, and its install button. New
registrations (`npm run register`) take all of this from `app-manifest.json`. For an App that already exists, such as
the live one (App id 5884420), paste the values below into **GitHub → Settings → Developer settings → GitHub Apps →
Isoklo**:

| Where in the App's settings | Field | Value |
|---|---|---|
| General → Basic information | **Homepage URL** | `https://euklo.com/isoklo` |
| General → Basic information | **Description** | the text block below |
| General → Post installation | **Setup URL** | `https://euklo.com/isoklo/#setup` |
| General → Post installation | **Redirect on update** | off |
| General → Post installation | **Request user authorization (OAuth) during installation** | off (it would replace the setup URL) |

After installing, GitHub sends people to the setup URL with `installation_id` and `setup_action` added. The Isoklo page
reads them and shows an "Isoklo is on" note at its setup section, with the one step left: require the `isoklo` check
in a ruleset. Without those parameters, visitors see the normal page.

The description is plain text (GitHub does not render Markdown there), 976 characters. Paste it as it is:

```text
Your unit tests passed. The agent deleted the assertions. Isoklo blocks it in 2 seconds.

Isoklo is a deterministic merge gate for AI-written pull requests. On every pull request it runs 62 fixed rules, with no model and no YAML, and blocks deleted or skipped tests, packages that do not exist on npm or PyPI, leaked secrets, hidden agent instructions, risky MCP servers and edits outside the task, with the exact line as evidence.

You get an "isoklo" check with one annotation per line, one summary comment that updates in place, and an Ed25519-signed evidence receipt anyone can verify. Read-only access to code; no code is stored.

After installing, require the "isoklo" check in Settings > Rules > Rulesets so GitHub refuses to merge until it passes. Maintainers accept a finding with /isoklo waive <rule-id> <reason>.

Free for every public repository and up to 2 private ones. Team: $29 a month per GitHub organisation. Demo, rules and pricing: https://euklo.com/isoklo
```

The App page has no room for screenshots, a long README or a pricing tab. A **GitHub Marketplace listing** does:
a full Markdown description, screenshots, plans with prices, and installs and upgrades through GitHub billing, which
this Worker already handles (`marketplace_purchase` events; see [GitHub Marketplace](#github-marketplace)). Once the
listing is approved, point `UPGRADE_URL` at it.

## Turn on billing

Billing is a switch. With `BILLING_MODE = "off"` (the default) every repository gets every feature, which is the
right setting for launch and beta. With `"on"`, plans are enforced:

| Plan | Unlocks |
|---|---|
| free | every public repository, up to 2 private repositories per account, all rules, signed receipts |
| team | + every private repository, organisation-wide policy, maintainer waivers, stored receipts and the receipts API, Slack or Discord alerts |
| enterprise | the same as team, for licences sold by hand (self-hosting, your own signing key, SLA) |

Public repositories are never metered. A plan comes from, in order: the KV record written by a payment webhook, the
`LICENSES` setting (licences you sell by hand, `{"acme": "team"}`; a trial is a KV plan record with an `until` date),
then free. The free plan's private repositories are counted per account (`private-repos:<account id>` in KV), first come
first served; a third gets a neutral check with an upgrade link (`UPGRADE_URL`, default
https://euklo.com/isoklo/#pricing, with `client_reference_id=<GitHub account id>` appended), and none of its code is
read. The old plan name `pro` is read as team.

### GitHub Marketplace

1. On the app's page: **Marketplace listing** → create the listing, with plans named **Free**, **Team** and
   **Enterprise** (or map other names with `MARKETPLACE_PLAN_MAP = '{"Business": "team"}'`, by name or plan id). A paid
   plan with a name the app does not know is read as team, never as free.
2. GitHub sends `marketplace_purchase` events (purchased, changed, cancelled) to the app's normal webhook; the app
   records the plan. Nothing else to configure. Submit the listing for review when ready to charge.
3. Set `UPGRADE_URL = "https://github.com/marketplace/<slug>"` and `BILLING_MODE = "on"`, then deploy.

### Stripe

1. Create products and prices for Team (and Enterprise); set `STRIPE_PRICE_PLANS = '{"price_…": "team", "price_…": "enterprise"}'`.
2. Create a Payment Link (or Checkout Session) per plan; add `metadata.plan = team|enterprise`. Set
   `UPGRADE_URL` to the Payment Link: the app appends `client_reference_id=<GitHub account id>` so the payment is
   linked to the right GitHub account. On the website, set `NEXT_PUBLIC_ISOKLO_TEAM_CHECKOUT` to the same link so the
   pricing section's Team button goes straight to checkout.
3. Add a webhook endpoint `https://<worker>/webhooks/stripe` for `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`, then:
   ```console
   npx wrangler secret put STRIPE_WEBHOOK_SECRET      # the endpoint's whsec_… signing secret
   ```
   Signatures are verified with a 5-minute tolerance, so a captured event cannot be replayed.
4. Set `BILLING_MODE = "on"` and deploy.

### Paid features

- **Alerts** (Team): `npx wrangler kv key put --binding ISOKLO_KV "alerts:<account id>" "https://hooks.slack.com/services/…"`
  (Slack or Discord incoming webhook). Blocked pull requests post a short summary there.
- **Organisation policy** (Team): commit `isoklo.config.json` to the organisation's `.github` repository. Its rule
  levels, forbidden paths and waiver setting override every repository's.
- **Waivers** (Team): `/isoklo waive` and `/isoklo revoke` in pull request comments, stored per pull request for 400
  days (`waivers:<owner>/<repo>#<number>`). On the free plan the app answers with how to accept a finding in the policy.
- **Receipt history** (Team): receipts are stored for 400 days. Issue an API key with
  `npx wrangler kv key put --binding ISOKLO_KV "apikey:<sha256 of the key>" "<org login>"`, then
  `GET /api/receipts/<owner>/<repo>` (100 receipts a page, `?cursor=` for the next) or
  `GET /api/receipts/<owner>/<repo>/<commit sha>`, with `Authorization: Bearer <key>`.

## Settings

| Name | Kind | Meaning |
|---|---|---|
| `GITHUB_APP_ID` | var | The app's numeric id. |
| `GITHUB_APP_PRIVATE_KEY` | secret | The app's private key (PEM; GitHub's PKCS#1 works as is). |
| `GITHUB_WEBHOOK_SECRET` | secret | The app's webhook secret. |
| `RECEIPT_SIGNING_JWK` | secret | Ed25519 private key (JWK, from `npx isoklo keygen`) for receipts anyone can verify. Wins over `RECEIPT_SIGNING_KEY`. |
| `RECEIPT_SIGNING_KEY` | secret | HMAC key for signed receipts, when no Ed25519 key is set. |
| `STRIPE_WEBHOOK_SECRET` | secret | Stripe endpoint signing secret. |
| `BILLING_MODE` | var | `off` (default) or `on`. |
| `UPGRADE_URL` | var | Where upgrade links point: the pricing page (default), a Stripe Payment Link or the Marketplace listing. |
| `LICENSES`, `STRIPE_PRICE_PLANS`, `MARKETPLACE_PLAN_MAP` | var | JSON objects, see above. |
| `ONLINE` | var | `false` turns npm and PyPI lookups off. |
| `COMMENT_ON_PASS` | var | `true` posts a comment on passing pull requests too. |
| `GITHUB_API_URL` | var | For GitHub Enterprise Server (`https://ghe.example.com/api/v3`). |
| `ISOKLO_KV` | KV binding | Plans, installations, receipts, waivers, private-repository counts, delivery de-duplication. |

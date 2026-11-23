# Isoklo GitHub App

Install once on a repository or an organisation; every pull request gets the Isoklo merge gate with **no workflow
file and no YAML**. It runs the exact engine the CLI runs (`isoklo/engine`), on Cloudflare Workers.

What a pull request gets:

- an **`isoklo` check run**: `success`, or `action_required` with annotations on the exact lines and a
  **Re-run Isoklo** button (re-runs from GitHub's own "Re-run" also work);
- **one summary comment**, updated in place on every push, posted only when there is something to say
  (`COMMENT_ON_PASS = "true"` to always post);
- an **evidence receipt** (SHA-256; HMAC-signed on paid plans) in the check and the comment.

Safety properties:

- every webhook's `X-Hub-Signature-256` is verified (HMAC-SHA256, constant-time compare) before anything is read;
- redeliveries are de-duplicated by `X-GitHub-Delivery`;
- the policy is read from the pull request's **merge base**, never from the pull request (and on Team, the org policy
  from `<org>/.github/isoklo.config.json` wins over the repository's);
- any failure completes the check as `failure` ("could not run"): the gate fails closed;
- the app asks only for `checks: write`, `contents: read`, `pull_requests: write`, `metadata: read`.

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
   npx wrangler secret put RECEIPT_SIGNING_KEY        # any long random string; signs paid-plan receipts
   ```
   PowerShell: `Get-Content -Raw .secrets/github-app.pem | npx wrangler secret put GITHUB_APP_PRIVATE_KEY`.
   Then set `GITHUB_APP_ID` in `wrangler.toml` and `npm run deploy` again.
5. **Install** the app from its page (`https://github.com/apps/<slug>/installations/new`) on a repository or a whole
   organisation. Open a pull request: the `isoklo` check appears within seconds.
6. **Make it required** (optional): Settings → Rules → Rulesets → require the status check **isoklo**.

## Turn on billing

Billing is a switch. With `BILLING_MODE = "off"` (the default) every repository gets every feature, which is the
right setting for launch and beta. With `"on"`, plans are enforced:

| Plan | Unlocks |
|---|---|
| free | public repositories |
| pro | + private repositories, signed receipts, Slack or Discord alerts |
| team | + organisation-wide policy, stored receipts and the receipt export API |

A plan comes from, in order: the KV record written by a payment webhook, the `LICENSES` setting (licences you sell by
hand, `{"acme": "team"}`), then free. A private repository without a paid plan gets a neutral check with an upgrade
link (`UPGRADE_URL`, with `client_reference_id=<GitHub account id>` appended), and none of its code is read.

### GitHub Marketplace

1. On the app's page: **Marketplace listing** → create the listing, with plans named **Free**, **Pro** and **Team**
   (or map other names with `MARKETPLACE_PLAN_MAP = '{"Business": "team"}'`, by name or plan id).
2. GitHub sends `marketplace_purchase` events (purchased, changed, cancelled) to the app's normal webhook; the app
   records the plan. Nothing else to configure. Submit the listing for review when ready to charge.
3. Set `UPGRADE_URL = "https://github.com/marketplace/<slug>"` and `BILLING_MODE = "on"`, then deploy.

### Stripe

1. Create products and prices for Pro and Team; set `STRIPE_PRICE_PLANS = '{"price_…": "pro", "price_…": "team"}'`.
2. Create a Payment Link (or Checkout Session) per plan; add `metadata.plan = pro|team`. Set
   `UPGRADE_URL` to the Payment Link: the app appends `client_reference_id=<GitHub account id>` so the payment is
   linked to the right GitHub account.
3. Add a webhook endpoint `https://<worker>/webhooks/stripe` for `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`, then:
   ```console
   npx wrangler secret put STRIPE_WEBHOOK_SECRET      # the endpoint's whsec_… signing secret
   ```
   Signatures are verified with a 5-minute tolerance, so a captured event cannot be replayed.
4. Set `BILLING_MODE = "on"` and deploy.

### Paid features

- **Alerts** (Pro, Team): `npx wrangler kv key put --binding ISOKLO_KV "alerts:<account id>" "https://hooks.slack.com/services/…"`
  (Slack or Discord incoming webhook). Blocked pull requests post a short summary there.
- **Organisation policy** (Team): commit `isoklo.config.json` to the organisation's `.github` repository. Its rule
  levels and forbidden paths override every repository's.
- **Receipt export** (Team): receipts are stored for 400 days. Issue an API key with
  `npx wrangler kv key put --binding ISOKLO_KV "apikey:<sha256 of the key>" "<org login>"`, then
  `GET /api/receipts/<owner>/<repo>/<commit sha>` with `Authorization: Bearer <key>`.

## Settings

| Name | Kind | Meaning |
|---|---|---|
| `GITHUB_APP_ID` | var | The app's numeric id. |
| `GITHUB_APP_PRIVATE_KEY` | secret | The app's private key (PEM; GitHub's PKCS#1 works as is). |
| `GITHUB_WEBHOOK_SECRET` | secret | The app's webhook secret. |
| `RECEIPT_SIGNING_KEY` | secret | HMAC key for signed receipts. |
| `STRIPE_WEBHOOK_SECRET` | secret | Stripe endpoint signing secret. |
| `BILLING_MODE` | var | `off` (default) or `on`. |
| `UPGRADE_URL` | var | Marketplace listing or Stripe Payment Link. |
| `LICENSES`, `STRIPE_PRICE_PLANS`, `MARKETPLACE_PLAN_MAP` | var | JSON objects, see above. |
| `ONLINE` | var | `false` turns npm and PyPI lookups off. |
| `COMMENT_ON_PASS` | var | `true` posts a comment on passing pull requests too. |
| `GITHUB_API_URL` | var | For GitHub Enterprise Server (`https://ghe.example.com/api/v3`). |
| `ISOKLO_KV` | KV binding | Plans, installations, receipts, delivery de-duplication. |

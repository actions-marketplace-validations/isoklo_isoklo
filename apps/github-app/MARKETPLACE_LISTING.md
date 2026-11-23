# Isoklo on GitHub Marketplace: the listing, ready to paste

`github.com/apps/isoklo` is a fixed GitHub page: a name, a logo, a plain-text description and an install button. A
**GitHub Marketplace listing** adds the rest: a feature card, screenshots with captions, a longer description and a
pricing tab. Everything for that listing is in this file and in [`marketplace-assets/`](marketplace-assets/).

The copy follows GitHub's [listing description guidelines](https://docs.github.com/en/apps/github-marketplace/listing-an-app-on-github-marketplace/writing-a-listing-description-for-your-app)
(lengths checked; character counts are given with each field). The images follow the
[listing requirements](https://docs.github.com/en/apps/github-marketplace/creating-apps-for-github-marketplace/requirements-for-listing-an-app).
To rebuild the images from the launch screenshots:

```console
cd apps/github-app
node scripts/marketplace-assets.mjs "<folder with the 01- to 05- launch screenshots>"
```

---

## 1. Listing description

**Listing name**

```text
Isoklo
```

**Very short description** (67 characters; shown under the name on the Marketplace home page)

```text
Deterministic merge gate for pull requests written by coding agents
```

**Introductory description** (203 characters; the top of the listing)

```text
Isoklo blocks pull requests that weaken tests, add packages that do not exist, leak secrets, or widen what coding agents may do. It runs 62 fixed rules with no model and marks the exact line as evidence.
```

**Detailed description** (983 of 1,000 characters; shown under "Read more", Markdown)

```markdown
### Catches what agents do to get a green build
Sixty-two fixed rules cover weakened tests, invented packages, secrets and CI, agent and MCP permissions, and out-of-scope edits. No model is involved, so the same change always gets the same verdict.

### A signed receipt for every check
Each check records a SHA-256 digest and an Ed25519 signature that anyone can verify with npx isoklo verify. Receipts hold rule ids and locations, never code.

### Only a maintainer can override
A maintainer who did not open the pull request accepts a finding with /isoklo waive and a reason. A comment inside the change never counts, and every waiver is recorded.

### The same verdict on your machine
Run npx isoklo@latest check before you push: the same engine and the same rules. The GitHub Action runs it in your own workflow.

### On in two minutes
Install the app, then require the isoklo check in a branch ruleset so GitHub refuses to merge until it passes. No YAML, and no code is stored.
```

**Categories**

- Primary category: **Code review**
- Secondary category: **Security**

(If the form's list differs, pick the closest pair: code quality or testing, then security.)

**Supported languages** (optional): JavaScript, TypeScript, Python. Package checks cover npm and PyPI; every other rule
reads any language.

---

## 2. Contact and links

| Field | Value |
|---|---|
| Customer support URL | `https://github.com/isoklo/isoklo/issues` |
| Company URL | `https://euklo.com` |
| Homepage or product URL | `https://euklo.com/isoklo` |
| Documentation URL | `https://euklo.com/isoklo` (or `https://github.com/isoklo/isoklo#readme`) |
| Privacy policy URL | `https://euklo.com/privacy` |
| Terms of service URL | `https://euklo.com/terms` |
| Status URL (optional) | `https://isoklo-github-app.manishguptha188.workers.dev/health` |
| Support, technical, marketing and finance email | `hello@euklo.com` |

All of these answered 200 on 23 Nov 2026 (`/privacy` and `/terms` redirect to the same page with a trailing slash).

---

## 3. Images

| Field | File | Notes |
|---|---|---|
| Logo | `marketplace-assets/logo-200.png` | 400 × 400 (GitHub asks for at least 200 × 200; it crops to a square). The symbol in paper on ink. |
| Badge background colour | `#11100E` | The logo's own background, so the badge is seamless. |
| Feature card background | `marketplace-assets/feature-card-965x482.png` | Exactly 965 × 482. No text in it: GitHub draws the logo, name and very short description on top. |
| Feature card text colour | light (white) | Ink background; choose the light option. |

**Screenshots**, in this order, each 1600 × 1000 (GitHub asks for at least 1,200 px wide and one shape for all). Real
runs on [isoklo-demo](https://github.com/isoklo/isoklo-demo), cropped to the part that matters, with no browser bar,
sidebar, taskbar or frame.

| # | File | Caption |
|---|---|---|
| 1 | `screenshot-1-required-check.png` | Unit tests pass, and the required isoklo check blocks the merge |
| 2 | `screenshot-2-invented-package.png` | A package that does not exist on npm, flagged critical |
| 3 | `screenshot-3-inline-annotation.png` | The finding sits on the exact line that caused it |
| 4 | `screenshot-4-evidence-receipt.png` | One comment per pull request, with a signed evidence receipt |
| 5 | `screenshot-5-cli-verdict.png` | The same verdict from npx isoklo check, before you push |

They show Isoklo 0.2.0. Screenshot 3 has two cards on one line because isoklo-demo runs both the GitHub Action and the
App; from 0.3 each draws one card per line and rule, with the same title. Replace it once a fresh run is captured.

---

## 4. Plans and pricing

Start with **one free plan**. Paid plans on GitHub Marketplace need an organisation-owned app (Isoklo is), at least 100
installations, [publisher verification](https://docs.github.com/en/apps/github-marketplace/github-marketplace-overview/applying-for-publisher-verification-for-your-organization)
(two-factor authentication required for the organisation, and a verified domain), and both monthly and annual billing.
Until then, Team and Enterprise are sold from https://euklo.com/isoklo/#pricing and switched on with the App's
`LICENSES` setting.

| Field | Value |
|---|---|
| Plan name | `Free` |
| Pricing model | Free |
| Available for | Personal accounts and organisations |
| Plan description | `For public repositories, and anyone trying Isoklo on real work.` |
| Bullet 1 | `Every public repository, without limit` |
| Bullet 2 | `Up to 2 private repositories` |
| Bullet 3 | `All 62 rules, with no model` |
| Bullet 4 | `Signed evidence receipts` |

When paid plans are possible, add **Team** ($29 a month per organisation, unlimited seats, with an annual price) and
map it with `MARKETPLACE_PLAN_MAP` if its name is not "Team". The Worker already handles `marketplace_purchase` events
(purchased, changed, cancelled, pending changes), and a paid plan with an unknown name is never read as free.

---

## 5. Plan-change webhook

In the listing's **Webhook** section:

| Field | Value |
|---|---|
| Payload URL | `https://isoklo-github-app.manishguptha188.workers.dev/webhooks/github` |
| Content type | `application/json` |
| Secret | the App's webhook secret (the value in `.secrets/webhook-secret.txt`, stored in the Worker as `GITHUB_WEBHOOK_SECRET`) |
| Active | on |

The Worker verifies every delivery's signature with that secret and refuses anything unsigned.

---

## 6. Paste checklist

1. **Before you start.** The isoklo organisation has two-factor authentication on, the App is public, and the App's
   Homepage URL, Setup URL and description are set (see "The App's public page" in [README.md](README.md)).
2. Open **https://github.com/marketplace/new**, signed in as an owner of the isoklo organisation, and choose
   **Isoklo** (or: the App's settings, then **List in Marketplace**).
3. **Listing description:** paste the listing name, very short description, introductory description and detailed
   description from section 1. Choose the categories, and add the supported languages if you want them.
4. **Contact info:** fill in every field from section 2.
5. **Logo and feature card:** upload `logo-200.png`, set the badge background colour to `#11100E`, upload
   `feature-card-965x482.png`, and choose the light text colour. Check the preview: the name must read clearly.
6. **Screenshots:** upload the five screenshots in the order in section 3, and paste each caption.
7. **Plans and pricing:** create the Free plan from section 4 and publish the plan.
8. **Webhook:** fill in section 5 and save. Use the webhook's test delivery and look for a 2xx response in its recent
   deliveries.
9. **Overview:** every section shows as complete. Choose **Request publish** and submit the listing for review.
10. **After approval:** set `UPGRADE_URL` in `wrangler.toml` to `https://github.com/marketplace/isoklo` (only once the
    listing is live, so upgrade links never land on a 404), and deploy the Worker.

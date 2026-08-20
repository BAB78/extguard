# Publishing Guide: ExtGuard

Phase 4. Free-only first, no payment wall, to gather installs and reviews before monetising.

Nothing here has been done on your behalf. Every step below involves an account or a
credential, so all of it is yours to execute.

---

## Publisher identity (already registered)

The extension is published under:

```json
"publisher": "babstudios"
```

Do not change it. The Marketplace identity is now permanently
`babstudios.extguard-security`; changing either part would create a different extension and
lose the existing install count and reviews.

---

## Step 1: Microsoft account and Azure DevOps organisation

The Marketplace authenticates through Azure DevOps, so you need an organisation even though
you will never use the rest of it.

1. Go to https://dev.azure.com and sign in with a Microsoft account.
2. If prompted, create an organisation. The name does not matter and is not public.

Use the same Microsoft account you used for the Edge Add-ons registration, so you have one
Microsoft identity rather than two to keep track of.

---

## Step 2: Create the Marketplace publisher

1. Go to https://marketplace.visualstudio.com/manage
2. **Create publisher**.
3. Fill in:
   - **ID**: the value you decided above. Lowercase, no spaces, permanent.
   - **Display name**: what users see, for example `BAB Studios`.
   - **Logo**: `media/icon.png` in this repo.

Registration is free. There is no fee at any point, unlike the Chrome Web Store.

---

## Step 3: Create the Personal Access Token

This token can publish updates to your extensions, so treat it as a credential of the same
weight as a signing key. ExtGuard's own secret scanner looks for leaked Azure DevOps PATs
precisely because of what one lets an attacker do.

1. In Azure DevOps, open the user menu, then **Personal access tokens**.
2. **New Token**, with these settings, which matter:
   - **Organization**: `All accessible organizations`. Anything narrower fails with a
     confusing 401 that looks like a wrong password.
   - **Expiration**: 90 days is a reasonable maximum. Shorter is better.
   - **Scopes**: choose **Custom defined**, then **Show all scopes**, then tick only
     **Marketplace: Manage**. Do not grant full access.
3. Copy the token immediately. It is shown once and never again.

**Do not put it in the repo, in `.env`, or in any file inside this folder.** Use it through
`vsce login` or the `VSCE_PAT` environment variable at publish time only.

---

## Step 4: Publish

```bash
npm run feed          # refresh the bundled threat snapshot so it ships current
npm test              # 48 tests
npm run compile
npm run preflight     # includes a public-repository check for listing images and links
npx @vscode/vsce login <your-publisher-id>
npx @vscode/vsce publish
```

The preflight intentionally blocks while `https://github.com/BAB78/extguard` returns 404.
`vsce` rewrites the three relative screenshot paths and SECURITY link to that repository, so
publishing before the repository is public would produce a broken Marketplace listing.

`vsce publish` runs `vscode:prepublish`, which compiles and copies the threat snapshot into
`out/`. If that copy step ever fails, the extension ships with no threat data and reports every
machine clean, so treat a failure there as a release blocker rather than a warning.

To publish an already-built artifact instead:

```bash
npx @vscode/vsce publish --packagePath extguard-security-1.0.2.vsix
```

### Version bumps

```bash
npx @vscode/vsce publish minor    # or patch / major
```

The Marketplace rejects a version that already exists, so each publish needs a new one.

---

## Step 5: After it is live

- Review usually completes within about 24 hours for a first submission.
- The listing appears at
  `https://marketplace.visualstudio.com/items?itemName=babstudios.extguard-security`.
- Installs and ratings show in the publisher management page. There is no separate console.

**Give it two to three weeks before touching monetisation.** That is the whole point of
publishing free-first: you need install numbers and reviews to know whether a Team tier has
anybody to sell to, and the backend in `backend/` is unnecessary cost until then.

---

## Security notes specific to this extension

- **Never commit the PAT.** If one leaks, revoke it in Azure DevOps immediately; a leaked
  publishing token is worse than a leaked password, because it can push malicious code to
  everyone who already trusts you.
- **The snapshot has a date.** `SECURITY.md` states it, and the sidebar shows it. Run
  `npm run feed` before each release so users are not running months-old threat data.
- **Keep the free tier free of network calls.** The privacy claim in the listing is the reason
  anyone will trust a security scanner. If the Team tier later adds reporting, it must be
  opt-in, clearly separated, and the listing must be updated in the same release.

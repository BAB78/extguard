# ExtGuard: Marketplace Listing

Everything below is paste-ready. Figures are taken from the shipped build, so re-check them
after a feed update: `node scripts/update-threat-feed.mjs` then regenerate this file's numbers.

## Title

```
ExtGuard: Extension Security Scanner
```

## Short description

```
Audit your installed extensions for leaked secrets, risky capability, and known-malicious IDs. Runs entirely on your machine.
```

## Full description

### Your VS Code extensions run with your full privileges. Have you read any of them?

VS Code has no permission model. Any extension with a `main` entry point runs as ordinary
Node.js with the reach of your user account: your files, your environment variables, your
terminal, your network. There is nothing to over-request, because everything is already
granted.

The median developer has around 80 installed and has audited none of them.

ExtGuard reads what is already on your disk and tells you which extensions earned their access.

---

### What it checks

**Known-malicious IDs.** Cross-references every installed extension against 1,981
malicious records and 1,300 blocked publishers, aggregated from public threat feeds
including Microsoft's own removed-packages list. The database ships inside the extension, so
this check never touches the network.

**Hardcoded secrets.** Structural detection of AWS keys, GitHub and GitLab tokens, Slack
webhooks and OAuth tokens, Stripe keys, Google API keys, npm tokens, private key blocks, and
Azure DevOps PATs. A leaked publisher PAT is the one that matters most: it lets an attacker
ship an update to somebody else's extension.

**Capability signals.** What each manifest reveals about reach: eager activation, proposed API
usage, workspace-trust posture, shell task registration. Plus what the shipped code actually
calls, including process spawning, dynamic evaluation, outbound connections, and reads of
credential stores such as `~/.ssh` and `~/.aws`.

**A risk score per extension**, worst first, in a sidebar panel. Every finding cites the file
and line that caused it.

---

### It is built to not cry wolf

This is the part most scanners get wrong, so it is worth being specific.

An early build of ExtGuard produced **2,850 findings across 57 of 82 extensions** on a clean
machine. That is not a security tool, it is a tool you learn to ignore. The current build
produces **zero critical or high findings on the same machine**.

Two design decisions did most of that work:

**Behaviour is not a verdict.** Rules that look for process spawning or network calls run only
on readable source, never on minified bundles, JSON schemas or documentation. Matching the word
"request" inside a schema description is not a network call.

**Broad capability is not a threat.** Jupyter, the PowerShell extension, GitLens and AI coding
agents execute code and read your codebase because that is their entire purpose. ExtGuard
labels these as capability, with an explanation, and never as findings. A tool that opens by
calling Microsoft's own PowerShell extension a threat has told you nothing except that it
cannot be trusted.

---

### What it is not

Not antivirus, and not a sandbox. It cannot stop an extension that is already running. It
reports what is installed and what it can reach, so the decision is yours. A clean result means
these specific checks found nothing, not that every extension is safe.

---

### Privacy, which is the whole point

A tool that audits your editor for spyware cannot itself phone home.

- All scanning is local. Files are read in read-only mode and nothing is modified.
- No telemetry, no analytics, no account, and no network calls during a scan.
- The threat database is bundled, not fetched. The trade is complete privacy in exchange for
  data that is only as fresh as your last update, and ExtGuard shows you the snapshot date
  rather than implying its knowledge is current.
- If the database fails to load, ExtGuard tells you it could not check. It never reports a
  clean result it did not establish.

Full detail in [SECURITY.md](https://github.com/BAB78/extguard/blob/main/SECURITY.md).

---

### Compatibility

VS Code, Cursor, Windsurf, and any editor built on the VS Code API v1.75 or later.

---

### How to use it

1. Install, then click the shield icon in the activity bar.
2. Press refresh, or run **ExtGuard: Scan Extensions** from the command palette.
3. Extensions are listed worst first. Expand any one to see its findings with file and line.
4. Trust a publisher permanently under Settings, ExtGuard, Allowed Publishers.

---

## Screenshots

Captured from the packaged 1.0.2 build in an isolated VS Code profile using a small set of
real installed extensions. The files are embedded in the Marketplace README.

### Screenshot 1: the sidebar after a scan

`media/screenshots/01-extension-overview.png`

The ExtGuard panel open in the activity bar, listing installed extensions sorted worst first.
Each row shows the extension name, a coloured icon, and a description reading
`(Score: 2/10 - Low)` or `(Score: 0/10)`. Include at least one green row so the shot shows the
tool clearing extensions as well as flagging them. A machine with nothing wrong is the honest
default state and it is worth showing.

### Screenshot 2: an expanded extension with findings

`media/screenshots/02-finding-with-file-line.png`

One extension expanded to reveal its child rows. Real examples from the current build:

- `Code: Spawns an OS process` with the description `scripts/build.js:56`
- `Perm: Registers custom tasks/terminal definitions which can execute shell operations.`
- `Code: Opens an outbound network connection`

This is the shot that shows every finding cites a file and a line.

### Screenshot 3: capability explained, not accused

`media/screenshots/03-capability-explained.png`

An extension such as Jupyter, PowerShell or GitLens expanded to show its informational row:

- `Capability: risky-code-execution` with the description explaining that it executes code by
  design and is not a defect, shown with a lightbulb icon rather than a warning.

This is the single most differentiating screenshot. It shows the tool distinguishing "this is
powerful" from "this is dangerous", which is the distinction every other scanner blurs.

---

## Search tags

```
security
extension-audit
secrets-scanner
malicious-extensions
supply-chain
```

---

## Before you submit

- [x] Publisher ID is registered as `babstudios`; the permanent Marketplace identity is
      `babstudios.extguard-security`.
- [ ] Repository URL in `package.json` points at a repo that exists and is public, or the
      SECURITY.md link and all three screenshots will 404 for every visitor. The release
      preflight currently blocks on this check.
- [x] `npm test` green (48 tests), `node scripts/scan-real-machine.mjs` reports zero hard
      findings.
- [x] Threat snapshot is current (generated 2026-08-19).
- [x] Three screenshots captured from the packaged build and embedded in the README.

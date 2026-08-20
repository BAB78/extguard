# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active |

## Privacy Statement

**ExtGuard is built on a single core principle: everything stays on your machine.**

- ✅ All extension scanning happens **100% locally** on your device.
- ✅ Source code analysis, regex matching, and blocklist checks are performed entirely in-process.
- ✅ No extension metadata, scan results, risk scores, or file contents are ever uploaded to any server.
- ✅ No telemetry, analytics, or usage tracking in the free tier (v1).
- ✅ No network connections are made during scanning. ExtGuard works fully offline.
- ✅ Extension files are read from the local file system (`~/.vscode/extensions/`) in read-only mode.

## What ExtGuard Scans

1. **Extension Manifests (`package.json`):** Workspace Trust configuration, proposed API usage, activation events, task/terminal definitions.
2. **Extension Source Code (`.js`, `.ts`, `.json`):** Hardcoded credentials (AWS keys, GitHub tokens, Slack webhooks, Stripe keys), dangerous function calls (`eval`, `child_process.exec`), suspicious network access patterns.
3. **Extension IDs:** Cross-referenced against a locally-stored blocklist of known malicious extensions.

## What ExtGuard Does NOT Do

- ❌ Does **not** modify, delete, disable, or alter any extension files.
- ❌ Does **not** send scan results or any data to external servers.
- ❌ Does **not** require an internet connection to perform scans.
- ❌ Does **not** access files outside of VS Code extension directories.
- ❌ Does **not** interfere with extension functionality or execution.

## Team Tier (Paid) Network Activity

The optional **Team tier** allows organizations to report scan results to a self-hosted or managed backend for centralized monitoring. This feature:
- Is **opt-in only** and requires an explicit license key.
- Only transmits extension IDs, risk scores, and finding summaries (never source code).
- Can be pointed at your own infrastructure for full data sovereignty.

## Reporting a Vulnerability

If you discover a security vulnerability in ExtGuard, please report it responsibly:

1. **Email:** [security@extguard.dev](mailto:security@extguard.dev)
2. **Subject line:** `[SECURITY] Brief description of the issue`
3. Include steps to reproduce, affected versions, and potential impact.

**Do not** open a public GitHub issue for security vulnerabilities.

## Responsible Disclosure

- We will acknowledge receipt within **48 hours**.
- We aim to provide an initial assessment within **5 business days**.
- We will coordinate disclosure timing with the reporter.
- Credit will be given to reporters (unless anonymity is requested).

## Security Design Principles

1. **Minimal dependencies:** ExtGuard relies primarily on Node.js standard libraries and VS Code APIs to minimize supply-chain risk.
2. **Read-only operations:** Extension directories are never written to.
3. **No secrets stored:** ExtGuard does not store, cache, or log any secrets it detects. Findings reference line numbers and pattern types only.
4. **Local blocklist:** The malicious extension database ships with the extension and requires no network fetch.

### What the bundled threat data is, and its limits

The malicious-extension database is a point-in-time snapshot of the public
[VSXSentry](https://vsxsentry.github.io/) feeds, which aggregate Microsoft's own
[RemovedPackages](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) list
among other sources.

- Snapshot in this build: **1981 malicious records, 1300 blocked publishers**, generated 2026-08-19.
- It ships inside the extension, so scanning never touches the network. That is the trade: complete privacy in exchange for data that is only as fresh as your last ExtGuard update.
- A threat published after this snapshot will not be detected until you update. ExtGuard states the snapshot date in the sidebar rather than implying its knowledge is current.
- If the snapshot fails to load, ExtGuard reports that it could not check. It never reports a clean result it did not establish.

**What is deliberately not used as a threat signal.** The upstream feeds also publish a
*risky* list of legitimate extensions with broad capability, such as Jupyter, the PowerShell
extension and GitLens, which execute code because that is their purpose. ExtGuard shows these
as capability context and never as findings. Treating that list as a blocklist would flag
ordinary, trusted extensions on a clean machine.

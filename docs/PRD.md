# Product Requirement Document (PRD): ExtGuard v1

## 1. Overview & Goal
**ExtGuard** is a VS Code extension that audits a developer's installed extensions for security risks. It aims to detect leaked credentials, excessive permissions, suspicious API usage, and known-malicious extensions, and present them in a clear, actionable risk report.

Since VS Code extensions execute with the user's full privileges (Node.js environment), a compromised or malicious extension can read any file, run arbitrary shell commands, or exfiltrate environment variables. ExtGuard provides a local-first security scanner to help developers maintain hygiene.

---

## 2. Key Features (Phase 1 Scope)

### A. Manifest Auditing (Permissions Scan)
VS Code extensions use `package.json` as their manifest. Unlike browsers, there is no sandbox or strict permission model, but extensions declare capabilities. ExtGuard will parse `package.json` for:
- **Workspace Trust (`workspaceTrust`):** Flag extensions that request `request: "never"` (i.e. run in untrusted workspaces) but perform dangerous operations.
- **Proposed APIs (`enabledApiProposals`):** Flag usage of unstable/proposed VS Code APIs, which might be used for low-level system access.
- **Virtual Workspaces support:** Scan for unsupported configurations.
- **Command & Terminal Contributions:** Flag custom shell execution integrations or task providers.

### B. VSIX & Installed Source Secret Scanner
Scan the javascript/typescript files of installed extensions (under the local `.vscode/extensions` folder or a provided `.vsix` file) for hardcoded secrets, dangerous functions, and suspicious system calls:
- **Credential Detection (Regex):**
  - VS Code/Azure DevOps PATs: `[0-9a-zA-Z]{52}`
  - AWS Access Keys: `AKIA[0-9A-Z]{16}`
  - Slack Webhooks: `https://hooks.slack.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/[A-Za-z0-9_]+`
  - GitHub Token: `gh[oprs]_[a-zA-Z0-9]{36}` or classic tokens.
  - Generic API keys / High-Entropy Secrets.
- **Suspicious Code Patterns:**
  - Network requests: `http.request`, `https.request`, `fetch`, `axios`, `request` imports/calls.
  - Execution/Process spawning: `child_process`, `exec`, `spawn`, `fork`, `execSync`.
  - Dynamic evaluation: `eval(`, `Function(`, `setTimeout` with string arguments.
  - File system operations outside workspace: `fs`, `fspromises` writing/reading sensitive files (e.g., `.git/config`, `id_rsa`, `.env`).

### C. Extension ID Blocklist Cross-Check
Cross-reference extension IDs (`publisher.name`) against a built-in blocklist of known malicious or reported extensions.
- The blocklist will be stored locally as a JSON file for quick access and to maintain absolute privacy.
- Example blocklist entries:
  - Impersonating popular extensions (typosquatting).
  - Documented malicious extensions removed from the VS Code Marketplace.

### D. Sidebar Panel UI
Provide a tree-view panel in the VS Code sidebar showing:
- List of installed extensions.
- Visual risk score badge/indicator (Low / Medium / High / Critical) or a numerical score (0 to 10).
- Dropdown details displaying the reasons for the risk score (e.g., "Found AWS Secret Key", "Executes shell commands in untrusted workspace", "On Malicious Blocklist").
- A "Scan Now" button to refresh results.

---

## 3. Risk Scoring Methodology

An extension's overall risk score (0 to 10) is calculated as the maximum or weighted sum of the following category scores:

| Severity | Score Range | Criteria / Triggers |
|---|---|---|
| **Critical** | 9 - 10 | On the Malicious Blocklist, or contains verified plaintext credentials/tokens. |
| **High** | 7 - 8 | Spawns child processes or makes arbitrary network requests while running in untrusted workspaces. |
| **Medium** | 4 - 6 | Uses proposed APIs, disables Workspace Trust, or uses dynamic evaluation (`eval`). |
| **Low** | 1 - 3 | Standard extensions with minimal system access declarations, or minor code warnings. |
| **Safe** | 0 | No suspicious patterns detected. |

---

## 4. Privacy & Trust Proposition
- **100% Local Scanning:** All audits, unzipping, regex grepping, and blocklist matching happen locally on the user's machine.
- **No Data Uploads:** Zero telemetry or telemetry-gated features in v1. No connection to remote servers (except when checking optional blocklist updates in future phases, which will be opt-in).
- Documented in `SECURITY.md`.

---

## 5. Technical Stack
- **Target Editors:** VS Code, Cursor, Windsurf (VS Code API compatible, target API v1.75+).
- **Language/Framework:** TypeScript, Node.js.
- **Testing:** Jest.
- **Dependency Minimization:** Rely on VS Code's built-in APIs and Node.js standard libraries (`fs`, `path`, `child_process`, `crypto`) where possible to avoid introducing security risks through third-party dependencies.

---

## 6. Implementation Milestones

1. **Phase 1: SPEC** (PRD and feedback alignment).
2. **Phase 2: BUILD** (Yo Code scaffolding, core scanning engines, Jest unit tests, tree view UI).
3. **Phase 3: HARDEN & TEST** (False positive assessment, publisher allowlist, SECURITY.md).
4. **Phase 4: PACKAGE** (VSCE packaging, store listing preparation, publishing strategy).
5. **Phase 5: MONETIZE** (Team tier, PostgreSQL licensing, Stripe subscriptions, secure client
   activation, and privacy-minimized report storage).
6. **Phase 6: LAUNCH** (Socials/HN strategy, analytics setup).

Phase 5 implementation is maintained separately from the free scanning boundary. Hosted checkout
must remain disabled until the Railway and Stripe test matrix in `docs/PAYMENT_TESTING.md` passes.

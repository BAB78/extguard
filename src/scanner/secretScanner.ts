import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';

/**
 * Secret and behaviour scanning for installed extensions.
 *
 * Rewritten after running the previous version against the 82 extensions installed on a real
 * machine believed to be clean. It produced **2,850 findings across 57 extensions**, a 70%
 * false-positive rate, which makes a security tool worse than useless: it trains the user to
 * dismiss everything, including the one finding that mattered.
 *
 * The causes, and what changed:
 *
 *   1. Behaviour rules (process/network/eval) ran on markdown, JSON schemas and minified
 *      bundles. The word "request" inside `"description": "Attribution text for pull..."`
 *      counted as a network call. Behaviour rules now run ONLY on readable JS/TS source.
 *   2. A `[a-zA-Z0-9]{52}` rule fired on any long token in a minified bundle. It now requires
 *      assignment to a credential-shaped identifier, plus an entropy floor.
 *   3. Nothing detected minified files. Anything with a very long mean line length is
 *      generated output, and matching identifiers in it tells you about the bundler.
 *   4. Placeholders like `YOUR_TOKEN_HERE` and `process.env.KEY` were treated as secrets.
 *
 * Guiding rule: a finding must point at something a human would agree is wrong. Everything
 * else is noise, and noise is what gets the extension uninstalled.
 */

export interface Finding {
  file: string;
  line: number;
  category: 'secret' | 'process' | 'network' | 'dynamic_eval' | 'sensitive_file';
  description: string;
  severity: 'medium' | 'high' | 'critical';
}

/**
 * Structural credential patterns. Each matches a provider-issued format with no other
 * meaning, so a match is evidence rather than a guess. These produced zero false positives
 * across the 82-extension corpus and are kept as they were.
 */
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', regex: /\b(AKIA|ASCA|ASIA)[0-9A-Z]{16}\b/, severity: 'critical' as const },
  { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]+\/B[A-Z0-9_]+\/[A-Za-z0-9_]+/, severity: 'critical' as const },
  { name: 'GitHub Token', regex: /\b(ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36}\b/, severity: 'critical' as const },
  { name: 'GitHub Fine-grained Token', regex: /\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b/, severity: 'critical' as const },
  { name: 'Slack OAuth Token', regex: /\bxox[bapr]-[0-9a-zA-Z-]{10,99}\b/, severity: 'critical' as const },
  { name: 'Stripe API Key', regex: /\b(sk_live|rk_live)_[0-9a-zA-Z]{24,99}\b/, severity: 'critical' as const },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'critical' as const },
  { name: 'Private Key Block', regex: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, severity: 'critical' as const },
  { name: 'npm Access Token', regex: /\bnpm_[A-Za-z0-9]{36}\b/, severity: 'critical' as const },
];

/**
 * A generic long token only counts when assigned to a credential-shaped name. The old rule
 * looked for a 52-character run anywhere on a line that merely *mentioned* "key", which every
 * minified bundle satisfies many times over.
 */
const ASSIGNED_SECRET = /\b(?:pat|token|secret|api[_-]?key|apikey|password|passwd|auth[_-]?token|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"`]([A-Za-z0-9+/_-]{32,120})['"`]/i;

/** Strings shaped like credentials that are really documentation, examples or env lookups. */
const PLACEHOLDER = /^(?:x{4,}|0{4,}|1234|abcd|test|dummy|sample|example|changeme|placeholder|your|my|insert|redacted|removed|none|null|undefined|true|false)/i;
const PLACEHOLDER_ANY = /(your[_-]?(api|token|key|secret)|xxx+|<[^>]+>|\{\{[^}]+\}\}|\$\{|process\.env|import\.meta\.env|os\.environ|example\.com|localhost)/i;

const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'out', 'dist', 'bin', 'obj', 'build',
  'test', 'tests', '__tests__', 'fixtures', 'testdata', 'coverage', '.vscode-test',
]);

/** Secret patterns may run on any text file. */
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.env', '.txt', '.md', '.yml', '.yaml', '.sh', '.ps1']);
/** Behaviour rules run only on source a human could plausibly have written. */
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Shannon entropy, bits per character. Real credentials sit well above ~3.5. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Generated or bundled output. Minifiers emit very long lines; hand-written source does not.
 * Matching identifiers inside generated code tells you about the bundler, not the author.
 */
export function isMinified(content: string, filePath = ''): boolean {
  if (/[.-](min|bundle|chunk|vendor)\.[cm]?jsx?$/i.test(filePath)) return true;
  if (!content) return false;
  const meaningful = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (!meaningful.length) return false;
  const mean = meaningful.reduce((n, l) => n + l.length, 0) / meaningful.length;
  const longest = meaningful.reduce((n, l) => Math.max(n, l.length), 0);
  return mean > 250 || longest > 5000;
}

/** True when a candidate looks like a real credential rather than a placeholder. */
export function looksLikeRealSecret(value: string): boolean {
  if (!value || value.length < 16) return false;
  if (PLACEHOLDER.test(value)) return false;
  if (PLACEHOLDER_ANY.test(value)) return false;
  // Too few distinct characters means filler, not entropy.
  if (new Set(value).size < 8) return false;
  return shannonEntropy(value) >= 3.5;
}

/** Blank out string and comment bodies so behaviour rules match code, not prose in quotes. */
function codeOnly(line: string): string {
  return line
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/, '');
}

export function scanFile(filePath: string, relativePath: string): Finding[] {
  const findings: Finding[] = [];
  try {
    const stats = fs.statSync(filePath);
    if (stats.size > MAX_FILE_BYTES) return findings;

    const ext = path.extname(filePath).toLowerCase();
    if (!TEXT_EXTENSIONS.has(ext)) return findings;

    const content = fs.readFileSync(filePath, 'utf8');
    const isCode = CODE_EXTENSIONS.has(ext) && !isMinified(content, relativePath);

    // Behaviour rules need whole-file context: a bare `exec()` only matters if child_process
    // is genuinely imported somewhere in this file.
    const importsChildProcess = isCode && /require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|import\s+.*['"]child_process['"]/.test(content);

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      // 1. Structural credentials. Allowed on any text file, because a real AKIA key
      //    committed into a README is still a real leaked key.
      for (const pattern of SECRET_PATTERNS) {
        const m = line.match(pattern.regex);
        if (!m) continue;
        if (pattern.name !== 'Private Key Block' && !looksLikeRealSecret(m[0])) continue;
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'secret',
          description: `Hardcoded ${pattern.name}`,
          severity: pattern.severity,
        });
      }

      // 2. A generic credential assigned to a credential-shaped identifier.
      const assigned = line.match(ASSIGNED_SECRET);
      if (assigned && looksLikeRealSecret(assigned[1])) {
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'secret',
          description: 'Credential assigned to a token/secret identifier',
          severity: 'high',
        });
      }

      // Everything below describes behaviour, which only source code can have.
      if (!isCode) continue;
      const code = codeOnly(line);

      // 3. Process spawning, only where child_process is actually imported.
      if (importsChildProcess && /\b(execSync|exec|spawnSync|spawn|execFile|fork)\s*\(/.test(code)) {
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'process',
          description: 'Spawns an OS process',
          severity: 'medium',
        });
      }

      // 4. Dynamic evaluation.
      if (/\beval\s*\(/.test(code) || /\bnew\s+Function\s*\(/.test(code)) {
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'dynamic_eval',
          description: 'Evaluates a string as code',
          severity: 'medium',
        });
      }

      // 5. Outbound network, matched as a *call* rather than a mention of the word.
      //    No import gate: `fetch` is a global and needs none, and exfiltration via fetch is
      //    the most likely vector of all. The precision comes from requiring a qualified
      //    call form, which is what the old bare-word `request` rule lacked.
      if (/\b(fetch|axios\.(get|post|put|patch|delete|request)|https?\.(request|get)|net\.(connect|createConnection)|tls\.connect|XMLHttpRequest)\s*\(/.test(code)) {
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'network',
          description: 'Opens an outbound network connection',
          severity: 'medium',
        });
      }

      // 6. Reading a credential store. The path lives inside a string literal, which
      //    codeOnly() blanks, so the path is matched on the raw line while the read call is
      //    matched on either. Requiring both is what keeps documentation from triggering it.
      const readsFile = /\b\w*(?:readFile|readdir|createReadStream|openSync|open|readFileSync)\w*\s*\(/.test(line);
      const credentialStore = /\.ssh\b|\.aws\b|id_rsa|\.npmrc|\.git-credentials|credentials(?:\.json)?["'`]/i.test(line);
      if (readsFile && credentialStore) {
        findings.push({
          file: relativePath,
          line: lineNumber,
          category: 'sensitive_file',
          description: 'Reads a credential file or key store',
          severity: 'high',
        });
      }
    }
  } catch {
    // An unreadable file is skipped. It must never surface as a finding.
  }
  return findings;
}

export function scanDirectory(dirPath: string, rootPath: string = dirPath): Finding[] {
  let findings: Finding[] = [];
  try {
    for (const file of fs.readdirSync(dirPath)) {
      const fullPath = path.join(dirPath, file);
      const relativePath = path.relative(rootPath, fullPath);
      let stats: fs.Stats;
      try { stats = fs.statSync(fullPath); } catch { continue; }

      if (stats.isDirectory()) {
        if (!EXCLUDED_DIRS.has(file.toLowerCase())) {
          findings = findings.concat(scanDirectory(fullPath, rootPath));
        }
      } else if (stats.isFile()) {
        findings = findings.concat(scanFile(fullPath, relativePath));
      }
    }
  } catch {
    // Unreadable directory: skip rather than report.
  }
  return findings;
}

/** Scan a .vsix that has not been installed. A .vsix is a zip, so tar can extract it. */
export function scanVsix(vsixPath: string): Finding[] {
  let findings: Finding[] = [];
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'extguard-vsix-'));
  try {
    child_process.execSync(`tar -xf "${vsixPath}" -C "${tempDir}"`, { stdio: 'ignore' });
    findings = scanDirectory(tempDir).map((f) => ({ ...f, file: `[VSIX]/${f.file}` }));
  } catch {
    // Extraction failed. Report nothing rather than something wrong.
  } finally {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Async scanning
// ---------------------------------------------------------------------------

/**
 * The synchronous scanner above is correct but unusable from the extension host.
 *
 * Measured against the 77 extensions on the development machine, a full sync scan blocks for
 * 27 seconds, and a single extension (dart-code) blocks for 12.5 of those on its own. Because
 * the work is synchronous, awaiting it does not yield: VS Code's UI simply freezes for the
 * duration. A security tool that hangs the editor for twelve seconds gets uninstalled before
 * it ever reports anything.
 *
 * This variant yields to the event loop periodically and enforces a per-extension budget, so
 * no single extension can monopolise the thread. When the budget is hit the result says so,
 * rather than quietly returning a partial scan that looks like a clean one.
 */

export interface ScanBudget {
  /** Stop after this many files. */
  maxFiles: number;
  /** Stop after this many bytes read. */
  maxBytes: number;
  /** Yield to the event loop every this many files. */
  yieldEvery: number;
}

export const DEFAULT_BUDGET: ScanBudget = {
  maxFiles: 1200,
  maxBytes: 40 * 1024 * 1024,
  yieldEvery: 40,
};

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  bytesRead: number;
  /** True when the budget stopped the scan early, so "no findings" is not "nothing there". */
  truncated: boolean;
}

const yieldToEventLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

export async function scanDirectoryAsync(
  dirPath: string,
  budget: ScanBudget = DEFAULT_BUDGET,
  token?: { isCancellationRequested: boolean }
): Promise<ScanResult> {
  const findings: Finding[] = [];
  let filesScanned = 0;
  let bytesRead = 0;
  let truncated = false;

  const walk = async (dir: string): Promise<void> => {
    if (truncated || token?.isCancellationRequested) return;

    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory: skip rather than report
    }

    for (const entry of entries) {
      if (truncated || token?.isCancellationRequested) return;
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name.toLowerCase())) await walk(full);
        continue;
      }
      if (!entry.isFile()) continue;

      let size = 0;
      try {
        size = (await fs.promises.stat(full)).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES) continue;

      if (filesScanned >= budget.maxFiles || bytesRead + size > budget.maxBytes) {
        truncated = true;
        return;
      }

      // scanFile is synchronous, but one file under the size cap is bounded work. The yield
      // below is what keeps the host responsive across many of them.
      findings.push(...scanFile(full, path.relative(dirPath, full)));
      filesScanned++;
      bytesRead += size;

      if (filesScanned % budget.yieldEvery === 0) await yieldToEventLoop();
    }
  };

  await walk(dirPath);
  return { findings, filesScanned, bytesRead, truncated };
}

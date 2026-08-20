import * as path from 'path';
import * as fs from 'fs';

/**
 * Threat intelligence for installed extensions, sourced from VSXSentry.
 *
 * The single most important rule in this file: the **malicious** feed and the **risky** feed
 * are not the same thing and must never be merged.
 *
 *   malicious  extensions removed for malware, impersonation or typosquatting. A finding.
 *   risky      legitimate extensions whose *job* is to execute code or read your codebase:
 *              Jupyter, Microsoft's PowerShell extension, GitLens, Cline, Continue.
 *              A capability label. Never a finding.
 *
 * Testing the combined list against a clean 80-extension machine flagged five well-known,
 * entirely legitimate extensions. Any tool that opens by calling Microsoft's own PowerShell
 * extension a threat gets uninstalled in the first minute, so the separation is enforced by
 * the type system here rather than left to the caller's discretion.
 */

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

/** A confirmed-malicious match. Always worth surfacing. */
export interface MaliciousMatch {
  kind: 'malicious';
  extensionId: string;
  category: string;
  severity: ThreatSeverity;
  reference: string;
  /** True when the whole publisher is blocked, not just this extension. */
  publisherBlocked: boolean;
}

/** A known high-capability extension. Context for the user, never an accusation. */
export interface CapabilityNote {
  kind: 'capability';
  extensionId: string;
  category: string;
  note: string;
}

interface Snapshot {
  source: string;
  generatedUtc: string;
  fetchedUtc: string;
  counts: { malicious: number; risky: number; publishers: number };
  malicious: Record<string, { c: string; s: string; r: string }>;
  risky: Record<string, { c: string; n: string }>;
  publishers: string[];
}

const EMPTY: Snapshot = {
  source: '',
  generatedUtc: '',
  fetchedUtc: '',
  counts: { malicious: 0, risky: 0, publishers: 0 },
  malicious: {},
  risky: {},
  publishers: [],
};

let snapshot: Snapshot = EMPTY;
let blockedPublishers: Set<string> = new Set();
let loadError: string | null = null;

function normaliseSeverity(s: string): ThreatSeverity {
  const v = String(s).toLowerCase();
  return v === 'critical' || v === 'high' || v === 'medium' || v === 'low' ? v : 'high';
}

/**
 * Load the bundled snapshot. Called once at module load, and re-callable from tests with an
 * explicit path so the scanners can be exercised without touching the shipped data.
 */
export function loadSnapshot(filePath?: string): boolean {
  const file = filePath ?? path.join(__dirname, 'data', 'threat-snapshot.json');
  try {
    if (!fs.existsSync(file)) {
      loadError = `threat snapshot not found at ${file}`;
      snapshot = EMPTY;
      blockedPublishers = new Set();
      return false;
    }
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Snapshot;
    snapshot = { ...EMPTY, ...parsed };
    blockedPublishers = new Set((snapshot.publishers || []).map((p) => p.toLowerCase()));
    loadError = null;
    return true;
  } catch (err) {
    // A corrupt snapshot must degrade to "we could not check", never to "nothing found".
    loadError = err instanceof Error ? err.message : String(err);
    snapshot = EMPTY;
    blockedPublishers = new Set();
    return false;
  }
}

loadSnapshot();

/** Metadata for the UI, so the user can see how fresh the intelligence is. */
export function feedInfo(): {
  loaded: boolean;
  error: string | null;
  generatedUtc: string;
  counts: Snapshot['counts'];
  source: string;
} {
  return {
    loaded: loadError === null && snapshot.counts.malicious > 0,
    error: loadError,
    generatedUtc: snapshot.generatedUtc,
    counts: snapshot.counts,
    source: snapshot.source,
  };
}

/**
 * Check an extension against the malicious feed and the blocked-publisher list.
 * Returns null when there is no match. The risky feed is deliberately not consulted.
 */
export function checkMalicious(extensionId: string): MaliciousMatch | null {
  const id = String(extensionId || '').toLowerCase().trim();
  if (!id) return null;

  const publisher = id.includes('.') ? id.split('.')[0] : '';
  const publisherBlocked = publisher !== '' && blockedPublishers.has(publisher);
  const entry = snapshot.malicious[id];

  if (!entry && !publisherBlocked) return null;

  return {
    kind: 'malicious',
    extensionId: id,
    category: entry?.c ?? 'blocked-publisher',
    // A blocked publisher with no specific entry is still serious, but the specific
    // record is the better source of severity when we have one.
    severity: entry ? normaliseSeverity(entry.s) : 'high',
    reference: entry?.r ?? '',
    publisherBlocked,
  };
}

/**
 * Look up the capability catalogue. This is context for the UI ("this extension executes
 * code, and that is what it is for") and must never be rendered as a problem.
 */
export function checkCapability(extensionId: string): CapabilityNote | null {
  const id = String(extensionId || '').toLowerCase().trim();
  const entry = snapshot.risky[id];
  if (!entry) return null;
  return { kind: 'capability', extensionId: id, category: entry.c, note: entry.n };
}

/** Exposed for tests and for the "N known-malicious extensions checked" line in the UI. */
export function snapshotCounts(): Snapshot['counts'] {
  return { ...snapshot.counts };
}

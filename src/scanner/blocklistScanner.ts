import { checkMalicious, checkCapability, feedInfo } from './threatFeed';

export type { MaliciousMatch, CapabilityNote } from './threatFeed';
export { checkMalicious, checkCapability, feedInfo, snapshotCounts } from './threatFeed';

/**
 * Is this extension on the malicious feed, or published by a blocked publisher?
 *
 * Kept as a boolean for the existing call sites. New code should prefer `checkMalicious`,
 * which returns the category, severity and reference needed to write a finding that explains
 * itself rather than merely asserting.
 */
export function isBlocklisted(extensionId: string): boolean {
  return checkMalicious(extensionId) !== null;
}

/**
 * True when the extension is a known high-capability tool: Jupyter, PowerShell, GitLens, an
 * AI agent. This is **not** a risk signal. It exists so the UI can explain why an extension
 * has broad reach, instead of leaving the user to assume the worst.
 */
export function isKnownHighCapability(extensionId: string): boolean {
  return checkCapability(extensionId) !== null;
}

/** True when threat data actually loaded. A failed load must never read as "all clear". */
export function isFeedAvailable(): boolean {
  return feedInfo().loaded;
}

import * as https from 'https';

/**
 * Marketplace status lookup.
 *
 * This is the strongest signal available, and it comes from the first party. If an extension
 * is installed on your machine but the Marketplace no longer returns it, it was removed by
 * Microsoft or withdrawn by its publisher. That catches threats no third-party feed has picked
 * up yet, because Microsoft acts before the aggregators do.
 *
 * It is also the ONLY part of ExtGuard that touches the network, which is why it is off by
 * default and gated behind an explicit setting. A tool that audits your editor for spyware
 * cannot quietly start making requests. When enabled, the only thing sent is the extension
 * ID: never file contents, never paths, never findings.
 */

export type MarketplaceState = 'published' | 'not-found' | 'unknown';

export interface MarketplaceStatus {
  extensionId: string;
  state: MarketplaceState;
  publisherDisplayName?: string;
  publisherVerified?: boolean;
  installs?: number;
  /** Set when the lookup itself failed, so the caller can report "could not check". */
  error?: string;
}

const API = 'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery';

/**
 * Hand-rolled with `https` rather than fetch so this compiles against the older Node the
 * VS Code extension host may provide, and so the single network call in the whole product is
 * plainly visible in one place rather than hidden behind a helper.
 */
function postJson(body: string, timeoutMs: number): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      API,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json;api-version=7.2-preview.1',
          'content-length': Buffer.byteLength(body),
          'user-agent': 'ExtGuard',
        },
        timeout: timeoutMs,
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { text += c; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Look up several extension IDs in one request.
 *
 * A failure never returns 'not-found'. Being unable to reach the Marketplace is not evidence
 * that an extension was removed, and reporting it that way would accuse an innocent extension
 * every time the user is offline.
 */
export async function checkMarketplaceStatus(
  extensionIds: string[],
  opts: { timeoutMs?: number } = {}
): Promise<Map<string, MarketplaceStatus>> {
  const results = new Map<string, MarketplaceStatus>();
  const ids = [...new Set(extensionIds.map((i) => i.trim()).filter(Boolean))];
  if (!ids.length) return results;

  const body = JSON.stringify({
    filters: [{
      criteria: ids.map((id) => ({ filterType: 7, value: id })),
      pageSize: Math.max(ids.length, 1),
      pageNumber: 1,
    }],
    // Include statistics and publisher metadata.
    flags: 914,
  });

  try {
    const res = await postJson(body, opts.timeoutMs ?? 15000);
    if (res.status < 200 || res.status >= 300) {
      for (const id of ids) results.set(id, { extensionId: id, state: 'unknown', error: `HTTP ${res.status}` });
      return results;
    }

    const parsed = JSON.parse(res.text);
    const found = new Map<string, any>();
    for (const ext of parsed?.results?.[0]?.extensions ?? []) {
      const fullId = `${ext.publisher?.publisherName}.${ext.extensionName}`.toLowerCase();
      found.set(fullId, ext);
    }

    for (const id of ids) {
      const ext = found.get(id.toLowerCase());
      if (!ext) {
        results.set(id, { extensionId: id, state: 'not-found' });
        continue;
      }
      const installs = ext.statistics?.find((s: any) => s.statisticName === 'install')?.value;
      results.set(id, {
        extensionId: id,
        state: 'published',
        publisherDisplayName: ext.publisher?.displayName,
        publisherVerified: Boolean(ext.publisher?.isDomainVerified),
        installs: typeof installs === 'number' ? installs : undefined,
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    for (const id of ids) results.set(id, { extensionId: id, state: 'unknown', error: message });
  }

  return results;
}

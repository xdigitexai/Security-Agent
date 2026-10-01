import type { SecurityFinding } from '@xdigitex/types';
import type { ScanHttpClient, ScanResponse } from '@xdigitex/scanner-core';

export const finding = (x: SecurityFinding) => x;

type RequestOptions = Parameters<ScanHttpClient['request']>[1];

/**
 * Request a URL and return null instead of throwing.
 *
 * Checks walk every discovered surface, and a guarded client legitimately
 * refuses off-scope URLs and enforces rate limits. A single unavailable URL
 * must not abandon the rest of the walk.
 */
export async function safeRequest(
  client: ScanHttpClient,
  url: string,
  init?: RequestOptions,
  timeoutMs = 8000,
): Promise<ScanResponse | null> {
  try {
    return await client.request(url, init, timeoutMs);
  } catch {
    return null;
  }
}

/** Evidence without the response body, for endpoints that may return secrets. */
export function evidenceSummary(response: ScanResponse) {
  const contentType = String(response.headers['content-type'] ?? 'unknown');
  return {
    ...response.evidence,
    responseExcerpt: `HTTP ${response.status}, ${response.body.length} bytes, content-type ${contentType}`,
  };
}

/** Same-host, de-duplicated, capped URL list. */
export function sameHostUrls(assetUrl: string, candidates: string[], limit: number) {
  let assetHost = '';
  try {
    assetHost = new URL(assetUrl).hostname;
  } catch {
    return [];
  }

  const seen = new Set<string>();
  const out: string[] = [];

  for (const candidate of candidates) {
    try {
      const url = new URL(candidate);
      if (url.hostname !== assetHost) continue;
      url.hash = '';
      const key = url.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(key);
      if (out.length >= limit) break;
    } catch {
      // skip unparseable entries
    }
  }

  return out;
}

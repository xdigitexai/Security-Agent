import type { SecurityCheck } from '@xdigitex/scanner-core';
import { evidenceSummary, finding, sameHostUrls, safeRequest } from './helpers';

const HEADERS = [
  { key: 'content-security-policy', title: 'Content-Security-Policy', severity: 'LOW' as const },
  { key: 'x-content-type-options', title: 'X-Content-Type-Options', severity: 'INFORMATIONAL' as const },
  { key: 'strict-transport-security', title: 'Strict-Transport-Security', severity: 'LOW' as const },
];

const SENSITIVE_PATH = /(login|signin|signup|register|account|admin|dashboard|profile|orders?|cart|checkout|payment|api)\b/i;
const MAX_ENDPOINTS = 40;
const MAX_LISTED = 10;

/**
 * The header, cookie and cache checks only ever request the root URL. That is
 * enough to characterise a homepage and useless for characterising an
 * application. This walks every discovered surface instead, so a missing
 * header, a session cookie without flags or a cacheable authenticated response
 * on any route is seen rather than only the ones on `/`.
 *
 * Findings are aggregated per issue type and list the affected URLs, so wide
 * coverage does not mean a flood of one-URL-per-finding noise.
 */
export const endpointCoverageCheck: SecurityCheck = {
  id: 'coverage.endpoints',
  name: 'Endpoint coverage sweep',
  category: 'Coverage',
  async run(ctx) {
    const candidates = [
      ...ctx.pages,
      ...ctx.endpoints.filter((e) => e.method === 'GET').map((e) => e.url),
      ...ctx.applicationMap.surfaces.filter((s) => s.method === 'GET').map((s) => s.url),
      ...ctx.applicationMap.authUrls,
      ...ctx.applicationMap.adminUrls,
      ...ctx.applicationMap.apiUrls,
    ];

    const urls = sameHostUrls(ctx.assetUrl, candidates, MAX_ENDPOINTS);
    if (!urls.length) return [];

    const missing = new Map<string, string[]>();
    const cookieIssues = new Map<string, string[]>();
    const cacheable: string[] = [];

    for (const url of urls) {
      const response = await safeRequest(ctx.http, url);
      if (!response) continue;

      const headers = Object.fromEntries(
        Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]),
      );
      const isHtml = String(headers['content-type'] ?? '').includes('text/html');
      const isHttps = response.url.startsWith('https://');

      if (isHtml) {
        for (const header of HEADERS) {
          if (header.key === 'strict-transport-security' && !isHttps) continue;
          if (headers[header.key]) continue;
          missing.set(header.title, [...(missing.get(header.title) ?? []), response.url]);
        }
      }

      const setCookie = headers['set-cookie'];
      if (setCookie) {
        const lowered = setCookie.toLowerCase();
        if (!lowered.includes('secure') && isHttps) {
          cookieIssues.set('Secure', [...(cookieIssues.get('Secure') ?? []), response.url]);
        }
        if (!lowered.includes('httponly')) {
          cookieIssues.set('HttpOnly', [...(cookieIssues.get('HttpOnly') ?? []), response.url]);
        }
      }

      const cacheControl = String(headers['cache-control'] ?? '').toLowerCase();
      const sharedCacheable = !cacheControl || cacheControl.includes('public') || /max-age=\d+/.test(cacheControl);
      const notPrivate = !cacheControl.includes('no-store') && !cacheControl.includes('private');
      if (sharedCacheable && notPrivate && SENSITIVE_PATH.test(new URL(response.url).pathname)) {
        cacheable.push(response.url);
      }
    }

    const out = [];
    const list = (items: string[]) =>
      items.slice(0, MAX_LISTED).join(', ') + (items.length > MAX_LISTED ? ` (+${items.length - MAX_LISTED} more)` : '');

    for (const [title, affected] of missing) {
      const severity = HEADERS.find((h) => h.title === title)?.severity ?? 'INFORMATIONAL';
      out.push(
        finding({
          checkId: this.id,
          title: `${title} header missing on ${affected.length} endpoint${affected.length === 1 ? '' : 's'}`,
          description: `${affected.length} of ${urls.length} crawled endpoints returned an HTML response without a ${title} header. The homepage-only check did not see these because it only requested /.`,
          category: this.category,
          severity,
          confidence: 'CONFIRMED',
          affectedUrl: affected[0]!,
          method: 'GET',
          impact:
            'A per-route gap means the hardening header is applied inconsistently. Browsers enforce these per response, so the unprotected routes carry none of the benefit the homepage suggests.',
          remediation: `Set ${title} in a shared response handler or server configuration so every HTML route inherits it, rather than adding it to individual pages.`,
          evidence: [{ requestMethod: 'GET', requestUrl: affected[0]!, responseStatus: 200, responseHeaders: {}, responseExcerpt: `Missing on: ${list(affected)}`, timestamp: new Date() }],
        }),
      );
    }

    for (const [flag, affected] of cookieIssues) {
      out.push(
        finding({
          checkId: this.id,
          title: `Cookie without ${flag} flag on ${affected.length} endpoint${affected.length === 1 ? '' : 's'}`,
          description: `A cookie was set without the ${flag} attribute by ${affected.length} endpoint(s). These routes were reached by crawling; the homepage-only check would not have seen them.`,
          category: 'Session Security',
          severity: flag === 'HttpOnly' ? 'LOW' : 'MEDIUM',
          confidence: 'HIGH',
          affectedUrl: affected[0]!,
          method: 'GET',
          impact:
            'A cookie set without Secure can cross a plaintext connection; without HttpOnly it is readable by client-side script, which raises the impact of any XSS on the same origin.',
          remediation: 'Set session cookies with Secure and HttpOnly in one central place so every route that issues a cookie is covered.',
          evidence: [{ requestMethod: 'GET', requestUrl: affected[0]!, responseStatus: 200, responseHeaders: {}, responseExcerpt: `Set without ${flag} by: ${list(affected)}`, timestamp: new Date() }],
        }),
      );
    }

    if (cacheable.length) {
      out.push(
        finding({
          checkId: this.id,
          title: `Sensitive endpoint may be stored by shared caches`,
          description: `${cacheable.length} route(s) with an authentication- or account-related path returned a response without no-store/private and with no caching directive or a positive max-age.`,
          category: 'Cache Policy',
          severity: 'MEDIUM',
          confidence: 'NEEDS_REVIEW',
          affectedUrl: cacheable[0]!,
          method: 'GET',
          impact:
            'If the response body varies by user and a shared or intermediary cache stores it, one user can be served another user\'s response.',
          remediation: 'Send Cache-Control: no-store (or private, no-store) on any response whose content depends on the session.',
          evidence: [{ requestMethod: 'GET', requestUrl: cacheable[0]!, responseStatus: 200, responseHeaders: {}, responseExcerpt: `Potentially shared-cacheable: ${list(cacheable)}`, timestamp: new Date() }],
        }),
      );
    }

    return out;
  },
};

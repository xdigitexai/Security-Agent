import type { SecurityCheck } from '@xdigitex/scanner-core';
import { maskSecret } from '@xdigitex/shared';
import { finding, sameHostUrls, safeRequest } from './helpers';

const SECRET_PATTERNS: Array<[string, RegExp, 'MEDIUM' | 'HIGH']> = [
  ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'HIGH'],
  ['JWT-like token', /eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}/, 'MEDIUM'],
  ['Likely API key', /(?:api[_-]?key|secret|token|access[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/i, 'MEDIUM'],
  ['Cloud access key', /(?:AKIA|ASIA)[0-9A-Z]{16}/, 'HIGH'],
];

const ENDPOINT_PATTERN = /["'](\/(?:api|v\d|graphql|rest)\/[A-Za-z0-9_\-./{}:]{2,80})["']/g;
const MAX_SCRIPTS = 20;

/**
 * Fetch the JavaScript the application actually ships and the source maps it
 * references, instead of only reporting that a bundle mentions something.
 *
 * A published source map hands over the original unminified source, including
 * comments, internal endpoints and sometimes credentials. Bundles also carry
 * hardcoded endpoints that the crawler cannot see, because they are assembled
 * at runtime rather than present in the HTML.
 */
export const artifactCheck: SecurityCheck = {
  id: 'client.artifacts',
  name: 'JavaScript bundles and source maps',
  category: 'Client-Side',
  async run(ctx) {
    const scripts = sameHostUrls(ctx.assetUrl, ctx.scripts, MAX_SCRIPTS);
    if (!scripts.length) return [];

    const out = [];
    const discovered = new Set<string>();
    const secretHits: Array<{ script: string; label: string; sample: string; severity: 'MEDIUM' | 'HIGH' }> = [];

    for (const script of scripts) {
      const response = await safeRequest(ctx.http, script, {}, 8000);
      if (!response || response.status !== 200) continue;
      const body = response.body;

      for (const match of body.matchAll(ENDPOINT_PATTERN)) {
        if (match[1]) discovered.add(match[1]);
      }

      for (const [label, pattern, severity] of SECRET_PATTERNS) {
        const match = body.match(pattern);
        if (!match) continue;
        secretHits.push({
          script: response.url,
          label,
          sample: maskSecret((match[1] || match[0]).slice(0, 96)),
          severity,
        });
      }

      // Publish of a source map is reported once, from the bundle that declares it.
      const mapMatch = body.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
      if (!mapMatch?.[1]) continue;

      let mapUrl: string;
      try {
        mapUrl = new URL(mapMatch[1], response.url).toString();
      } catch {
        continue;
      }
      if (new URL(mapUrl).hostname !== new URL(response.url).hostname) continue;

      const map = await safeRequest(ctx.http, mapUrl, {}, 8000);
      if (!map || map.status !== 200) continue;

      let sources: unknown = null;
      try {
        sources = (JSON.parse(map.body) as { sources?: unknown }).sources;
      } catch {
        sources = null;
      }
      const sourceCount = Array.isArray(sources) ? sources.length : 0;

      out.push(
        finding({
          checkId: this.id,
          title: 'Source map publicly served',
          description: `${response.url} declares a source map and ${mapUrl} returned HTTP 200${sourceCount ? ` listing ${sourceCount} original source file(s)` : ''}. Source maps reconstruct the unminified application, including comments and internal structure.`,
          category: this.category,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          affectedUrl: mapUrl,
          method: 'GET',
          impact:
            'Publishing a map removes the effort of reverse engineering the bundle. It exposes original function and route names, TODO comments, internal endpoint paths and occasionally credentials left in source.',
          remediation:
            'Do not ship source maps to production, or restrict them to authenticated internal tooling. If maps are needed for error reporting, upload them to the error service instead of serving them.',
          evidence: [
            { ...map.evidence, responseExcerpt: `Source map served: ${sourceCount ? `${sourceCount} sources` : 'no sources array'}` },
          ],
        }),
      );
    }

    if (secretHits.length) {
      const worst = secretHits.some((h) => h.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';
      out.push(
        finding({
          checkId: this.id,
          title: `${secretHits.length} credential-shaped string${secretHits.length === 1 ? '' : 's'} in shipped JavaScript`,
          description: `Public bundles contained ${secretHits.length} value(s) matching credential patterns: ${secretHits
            .map((h) => h.label)
            .join(', ')}. Samples are redacted. A value in a public bundle is readable by anyone.`,
          category: this.category,
          severity: worst,
          confidence: 'NEEDS_REVIEW',
          affectedUrl: secretHits[0]!.script,
          method: 'GET',
          impact:
            'Any key shipped to the browser must be treated as public. If it authenticates to a backend or third-party service it should be rotated and moved server-side.',
          remediation:
            'Move server-side secrets out of the front-end build, rotate anything exposed, and inject only publishable keys at runtime.',
          evidence: secretHits.slice(0, 3).map((h) => ({
            requestMethod: 'GET',
            requestUrl: h.script,
            responseStatus: 200,
            responseHeaders: {},
            responseExcerpt: `${h.label}: ${h.sample}`,
            timestamp: new Date(),
          })),
        }),
      );
    }

    if (discovered.size) {
      const list = [...discovered].slice(0, 15);
      out.push(
        finding({
          checkId: this.id,
          title: `${discovered.size} endpoint path${discovered.size === 1 ? '' : 's'} hardcoded in JavaScript`,
          description: `Bundles contain ${discovered.size} endpoint path(s) that are not visible in the HTML the crawler parses, because they are assembled at runtime. These extend the testable surface.`,
          category: this.category,
          severity: 'INFORMATIONAL',
          confidence: 'CONFIRMED',
          affectedUrl: scripts[0]!,
          method: 'GET',
          impact: 'Runtime-only endpoints are routinely missed by crawlers and left out of authentication and access-control review.',
          remediation: 'Confirm each of these routes enforces the same authentication and object-level authorization as the rest of the application.',
          evidence: [
            {
              requestMethod: 'GET',
              requestUrl: scripts[0]!,
              responseStatus: 200,
              responseHeaders: {},
              responseExcerpt: `Endpoints: ${list.join(', ')}${discovered.size > list.length ? ` (+${discovered.size - list.length} more)` : ''}`,
              timestamp: new Date(),
            },
          ],
        }),
      );
    }

    return out;
  },
};

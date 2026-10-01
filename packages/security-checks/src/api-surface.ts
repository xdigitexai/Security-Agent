import type { SecurityCheck } from '@xdigitex/scanner-core';
import { finding, sameHostUrls, safeRequest } from './helpers';

const API_PATH = /(\/api\b|\/api\.|\/graphql|\/rest\b|\/v\d\/|action=|\.json(\?|$)|\/rpc\b)/i;
const ERROR_ONLY_KEYS = new Set(['error', 'errors', 'message', 'detail', 'details', 'status', 'success', 'ok', 'code']);
const MAX_ENDPOINTS = 20;

/**
 * Exercise discovered API surfaces without credentials.
 *
 * The crawler records API URLs and the application map classifies them, but no
 * existing check requests one. A typical result: an endpoint answers 200 to an
 * unauthenticated request and describes the exact parameter contract it
 * expects, handing an attacker the interface for free.
 *
 * One GET per endpoint, no parameters, no authentication, no writes.
 */
export const apiSurfaceCheck: SecurityCheck = {
  id: 'api.unauthenticated',
  name: 'Unauthenticated API surface',
  category: 'API Security',
  async run(ctx) {
    const candidates = [
      ...ctx.applicationMap.apiUrls,
      ...ctx.applicationMap.graphqlUrls,
      ...ctx.applicationMap.apiDocsUrls,
      ...ctx.endpoints.filter((e) => e.method === 'GET' && API_PATH.test(e.url)).map((e) => e.url),
    ];

    const urls = sameHostUrls(ctx.assetUrl, candidates, MAX_ENDPOINTS);
    if (!urls.length) return [];

    const out = [];

    for (const url of urls) {
      const response = await safeRequest(ctx.http, url, {}, 8000);
      if (!response) continue;

      const body = response.body.trim();
      const contentType = String(response.headers['content-type'] ?? '');
      const evidence = [{ ...response.evidence, responseExcerpt: `HTTP ${response.status}, ${body.length} bytes` }];

      if (response.status >= 500) {
        out.push(
          finding({
            checkId: this.id,
            title: 'API endpoint returned a server error to an unauthenticated request',
            description: `An unauthenticated GET to this endpoint produced HTTP ${response.status}. Unhandled errors on an API route often leak stack traces or internal paths and indicate untested error handling.`,
            category: this.category,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            affectedUrl: response.url,
            method: 'GET',
            impact: 'Verbose errors disclose implementation detail that shortcuts further attacks, and a 5xx on unauthenticated input suggests the input is not validated before use.',
            remediation: 'Return a generic error for unauthenticated or malformed requests and log the detail server-side only.',
            evidence,
          }),
        );
        continue;
      }

      if (response.status < 200 || response.status >= 300) continue;

      let parsed: unknown = null;
      let jsonLike = false;
      if (contentType.includes('json') || body.startsWith('{') || body.startsWith('[')) {
        try {
          parsed = JSON.parse(body);
          jsonLike = true;
        } catch {
          jsonLike = false;
        }
      }

      // 200 + an error envelope naming required parameters: contract disclosure.
      if (jsonLike && parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const keys = Object.keys(parsed as Record<string, unknown>).map((k) => k.toLowerCase());
        const errorShaped = keys.length > 0 && keys.every((k) => ERROR_ONLY_KEYS.has(k));
        if (errorShaped) {
          const sample = Object.values(parsed as Record<string, unknown>)
            .filter((v) => typeof v === 'string')
            .join(' ')
            .slice(0, 160);
          out.push(
            finding({
              checkId: this.id,
              title: 'API describes its parameter contract to unauthenticated callers',
              description: `This endpoint answered HTTP 200 to an unauthenticated GET and returned a structured error that names what it expects: "${sample}". The interface is discoverable without any credential.`,
              category: this.category,
              severity: 'LOW',
              confidence: 'CONFIRMED',
              affectedUrl: response.url,
              method: 'GET',
              impact:
                'Revealing the accepted parameters and the requirement for a key shortens reconnaissance and tells an attacker exactly which requests to shape. It also reveals that the endpoint is live and unauthenticated.',
              remediation:
                'Answer unauthenticated callers with a uniform 401 and no detail about the expected parameters. Keep contract hints out of production error responses.',
              evidence,
            }),
          );
          continue;
        }

        // 200 + real data without credentials.
        const dataKeys = keys.filter((k) => !ERROR_ONLY_KEYS.has(k));
        if (dataKeys.length) {
          out.push(
            finding({
              checkId: this.id,
              title: 'API endpoint returned data without authentication',
              description: `An unauthenticated GET returned a JSON object with ${dataKeys.length} field(s) that are not error fields. No credential was supplied.`,
              category: this.category,
              severity: 'HIGH',
              confidence: 'NEEDS_REVIEW',
              affectedUrl: response.url,
              method: 'GET',
              impact:
                'If the endpoint is meant to require authentication, whatever it returns is available to anyone who can reach the host. Confirm whether the fields are public by design.',
              remediation: 'Require authentication before returning any record, and confirm the response cannot vary by user while remaining unauthenticated.',
              evidence,
            }),
          );
          continue;
        }
      }

      if (!jsonLike && body.length > 0) {
        out.push(
          finding({
            checkId: this.id,
            title: 'API-shaped endpoint answered an unauthenticated request',
            description: `An unauthenticated GET returned HTTP 200 with ${body.length} bytes of ${contentType || 'unclassified'} content. Review whether this endpoint is intended to be public.`,
            category: this.category,
            severity: 'LOW',
            confidence: 'NEEDS_REVIEW',
            affectedUrl: response.url,
            method: 'GET',
            impact: 'An endpoint reachable without a credential is part of the public attack surface whether or not that was intended.',
            remediation: 'Confirm the intended authentication requirement for this route and enforce it centrally.',
            evidence,
          }),
        );
      }
    }

    return out;
  },
};

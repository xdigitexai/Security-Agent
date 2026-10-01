# Xdigitex Security Agent

Production-oriented MVP for **authorized defensive web-security testing**. An organization registers a web asset, proves ownership, and only then can queue a bounded security scan. Scans run in a separate BullMQ worker; the web process never performs a scan inside a request handler.

> Safety boundary: this project intentionally excludes DDoS testing, malware, destructive exploitation, password spraying/credential stuffing, credential theft, and active testing of unrelated third-party systems.

## Architecture

- `apps/web` — Next.js 16.3.8 App Router dashboard + API routes.
- `apps/worker` — BullMQ worker, crawl/orchestration, lifecycle persistence.
- `apps/test-target` — deliberately vulnerable **local-only** fake application.
- `packages/database` — Prisma/PostgreSQL schema and seed.
- `packages/scanner-core` — scope validator, SSRF guard, centralized scan HTTP client, Playwright crawler, orchestrator.
- `packages/security-checks` — small independent checks using the common `SecurityCheck` interface.
- `packages/shared` — environment limits, redaction, finding fingerprints.
- `packages/types` — scan and finding contracts.

## Safety model

1. An asset must be ownership-verified before `POST /api/scans` accepts it.
2. Each scan persists an immutable-at-start `ScanScope` with allowed hosts/protocols and hard page/request/rate limits.
3. Scanner modules receive a single `ScanHttpClient`; they do not call arbitrary network clients.
4. The client validates same-scope URLs, resolves DNS, blocks loopback/private/link-local/metadata ranges, manually validates redirects, limits redirects/body size/time, rate limits requests, and uses a guarded DNS lookup at connect time to reduce DNS-rebinding risk.
5. Playwright request routing aborts off-scope traffic. Third-party origins are recorded only as external dependencies.
6. Evidence automatically redacts authentication headers, cookies, tokens, secrets and limits excerpts.
7. Cancellation and the global 30-minute deadline are checked throughout orchestration/crawling.

## Implemented scanners

- Security header baseline (CSP, HSTS, nosniff; missing headers are not classified critical)
- Cookie flags (Secure, HttpOnly)
- Public secret-pattern discovery with redacted evidence
- CORS reflected-origin / credential behavior
- Passive client-side DOM-sink and source-map indicators
- Benign reflected-input marker detection (no JavaScript payload execution)
- Bounded open-redirect marker check; off-scope redirect following is blocked by the HTTP client

The crawler also discovers links, forms, JS resources, browser network requests and external dependencies. This MVP stores method/URL/form-parameter metadata. OpenAPI/Swagger/GraphQL enrichment and dependency-CVE matching are extension points for the next scanner set.

## Local setup

Requirements: Docker + Docker Compose.

```bash
cp .env.example .env
# Replace SESSION_SECRET before use.
docker compose up --build
```

Then in another terminal:

```bash
docker compose exec web npm run db:migrate
# optional seed account for local development only
docker compose exec web npm run db:seed
```

Open `http://localhost:3000`. The deliberately vulnerable target is `http://localhost:4010`, but private/localhost scanning is deliberately blocked by the production SSRF policy. To exercise scanner modules against the fixture in CI, use a dedicated isolated test mode/network adapter rather than weakening production SSRF rules.

### Development without Compose

```bash
npm install
npm run db:generate
npm run db:migrate
npm run dev
```

Playwright Chromium must be installed for the worker:

```bash
npx playwright install chromium
```

## Environment variables

- `DATABASE_URL` — PostgreSQL DSN
- `REDIS_URL` — Redis connection
- `SESSION_SECRET` — at least 32 random bytes
- `APP_URL` — public web URL
- `WORKER_CONCURRENCY` — max 10, default 2
- `MAX_SCAN_DURATION_MS` — hard-capped at 30 minutes
- `MAX_PAGES` — hard-capped at 500
- `MAX_REQUESTS` — hard-capped at 5000
- `MAX_RESPONSE_SIZE` — hard-capped at 5 MB
- `MAX_CONCURRENT_REQUESTS` — hard-capped at 5
- `MAX_REQUESTS_PER_SECOND` — hard-capped at 5
- `SCAN_USER_AGENT` — scanner user agent

## Ownership verification

Three methods are implemented:

- DNS TXT containing `xdigitex-security-verification=<token>`
- `/.well-known/xdigitex-security-verification.txt` whose body exactly equals the token
- `<meta name="xdigitex-security-verification" content="<token>">`

Verification attempts expire after 24 hours. Successful verification stamps `Asset.verifiedAt`; the scan API refuses unverified or disabled assets.

## Finding lifecycle

Findings are keyed by a SHA-256 fingerprint derived from check id, method, normalized affected URL and parameter. Reproduced findings update `lastSeenAt` and retain historical evidence. Findings from prior scans that are not reproduced are marked `FIXED`, not deleted. User lifecycle states include `OPEN`, `FIXED`, `IGNORED`, `FALSE_POSITIVE`, and `RETESTING`.

## Adding a new SecurityCheck

Implement a small module in `packages/security-checks/src`:

```ts
import type { SecurityCheck } from '@xdigitex/scanner-core';

export const myCheck: SecurityCheck = {
  id: 'category.unique-id',
  name: 'Readable name',
  category: 'Configuration',
  async run(context) {
    const response = await context.http.request(context.assetUrl);
    return [];
  }
};
```

Register it in `registry.ts`. Do not instantiate another network client; all scanner traffic must go through `context.http` so scope, SSRF, rate, timeout, response-size and evidence policies remain enforced.

## Recommended next scanners

- Passive authentication-flow analysis and account-enumeration heuristics
- Strictly bounded rate-limit checks for login/signup/reset/OTP (20 requests maximum, 2 req/s, immediate stop on throttling)
- API schema discovery for OpenAPI/Swagger and GraphQL metadata
- CSRF heuristics with evidence and framework-aware confidence
- File-upload policy inspection using inert marker files only
- Dependency version discovery + external vulnerability database integration
- TLS certificate/protocol posture via a non-invasive transport inspector
- Higher-confidence authorization/business-logic checks requiring user-provided test accounts and explicit per-test approval

## Known MVP limitations

- Retest currently queues a reduced bounded asset scan rather than executing a single check/endpoint in isolation.
- Server-Sent Events/WebSockets are represented by a pollable scan API and dynamic scan page; add Redis Pub/Sub + SSE for sub-second UI updates.
- RBAC roles are modeled and tenant queries are scoped to organization, but a full member-management UI is not included.
- CSRF helper is included for JSON/action-style APIs; the simple HTML form routes rely on SameSite session cookies and same-origin form submission. Before internet production, wire the helper into every state-changing non-form endpoint and consider middleware-based Origin enforcement globally.
- The local vulnerable target cannot be scanned under production SSRF rules by design; CI should inject a mock/isolated transport rather than create a localhost exception in production policy.
- Dependency CVE correlation is intentionally left for an external vulnerability database integration.

## Validation commands

```bash
npm run typecheck
npm run lint
npm test
npm run build
```

Run these after dependency installation. Docker was not required to author the source, but is the intended local integration environment.

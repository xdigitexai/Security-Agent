# Xdigitex Security Agent — Advanced Assessment Engine

The scanner now follows a map-first workflow: **Discover → Map → Test → Verify → Explain → Recommend Fix → Retest**.

## Application map

After bounded Playwright discovery the worker classifies first-party surfaces into authentication, administration, uploads, payments, APIs, GraphQL, API documentation, WebSockets, account management and search. Technology signals and third-party dependencies are recorded in scan logs. Third-party origins are discovery-only and remain outside active testing.

## Focused retesting

Retests no longer behave like ordinary full scans. A retest job carries the original `findingId`; the worker resolves the original `checkId`, executes only that security check inside the verified asset scope, compares the new fingerprint to the original and records one of:

- `RETEST_STILL_VULNERABLE`
- `RETEST_FIXED`
- `RETEST_CHANGED_BEHAVIOR`
- `RETEST_FAILED`

Unrelated findings are never auto-fixed by a focused retest.

## Advanced safe checks

In addition to the original header, cookie, CORS, secret, client-side, reflection and redirect modules:

- `api.public-docs` identifies confirmed first-party Swagger/OpenAPI/GraphQL documentation/interface exposure as informational discovery evidence.
- `disclosure.error-details` reports concrete stack trace, SQL state, exception or server filesystem leakage.
- `auth.cache-policy` checks authentication pages for shared-cache directives when sensitive form semantics are present.

These modules deliberately favor evidence and low false-positive rates over severity inflation.

## Next controlled capabilities

The architecture is ready for owner-supplied test identities/roles, which should unlock BOLA/BFLA comparisons, tenant isolation tests, session lifecycle verification and controlled business-logic checks. Those checks should never run against real unrelated users or financial transactions.

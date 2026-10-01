# Authorized Test Identities

Xdigitex Security Agent can model multiple controlled users, roles and tenants for a verified asset without storing reusable access material in PostgreSQL.

## Data model

`TestIdentity` stores only:

- label
- role label
- tenant label
- profile type
- deployment credential reference
- expected session state (`ACTIVE` or `REVOKED`)
- optional expiry

`TestResource` stores an owner-declared read-only resource URL, its intended owner identity, comparator identities that are expected to be denied, and an optional harmless proof marker.

Only `GET` and `HEAD` resources on the verified asset host are accepted. The normal scanner scope validator, DNS/SSRF guard, request caps and response redaction still apply.

## Local profile broker

The worker never retrieves reusable access material from the web application database. If `IDENTITY_PROFILE_BROKER_URL` is configured, it must point to loopback (`localhost`, `127.0.0.1`, or `::1`).

The worker sends:

```json
{"credentialRef":"XD_TEST_PROFILE_MEMBER_A"}
```

to `POST /resolve` on the local broker. The broker returns a prepared request-header profile:

```json
{"headers":{"x-example-profile":"opaque-runtime-value"}}
```

The broker is intentionally a deployment boundary. Production installations should back it with an approved secret manager or local vault and should never log returned values.

If no broker is configured, or a profile cannot be resolved, Xdigitex performs no identity-authenticated differential request for that identity.

## Controlled authorization testing

The `authorization.controlled-differential` module:

1. Loads only owner-declared test resources.
2. Sends a read-only request as the expected owner.
3. Sends the same read-only request as up to five explicitly selected comparator identities.
4. Requires either the configured proof marker or a matching normalized response body before reporting access.
5. Labels cross-tenant cases separately when identity tenant labels differ.
6. Stores sanitized evidence through the standard evidence pipeline.

The module does not enumerate IDs, alter identifiers, guess customer resources, write data, delete data, or test unrelated users.

## Revoked-session validation

An identity can be marked `REVOKED`. When a resolved profile for that controlled identity can still read a configured resource containing its harmless proof marker, the scanner records a confirmed session-invalidation finding.

## Recommended test setup

Use dedicated staging/test users and fixtures. A strong setup is:

- `member-a` in `tenant-a`
- `member-b` in `tenant-b`
- `admin-test` in a dedicated test tenant
- one or more deterministic test resources containing harmless markers such as `TEST-RESOURCE-A`

Do not register real customer objects as controlled test resources.

## Next identity-aware modules

The same identity/broker layer can safely support additional bounded modules for role/function authorization, recovery-flow test fixtures, and business-logic scenarios when those scenarios use dedicated sandbox resources and explicit owner declarations.

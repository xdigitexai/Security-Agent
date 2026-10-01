import { createHash } from 'node:crypto';

/**
 * Stable identity for a finding, used to decide whether a later scan has
 * re-detected the same issue or found a new one.
 *
 * `title` is part of the identity. Without it, every finding a single check
 * reports for the same URL collides: headers.baseline reports a missing CSP, a
 * missing HSTS header and a missing X-Content-Type-Options header as three
 * separate findings, all with the same checkId, method, URL and (absent)
 * parameter. They hashed identically, so the scan stored one row instead of
 * three, and the row kept the first finding's title while its severity,
 * description, impact and remediation were overwritten by the last - a missing
 * CSP reported with X-Content-Type-Options' INFORMATIONAL severity.
 *
 * Findings a check can distinguish should therefore give each a distinct title.
 */
export function findingFingerprint(input: {checkId:string; affectedUrl:string; method?:string; parameter?:string; title?:string}) {
  const normalized = [input.checkId, input.method?.toUpperCase() ?? 'GET', input.affectedUrl.replace(/#.*$/,''), input.parameter ?? '', input.title ?? ''].join('|');
  return createHash('sha256').update(normalized).digest('hex');
}

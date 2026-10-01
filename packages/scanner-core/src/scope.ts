import type { ScanScope } from '@xdigitex/types';
import { resolvePublic } from './ssrf';

export function normalizeUrl(input:string): URL {
  const u=new URL(input.trim());
  u.hash='';
  if (!['http:','https:'].includes(u.protocol)) throw new Error('UNSUPPORTED_PROTOCOL');
  u.hostname=u.hostname.toLowerCase();
  if ((u.protocol==='https:'&&u.port==='443')||(u.protocol==='http:'&&u.port==='80')) u.port='';
  return u;
}
export function hostAllowed(hostname:string, scope:ScanScope): boolean {
  const h=hostname.toLowerCase();
  return scope.allowedHosts.some(base=>h===base.toLowerCase() || (scope.allowSubdomains && h.endsWith('.'+base.toLowerCase())));
}
export async function validateScopedUrl(input:string|URL, scope:ScanScope): Promise<URL> {
  const u=normalizeUrl(input.toString());
  if (!scope.allowedProtocols.includes(u.protocol.slice(0,-1) as 'http'|'https')) throw new Error('SCOPE_PROTOCOL_BLOCKED');
  if (!hostAllowed(u.hostname,scope)) throw new Error('SCOPE_HOST_BLOCKED');
  await resolvePublic(u.hostname);
  return u;
}
export function defaultScope(host:string, protocol:'http'|'https'='https'):ScanScope {
  return {allowedHosts:[host.toLowerCase()],allowedProtocols:[protocol],maxDepth:5,maxPages:500,maxRequests:5000,maxRequestsPerSecond:5,allowSubdomains:false};
}

import { describe,it,expect,vi } from 'vitest';
import { hostAllowed, normalizeUrl } from './scope';
import { isBlockedIp } from './ssrf';
describe('scope',()=>{
  it('normalizes',()=>expect(normalizeUrl('https://EXAMPLE.com:443/a#b').toString()).toBe('https://example.com/a'));
  it('enforces host/subdomain rules',()=>{ const s={allowedHosts:['example.com'],allowedProtocols:['https'] as ['https'],maxDepth:5,maxPages:10,maxRequests:20,maxRequestsPerSecond:2,allowSubdomains:false}; expect(hostAllowed('example.com',s)).toBe(true); expect(hostAllowed('api.example.com',s)).toBe(false); });
  it('blocks internal IPs',()=>{expect(isBlockedIp('127.0.0.1')).toBe(true);expect(isBlockedIp('10.1.2.3')).toBe(true);expect(isBlockedIp('169.254.169.254')).toBe(true);expect(isBlockedIp('8.8.8.8')).toBe(false);});
});

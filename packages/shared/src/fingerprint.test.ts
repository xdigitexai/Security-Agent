import { describe, it, expect } from 'vitest';
import { findingFingerprint } from './fingerprint';

const url = 'https://digitexsmartsolutions.com/';

describe('fingerprint', () => {
  it('is stable', () => {
    const a = findingFingerprint({ checkId: 'a', affectedUrl: 'https://e.test/x#y' });
    const b = findingFingerprint({ checkId: 'a', affectedUrl: 'https://e.test/x' });
    expect(a).toBe(b);
  });

  it('is stable for the same finding across scans', () => {
    const a = findingFingerprint({ checkId: 'headers.baseline', affectedUrl: url, title: 'HSTS header missing' });
    const b = findingFingerprint({ checkId: 'headers.baseline', affectedUrl: url, title: 'HSTS header missing' });
    expect(a).toBe(b);
  });

  it('keeps distinct findings from the same check on the same URL separate', () => {
    // headers.baseline reports several missing headers on one URL. They share
    // checkId/method/url/parameter, so only the title separates them.
    const titles = [
      'Content-Security-Policy header missing',
      'HSTS header missing',
      'X-Content-Type-Options header missing',
    ];
    const fingerprints = new Set(titles.map((title) => findingFingerprint({ checkId: 'headers.baseline', affectedUrl: url, method: 'GET', title })));
    expect(fingerprints.size).toBe(titles.length);
  });

  it('still separates findings that differ by parameter', () => {
    const a = findingFingerprint({ checkId: 'reflection.marker', affectedUrl: url, parameter: 'q', title: 'Reflected input' });
    const b = findingFingerprint({ checkId: 'reflection.marker', affectedUrl: url, parameter: 'search', title: 'Reflected input' });
    expect(a).not.toBe(b);
  });
});

import { describe, it, expect } from 'vitest';
import { findingFingerprint } from './fingerprint';

describe('fingerprint', () => {
  it('is stable', () => {
    const a = findingFingerprint({ checkId: 'a', affectedUrl: 'https://e.test/x#y' });
    const b = findingFingerprint({ checkId: 'a', affectedUrl: 'https://e.test/x' });
    expect(a).toBe(b);
  });
});

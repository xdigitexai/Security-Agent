import { describe, it, expect } from 'vitest';
import { sameHostUrls } from './helpers';

const asset = 'https://example.test/';

describe('sameHostUrls', () => {
  it('keeps only the asset host', () => {
    const out = sameHostUrls(
      asset,
      [
        'https://example.test/a',
        'https://www.example.test/a',
        'https://cdn.other.test/a.js',
        'https://example.test/b',
      ],
      10,
    );
    expect(out).toEqual(['https://example.test/a', 'https://example.test/b']);
  });

  it('rejects subdomains unless they are the asset host', () => {
    // allowSubdomains is false on the scope, so a www. variant belongs to a
    // different host and must not be walked.
    expect(sameHostUrls(asset, ['https://api.example.test/x'], 10)).toEqual([]);
  });

  it('de-duplicates and drops fragments', () => {
    const out = sameHostUrls(asset, ['https://example.test/p#one', 'https://example.test/p#two'], 10);
    expect(out).toEqual(['https://example.test/p']);
  });

  it('caps the list', () => {
    const many = Array.from({ length: 50 }, (_, i) => `https://example.test/p${i}`);
    expect(sameHostUrls(asset, many, 5)).toHaveLength(5);
  });

  it('skips unparseable candidates and returns empty for a bad asset URL', () => {
    expect(sameHostUrls(asset, ['not a url', '/relative'], 10)).toEqual([]);
    expect(sameHostUrls('not a url', ['https://example.test/a'], 10)).toEqual([]);
  });
});

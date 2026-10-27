// Regression (live 2026-10-26): with Referrer-Policy no-referrer, real browsers sent `Origin: null` on the
// pairing form post and Perch answered "Forbidden origin". The sign-in pages must keep the real Origin on
// same-origin posts and still leak no referrer to other sites.
import { describe, expect, it } from 'vitest';
import { pageHeaders } from '../src/access/pages.js';

describe('sign-in page headers', () => {
  it('use Referrer-Policy same-origin (not no-referrer, which turns Origin into null)', () => {
    expect(pageHeaders()['referrer-policy']).toBe('same-origin');
  });
});

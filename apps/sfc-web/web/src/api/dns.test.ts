// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { fqdn, idna, inRange, nameProblem, normDomain, parseRecordLine, setText, underDomain } from './dns';

describe('dns helpers', () => {
  it('inRange follows the daemon pattern rule', () => {
    expect(inRange('shop', ['shop', '*.shop'])).toBe(true);
    expect(inRange('api.shop', ['*.shop'])).toBe(true);
    expect(inRange('a.b.shop', ['*.shop'])).toBe(true);
    expect(inRange('*.shop', ['*.shop'])).toBe(true);
    expect(inRange('shop', ['*.shop'])).toBe(false);
    expect(inRange('myshop', ['*.shop'])).toBe(false);
    expect(inRange('blog', ['shop'])).toBe(false);
  });
  it('checks relative names', () => {
    expect(nameProblem('@')).toBeUndefined();
    expect(nameProblem('*.shop')).toBeUndefined();
    expect(nameProblem('*.shop', false)).toBeDefined();
    expect(nameProblem('a*b')).toBeDefined();
    expect(nameProblem('')).toBeDefined();
  });
  it('parses record lines by type', () => {
    expect(parseRecordLine('MX', '10 mx1.example.com.')).toEqual({ priority: 10, content: 'mx1.example.com.' });
    expect(typeof parseRecordLine('MX', 'mx1.example.com.')).toBe('string');
    expect(typeof parseRecordLine('A', '300.1')).toBe('string');
    expect(parseRecordLine('A', '203.0.113.10')).toEqual({ content: '203.0.113.10' });
    expect(setText({ name: '@', type: 'MX', ttl: 300, records: [{ content: 'mx.', priority: 10 }] })).toBe('10 mx.');
    expect(fqdn('@', 'example.com')).toBe('example.com');
    expect(fqdn('shop', 'example.com')).toBe('shop.example.com');
  });

  it('reads the current daemon domain shape and the cluster one alike', () => {
    const base = { domain: 'example.com', defaultTtl: 300, assignments: null };
    expect(normDomain({ ...base, provider: 'p-1', providerName: 'hostinger-main', vendor: 'hostinger' }).provider).toEqual({ id: 'p-1', vendor: 'hostinger', name: 'hostinger-main' });
    expect(normDomain({ ...base, provider: { id: 'p-1', vendor: 'hostinger', name: 'h' } }).provider?.name).toBe('h');
    expect(normDomain({ ...base, provider: null }).provider).toBeNull();
    expect(normDomain({ ...base, provider: '' }).provider).toBeNull();
  });
  it('idna lowercases and punycodes, rejects junk', () => {
    expect(idna('Example.COM.')).toBe('example.com');
    expect(idna('예시.kr')).toMatch(/^xn--[a-z0-9]+\.kr$/);
    expect(idna('nodot')).toBeUndefined();
    expect(idna('a b.com')).toBeUndefined();
    expect(idna('-a.com')).toBeUndefined();
  });
  it('underDomain covers the domain, its subnames and wildcards', () => {
    expect(underDomain('example.com', 'example.com')).toBe(true);
    expect(underDomain('a.b.example.com', 'example.com')).toBe(true);
    expect(underDomain('*.shop.example.com', 'example.com')).toBe(true);
    expect(underDomain('myexample.com', 'example.com')).toBe(false);
  });
});

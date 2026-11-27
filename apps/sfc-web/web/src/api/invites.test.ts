// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { fullLink, inviteExpiresAt, inviteLeft, isInviteCredential, parseInviteLink } from './invites';

describe('invites', () => {
  it('parses the link and keeps the code out of the query', () => {
    expect(parseInviteLink('?u=carol', '#k7Qm-2xWp')).toEqual({ username: 'carol', code: 'k7Qm-2xWp' });
    expect(parseInviteLink('', '')).toEqual({ username: '', code: '' });
  });
  it('reads the invite credential id', () => {
    expect(isInviteCredential('invite-1795759923-b79077b5')).toBe(true);
    expect(isInviteCredential('browser')).toBe(false);
    expect(inviteExpiresAt('invite-1795759923-b79077b5')?.getTime()).toBe(1795759923000);
  });
  it('shows the time left', () => {
    const now = Date.parse('2026-11-27T00:00:00Z');
    expect(inviteLeft('2026-11-27T23:30:00Z', now)).toBe('23시간 남음');
    expect(inviteLeft('2026-11-27T00:12:00Z', now)).toBe('12분 남음');
    expect(inviteLeft('2026-12-04T00:00:00Z', now)).toBe('7일 남음');
    expect(inviteLeft('2026-11-26T00:00:00Z', now)).toBe('만료');
  });
  it('makes a relative link absolute', () => {
    expect(fullLink('/login/invite?u=a#x', 'https://sfc.example.org')).toBe('https://sfc.example.org/login/invite?u=a#x');
  });
});

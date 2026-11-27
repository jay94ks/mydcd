// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { deltaText, portsError, prefixError, ruleErrors, ruleKey, ruleText } from './firewallRules';
import { lockedRows } from '../pages/NodeFirewall';

describe('firewall rules (internal/firewall/rules.go와 같은 판정)', () => {
  it('포트: 하나 또는 작은 수부터 범위', () => {
    expect(portsError('443')).toBeUndefined();
    expect(portsError('30000-30100')).toBeUndefined();
    expect(portsError('80-70')).toBe('범위는 작은 수부터: 70-80');
    expect(portsError('0')).toBeDefined();
    expect(portsError('65536')).toBeDefined();
    expect(portsError('080')).toBeDefined();
    expect(portsError('443,80')).toBeDefined();
  });
  it('출처: 호스트 비트 없는 IPv4·IPv6 prefix', () => {
    for (const ok of ['203.0.113.0/24', '198.51.100.7/32', '0.0.0.0/0', '2001:db8::/32', 'fd00::/8', '::/0', '2001:db8:0:0:0:0:0:1/128']) expect(prefixError(ok), ok).toBeUndefined();
    expect(prefixError('10.0.0.300/8')).toBe('올바른 CIDR가 아닙니다');
    expect(prefixError('10.0.0.1/8')).toMatch(/호스트 비트/);
    expect(prefixError('2001:db8::1/32')).toMatch(/호스트 비트/);
    for (const bad of ['10.0.0.0', '10.0.0.0/33', 'fe80::/10%eth0', '::ffff:1.2.3.4/128', '1:2:3:4:5:6:7:8:9/64', '2001:db8:::/32']) expect(prefixError(bad), bad).toBeDefined();
  });
  it('규칙 칸 검사', () => {
    expect(ruleErrors({ action: 'allow', proto: 'tcp', from: [] }).ports).toBeDefined();
    expect(ruleErrors({ action: 'allow', proto: 'icmp', ports: '1', from: [] }).ports).toBeDefined();
    expect(ruleErrors({ action: 'allow', proto: 'any', from: ['10.0.0.0/8', '10.0.0.0/8'] }).from).toBeDefined();
    expect(ruleErrors({ action: 'deny', proto: 'udp', ports: '53', from: ['10.0.0.0/8'], comment: 'x'.repeat(121) }).comment).toBeDefined();
    expect(Object.keys(ruleErrors({ action: 'deny', proto: 'udp', ports: '53', from: ['10.0.0.0/8'], comment: '사내' }))).toEqual([]);
    expect(Object.keys(ruleErrors({ action: 'allow', proto: 'any', from: [] }))).toEqual([]);
  });
  it('같은 규칙은 출처 순서·메모와 상관없다', () => {
    expect(ruleKey({ action: 'allow', proto: 'tcp', ports: '5432', from: ['fd00::/8', '10.0.0.0/8'], comment: 'a' })).toBe(ruleKey({ action: 'allow', proto: 'tcp', ports: '5432', from: ['10.0.0.0/8', 'fd00::/8'] }));
  });
  it('글', () => {
    expect(ruleText({ action: 'allow', proto: 'tcp', ports: '443', from: [] })).toBe('허용 tcp/443 모든 곳');
    expect(deltaText({ add: [{ action: 'allow', proto: 'udp', ports: '30000-30100', from: ['203.0.113.0/24'] }] }, ['r6'])).toBe('r6 허용 udp/30000-30100 ← 203.0.113.0/24 추가');
    expect(deltaText({ delete: ['r5'], policy: 'drop' })).toBe('r5 지움 · 기본 정책 막기');
  });
  it('잠금 규칙은 이름별 한 줄, 포트는 모은다', () => {
    const rows = lockedRows([
      { name: 'established', reason: 'x' },
      { name: 'sfcp', proto: 'udp', port: 7443, reason: 'x' },
      { name: 'ingress', proto: 'tcp', port: 80, reason: 'x' },
      { name: 'ingress', proto: 'tcp', port: 443, reason: 'x' },
      { name: 'future-lock', reason: 'something new' },
    ]);
    expect(rows.map((r) => [r.label, r.open])).toEqual([
      ['이미 맺은 연결 · 관련 연결', '모두'],
      ['SFCP', 'udp/7443'],
      ['외부 접속 입구', 'tcp/80 · tcp/443'],
      ['future-lock', ''],
    ]);
  });
});

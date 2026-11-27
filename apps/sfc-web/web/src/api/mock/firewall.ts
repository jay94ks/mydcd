// SPDX-License-Identifier: Apache-2.0

// 서버 방화벽 목업 (node-firewall, #740). 고정 자료: node-b는 캔버스 NodeFirewall 그대로(규칙 4개, revision 14),
// node-a는 켠 직후(규칙 없음), node-c는 연결되지 않은 서버(503 unavailable).
// 실제처럼 응답은 늘 200이고 실패는 code로 온다. 판정 규칙은 internal/firewall/rules.go를 따른다.
import type { RawResponse } from '../client';
import type { DFirewall, DFirewallChange, DFirewallDelta, DFirewallResult, DFirewallRule } from '../dto';
import { ruleErrors, ruleKey, needsPorts } from '../../lib/firewallRules';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, q: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  user: () => { id: string; username: string; systemAdmin: boolean };
}

interface Fw {
  managed: boolean;
  revision: number;
  policy: 'return' | 'drop';
  nextId: number;
  rules: DFirewallRule[];
  locked: DFirewall['locked'];
  operator4: string[];
  operator6: string[];
  applied: boolean;
  applyError?: string;
  log: DFirewallChange[];
  ops: Map<string, { key: string; res: DFirewallResult }>;
}

const now = () => Math.floor(Date.now() / 1000);
const LOCKED = (ingress: number[]): DFirewall['locked'] => [
  { name: 'established', reason: 'replies to connections already accepted' },
  { name: 'loopback', reason: 'traffic inside the server' },
  { name: 'sfc-devices', reason: 'bridge and TUN packets; isolation rules decide' },
  { name: 'icmpv6-neighbor', reason: 'IPv6 neighbor discovery and packet-too-big' },
  { name: 'sfcp', proto: 'udp', port: 7443, reason: 'node.listen' },
  { name: 'keep-open', proto: 'tcp', port: 22, reason: 'node.yaml firewall.keep_open' },
  ...ingress.map((port) => ({ name: 'ingress', proto: 'tcp', port, reason: 'ingress listener' })),
];

const fws: Record<string, Fw> = {
  'node-b': {
    managed: true,
    revision: 14,
    policy: 'return',
    nextId: 7,
    rules: [
      { id: 'r1', action: 'deny', proto: 'tcp', ports: '8080', from: ['198.51.100.7/32'], comment: '스캐너 차단' },
      { id: 'r2', action: 'allow', proto: 'tcp', ports: '443', from: [] },
      { id: 'r3', action: 'allow', proto: 'tcp', ports: '5432', from: ['10.0.0.0/8', 'fd00::/8'], comment: '사내망 DB' },
      { id: 'r6', action: 'allow', proto: 'udp', ports: '30000-30100', from: ['203.0.113.0/24'], comment: '게임 서버 시험' },
    ],
    locked: LOCKED([80, 443]),
    operator4: ['-P INPUT ACCEPT', '-A INPUT -j SFC-INPUT', '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT', '-A INPUT -s 192.168.1.0/24 -p tcp -m tcp --dport 3000 -j ACCEPT', '-A INPUT -j DROP'],
    operator6: ['-P INPUT ACCEPT', '-A INPUT -j SFC-INPUT', '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'],
    applied: true,
    log: [
      { operation: 'fw-0010', user: 'u-bob', at: now() - 2 * 86400, from: 10, to: 11, delta: { add: [{ action: 'allow', proto: 'tcp', ports: '5432', from: ['10.0.0.0/8', 'fd00::/8'], comment: '사내망 DB' }] }, added: ['r3'] },
      { operation: 'fw-0011', user: 'u-bob', at: now() - 86400 - 3600, from: 11, to: 12, delta: { delete: ['r5'] } },
      { operation: 'fw-0012', user: 'u-alice', at: now() - 5 * 3600, from: 12, to: 13, delta: { update: [{ id: 'r1', action: 'deny', proto: 'tcp', ports: '8080', from: ['198.51.100.7/32'], comment: '스캐너 차단' }] } },
      { operation: 'fw-0013', user: 'u-alice', at: now() - 1800, from: 13, to: 14, delta: { add: [{ action: 'allow', proto: 'udp', ports: '30000-30100', from: ['203.0.113.0/24'], comment: '게임 서버 시험' }] }, added: ['r6'] },
    ],
    ops: new Map(),
  },
  'node-a': {
    managed: true,
    revision: 0,
    policy: 'return',
    nextId: 1,
    rules: [],
    locked: LOCKED([]),
    operator4: ['-P INPUT ACCEPT', '-A INPUT -j SFC-INPUT'],
    operator6: ['-P INPUT ACCEPT', '-A INPUT -j SFC-INPUT'],
    applied: true,
    log: [],
    ops: new Map(),
  },
};
// 기록 '더 보기'(50건씩)를 시험하려고 node-a에 오래된 기록 60건을 둔다. 마지막에 모두 지워 규칙은 없다
for (let r = 0; r < 60; r++) fws['node-a'].log.push({ operation: `fw-a-${r}`, user: 'u-alice', at: now() - (70 - r) * 86400, from: r, to: r + 1, delta: r % 2 ? { delete: [`r${(r + 1) / 2}`] } : { add: [{ action: 'allow', proto: 'tcp', ports: String(9000 + r), from: [] }] }, added: r % 2 ? undefined : [`r${r / 2 + 1}`] });
Object.assign(fws['node-a'], { revision: 60, nextId: 31 });

/** 목업 조작(스모크 시험) */
export const mockFirewall = {
  /** 다음 변경 하나를 iptables 적용 실패로 끝낸다 */
  failNext: false,
  /** 다른 사람이 먼저 바꾼 것처럼 revision을 올린다 */
  bumpBy: (node: string, user = 'u-bob') => {
    const f = fws[node];
    f.log.push({ operation: `fw-other-${f.revision}`, user, at: now(), from: f.revision, to: f.revision + 1, delta: { policy: f.policy } });
    f.revision++;
  },
  setManaged: (node: string, on: boolean) => fws[node] && (fws[node].managed = on),
  setApplied: (node: string, applied: boolean, error?: string) => fws[node] && Object.assign(fws[node], { applied, applyError: applied ? undefined : error }),
};

function view(node: string, f: Fw): DFirewall {
  if (!f.managed) return { node, managed: false, revision: 0, rules: [], locked: [], operator4: [], operator6: [], applied: false };
  return { node, managed: true, revision: f.revision, policy: f.policy, rules: f.rules.map((r) => ({ ...r, from: [...r.from] })), maxRules: 256, locked: f.locked, operator4: f.operator4, operator6: f.operator6, applied: f.applied, applyError: f.applyError };
}

const cleanRule = (x: unknown): DFirewallRule => {
  const r = (x ?? {}) as Record<string, unknown>;
  return { id: r.id ? String(r.id) : undefined, action: String(r.action ?? '') as DFirewallRule['action'], proto: String(r.proto ?? '') as DFirewallRule['proto'], ports: r.ports ? String(r.ports) : undefined, from: Array.isArray(r.from) ? r.from.map(String) : [], comment: r.comment ? String(r.comment) : undefined };
};
const ruleBad = (r: DFirewallRule) => !['allow', 'deny'].includes(r.action) || !['tcp', 'udp', 'icmp', 'any'].includes(r.proto) || (needsPorts(r.proto) && !r.ports) || Object.keys(ruleErrors(r)).length > 0;

export function registerFirewall({ on, ok, err, user }: Ctx) {
  const gate = (node: string): Fw | RawResponse => {
    if (!user().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    const f = fws[node];
    if (!f) return err(503, 'unavailable', `${node}에 연결되어 있지 않습니다.`);
    return f;
  };
  const isFw = (x: Fw | RawResponse): x is Fw => 'ops' in x;
  on('GET', '/nodes/:id/firewall', (m) => {
    const f = gate(m[0]);
    return isFw(f) ? ok({ firewall: view(m[0], f) } satisfies DFirewallResult) : f;
  });
  on('GET', '/nodes/:id/firewall/log', (m, _b, q) => {
    const f = gate(m[0]);
    if (!isFw(f)) return f;
    if (!f.managed) return ok({ firewall: view(m[0], f) });
    const before = Number(q.get('before') ?? 0);
    const rows = [...f.log].reverse().filter((c) => !before || c.to < before);
    return ok({ log: rows.slice(0, 50), more: rows.length > 50 } satisfies DFirewallResult);
  });
  on('POST', '/nodes/:id/firewall', (m, body) => {
    const node = m[0];
    const f = gate(node);
    if (!isFw(f)) return f;
    const opId = String(body.opId ?? '');
    const d: DFirewallDelta = {
      add: Array.isArray(body.add) ? body.add.map(cleanRule) : undefined,
      update: Array.isArray(body.update) ? body.update.map(cleanRule) : undefined,
      delete: Array.isArray(body.delete) ? body.delete.map(String) : undefined,
      policy: body.policy ? (String(body.policy) as DFirewallDelta['policy']) : undefined,
    };
    if (!opId || typeof body.revision !== 'number' || !(d.add?.length || d.update?.length || d.delete?.length || d.policy)) return err(422, 'invalid', 'opId, revision and at least one of add, update, delete, policy');
    const res = (code: string, error: string): RawResponse => ok({ code, error, firewall: view(node, f) } satisfies DFirewallResult);
    if (!f.managed) return res('not-managed', `node.yaml firewall.managed is off on ${node}`);
    const key = JSON.stringify(body);
    const prev = f.ops.get(opId);
    if (prev) return prev.key === key ? ok(prev.res) : res('operation-conflict', 'opId is used for another change');
    if (body.revision !== f.revision) return res('revision', 'firewall changed since it was read');
    if (d.policy && d.policy !== 'return' && d.policy !== 'drop') return res('invalid', 'policy must be return or drop');
    const rules = f.rules.map((r) => ({ ...r }));
    const touched = new Set<string>();
    for (const id of d.delete ?? []) {
      const i = rules.findIndex((r) => r.id === id);
      if (i < 0 || touched.has(id)) return res('missing', `no such firewall rule: ${id}`);
      touched.add(id);
      rules.splice(i, 1);
    }
    for (const u of d.update ?? []) {
      const i = rules.findIndex((r) => r.id === u.id);
      if (i < 0 || touched.has(u.id ?? '')) return res('missing', `no such firewall rule: ${u.id}`);
      if (ruleBad(u)) return res('invalid', 'invalid firewall rule');
      touched.add(u.id ?? '');
      rules[i] = u;
    }
    let next = f.nextId;
    const added: string[] = [];
    for (const a of d.add ?? []) {
      if (a.id) return res('invalid', 'a new rule gets its ID from the server');
      if (ruleBad(a)) return res('invalid', 'invalid firewall rule');
      const id = `r${next++}`;
      rules.push({ ...a, id });
      added.push(id);
    }
    if (rules.length > 256) return res('too-many', 'too many firewall rules');
    const seen = new Map<string, string>();
    for (const r of rules) {
      const k = ruleKey(r);
      if (seen.has(k)) return res('duplicate', `the same firewall rule already exists: ${seen.get(k)} and ${r.id}`);
      seen.set(k, r.id ?? '');
    }
    if (mockFirewall.failNext) {
      mockFirewall.failNext = false;
      return res('apply-failed', 'ip6tables-restore: line 4 failed');
    }
    const change: DFirewallChange = { operation: opId, user: user().id, at: now(), from: f.revision, to: f.revision + 1, delta: d, added: added.length ? added : undefined };
    Object.assign(f, { rules, nextId: next, revision: f.revision + 1, policy: d.policy ?? f.policy, applied: true, applyError: undefined });
    f.log.push(change);
    const out: DFirewallResult = { change, firewall: view(node, f) };
    f.ops.set(opId, { key, res: out });
    return ok(out);
  });
}

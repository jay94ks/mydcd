// SPDX-License-Identifier: Apache-2.0

// 외부 DNS 목업. 데몬의 fake 공급자(internal/web/dns/fake.go)와 같은 세계를 흉내 낸다.
// 토큰은 받기만 하고 남기지 않는다(끝 4자리만).
import type { RawResponse } from '../client';
import type { DnsAssignment, DnsChangeReq, DnsDomain, DnsHistory, DnsManaged, DnsPlannedChange, DnsProvider, RRSet, DnsSnapshot } from '../dns';
import { idna, inRange } from '../dns';

/** 인증서 목업이 알려 준다: 지금 링크가 있는 인증서 ID들, 도메인 아래 링크된 호스트·인증서 수 */
let linkedIds: () => Set<string> = () => new Set();
let counts: ((domain: string) => { hosts: number; certificates: number }) | undefined;
export const setDomainHooks = (ids: typeof linkedIds, cnt: typeof counts) => {
  linkedIds = ids;
  counts = cnt;
};
const diff = (a: Set<string>, b: Set<string>) => [...a].filter((x) => !b.has(x)).length;

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse | Promise<RawResponse>) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  user: () => { id: string; username: string; systemAdmin: boolean };
  roleIn: (u: { id: string }, tenant: string) => string | undefined;
}

const now = () => new Date().toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const CAPS = { recordTypes: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV', 'NS'], wildcard: true, minTtl: 60, perRecordId: false, validate: true, snapshots: true, nameservers: true, propagation: true, rateLimit: { requests: 90, per: 60e9 } };

/** 공급자 쪽 세계: 도메인 → 레코드 묶음 */
const zones: Record<string, RRSet[]> = {
  'example.com': [
    { name: '@', type: 'A', ttl: 3600, records: [{ content: '198.51.100.20' }] },
    { name: '@', type: 'MX', ttl: 3600, records: [{ content: 'mx1.hostinger.com.', priority: 10 }] },
    { name: '@', type: 'TXT', ttl: 3600, records: [{ content: 'v=spf1 include:_spf.hostinger.com ~all' }] },
    { name: '@', type: 'CAA', ttl: 3600, records: [{ content: '0 issue "letsencrypt.org"' }] },
    { name: 'shop', type: 'A', ttl: 300, records: [{ content: '203.0.113.10' }, { content: '203.0.113.11' }] },
    { name: '*.shop', type: 'A', ttl: 300, records: [{ content: '203.0.113.10' }, { content: '203.0.113.11' }] },
    { name: 'blog', type: 'CNAME', ttl: 3600, records: [{ content: 'shop.example.com.' }] },
    { name: 'old-api', type: 'A', ttl: 3600, records: [{ content: '203.0.113.99' }] },
  ],
  'acme.dev': [
    { name: '@', type: 'A', ttl: 300, records: [{ content: '203.0.113.12' }] },
    { name: 'www', type: 'CNAME', ttl: 3600, records: [{ content: 'acme.dev.' }] },
  ],
  'example.net': [],
};
const elsewhere: Record<string, string> = { 'old-shop.net': 'ns1.gabia.co.kr' };
const owned: Record<string, string[]> = { hostinger: ['example.com', 'acme.dev', 'old-shop.net'], fake: ['example.com', 'example.net', 'old-shop.net'] };
const snaps: Record<string, (DnsSnapshot & { sets: RRSet[] })[]> = {};

const fp = (s?: RRSet | null) => {
  if (!s) return 'absent';
  const vals = s.records.map((r) => `${r.priority ?? 0} ${r.content}`).sort();
  let h = 0;
  for (const c of `${s.name}\0${s.type}\0${s.ttl}\0${vals.join('\0')}`) h = (Math.imul(h, 31) + c.charCodeAt(0)) | 0;
  return (h >>> 0).toString(16).padStart(8, '0') + 'a1b2c3d4e5f6'.slice(0, 16);
};
const k = (name: string, type: string) => `${name}|${type}`;

const providers: (DnsProvider & { token: string })[] = [
  { id: 'p-hst', vendor: 'hostinger', name: 'hostinger-main', tokenHint: '3f9a', token: 'x', tokenExpires: '2027-05-01T00:00:00Z', account: 'ops@example.com', lastCheck: ago(120), lastCheckOk: true, remaining: 84, createdBy: 'alice', createdAt: ago(86400 * 30) },
];
const domains: DnsDomain[] = [
  {
    domain: 'example.com',
    provider: { id: 'p-hst', vendor: 'hostinger', name: 'hostinger-main' },
    hosts: 4,
    certificates: 3,
    defaultTtl: 300,
    assignments: [
      { tenant: 'shop', names: ['shop', '*.shop'] },
      { tenant: 'blog', names: ['blog'] },
    ],
    addedBy: 'alice',
    addedAt: ago(86400 * 20),
  },
  // 공급자 없이 등록한 도메인(sfcd domain add만): 레코드는 직접 관리, 인증서는 HTTP 확인만
  { domain: 'intra.example.org', provider: null, hosts: 1, certificates: 0, defaultTtl: 3600, assignments: [], addedBy: 'bob', addedAt: ago(3600 * 5) },
];
/** 공개 접미사 (sfcd는 golang.org/x/net/publicsuffix 목록을 쓴다) */
const SUFFIX = new Set(['com', 'net', 'org', 'io', 'dev', 'kr', 'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'jp', 'co.jp', 'uk', 'co.uk', 'xn--3e0b707e']);
const managed: Record<string, Record<string, DnsManaged>> = {
  'example.com': {
    [k('shop', 'A')]: { name: 'shop', type: 'A', tenant: 'shop', app: 'php-shop', by: 'alice', fingerprint: '', at: ago(3600) },
    [k('*.shop', 'A')]: { name: '*.shop', type: 'A', tenant: 'shop', by: 'alice', fingerprint: '', at: ago(3600) },
    [k('blog', 'CNAME')]: { name: 'blog', type: 'CNAME', tenant: 'blog', app: 'ghost', by: 'bob', fingerprint: 'changed-outside', at: ago(86400) },
    [k('old-api', 'A')]: { name: 'old-api', type: 'A', tenant: 'shop', app: 'api-v1', by: 'alice', fingerprint: '', at: ago(86400 * 19) },
    [k('legacy', 'A')]: { name: 'legacy', type: 'A', tenant: 'shop', app: 'legacy', by: 'alice', fingerprint: 'gone', at: ago(86400 * 40) },
  },
};
for (const [d, ms] of Object.entries(managed))
  for (const m of Object.values(ms)) if (!m.fingerprint) m.fingerprint = fp(zones[d].find((s) => s.name === m.name && s.type === m.type));
const history: Record<string, (DnsHistory & { digest: string })[]> = {
  'example.com': [
    {
      id: '7a1f0b2c-1111-4c3d-9e00-000000000001',
      domain: 'example.com',
      at: ago(3600),
      user: 'u-alice',
      username: 'alice',
      tenant: 'shop',
      changes: [{ name: 'shop', type: 'A', before: null, after: { name: 'shop', type: 'A', ttl: 300, records: [{ content: '203.0.113.10' }, { content: '203.0.113.11' }] } }],
      result: 'applied',
      digest: '',
    },
  ],
};

function access(c: Ctx, d: DnsDomain) {
  const u = c.user();
  if (u.systemAdmin) return { admin: true, mine: [] as string[], write: [] as string[], tenants: d.assignments?.map((a) => a.tenant) ?? [] };
  const mine: string[] = [];
  const write: string[] = [];
  const tenants: string[] = [];
  for (const a of d.assignments ?? []) {
    const r = c.roleIn(u, a.tenant);
    if (!r) continue;
    tenants.push(a.tenant);
    mine.push(...a.names);
    if (r === 'manager') write.push(...a.names);
  }
  return { admin: false, mine, write, tenants };
}

/** 연결된 외부 도메인 이름(인증서 목업이 쓴다) */
export const zoneNames = () => domains.map((d) => d.domain);

export function registerDns(c: Ctx) {
  const { on, ok, err } = c;
  const admin = () => {
    const u = c.user();
    if (!u.systemAdmin) throw err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    return u;
  };  // ── 연결된 서버 (web 몫). 외부 접속 목업(ingress.ts)의 node-a·node-b·node-c와 같은 주소 ──
  const NODES: Record<string, { listen: number[]; addr: string[]; isolated?: boolean }> = { 'node-a': { listen: [80, 443], addr: ['203.0.113.10'] }, 'node-b': { listen: [443], addr: ['203.0.113.11'] }, 'node-c': { listen: [443], addr: ['198.51.100.7'], isolated: true } };
  const links = new Map<string, { rev: number; rows: Map<string, { addressSource: 'node' | 'manual'; addresses: string[]; autoRemove: boolean; reach?: { ok: boolean; at: string; error?: string } }> }>();
  const linksOf = (d: string) => {
    if (!links.has(d))
      links.set(d, {
        rev: 1,
        rows: new Map(
          d === 'example.com'
            ? [
                ['node-a', { addressSource: 'manual', addresses: ['203.0.113.10'], autoRemove: true, reach: { ok: true, at: new Date(Date.now() - 120000).toISOString() } }],
                ['node-b', { addressSource: 'node', addresses: ['203.0.113.11'], autoRemove: true, reach: { ok: true, at: new Date(Date.now() - 120000).toISOString() } }],
              ]
            : [],
        ),
      });
    return links.get(d)!;
  };
  const serverView = (d: string) => {
    const l = linksOf(d);
    const items = Object.entries(NODES).map(([node, n]) => {
      const r = l.rows.get(node);
      return r
        ? { node, listen: n.listen, addresses: r.addresses, addressSource: r.addressSource, linked: true, autoRemove: r.autoRemove, reach: r.reach, state: n.isolated && r.autoRemove ? 'removed' : 'in-dns', ...(n.isolated ? { isolated: true } : {}) }
        : { node, listen: n.listen, addresses: n.addr, addressSource: 'node', linked: false, autoRemove: true, state: 'not-linked', ...(n.isolated ? { isolated: true } : {}) };
    });
    // Seafield가 만든 A·AAAA 이름마다 DNS에 있는 서버 주소로 맞추는 바꿀 내용(데몬 #178과 같은 규칙)
    const live = items.filter((x) => x.linked && x.state === 'in-dns').flatMap((x) => x.addresses);
    const v4 = live.filter((a) => a.includes('.'));
    const v6 = live.filter((a) => a.includes(':'));
    const names = [...new Set(Object.values(managed[d] ?? {}).filter((m) => m.type === 'A' || m.type === 'AAAA').map((m) => m.name))];
    const upsert: RRSet[] = [];
    const del: { name: string; type: string }[] = [];
    if (l.rows.size)
      for (const name of names)
        for (const [type, want] of [['A', v4], ['AAAA', v6]] as const) {
          const cur = (zones[d] ?? []).find((r) => r.name === name && r.type === type);
          const same = cur && cur.records.map((r) => r.content).sort().join() === [...want].sort().join();
          if (want.length && !same) upsert.push({ name, type, ttl: cur?.ttl ?? 300, records: want.map((content) => ({ content })) });
          if (!want.length && cur) del.push({ name, type });
        }
    return { items, revision: l.rev, changes: { upsert, delete: del }, staged: upsert.length + del.length };
  };
  const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+)$/i;
  on('GET', '/dns/domains/:d/servers', (m) => {
    const u = c.user();
    const v = serverView(m[0]);
    if (u.systemAdmin) return ok(v);
    // 관리자가 아니면 연결한 서버만 저장된 그대로(서버 주소·격리는 모름), 바꿀 내용은 없다.
    return ok({ items: v.items.filter((x) => x.linked).map(({ isolated: _i, ...x }) => ({ ...x, addresses: x.addressSource === 'node' ? [] : x.addresses })), revision: v.revision, partial: true });
  });
  on('PUT', '/dns/domains/:d/servers/:n', (m, b) => {
    admin();
    const l = linksOf(m[0]);
    const n = NODES[m[1]];
    if (!n) return err(404, 'not-found', '외부 접속이 켜진 서버가 아닙니다.');
    if (b.revision !== l.rev) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다. 다시 읽어 주세요.');
    if (!b.linked) {
      if (l.rows.size <= 1 && l.rows.has(m[1])) return err(422, 'last-server', '마지막 서버는 끊을 수 없습니다. 레코드를 먼저 지우세요.');
      l.rows.delete(m[1]);
    } else {
      const src = b.addressSource === 'manual' ? 'manual' : 'node';
      const addrs = src === 'manual' ? ((b.addresses as string[] | undefined) ?? []).map((x) => String(x).trim()).filter(Boolean) : n.addr;
      if (!addrs.length || addrs.some((x) => !IP_RE.test(x))) return err(422, 'invalid', '공개 주소는 IPv4·IPv6 주소입니다.');
      const prev = l.rows.get(m[1]);
      l.rows.set(m[1], { addressSource: src, addresses: addrs, autoRemove: b.autoRemove !== false, reach: prev?.reach });
    }
    l.rev += 1;
    return ok(serverView(m[0]));
  });
  on('POST', '/dns/domains/:d/servers/check', (m, b) => {
    c.user();
    const l = linksOf(m[0]);
    const at = new Date().toISOString();
    const nodes = b.node ? [String(b.node)] : [...l.rows.keys()];
    const items = nodes.map((node) => {
      const bad = NODES[node]?.isolated;
      const res = bad ? { ok: false, at, error: '연결 시간 초과 (:443)' } : { ok: true, at };
      const r = l.rows.get(node);
      if (r) r.reach = res;
      return { node, ...res };
    });
    return ok({ items });
  });

  const wrap =
    (h: (m: string[], b: Record<string, unknown>, q: URLSearchParams) => RawResponse) =>
    (m: string[], b: Record<string, unknown>, q: URLSearchParams): RawResponse => {
      try {
        return h(m, b, q);
      } catch (e) {
        if (e && typeof e === 'object' && 'status' in e && 'json' in e) return e as RawResponse;
        throw e;
      }
    };
  const pub = ({ token: _t, ...p }: DnsProvider & { token: string }): DnsProvider => p;
  const domainOf = (name: string) => {
    const d = domains.find((x) => x.domain === name);
    if (!d) throw err(404, 'missing', '등록되지 않은 도메인입니다.');
    return d;
  };
  const check = (p: DnsProvider & { token: string }) => {
    p.lastCheck = now();
    p.lastCheckOk = !p.token.startsWith('bad');
    p.lastError = p.lastCheckOk ? undefined : 'dns-auth-failed';
    if (p.lastCheckOk) p.remaining = 88;
    return p.lastCheckOk;
  };

  on('GET', '/dns/vendors', () => {
    c.user();
    return ok({
      items: [
        { id: 'hostinger', name: 'Hostinger', tokenUrl: 'https://hpanel.hostinger.com/profile/api', ready: true, capabilities: CAPS },
        { id: 'cloudflare', name: 'Cloudflare', ready: false, note: '어댑터 준비 중', capabilities: CAPS },
        { id: 'route53', name: 'AWS Route 53', ready: false, note: '어댑터 준비 중', capabilities: CAPS },
        { id: 'rfc2136', name: 'RFC 2136 (사내 DNS)', ready: false, note: '어댑터 준비 중', capabilities: CAPS },
      ],
      sealReady: true,
    });
  });
  on('GET', '/dns/providers', wrap(() => (admin(), ok({ items: providers.map(pub) }))));
  on(
    'POST',
    '/dns/providers',
    wrap((_m, b) => {
      const u = admin();
      const token = String(b.token ?? '');
      if (!b.name || !token) return err(400, 'bad-request', '이름과 토큰이 필요합니다.');
      if (b.vendor !== 'hostinger') return err(422, 'invalid', '이 공급자 어댑터는 아직 준비 중입니다.');
      if (token.startsWith('bad')) return err(502, 'dns-auth-failed', '연결 시험 실패', { detail: '401 Unauthorized' });
      const p = { id: `p-${Date.now().toString(36)}`, vendor: String(b.vendor), name: String(b.name), tokenHint: token.slice(-4), token, tokenExpires: '2027-05-01T00:00:00Z', account: 'ops@example.com', lastCheck: now(), lastCheckOk: true, remaining: 88, createdBy: u.username, createdAt: now() };
      providers.push(p);
      return ok({ provider: pub(p), account: { name: 'ops@example.com', domains: owned.hostinger.length, remaining: 88, expiresAt: p.tokenExpires } }, 201);
    }),
  );
  const provider = (id: string) => {
    const p = providers.find((x) => x.id === id);
    if (!p) throw err(404, 'missing', '없는 연결입니다.');
    return p;
  };
  on(
    'POST',
    '/dns/providers/:id/check',
    wrap((m) => {
      admin();
      const p = provider(m[0]);
      return check(p) ? ok({ provider: pub(p), account: { name: p.account, domains: 3, remaining: p.remaining, expiresAt: p.tokenExpires } }) : err(502, 'dns-auth-failed', '인증 실패');
    }),
  );
  on(
    'PUT',
    '/dns/providers/:id/token',
    wrap((m, b) => {
      admin();
      const p = provider(m[0]);
      const token = String(b.token ?? '');
      if (token.startsWith('bad')) return err(502, 'dns-auth-failed', '새 토큰이 시험을 통과하지 못했습니다. 옛 토큰을 그대로 씁니다.');
      p.token = token;
      p.tokenHint = token.slice(-4);
      check(p);
      return ok({ provider: pub(p) });
    }),
  );
  on(
    'PUT',
    '/dns/providers/:id',
    wrap((m, b) => {
      admin();
      const p = provider(m[0]);
      const name = String(b.name ?? '').trim();
      if (!name || name.length > 100) return err(422, 'invalid', '이름은 1~100자입니다.');
      p.name = name;
      for (const d of domains) if (d.provider?.id === p.id) d.provider = { ...d.provider, name: p.name };
      return ok({ provider: pub(p) });
    }),
  );
  on(
    'DELETE',
    '/dns/providers/:id',
    wrap((m) => {
      admin();
      const p = provider(m[0]);
      // 연결을 지우면 그 연결을 쓰던 도메인에서 공급자만 떨어진다(도메인은 클러스터 목록에 남음)
      for (const d of domains) if (d.provider?.id === p.id) d.provider = null;
      providers.splice(providers.indexOf(p), 1);
      return { status: 204, json: null };
    }),
  );
  on(
    'GET',
    '/dns/providers/:id/domains',
    wrap((m) => {
      admin();
      const p = provider(m[0]);
      return ok({ items: (owned[p.vendor] ?? []).map((name) => ({ name, hasZone: !elsewhere[name], connected: domains.some((d) => d.domain === name && d.provider?.id === p.id), registered: domains.some((d) => d.domain === name), records: elsewhere[name] ? undefined : (zones[name]?.length ?? 0), nameservers: elsewhere[name] })) });
    }),
  );

  on(
    'GET',
    '/dns/domains',
    wrap(() => {
      const u = c.user();
      const out = domains.flatMap((d) => {
        if (u.systemAdmin) return [{ ...d, ...(counts ? counts(d.domain) : {}) }];
        const a = access(c, d);
        if (!a.tenants.length) return [];
        return [{ ...d, assignments: (d.assignments ?? []).filter((x) => a.tenants.includes(x.tenant)), myNames: a.write }];
      });
      return ok({ items: out, cluster: true });
    }),
  );
  const checkAssign = (as: DnsAssignment[]) => {
    const seen = new Set<string>();
    for (const a of as) {
      if (!a.tenant || seen.has(a.tenant)) return '작업 공간마다 배정 하나입니다';
      seen.add(a.tenant);
      if (!a.names.length) return '이름이 하나 이상 있어야 합니다';
    }
    return undefined;
  };
  on(
    'POST',
    '/dns/domains',
    wrap((_m, b) => {
      const u = admin();
      const name = idna(String(b.domain ?? ''));
      if (!name) return err(422, 'invalid-domain', '도메인 이름 형식이 아닙니다.');
      if (SUFFIX.has(name)) return err(422, 'public-suffix', `${name}은 공개 접미사라 등록할 수 없습니다.`);
      const p = b.provider ? provider(String(b.provider)) : undefined;
      if (domains.some((d) => d.domain === name)) return err(409, 'exists', '이미 등록된 도메인입니다.');
      if (p && elsewhere[name]) return err(409, 'zone-elsewhere', `DNS가 다른 곳에 있습니다(${elsewhere[name]}).`);
      const as = (b.assignments as DnsAssignment[] | undefined) ?? [];
      const bad = checkAssign(as);
      if (bad) return err(422, 'invalid', bad);
      if (p) zones[name] ??= [];
      const before = linkedIds();
      const raw = String(b.domain).trim().toLowerCase();
      const d: DnsDomain = { domain: name, ...(raw !== name ? { unicode: raw } : {}), provider: p ? { id: p.id, vendor: p.vendor, name: p.name } : null, hosts: 0, certificates: 0, defaultTtl: Number(b.defaultTtl) || 3600, assignments: as, addedBy: u.username, addedAt: now() };
      domains.push(d);
      // 남아 있던 미연결 인증서 가운데 이 도메인 아래 이름을 가진 것이 링크된다
      // 남아 있던 인증서 가운데 이 도메인 아래 이름을 가진 것이 링크된다
      const linked = diff(linkedIds(), before);
      return ok({ domain: d, linked }, 201);
    }),
  );
  on(
    'PUT',
    '/dns/domains/:d',
    wrap((m, b) => {
      admin();
      const d = domainOf(m[0]);
      const as = (b.assignments as DnsAssignment[] | undefined) ?? [];
      const bad = checkAssign(as);
      if (bad) return err(422, 'invalid', bad);
      d.defaultTtl = Number(b.defaultTtl) || d.defaultTtl;
      d.assignments = as;
      return ok({ domain: d });
    }),
  );
  on(
    'DELETE',
    '/dns/domains/:d',
    wrap((m) => {
      admin();
      const d = domainOf(m[0]);
      const before = linkedIds();
      const hosts = counts?.(d.domain).hosts ?? 0;
      domains.splice(domains.indexOf(d), 1);
      return ok({ unlinkedHosts: hosts, unlinkedCertificates: diff(before, linkedIds()) });
    }),
  );
  on(
    'PUT',
    '/dns/domains/:d/provider',
    wrap((m, b) => {
      admin();
      const d = domainOf(m[0]);
      const p = provider(String(b.provider ?? ''));
      if (elsewhere[d.domain]) return err(409, 'zone-elsewhere', `DNS가 다른 곳에 있습니다(${elsewhere[d.domain]}).`);
      zones[d.domain] ??= [];
      d.provider = { id: p.id, vendor: p.vendor, name: p.name };
      return ok({ domain: d });
    }),
  );
  on(
    'DELETE',
    '/dns/domains/:d/provider',
    wrap((m) => {
      admin();
      const d = domainOf(m[0]);
      d.provider = null;
      return ok({ domain: d });
    }),
  );
  on(
    'GET',
    '/dns/domains/:d/records',
    wrap((m) => {
      const d = domainOf(m[0]);
      if (!d.provider) return err(409, 'no-provider', '공급자가 없는 도메인입니다. 레코드는 직접 관리합니다.');
      const a = access(c, d);
      if (!a.admin && !a.tenants.length) return err(403, 'denied', '이 도메인을 볼 권한이 없습니다.');
      const ms = managed[d.domain] ?? {};
      const all = (d.assignments ?? []).flatMap((x) => x.names);
      const z = zones[d.domain] ?? [];
      const items = z
        .filter((s) => a.admin || inRange(s.name, a.mine))
        .map((s) => {
          const mm = ms[k(s.name, s.type)];
          return { ...s, fingerprint: fp(s), managed: mm, outside: !mm && !inRange(s.name, all), writable: a.admin || inRange(s.name, a.write) };
        });
      const orphans = Object.values(ms).filter((x) => !z.some((s) => s.name === x.name && s.type === x.type) && (a.admin || inRange(x.name, a.mine)));
      return ok({ items, orphans, capabilities: CAPS, readAt: now() });
    }),
  );
  const plan = (d: DnsDomain, req: DnsChangeReq): DnsPlannedChange[] | RawResponse => {
    const a = access(c, d);
    const z = zones[d.domain] ?? [];
    const ms = managed[d.domain] ?? {};
    const all = (d.assignments ?? []).flatMap((x) => x.names);
    const n = (req.upsert?.length ?? 0) + (req.delete?.length ?? 0);
    if (!n || n > 200) return err(422, 'invalid', '1..200 changes');
    const out: DnsPlannedChange[] = [];
    const seen = new Set<string>();
    const add = (name: string, type: string, after: RRSet | null): RawResponse | undefined => {
      if (seen.has(k(name, type))) return err(422, 'invalid', `a record set appears twice: ${name} ${type}`);
      seen.add(k(name, type));
      let tenant: string | undefined;
      let outside = false;
      if (!a.admin) {
        tenant = (d.assignments ?? []).find((x) => inRange(name, x.names) && c.roleIn(c.user(), x.tenant) === 'manager')?.tenant;
        if (!tenant) return err(403, 'out-of-range', `${name} is outside the names assigned to your workspaces`);
      } else if (!ms[k(name, type)] && !inRange(name, all)) {
        if (!req.outside) return err(409, 'outside', `${name} ${type} is not managed by Seafield Cluster; confirm to change it`);
        outside = true;
      }
      const before = z.find((s) => s.name === name && s.type === type) ?? null;
      out.push({ name, type, before, after, fingerprint: fp(before), tenant, outside: outside || undefined });
      return undefined;
    };
    for (const u of req.upsert ?? []) {
      const s = { ...u, ttl: u.ttl || d.defaultTtl };
      if (s.ttl < CAPS.minTtl) return err(422, 'invalid', `TTL은 ${CAPS.minTtl}초 이상입니다`);
      if (!s.records.length) return err(422, 'invalid', '값이 하나 이상 있어야 합니다');
      if (s.type === 'CNAME' && z.some((x) => x.name === s.name && x.type !== 'CNAME') && !(req.delete ?? []).some((x) => x.name === s.name)) return err(422, 'invalid', `CNAME ${s.name}: 같은 이름에 다른 레코드가 있습니다`);
      const r = add(s.name, s.type, s);
      if (r) return r;
    }
    for (const x of req.delete ?? []) {
      if (!z.some((s) => s.name === x.name && s.type === x.type)) return err(422, 'invalid', `no record set ${x.name} ${x.type} to delete`);
      const r = add(x.name, x.type, null);
      if (r) return r;
    }
    return out;
  };
  on(
    'POST',
    '/dns/domains/:d/plan',
    wrap((m, b) => {
      const d = domainOf(m[0]);
      const p = plan(d, b as unknown as DnsChangeReq);
      if (!Array.isArray(p)) return p;
      const problems = p.filter((x) => x.after?.records.some((r) => r.content.includes('invalid'))).map((x) => ({ name: x.name, type: x.type, message: '공급자 미리 검사: 값이 올바르지 않습니다' }));
      return ok({ changes: p, problems });
    }),
  );
  on(
    'POST',
    '/dns/domains/:d/apply',
    wrap((m, b) => {
      const d = domainOf(m[0]);
      const req = b as unknown as DnsChangeReq & { opId: string; basis: Record<string, string> };
      const u = c.user();
      const digest = JSON.stringify([req.upsert, req.delete, req.outside, req.basis]);
      const hs = (history[d.domain] ??= []);
      const prev = hs.find((h) => h.id === req.opId);
      if (prev) return prev.digest === digest && prev.user === u.id ? ok({ history: prev }) : err(409, 'op-conflict', 'this opId was already used for a different change');
      const p = plan(d, req);
      if (!Array.isArray(p)) return p;
      const changed = p.filter((x) => (req.basis ?? {})[k(x.name, x.type)] !== x.fingerprint);
      if (changed.length) return { status: 409, json: { error: { code: 'zone-changed', message: 'records changed since the plan; plan again' }, changes: changed } };
      if (p.some((x) => x.after?.records.some((r) => r.content.includes('invalid')))) return { status: 422, json: { error: { code: 'dns-invalid', message: 'the provider rejected the change' }, problems: [] } };
      const z = (zones[d.domain] ??= []);
      const snap = { id: `s-${Date.now().toString(36)}`, createdAt: now(), reason: `적용 직전 (${u.username})`, sets: structuredClone(z) };
      (snaps[d.domain] ??= []).unshift(snap);
      const ms = (managed[d.domain] ??= {});
      for (const x of p) {
        const i = z.findIndex((s) => s.name === x.name && s.type === x.type);
        if (i >= 0) z.splice(i, 1);
        if (x.after) {
          z.push(x.after);
          if (!x.outside) ms[k(x.name, x.type)] = { name: x.name, type: x.type, tenant: x.tenant ?? ms[k(x.name, x.type)]?.tenant, app: req.app ?? ms[k(x.name, x.type)]?.app, by: u.username, fingerprint: fp(x.after), at: now() };
        } else delete ms[k(x.name, x.type)];
      }
      const h = { id: req.opId, domain: d.domain, at: now(), user: u.id, username: u.username, tenant: req.tenant ?? p.find((x) => x.tenant)?.tenant, changes: p.map((x) => ({ name: x.name, type: x.type, before: x.before, after: x.after })), result: 'applied' as const, snapshot: snap.id, revertOf: (b.revertOf as string) || undefined, digest };
      hs.unshift(h);
      return ok({ history: h });
    }),
  );
  on(
    'GET',
    '/dns/domains/:d/history',
    wrap((m) => {
      const d = domainOf(m[0]);
      const a = access(c, d);
      if (!a.admin && !a.tenants.length) return err(403, 'denied', '이 도메인을 볼 권한이 없습니다.');
      return ok({ items: (history[d.domain] ?? []).filter((h) => a.admin || (h.tenant && a.tenants.includes(h.tenant))).slice(0, 200) });
    }),
  );
  on(
    'POST',
    '/dns/domains/:d/history/:id/revert',
    wrap((m) => {
      const d = domainOf(m[0]);
      const h = (history[d.domain] ?? []).find((x) => x.id === m[1]);
      if (!h) return err(404, 'missing', 'no such change');
      const req: DnsChangeReq = { upsert: [], delete: [], tenant: h.tenant };
      for (const ch of h.changes) {
        if (ch.before) req.upsert.push(ch.before);
        else req.delete.push({ name: ch.name, type: ch.type });
      }
      return ok({ request: req, revertOf: h.id });
    }),
  );
  on(
    'DELETE',
    '/dns/domains/:d/history/:id',
    wrap((m) => {
      admin();
      const hs = history[domainOf(m[0]).domain] ?? [];
      const i = hs.findIndex((x) => x.id === m[1]);
      if (i < 0) return err(404, 'missing', 'no such change');
      hs.splice(i, 1);
      return { status: 204, json: null };
    }),
  );
  on(
    'GET',
    '/dns/domains/:d/snapshots',
    wrap((m) => {
      admin();
      const d = domainOf(m[0]);
      return ok({ items: (snaps[d.domain] ?? []).map(({ sets: _s, ...x }) => x) });
    }),
  );
  on(
    'POST',
    '/dns/domains/:d/snapshots/:id/restore',
    wrap((m, b) => {
      admin();
      const d = domainOf(m[0]);
      if (b.confirm !== d.domain) return err(400, 'confirm-mismatch', 'type the domain name to confirm');
      const s = (snaps[d.domain] ?? []).find((x) => x.id === m[1]);
      if (!s) return err(404, 'missing', 'no such snapshot');
      zones[d.domain] = structuredClone(s.sets);
      return ok({ restored: s.id });
    }),
  );
  on(
    'GET',
    '/dns/domains/:d/propagation',
    wrap((m, _b, q) => {
      const d = domainOf(m[0]);
      const name = q.get('name') ?? '@';
      const type = q.get('type') ?? 'A';
      const set = (zones[d.domain] ?? []).find((s) => s.name === name && s.type === type);
      const want = set?.records.map((r) => r.content) ?? [];
      const old = want.slice(0, 1);
      return ok({
        name,
        type,
        want,
        checkedAt: now(),
        resolvers: [
          { kind: 'authoritative', server: 'ns1.dns-parking.com', values: want, fresh: true },
          { kind: 'authoritative', server: 'ns2.dns-parking.com', values: want, fresh: true },
          { kind: 'public', server: '1.1.1.1', values: want.length > 1 ? old : want, fresh: want.length <= 1, ttlLeft: want.length > 1 ? 240 : undefined },
          { kind: 'public', server: '8.8.8.8', values: want, fresh: true },
          { kind: 'public', server: '9.9.9.9', values: [], fresh: false, error: 'unavailable' },
        ],
      });
    }),
  );
}

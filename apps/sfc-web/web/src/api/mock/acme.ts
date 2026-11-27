// SPDX-License-Identifier: Apache-2.0

// 인증서 자동화 목업. 주문은 시작 시각에서 흐른 시간으로 단계를 하나씩 넘긴다.
// 비공개 키는 다루지 않는다(데몬도 화면에 주지 않는다).
import type { RawResponse } from '../client';
import type { AcmeAccount, AcmeAuto, AcmeCA, AcmeCert, AcmeOrder, AcmeStep } from '../acme';
import { STEP_ORDER } from '../acme';
import { setDomainHooks, zoneNames } from './dns';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  user: () => { id: string; username: string; systemAdmin: boolean };
}

const now = () => new Date().toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const later = (s: number) => new Date(Date.now() + s * 1000).toISOString();
const fp = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('');

const cas: AcmeCA[] = [
  { id: 'letsencrypt', name: "Let's Encrypt", directory: 'https://acme-v02.api.letsencrypt.org/directory', staging: false, needsEab: false, caa: 'letsencrypt.org', keyTypes: ['ec256', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'], ready: true },
  { id: 'letsencrypt-staging', name: "Let's Encrypt (시험용)", directory: 'https://acme-staging-v02.api.letsencrypt.org/directory', staging: true, needsEab: false, caa: 'letsencrypt.org', keyTypes: ['ec256', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'], ready: true },
  { id: 'zerossl', name: 'ZeroSSL', directory: 'https://acme.zerossl.com/v2/DV90', staging: false, needsEab: true, caa: 'sectigo.com', keyTypes: ['ec256', 'rsa2048'], ready: false, note: '준비 중' },
];
const accounts: AcmeAccount[] = [
  { id: 'acc-le', ca: 'letsencrypt', email: 'ops@example.com', url: 'https://acme-v02.api.letsencrypt.org/acme/acct/1', eab: false, agreedAt: ago(86400 * 120), createdBy: 'alice', createdAt: ago(86400 * 120) },
  { id: 'acc-les', ca: 'letsencrypt-staging', email: 'ops@example.com', url: 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/9', eab: false, agreedAt: ago(86400 * 120), createdBy: 'alice', createdAt: ago(86400 * 120) },
];
const step = (name: string, at: string, state: AcmeStep['state'] = 'done', detail?: string): AcmeStep => ({ name, state, at, detail });
const doneSteps = (at: string) => STEP_ORDER.map((n) => step(n, at));
const certs: AcmeCert[] = [
  { name: 'shop-example', names: ['shop.example.com', '*.shop.example.com'], account: 'acc-le', keyTypes: ['ec256'], autoRenew: true, fingerprint: fp(), keyType: 'ec256', issuer: "Let's Encrypt E6", notBefore: ago(3600), notAfter: later(86400 * 89), nextRenew: later(86400 * 59), failures: 0, createdBy: 'alice', createdAt: ago(86400 * 120), running: false },
  { name: 'blog-example', names: ['blog.example.com'], account: 'acc-le', keyTypes: ['ec256'], autoRenew: true, fingerprint: fp(), keyType: 'ec256', issuer: "Let's Encrypt E5", notBefore: ago(86400 * 66), notAfter: later(86400 * 24), nextRenew: ago(600), failures: 0, createdBy: 'alice', createdAt: ago(86400 * 70), running: false, renewBlocked: ago(600) },
  { name: 'api-acme', names: ['api.acme.dev'], account: 'acc-le', keyTypes: ['ec256'], autoRenew: true, fingerprint: fp(), keyType: 'ec256', issuer: "Let's Encrypt E6", notBefore: ago(86400 * 84), notAfter: later(86400 * 6), nextRenew: ago(86400 * 24), nextTry: later(3600 * 4), failures: 3, createdBy: 'alice', createdAt: ago(86400 * 200), running: false },
  { name: 'lab-wild', names: ['*.lab.example.com'], account: 'acc-les', keyTypes: ['ec256'], autoRenew: false, fingerprint: fp(), keyType: 'ec256', issuer: '(STAGING) Pretend Pear X1', notBefore: ago(86400 * 2), notAfter: later(86400 * 88), failures: 0, createdBy: 'alice', createdAt: ago(86400 * 2), running: false },
  // 자동 발급이 만든 정의: 이름은 호스트의 '.'을 '-'로 바꾼 것, 만든 사람은 '자동 발급'
  { name: 'status-example-com', names: ['status.example.com'], account: 'acc-le', keyTypes: ['ec256'], autoRenew: true, failures: 0, createdBy: '자동 발급', createdAt: ago(240), running: false, autoIssued: { host: 'status.example.com', detectedAt: ago(240) } },
];
const orders: (AcmeOrder & { started: number; fail?: string })[] = [
  { id: 'o-shop-4', cert: 'shop-example', at: ago(3600), by: 'alice', auto: false, state: 'done', steps: doneSteps(ago(3600)), keyType: 'ec256', fingerprint: certs[0].fingerprint, storeOp: 'acme-o-shop-4', updatedAt: ago(3500), started: 0 },
  { id: 'o-shop-3', cert: 'shop-example', at: ago(86400 * 60), by: 'alice', auto: false, state: 'done', steps: doneSteps(ago(86400 * 60)), keyType: 'ec256', updatedAt: ago(86400 * 60), started: 0 },
  {
    id: 'o-api-9',
    cert: 'api-acme',
    at: ago(3600 * 2),
    by: 'alice',
    auto: false,
    state: 'failed',
    errorCode: 'propagation',
    steps: [step('preflight', ago(7200)), step('order', ago(7200)), step('txt', ago(7190)), step('propagation', ago(6590), 'failed', '_acme-challenge.api.acme.dev TXT가 권한 네임서버 2곳 중 1곳에서 10분 안에 보이지 않음'), step('cleanup', ago(6580))],
    updatedAt: ago(6580),
    started: 0,
  },
];

/** 흐른 시간으로 주문 단계를 넘긴다(단계당 1.5초). */
function advance(o: (typeof orders)[number]) {
  if (o.state !== 'running') return;
  const n = Math.floor((Date.now() - o.started) / 1500);
  const c = certs.find((x) => x.name === o.cert)!;
  o.steps = STEP_ORDER.slice(0, Math.min(n, STEP_ORDER.length)).map((s) => step(s, now()));
  if (o.fail && n >= 1) {
    o.steps = [step('preflight', now(), 'failed', o.fail)];
    o.state = 'failed';
    o.errorCode = 'no-domain';
    c.running = false;
    return;
  }
  if (n < STEP_ORDER.length) {
    o.steps.push(step(STEP_ORDER[n], now(), 'running'));
    return;
  }
  o.state = 'done';
  o.keyType = c.keyTypes[0];
  o.fingerprint = fp();
  o.updatedAt = now();
  store.push({ id: o.fingerprint, names: c.names, keyType: storeKey(o.keyType), issuer: c.account === 'acc-les' ? "CN=(STAGING) Pretend Pear X1, O=(STAGING) Let's Encrypt" : LE, serial: ser(), notBefore: now(), notAfter: later(86400 * 90), uploadedBy: o.auto ? 'sfc-web-tls' : o.by, uploadedAt: now(), definition: c.name });
  Object.assign(c, { fingerprint: o.fingerprint, keyType: o.keyType, issuer: c.account === 'acc-les' ? '(STAGING) Pretend Pear X1' : "Let's Encrypt E6", notBefore: now(), notAfter: later(86400 * 90), nextRenew: later(86400 * 60), nextTry: undefined, failures: 0, renewBlocked: undefined, running: false, lastOrder: o.id });
}


// ── 자동 발급(웹 몫) ──
const auto: AcmeAuto = {
  enabled: true,
  account: 'acc-le',
  keyTypes: ['ec256'],
  dualRsa: false,
  notifyAfterMinutes: 10,
  domains: [
    { domain: 'shop.example.com', enabled: true, mode: 'per-host', tenants: ['shop'] },
    { domain: 'example.com', enabled: true, mode: 'wildcard', keyTypes: ['ec384', 'ec256'], tenants: ['shop', 'blog'] },
    { domain: 'acme.dev', enabled: false, mode: 'per-host', tenants: [] },
  ],
  waiting: [{ host: 'grafana.internal', reason: 'no-domain', tenant: 'internal', app: 'metrics', node: 'node-a', listen: ':443', since: ago(12 * 60) },
    { host: 'docs.example.com', reason: 'not-assigned', tenant: 'blog', app: 'docs', node: 'node-b', listen: ':443', since: ago(5 * 60) },
  ],
  revision: 1,
};

// ── 클러스터 인증서 보관함 목업 (certificate-store.md 2~5절) ──
// 링크는 (호스트, 알고리즘 계열)마다 하나: 등록된 도메인 아래 이름 가운데, 지금 유효하고 끊지 않은 것 중 가장 늦게 만료되는 인증서.
interface SC {
  id: string;
  names: string[];
  keyType: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  uploadedBy?: string;
  uploadedAt: string;
  disabled?: boolean;
  definition?: string;
}
const ser = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join(':');
const LE = "CN=E6, O=Let's Encrypt, C=US";
const storeKey = (k?: string) => ({ ec256: 'ecdsa-p256', ec384: 'ecdsa-p384', rsa2048: 'rsa-2048', rsa3072: 'rsa-3072', rsa4096: 'rsa-4096' })[k ?? 'ec256'] ?? k ?? 'ecdsa-p256';
const store: SC[] = [
  ...certs.filter((c) => c.fingerprint).map((c) => ({ id: c.fingerprint!, names: c.names, keyType: storeKey(c.keyType), issuer: c.account === 'acc-les' ? 'CN=(STAGING) Pretend Pear X1, O=(STAGING) Let\'s Encrypt' : LE, serial: ser(), notBefore: c.notBefore!, notAfter: c.notAfter!, uploadedBy: 'sfc-web-tls', uploadedAt: c.notBefore!, definition: c.name })),
  // 직접 올린 RSA: 같은 호스트에 ECDSA와 함께 둔다
  { id: fp(), names: ['shop.example.com'], keyType: 'rsa-2048', issuer: 'CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited', serial: ser(), notBefore: ago(86400 * 305), notAfter: later(86400 * 60), uploadedBy: 'alice', uploadedAt: ago(86400 * 300) },
  // 이전 갱신분: 새 인증서가 링크를 모두 가져가 파기 대기
  { id: fp(), names: ['shop.example.com', '*.shop.example.com'], keyType: 'ecdsa-p256', issuer: LE, serial: ser(), notBefore: ago(86400 * 49), notAfter: later(86400 * 41), uploadedBy: 'sfc-web-tls', uploadedAt: ago(86400 * 49) },
  // 사내 인증 기관: 등록된 도메인 아래 이름이 아니라 미연결
  { id: fp(), names: ['grafana.internal'], keyType: 'ecdsa-p256', issuer: 'CN=Intra Root CA, O=사내 인증 기관', serial: ser(), notBefore: ago(86400 * 353), notAfter: later(86400 * 12), uploadedBy: 'alice', uploadedAt: ago(86400 * 353) },
];
const fam = (k: string) => (k.startsWith('rsa') ? 'rsa' : 'ecdsa');
const underReg = (name: string) => {
  const n = name.replace(/^\*\./, '');
  return zoneNames().some((z) => n === z || n.endsWith(`.${z}`));
};
const SERVED: Record<string, string[]> = { 'example.com': ['node-a', 'node-b'], 'acme.dev': ['node-a'], 'intra.example.org': ['node-a'] };
const servedBy = (host: string) => Object.entries(SERVED).find(([z]) => host.replace(/^\*\./, '') === z || host.endsWith(`.${z}`))?.[1] ?? [];
/** 지금 링크: "host|alg" → id */
function linkMap() {
  const t = Date.now();
  const m = new Map<string, SC>();
  for (const c of store) {
    if (c.disabled || Date.parse(c.notBefore) > t || Date.parse(c.notAfter) <= t) continue;
    for (const h of c.names) {
      if (!underReg(h)) continue;
      const k = `${h}|${fam(c.keyType)}`;
      const cur = m.get(k);
      if (!cur || Date.parse(c.notAfter) > Date.parse(cur.notAfter)) m.set(k, c);
    }
  }
  return m;
}
function view(c: SC, lm = linkMap(), detail = false) {
  const links = [...lm.entries()].filter(([, x]) => x.id === c.id).map(([k]) => {
    const [host, alg] = k.split('|');
    return detail ? { host, alg, servedBy: servedBy(host) } : { host, alg };
  });
  const state = links.length ? 'linked' : c.names.some(underReg) ? 'pending-destroy' : 'unlinked';
  const { definition, ...rest } = c;
  // 정의 이름은 그 정의가 마지막으로 받은 인증서일 때만
  const def = definition && certs.find((x) => x.name === definition)?.fingerprint === c.id ? definition : undefined;
  return { ...rest, state, links, ...(def ? { definition: def } : {}), ...(detail ? { chain: [`CN=${c.names[0]}`, c.issuer] } : {}) };
}
/** 만료된 인증서는 서버가 지운다 */
const sweep = () => {
  for (let i = store.length - 1; i >= 0; i--) if (Date.parse(store[i].notAfter) <= Date.now()) store.splice(i, 1);
};
const linkedIds = () => new Set([...linkMap().values()].map((x) => x.id));
// 외부 도메인 목업이 등록·빼기 전후의 링크를 비교한다
setDomainHooks(linkedIds, (d) => {
  const lm = linkMap();
  const keys = [...lm.keys()].filter((k) => {
    const h = k.split('|')[0].replace(/^\*\./, '');
    return h === d || h.endsWith(`.${d}`);
  });
  return { hosts: new Set(keys.map((k) => k.split('|')[0])).size, certificates: new Set(keys.map((k) => lm.get(k)!.id)).size };
});

export function registerAcme(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const admin = () => {
    const u = ctx.user();
    if (!u.systemAdmin) throw err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    return u;
  };
  const wrap =
    (h: (m: string[], b: Record<string, unknown>, q?: URLSearchParams) => RawResponse) =>
    (m: string[], b: Record<string, unknown>, q?: URLSearchParams): RawResponse => {
      try {
        return h(m, b, q);
      } catch (e) {
        if (e && typeof e === 'object' && 'status' in e && 'json' in e) return e as RawResponse;
        throw e;
      }
    };
  const cert = (name: string) => {
    const c = certs.find((x) => x.name === name);
    if (!c) throw err(404, 'missing', 'no such certificate');
    orders.filter((o) => o.cert === name).forEach(advance);
    return c;
  };
  on('GET', '/acme/cas', wrap(() => (admin(), ok({ items: cas }))));
  on('GET', '/acme/responder', wrap(() => (admin(), ok({ address: '10.88.0.5:8402', advertised: '10.88.0.5:8402', listening: true, setBy: 'sfc-web', setAt: new Date(Date.now() - 3600e3 * 6).toISOString() }))));
  on('GET', '/acme/accounts', wrap(() => (admin(), ok({ items: accounts }))));
  on(
    'POST',
    '/acme/accounts',
    wrap((_m, b) => {
      const u = admin();
      const ca = cas.find((x) => x.id === b.ca);
      if (!ca || !ca.ready) return err(422, 'invalid', '쓸 수 없는 인증 기관입니다.');
      if (b.agreeTos !== true) return err(422, 'invalid', 'the CA terms must be accepted');
      if (ca.needsEab && !b.eab) return err(422, 'invalid', 'this CA needs an external account binding (key ID and HMAC)');
      const a: AcmeAccount = { id: `acc-${Date.now().toString(36)}`, ca: ca.id, email: (b.email as string) || undefined, url: `${ca.directory}/acct/${Date.now()}`, eab: !!b.eab, agreedAt: now(), createdBy: u.username, createdAt: now() };
      accounts.push(a);
      return ok({ account: a }, 201);
    }),
  );
  on(
    'DELETE',
    '/acme/accounts/:id',
    wrap((m) => {
      admin();
      const i = accounts.findIndex((a) => a.id === m[0]);
      if (i < 0) return err(404, 'missing', 'no such account');
      if (certs.some((c) => c.account === m[0])) return err(409, 'in-use', 'certificates use this account');
      accounts.splice(i, 1);
      return { status: 204, json: null };
    }),
  );
  on(
    'GET',
    '/acme/certs',
    wrap(() => {
      admin();
      orders.forEach(advance);
      return ok({ items: certs, certStore: true });
    }),
  );
  on(
    'POST',
    '/acme/certs',
    wrap((_m, b) => {
      const u = admin();
      const name = String(b.name ?? '');
      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name)) return err(422, 'invalid', "name: lowercase letters, digits and '-', at most 63");
      if (certs.some((c) => c.name === name)) return err(409, 'exists', 'a certificate with this name exists');
      const names = (b.names as string[]) ?? [];
      if (!names.length) return err(422, 'invalid', '1..100 names');
      if (!accounts.some((a) => a.id === b.account)) return err(422, 'invalid', 'no such account');
      const zones = zoneNames();
      const bad = names.find((n) => !zones.some((z) => n.replace(/^\*\./, '') === z || n.replace(/^\*\./, '').endsWith(`.${z}`)));
      if (bad) return err(422, 'no-domain', `${bad}: no connected external domain`);
      const c: AcmeCert = { name, names, account: String(b.account), keyTypes: (b.keyTypes as string[]) ?? ['ec256'], autoRenew: b.autoRenew !== false, failures: 0, createdBy: u.username, createdAt: now(), running: false };
      certs.push(c);
      return ok({ certificate: c }, 201);
    }),
  );
  on('GET', '/acme/certs/:name', wrap((m) => {
    admin();
    const c = cert(m[0]) as { names?: string[]; methods?: Record<string, string | null> } | undefined;
    const methods = c?.methods;
    // 받을 수 없는 이름에는 이유를 붙인다(목업: 와일드카드면 no-domain, 아니면 not-registered)
    const methodReasons = methods ? Object.fromEntries(Object.entries(methods).filter(([, v]) => v === null).map(([n]) => [n, n.startsWith('*.') ? 'no-domain' : 'not-registered'])) : undefined;
    return ok({ certificate: c, orders: orders.filter((o) => o.cert === m[0]).slice(0, 20).map(({ started: _s, fail: _f, ...o }) => o), methods, methodReasons });
  }));
  on(
    'PUT',
    '/acme/certs/:name',
    wrap((m, b) => {
      admin();
      const c = cert(m[0]);
      c.autoRenew = !!b.autoRenew;
      if (Array.isArray(b.keyTypes) && b.keyTypes.length) c.keyTypes = b.keyTypes as string[];
      return ok({ certificate: c });
    }),
  );
  on(
    'DELETE',
    '/acme/certs/:name',
    wrap((m) => {
      admin();
      const c = cert(m[0]);
      certs.splice(certs.indexOf(c), 1);
      return { status: 204, json: null };
    }),
  );
  on(
    'POST',
    '/acme/certs/:name/issue',
    wrap((m, b) => {
      const u = admin();
      const c = cert(m[0]);
      const same = orders.find((o) => o.id === b.opId);
      if (same) return ok({ order: same }, 202);
      if (c.running) return err(409, 'running', 'an order is running');
      const o = { id: String(b.opId), cert: c.name, at: now(), by: u.username, auto: false, state: 'running' as const, steps: [], updatedAt: now(), started: Date.now(), fail: c.names.some((n) => n.includes('fail')) ? '연결된 외부 도메인이 없는 이름이 있습니다' : undefined };
      orders.unshift(o);
      c.running = true;
      c.lastOrder = o.id;
      return ok({ order: o }, 202);
    }),
  );
  on(
    'POST',
    '/acme/certs/:name/revoke',
    wrap((m, b) => {
      admin();
      const c = cert(m[0]);
      if (b.confirm !== c.name) return err(400, 'confirm-mismatch', 'type the certificate name to confirm');
      if (!c.fingerprint) return err(409, 'not-issued', 'nothing to revoke');
      c.autoRenew = false;
      return ok({ certificate: c, revoked: c.fingerprint });
    }),
  );
  const sc = (id: string) => {
    sweep();
    const xs = store.filter((c) => c.id.startsWith(id.toLowerCase()));
    if (id.length < 12 || xs.length !== 1) throw err(404, 'not-found', '없는 인증서입니다(ID 앞 12자 이상).');
    return xs[0];
  };
  on(
    'GET',
    '/certificates',
    wrap((_m, _b, q) => {
      admin();
      orders.forEach(advance);
      sweep();
      const lm = linkMap();
      let items = store.map((c) => view(c, lm));
      const host = q?.get('host');
      const st = q?.get('state');
      if (host) items = items.filter((c) => c.names.includes(host));
      if (st) items = items.filter((c) => c.state === st);
      return ok({ items, store: true });
    }),
  );
  on(
    'POST',
    '/certificates/check',
    wrap((_m, b) => {
      admin();
      const chain = String(b.chain ?? '');
      if (!/-----BEGIN CERTIFICATE-----/.test(chain)) return err(422, 'invalid-chain', '체인 PEM이 아닙니다.');
      const names = [/partner/.test(chain) ? 'partner.acme.dev' : /internal/.test(chain) ? 'wiki.internal' : 'upload.example.com'];
      const keyType = /rsa/i.test(chain) ? 'rsa-2048' : 'ecdsa-p256';
      if (/expired/.test(chain)) return ok({ id: fp(), names: ['old.example.com'], keyType, notAfter: ago(86400 * 3), issuer: 'CN=Sectigo, O=Sectigo Limited', invalid: 'expired', links: [] });
      const lm = linkMap();
      return ok({ id: fp(), names, keyType, notAfter: later(86400 * 365), issuer: 'CN=Sectigo ECC Domain Validation Secure Server CA, O=Sectigo Limited', links: names.filter(underReg).map((h) => ({ host: h, alg: fam(keyType), replaces: lm.get(`${h}|${fam(keyType)}`)?.id })) });
    }),
  );
  on('GET', '/certificates/:id', wrap((m) => (admin(), ok(view(sc(m[0]), linkMap(), true)))));
  on(
    'POST',
    '/certificates',
    wrap((_m, b) => {
      const u = admin();
      const chain = String(b.chain ?? '');
      const key = String(b.key ?? '');
      if (!/-----BEGIN CERTIFICATE-----/.test(chain)) return err(422, 'invalid-chain', '체인 PEM이 아닙니다.');
      if (!/-----BEGIN (EC |RSA )?PRIVATE KEY-----/.test(key)) return err(422, 'invalid-key', '비공개 키 PEM이 아닙니다.');
      if (/mismatch/.test(chain)) return err(422, 'mismatch', '체인의 공개 키와 비공개 키가 짝이 아닙니다.');
      if (/refuse/.test(chain)) return err(422, 'not-valid-now', '지금 유효한 인증서가 아닙니다.');
      const names = [/partner/.test(chain) ? 'partner.acme.dev' : /internal/.test(chain) ? 'wiki.internal' : 'upload.example.com'];
      const c: SC = { id: fp(), names, keyType: /rsa/i.test(chain) ? 'rsa-2048' : 'ecdsa-p256', issuer: 'CN=Sectigo ECC Domain Validation Secure Server CA, O=Sectigo Limited', serial: ser(), notBefore: now(), notAfter: later(86400 * 365), uploadedBy: u.username, uploadedAt: now() };
      store.push(c);
      return ok({ id: c.id, created: true, links: view(c).links }, 201);
    }),
  );
  on(
    'DELETE',
    '/certificates/:id',
    wrap((m) => {
      admin();
      const c = sc(m[0]);
      const v = view(c);
      if (v.state === 'linked') return { status: 409, json: { error: { code: 'linked', message: '연결된 인증서입니다.' }, links: v.links } };
      store.splice(store.indexOf(c), 1);
      return { status: 204, json: null };
    }),
  );
  on(
    'POST',
    '/certificates/:id/disable',
    wrap((m) => {
      admin();
      const c = sc(m[0]);
      const n = view(c).links.length;
      c.disabled = true;
      return ok({ unlinkedHosts: n });
    }),
  );
  on('GET', '/acme/auto', wrap(() => (admin(), ok(auto))));
  on(
    'PUT',
    '/acme/auto',
    wrap((_m, b) => {
      admin();
      if (b.revision !== auto.revision) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다. 다시 읽어 주세요.');
      const kt = (b.keyTypes as string[]) ?? [];
      if (!kt.length) return err(422, 'invalid', 'keyTypes: 하나 이상');
      if (b.account && !accounts.some((a) => a.id === b.account)) return err(422, 'invalid', '없는 인증 기관 계정입니다.');
      if (b.enabled && !b.account) return err(422, 'invalid', 'account: 자동 발급을 켜려면 인증 기관 계정이 있어야 합니다.');
      const nm = Number(b.notifyAfterMinutes ?? 10);
      if (!Number.isInteger(nm) || nm < 1 || nm > 1440) return err(422, 'invalid', 'notifyAfterMinutes: 1~1440');
      // 도메인 목록은 연결된 외부 도메인 전부다. 받은 값으로는 켬·방식·알고리즘만 바꾸고 tenants는 무시한다.
      const got = new Map(((b.domains as AcmeAuto['domains']) ?? []).map((d) => [d.domain, d]));
      const ds = auto.domains.map((d) => {
        const x = got.get(d.domain);
        return x ? { ...d, enabled: !!x.enabled, mode: x.mode, keyTypes: x.keyTypes?.length ? x.keyTypes : undefined } : d;
      });
      Object.assign(auto, { enabled: !!b.enabled, account: (b.account as string) || undefined, keyTypes: kt, dualRsa: !!b.dualRsa, notifyAfterMinutes: nm, domains: ds, revision: auto.revision + 1 });
      return ok(auto);
    }),
  );
  on(
    'POST',
    '/acme/auto/ignore',
    wrap((_m, b) => {
      admin();
      const i = auto.waiting.findIndex((w) => w.host === b.host);
      if (i < 0) return err(404, 'not-found', '대기 목록에 없는 호스트입니다.');
      auto.waiting.splice(i, 1);
      auto.revision++;
      return ok(auto);
    }),
  );
}

// SPDX-License-Identifier: Apache-2.0

// 망 › 도메인 이름의 직접 더한 이름(A·AAAA·CNAME·TXT·MX·SRV·CAA). PATCH …/dns/records로 읽은 revision 기준의 변경분(remove·add)만 보낸다.
// 규칙(docs/reference/web-api/50-network-dns-names.md): value는 zone 파일 형식 한 줄이고 sfcd가 정규형(miekg/dns 출력)으로 바꿔 둔다.
// 화면은 그 정규형과 같은 문자열을 만들어 보낸다. 그래야 고치기에서 안 바뀐 값이 변경분에 들어가지 않는다.
// 한 이름·종류에 값 최대 8개, TTL 하나. CNAME은 하나만이고 같은 이름에 다른 종류와 같이 못 둔다. 목록 최대 64줄.

export type RecordType = 'A' | 'AAAA' | 'CNAME' | 'TXT' | 'MX' | 'SRV' | 'CAA';
export const RECORD_TYPES: [RecordType, string, string][] = [
  ['A', 'A · IPv4 주소', '주소'],
  ['AAAA', 'AAAA · IPv6 주소', '주소'],
  ['CNAME', 'CNAME · 다른 이름으로', '하나만 · 같은 이름에 다른 종류 못 둠'],
  ['TXT', 'TXT · 글', '따옴표 문자열 · 전체 1024바이트'],
  ['MX', 'MX · 메일 서버', '우선순위 + 서버 이름'],
  ['SRV', 'SRV · 서비스 위치', '우선순위 · 가중치 · 포트 · 대상'],
  ['CAA', 'CAA · 인증서 발급 허용', '플래그 0·128 · 태그 · 값 255바이트'],
];
/** 종류별 값 칸 이름(한 줄의 칸 순서) */
export const VALUE_COLS: Record<RecordType, string[]> = {
  A: ['주소'],
  AAAA: ['주소'],
  CNAME: ['대상 이름'],
  TXT: ['값'],
  MX: ['우선순위', '메일 서버'],
  SRV: ['우선순위', '가중치', '포트', '대상'],
  CAA: ['태그', '값', '플래그'],
};
export const MAX_SET = 8;
export const MAX_RECORDS = 64;

export interface DnsRecord {
  name: string;
  type: RecordType;
  value: string;
  ttl?: number;
  served?: boolean;
}
/** 화면의 한 줄: 같은 이름·종류의 값은 묶는다. name ''은 도메인 영역 자체(@) */
export interface RecordGroup {
  name: string;
  type: RecordType;
  values: string[];
  ttl?: number;
  served: boolean;
}

const nodot = (s: string) => s.trim().replace(/\.$/, '').toLowerCase();
/** 'www.shop.internal.' → 'www' (zone 아래 상대 이름), zone 자체 → ''. zone 밖이면 그대로 */
export function relName(name: string, zone?: string): string {
  const n = nodot(name);
  const z = zone ? nodot(zone) : '';
  if (z && n === z) return '';
  return z && n.endsWith(`.${z}`) ? n.slice(0, -z.length - 1) : n;
}
/** 상대 이름 → 화면의 전체 이름 */
export const fullName = (rel: string, zone?: string) => {
  const z = zone ? nodot(zone) : '';
  return rel ? (z ? `${rel}.${z}` : rel) : z;
};

export function groupRecords(rs: DnsRecord[], zone?: string): RecordGroup[] {
  const by = new Map<string, RecordGroup>();
  for (const r of rs) {
    const name = relName(r.name, zone);
    const k = `${name}/${r.type}`;
    const g = by.get(k) ?? { name, type: r.type, values: [], served: true, ...(r.ttl ? { ttl: r.ttl } : {}) };
    g.values.push(r.value);
    if (r.served === false) g.served = false;
    by.set(k, g);
  }
  return [...by.values()].sort((a, b) => (a.name === b.name ? (a.type < b.type ? -1 : 1) : a.name < b.name ? -1 : 1));
}

// ── 정규형 문자열(miekg/dns와 같은 꼴) ──
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
/** 바이트 → 따옴표 안 글(" \는 \로, 인쇄 못 하는 바이트는 \DDD) */
function escBytes(b: Uint8Array): string {
  let out = '';
  for (const x of b) {
    if (x === 0x22 || x === 0x5c) out += `\\${String.fromCharCode(x)}`;
    else if (x < 0x20 || x > 0x7e) out += `\\${String(x).padStart(3, '0')}`;
    else out += String.fromCharCode(x);
  }
  return out;
}
const quote = (b: Uint8Array) => `"${escBytes(b)}"`;

/** 따옴표 문자열들('"a" "b\\"c"') → 조각 바이트들. 꼴이 틀리면 undefined */
function unquoteAll(s: string): Uint8Array[] | undefined {
  const out: Uint8Array[] = [];
  let i = 0;
  const t = s.trim();
  while (i < t.length) {
    if (t[i] !== '"') return undefined;
    i++;
    const bytes: number[] = [];
    let closed = false;
    while (i < t.length) {
      const c = t[i];
      if (c === '"') {
        closed = true;
        i++;
        break;
      }
      if (c === '\\') {
        const d = t.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(d) && Number(d) < 256) {
          bytes.push(Number(d));
          i += 4;
          continue;
        }
        if (i + 1 >= t.length) return undefined;
        bytes.push(...utf8.encode(t[i + 1]));
        i += 2;
        continue;
      }
      const cp = t.codePointAt(i)!;
      const ch = String.fromCodePoint(cp);
      bytes.push(...utf8.encode(ch));
      i += ch.length;
    }
    if (!closed) return undefined;
    out.push(Uint8Array.from(bytes));
    while (t[i] === ' ' || t[i] === '\t') i++;
  }
  return out.length ? out : undefined;
}
function cat(bs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(bs.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of bs) {
    out.set(b, o);
    o += b.length;
  }
  return out;
}
/** 255바이트 조각으로(miekg/dns가 긴 문자열을 나누는 것과 같이) */
function chunks(b: Uint8Array): Uint8Array[] {
  if (b.length <= 255) return [b];
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += 255) out.push(b.slice(i, i + 255));
  return out;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
const hostOk = (s: string) => s.length <= 253 && s.split('.').every((l) => LABEL.test(l));
/** 대상 이름: 전체 이름(점 하나 이상)으로, 끝에 점 */
const target = (s: string): string | undefined => {
  const n = nodot(s);
  return n.includes('.') && hostOk(n) ? `${n}.` : undefined;
};
const u16 = (s: string): number | undefined => (/^\d{1,5}$/.test(s.trim()) && Number(s) <= 65535 ? Number(s) : undefined);

/** IPv6 → Go net.IP.String()과 같은 꼴(RFC 5952). 아니면 undefined */
export function ipv6(s: string): string | undefined {
  let t = s.trim().toLowerCase();
  if (!t.includes(':') || /[^0-9a-f:.]/.test(t)) return undefined;
  const v4 = t.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    if (!IPV4.test(v4[2])) return undefined;
    const p = v4[2].split('.').map(Number);
    t = `${v4[1]}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  const halves = t.split('::');
  if (halves.length > 2) return undefined;
  const part = (h: string) => (h ? h.split(':') : []);
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  if ([...head, ...tail].some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return undefined;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return undefined;
  const g = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail].map((x) => parseInt(x, 16));
  // 가장 긴 0 묶음(2개 이상, 같으면 앞)을 ::로
  let bs = -1;
  let bl = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bl) [bs, bl] = [i, j - i];
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bl < 2) return hex.join(':');
  return `${hex.slice(0, bs).join(':')}::${hex.slice(bs + bl).join(':')}`;
}
const v6bad = (c: string) => c === '::' || c.startsWith('ff') || /^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(c) || /^::ffff:0?$/.test(c);

/** 화면 칸 값들 → 보낼 정규형 value. 틀리면 error */
export function composeValue(type: RecordType, parts: string[]): { value?: string; error?: string } {
  const [a = '', b = '', c = '', d = ''] = parts.map((x) => x.trim());
  switch (type) {
    case 'A':
      return IPV4.test(a) && a !== '0.0.0.0' && a !== '255.255.255.255' && !/^2(2[4-9]|3\d)\./.test(a) ? { value: a } : { error: `IPv4 주소가 아닙니다(0.0.0.0·멀티캐스트 제외): ${a}` };
    case 'AAAA': {
      const v = ipv6(a);
      return v && !v6bad(v) ? { value: v } : { error: `IPv6 주소가 아닙니다(::·멀티캐스트·IPv4 매핑 제외): ${a}` };
    }
    case 'CNAME': {
      const v = target(a);
      return v ? { value: v } : { error: '대상은 example.org처럼 전체 이름으로 씁니다.' };
    }
    case 'MX': {
      const p = u16(a);
      const h = target(b);
      if (p === undefined) return { error: '우선순위는 0–65535입니다.' };
      return h ? { value: `${p} ${h}` } : { error: '메일 서버는 mail.example.org처럼 전체 이름으로 씁니다.' };
    }
    case 'SRV': {
      const [p, w, port] = [u16(a), u16(b), u16(c)];
      const h = target(d);
      if (p === undefined || w === undefined || port === undefined) return { error: '우선순위·가중치·포트는 0–65535입니다.' };
      return h ? { value: `${p} ${w} ${port} ${h}` } : { error: '대상은 db.example.org처럼 전체 이름으로 씁니다.' };
    }
    case 'CAA': {
      const tag = a.toLowerCase();
      const flag = c === '' ? 0 : /^\d+$/.test(c) ? Number(c) : -1;
      if (!['issue', 'issuewild', 'iodef'].includes(tag)) return { error: '태그는 issue · issuewild · iodef 중 하나입니다.' };
      if (flag !== 0 && flag !== 128) return { error: '플래그는 0이나 128입니다.' };
      const raw = b.startsWith('"') ? unquoteAll(b) : [utf8.encode(b)];
      if (!raw || raw.length !== 1) return { error: '값은 따옴표 없이 하나만 씁니다.' };
      if (raw[0].length > 255) return { error: 'CAA 값은 255바이트까지입니다.' };
      return { value: `${flag} ${tag} ${quote(raw[0])}` };
    }
    case 'TXT': {
      const raw = a.startsWith('"') ? unquoteAll(a) : [utf8.encode(a)];
      if (!raw) return { error: '따옴표 문자열은 "a" "b"처럼 씁니다.' };
      const cs = raw.flatMap(chunks);
      if (cs.length > 16) return { error: '조각이 16개를 넘습니다(255바이트 조각).' };
      const value = cs.map(quote).join(' ');
      if (value.length > 1024) return { error: '값이 너무 깁니다(전체 1024바이트까지, 한글 한 글자는 저장 형식으로 12바이트).' };
      return { value };
    }
  }
}

/** 읽은 정규형 value → 화면 칸 값들(고치기의 처음 값) */
export function valueParts(type: RecordType, value: string): string[] {
  const v = value.trim();
  switch (type) {
    case 'A':
    case 'AAAA':
      return [v];
    case 'CNAME':
      return [nodot(v)];
    case 'MX': {
      const [p = '', h = ''] = v.split(/\s+/);
      return [p, nodot(h)];
    }
    case 'SRV': {
      const [p = '', w = '', port = '', h = ''] = v.split(/\s+/);
      return [p, w, port, nodot(h)];
    }
    case 'CAA': {
      const m = v.match(/^(\d+)\s+(\S+)\s+(".*")$/);
      if (!m) return ['', v, ''];
      const raw = unquoteAll(m[3]);
      return [m[2], raw ? fromUtf8.decode(cat(raw)) : m[3], m[1]];
    }
    case 'TXT':
      return [showTxt(v)];
  }
}

/** TXT 정규형 → 읽기 쉬운 따옴표 문자열. 255바이트로 나뉜 조각은 하나로 붙여 보인다 */
function showTxt(v: string): string {
  const raw = unquoteAll(v);
  if (!raw) return v;
  const show = (b: Uint8Array) => `"${fromUtf8.decode(b).replace(/[\\"]/g, (c) => `\\${c}`)}"`;
  const split = raw.length > 1 && raw.slice(0, -1).every((b) => b.length === 255);
  return split ? show(cat(raw)) : raw.map(show).join(' ');
}

/** 표에 보일 값 */
export function showValue(type: RecordType, value: string): string {
  const p = valueParts(type, value);
  if (type === 'CAA') return `${p[2]} ${p[0]} "${p[1]}"`;
  return p.join(' ');
}

export interface RecordSpec {
  /** 사용자가 적은 이름(''·@는 영역 자체) */
  name: string;
  type: RecordType;
  rows: string[][];
  ttl: string;
}
export interface SpecCheck {
  /** 보낼 상대 이름(''은 영역 자체) */
  rel?: string;
  values: string[];
  ttl?: number;
  name?: string;
  type?: string;
  value?: string[];
  ttlError?: string;
}

/** 이름 칸 → 상대 이름. 끝에 점을 찍은 전체 이름은 zone 안이어야 한다 */
export function nameOf(input: string, zone: string): { rel?: string; outside?: boolean } {
  const s = input.trim().toLowerCase();
  const z = nodot(zone);
  if (s === '' || s === '@') return { rel: '' };
  if (s.endsWith('.')) {
    const n = nodot(s);
    if (n !== z && !n.endsWith(`.${z}`)) return { outside: true };
    return { rel: relName(n, z) };
  }
  return { rel: relName(s, z) };
}

const TYPE_JOIN = (ts: string[]) => ts.join(' · ');
/**
 * 다이얼로그 칸 검사. others는 지금 고치는 줄을 뺀 직접 더한 줄들, appNames는 앱 서비스 이름(상대 이름).
 * editing은 고치는 줄(이름·종류가 같으면 이미 있는 이름 검사를 하지 않는다).
 */
export function checkSpec(spec: RecordSpec, ctx: { zone: string; net: string; others: RecordGroup[]; appNames: string[]; editing?: RecordGroup }): SpecCheck {
  const z = nodot(ctx.zone);
  const out: SpecCheck = { values: [] };
  const n = nameOf(spec.name, z);
  if (n.outside) out.name = `${ctx.net}의 도메인 영역(${z}) 안의 이름만 더할 수 있습니다`;
  else if (n.rel === 'ns') out.name = `ns.${z}는 이름 확인 서버가 쓰는 이름이라 더할 수 없습니다`;
  else if (n.rel && !hostOk(n.rel)) out.name = '이름은 www나 _ldap._tcp처럼 영문 소문자·숫자·-·_로 씁니다.';
  else out.rel = n.rel;
  if (out.rel !== undefined) {
    const full = fullName(out.rel, z);
    const same = ctx.editing && ctx.editing.name === out.rel && ctx.editing.type === spec.type;
    const at = ctx.others.filter((g) => g.name === out.rel);
    if (spec.type === 'CNAME' && out.rel === '') out.type = `도메인 영역 자체(${z})에는 CNAME을 둘 수 없습니다`;
    else if (spec.type === 'CNAME' && at.some((g) => g.type !== 'CNAME')) out.type = `${full}에 이미 ${TYPE_JOIN(at.filter((g) => g.type !== 'CNAME').map((g) => g.type))}가 있어 CNAME을 둘 수 없습니다`;
    else if (spec.type !== 'CNAME' && at.some((g) => g.type === 'CNAME')) out.type = `${full}에 이미 CNAME이 있어 ${spec.type}를 둘 수 없습니다`;
    else if (at.some((g) => g.type === spec.type)) out.type = `${full}에 이미 ${spec.type}가 있습니다. 그 줄을 고쳐 값을 더하세요`;
    const kept = ctx.editing && ctx.editing.name === out.rel;
    if (!same && !kept && ctx.appNames.includes(out.rel)) out.name = `앱 서비스가 이미 쓰는 이름입니다: ${full}`;
  }
  const filled = spec.rows.filter((r) => r.some((x) => x.trim()));
  const errs: string[] = [];
  for (const r of filled) {
    const c = composeValue(spec.type, r);
    if (c.value) out.values.push(c.value);
    else if (c.error) errs.push(c.error);
  }
  out.values = [...new Set(out.values)];
  if (!filled.length) errs.push(spec.type === 'CNAME' ? '대상 이름을 적으세요.' : '값을 하나 이상 적으세요.');
  if (spec.type === 'CNAME' && filled.length > 1) errs.push('CNAME은 대상 하나만 둡니다.');
  if (filled.length > MAX_SET) errs.push(`한 이름·종류에 값은 ${MAX_SET}개까지입니다.`);
  if (errs.length) out.value = [...new Set(errs)];
  const t = spec.ttl.trim();
  if (t) {
    if (/^\d+$/.test(t) && Number(t) >= 1 && Number(t) <= 3600) out.ttl = Number(t);
    else out.ttlError = 'TTL은 1–3600초입니다.';
  }
  return out;
}
export const specOk = (c: SpecCheck) => c.rel !== undefined && !c.name && !c.type && !c.value && !c.ttlError && c.values.length > 0;

export type Row = { name: string; type: RecordType; value: string; ttl?: number };
const sendName = (rel: string) => rel || '@';
/** 보낼 변경분(PATCH …/dns/records): 옛 줄(old)과 새 줄(next)의 차이만. next가 없으면 빼기. TTL이 바뀌면 그 종류의 값을 모두 빼고 다시 더한다 */
export function recordDelta(old?: RecordGroup, next?: { name: string; type: RecordType; values: string[]; ttl?: number }): { remove: Row[]; add: Row[] } {
  const rows = (g?: { name: string; type: RecordType; values: string[]; ttl?: number }): Row[] => (g ? [...new Set(g.values)].map((value) => ({ name: sendName(g.name), type: g.type, value, ...(g.ttl ? { ttl: g.ttl } : {}) })) : []);
  const key = (r: Row) => `${r.name}/${r.type}/${r.value}/${r.ttl ?? ''}`;
  const before = rows(old);
  const after = rows(next);
  const keep = new Set(before.map(key));
  const now = new Set(after.map(key));
  // 빼는 줄에는 ttl을 싣지 않는다(이름·종류·값으로 찾는다)
  return { remove: before.filter((r) => !now.has(key(r))).map(({ ttl: _t, ...r }) => r), add: after.filter((r) => !keep.has(key(r))) };
}

/** 변경분을 적용한 뒤의 줄 수(목록 최대 64줄 검사) */
export const countAfter = (rs: DnsRecord[], d: { remove: Row[]; add: Row[] }) => rs.length - d.remove.length + d.add.length;

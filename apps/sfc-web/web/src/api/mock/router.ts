// SPDX-License-Identifier: Apache-2.0

// 브라우저 안 목업 계층. docs/reference/web-api.md(/api/v1)와 같은 경로·DTO 모양·오류를 돌려준다.
// 실제 성공 근거가 아니다. 화면 개발과 실패 상태 확인용이다.
import opActionCatalog from './opActions.json';
import { appYamlOldKeys, ingressListProblem } from './appYamlKeys';
import YAML from 'yaml';
import { cidrText, hostIn, inSystem, overlaps, parseCidr, type Cidr } from '../../lib/cidr';
import type { RawResponse } from '../client';
import type * as D from '../dto';
import { lineDiff } from '../../lib/diff';
import { matchRule } from '../../lib/trust';
import * as fx from './fixtures';
import { ed25519 } from '@noble/curves/ed25519.js';
import { credentialAdditionBytes } from '../../auth/credentialProof';
import { randomUUID, sha256Hex } from '../../lib/cryptoCompat';
import { registerDns } from './dns';
import { registerAcme } from './acme';
import { registerNodeShell } from './nodeShell';
import { registerBuilds } from './builds';
import { registerTasks } from './tasks';
import { registerImageTools } from './imagetools';
import { registerAi, registerCoordinator } from './ai';
import { registerIncidents } from './incidents';
import { registerGuides } from './guides';
import { registerMcp } from './mcp';
import { cdGateOf, registerWebhooks } from './webhooks';
import { addTrash, registerTrash, setTrashRetention } from './trash';
import { registerIngress } from './ingress';
import { registerVps } from './vps';
import { registerFirewall } from './firewall';

// ── 실패 주입 ───────────────────────────────────────────

export type MockFailure = 'none' | 'unknown' | 'denied' | 'condition-failed' | 'unavailable' | 'disconnected';
export const mockControls = {
  nextMutation: 'none' as MockFailure,
  latencyMs: 250,
  expireSession() {
    const s = loadSession();
    if (s) saveSession({ ...s, expiresAt: new Date(Date.now() - 1000).toISOString() });
  },
};
const takeFailure = (): MockFailure => {
  const f = mockControls.nextMutation;
  mockControls.nextMutation = 'none';
  return f;
};

// ── 저장 (세션은 sessionStorage, 등록한 키는 localStorage) ──

interface MockSession {
  user: string;
  method: D.DSession['method'];
  expiresAt: string;
}
const SESSION_KEY = 'sfc.mock.session';
const KEYS_KEY = 'sfc.mock.registered-keys.v2';

function loadSession(): MockSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as MockSession) : null;
  } catch {
    return null;
  }
}
function saveSession(s: MockSession | null) {
  try {
    if (s) sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {
    /* 저장 불가여도 이번 페이지 동안은 동작 */
  }
}

/** 등록한 브라우저 키. 새로고침 뒤에도 로그인되도록 localStorage에 둔다. */
interface KeyState {
  keys: { user: string; id: string; publicKey: string; enabled: boolean }[];
  /** 사용자별 계정 버전 증가분 */
  bumps: Record<string, number>;
}
function loadKeys(): KeyState {
  try {
    const v = JSON.parse(localStorage.getItem(KEYS_KEY) ?? 'null') as KeyState | null;
    return v ?? { keys: [], bumps: {} };
  } catch {
    return { keys: [], bumps: {} };
  }
}
function saveKeys(k: KeyState) {
  try {
    localStorage.setItem(KEYS_KEY, JSON.stringify(k));
  } catch {
    /* 무시 */
  }
}
const MOCK_CLUSTER_ID = '6d6f636b'.repeat(8); // 목업 클러스터 ID(64자 hex)
const accountRevision = (u: fx.MockUser) => u.revision + (loadKeys().bumps[u.id] ?? 0);
function credentialsOf(u: fx.MockUser): D.DCredential[] {
  return [
    ...(u.credentials ?? []),
    ...loadKeys()
      .keys.filter((k) => k.user === u.id)
      .map((k) => ({ id: k.id, method: 'private-key', publicKey: k.publicKey, enabled: k.enabled })),
  ];
}

const tickets = new Map<string, { user: string; kind: 'credential' | 'key' | 'approve'; method?: string; publicKey?: string; proof?: Uint8Array; deadline: number }>();

// ── 응답 도우미 ─────────────────────────────────────────

const ok = (json: unknown, status = 200): RawResponse => ({ status, json });
const err = (status: number, code: string, message?: string, extra?: Record<string, unknown>): RawResponse => ({ status, json: { error: { code, message, ...extra } } });
const arrOf = <T,>(x: T[] | null | undefined): T[] => x ?? [];
const nowIso = () => new Date().toISOString();
const page = <T>(items: T[], revision = 1): D.ListPage<T> => ({ items, revision, asOf: nowIso() });
const strip = <T extends object>(xs: (T & { tenant?: string })[]) => xs.map((x) => ({ ...x }));

class Halt {
  constructor(readonly res: RawResponse) {}
}
type User = fx.MockUser;

function requireSession(): { session: MockSession; user: User } {
  const s = loadSession();
  if (!s || Date.parse(s.expiresAt) <= Date.now()) throw new Halt(err(401, 'session-expired', '세션이 만료됐습니다. 다시 로그인해 주세요.'));
  const user = fx.users.find((u) => u.id === s.user);
  if (!user || !user.enabled) throw new Halt(err(401, 'session-expired'));
  return { session: s, user };
}
/** 목업 스트림이 작업 기록에 남길 때 쓴다 */
export const currentUser = () => loadSession()?.user ?? '';
const roleIn = (u: User, t: string) => fx.memberships[t]?.[u.id];
function requireTenant(u: User, t: string, write = false) {
  if (!(t in fx.memberships)) throw new Halt(err(403, 'denied', '이 작업 공간이 없거나 볼 권한이 없습니다.'));
  const r = roleIn(u, t);
  if (!r && !u.systemAdmin) throw new Halt(err(403, 'denied', '이 작업 공간이 없거나 볼 권한이 없습니다.'));
  if (write && r !== 'manager' && !u.systemAdmin) throw new Halt(err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.'));
}
function requireAdmin(u: User) {
  if (!u.systemAdmin) throw new Halt(err(403, 'denied', '시스템 관리자 권한이 필요합니다.'));
}
const visibleTenants = (u: User) => Object.keys(fx.memberships).filter((t) => u.systemAdmin || roleIn(u, t));

async function sha256hex(text: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(text));
}
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const hex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
const ROOT_REVISION = 401;

// ── 작업 ────────────────────────────────────────────────

type Applied = { code: number; errorCode?: string } | void;
const fingerprints = new Map<string, string>();
const pendingApply = new Map<string, () => Applied>();
const findOp = (id: string, user: string) => fx.ops.find((o) => o.id === id && o.user === user);

function newOp(user: User, id: string, action: string, tenant: string | undefined, target: string | undefined, digest: string, parent?: string): fx.MockOp {
  const at = nowIso();
  return { id, requestId: randomUUID().slice(0, 8), action, tenant, target, state: 'pending', resultFound: false, submittedAt: at, updatedAt: at, user: user.id, digest, parent };
}

/** 한 원 operation을 실행한다. 결과 불명이면 apply를 미뤄 둔다. */
function execute(op: fx.MockOp, failure: MockFailure, apply: () => Applied) {
  op.updatedAt = nowIso();
  if (failure === 'denied') {
    op.state = 'rejected';
    op.errorCode = 'denied';
  } else if (failure === 'unavailable' || failure === 'disconnected' || failure === 'unknown') {
    op.state = 'unknown';
    op.errorCode = failure === 'unknown' ? 'unknown' : failure;
    pendingApply.set(op.id, apply);
  } else if (failure === 'condition-failed') {
    op.state = 'failed';
    op.resultFound = true;
    op.resultCode = 1;
  } else settle(op, apply());
}
function settle(op: fx.MockOp, r: Applied) {
  const code = r ? r.code : 0;
  op.resultFound = true;
  op.resultCode = code;
  op.state = code === 0 ? 'applied' : 'failed';
  op.errorCode = r && r.errorCode ? r.errorCode : undefined;
  op.index = 48300 + fx.ops.length;
  op.revision = code === 0 ? ROOT_REVISION + fx.ops.length : undefined;
  op.updatedAt = nowIso();
}
const opReply = (op: D.DOp) => ok({ op: publicOp(op) }, op.state === 'unknown' ? 202 : 200);
const publicOp = (o: D.DOp): D.DOp => {
  const { user: _u, digest: _d, ...rest } = o as fx.MockOp;
  return { ...rest, revert: revertKind(o) };
};
// 변경 되돌리기 (UI-A4): 목업은 망 DNS 설정(configure-network-dns)만 보낼 때 대상 기록을 남긴다
type DnsSnap = { Enabled: boolean; Zone: string; TTL: number; Upstreams: string[]; Records: { Name: string; Type: string; Value: string; TTL?: number }[] };
const revertRecs = new Map<string, { t: string; n: string; before: DnsSnap; after: DnsSnap }>();
const IRREVERSIBLE = new Set(['delete-volume', 'discard-volume-archive', 'purge-archived', 'remove-node', 'revoke-session', 'disable-credential', 'vault-destroy', 'prune-images', 'clear-logs']);
function revertKind(o: D.DOp): D.DOp['revert'] {
  if (o.state !== 'applied' || o.parent) return 'no';
  if (o.action === 'deploy' || o.action === 'down-app') return 'link';
  return revertRecs.has(o.id) ? 'here' : 'no';
}

/** POST /ops 공통: 같은 opId·같은 내용은 저장된 op, 다른 내용은 409. */
function submit(user: User, body: Record<string, unknown>, action: string, apply: () => Applied): RawResponse {
  const opId = String(body.opId ?? '');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
  if (body.principal !== undefined && body.principal !== '' && body.principal !== user.id) return err(400, 'bad-request', 'principal이 로그인한 사용자와 다릅니다.');
  const batch = typeof body.batch === 'string' && body.batch ? body.batch : undefined;
  if (batch && !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(batch)) return err(400, 'bad-request', 'batch must be a lowercase UUID v4');
  let reason: D.DOp['reason'];
  try {
    const r = reqHeaders['X-SFC-Reason'] ? decodeURIComponent(reqHeaders['X-SFC-Reason']) : undefined;
    const i = reqHeaders['X-SFC-Incident'] ? decodeURIComponent(reqHeaders['X-SFC-Incident']) : undefined;
    if ((r && r.length > 512) || (i && i.length > 128)) throw new Error();
    reason = r || i ? { reason: r, incident: i } : undefined;
  } catch {
    return err(400, 'bad-request', 'X-SFC-Reason: percent-encoded UTF-8 on one line, the reason at most 512 characters, the incident at most 128 bytes');
  }
  const fp = JSON.stringify({ ...body, opId: undefined });
  const existing = findOp(opId, user.id);
  if (existing) return fingerprints.get(opId) !== fp ? err(409, 'op-conflict', '같은 작업 ID에 다른 내용이 왔습니다.') : opReply(existing);
  const failure = takeFailure();
  if (failure === 'disconnected') return err(503, 'disconnected', 'sfcd 연결이 끊겼습니다(목업 주입).');
  const op = newOp(user, opId, action, body.tenant as string | undefined, body.target as string | undefined, fp);
  if (batch) op.batch = batch;
  if (reason) op.reason = reason;
  fingerprints.set(opId, fp);
  fx.ops.unshift(op);
  execute(op, failure, apply);
  return opReply(op);
}

type Payload = Record<string, unknown>;
/** payload 키는 Go 필드 이름이고 대소문자를 가리지 않는다. */
function pick(p: Payload, key: string): unknown {
  const k = Object.keys(p).find((x) => x.toLowerCase() === key.toLowerCase());
  return k === undefined ? undefined : p[k];
}
const CAS = { code: 1 };
const ledgerState = { epoch: 6, revision: 6 };
const INVALID = { code: 2 };
const FORBIDDEN = { code: 4 };

/** action별 상태 변경. 반환 code는 sfcd Result.Code */
function actionApply(user: User, action: string, expected: number, p: Payload): (() => Applied) | RawResponse {
  const s = (k: string) => String(pick(p, k) ?? '');
  switch (action) {
    case 'create-tenant':
      return () => {
        const id = s('ID');
        if (!user.systemAdmin) return FORBIDDEN;
        if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(id)) return INVALID;
        if (id in fx.memberships) return CAS;
        fx.memberships[id] = {};
        fx.tenantRev[id] = 1;
        fx.tenantNodes[id] = [];
      };
    case 'set-membership':
      return () => {
        const t = s('Tenant');
        const target = s('User');
        if (!user.systemAdmin && roleIn(user, t) !== 'manager') return FORBIDDEN;
        if (!fx.users.some((u) => u.id === target)) return INVALID;
        if (expected !== fx.tenantRev[t]) return CAS;
        if (pick(p, 'Enabled') === true) fx.memberships[t][target] = s('Role') === 'manager' ? 'manager' : 'viewer';
        else delete fx.memberships[t][target];
        fx.tenantRev[t]++;
      };
    case 'set-nodes':
      return () => {
        if (!user.systemAdmin) return FORBIDDEN;
        // sfcd와 같이 작업 공간 revision을 expected로 지킨다(0은 옛 화면 호환으로 통과).
        if (expected && expected !== fx.tenantRev[s('Tenant')]) return CAS;
        {
          // sfcd처럼 바뀐 서버만 받는다. 이미 있는 서버 Add·없는 서버 Remove는 CAS.
          const add = (pick(p, 'Add') as string[] | undefined) ?? [];
          const remove = (pick(p, 'Remove') as string[] | undefined) ?? [];
          const cur = fx.tenantNodes[s('Tenant')] ?? [];
          if (add.length + remove.length === 0 || add.some((n) => remove.includes(n))) return INVALID;
          if (add.some((n) => cur.includes(n)) || remove.some((n) => !cur.includes(n))) return CAS;
          fx.tenantNodes[s('Tenant')] = [...cur.filter((n) => !remove.includes(n)), ...add].sort();
        }
        fx.tenantRev[s('Tenant')]++;
      };
    case 'rotate-ledger':
      return () => {
        if (!user.systemAdmin) return FORBIDDEN;
        if (expected !== ledgerState.epoch || Number(pick(p, 'NextEpoch')) !== ledgerState.epoch + 1) return CAS;
        // sfcd는 진행 중인 작업이 없을 때만(storageQuiescent) 바꾼다. 목업은 늘 조용하다고 본다.
        ledgerState.epoch++;
        ledgerState.revision++;
      };
    case 'put-user':
      return () => {
        if (!user.systemAdmin) return FORBIDDEN;
        const id = s('ID');
        const old = fx.users.find((u) => u.id === id);
        if ((old ? old.revision : 0) !== expected) return CAS;
        // 있는 계정은 계정 자체의 칸만 바꾼다(sfcd와 같다). 로그인 수단·범위는 다른 동작으로
        if (old) {
          if (pick(p, 'Credentials') != null || pick(p, 'Operations') != null || pick(p, 'AutomationOnly') === true) return INVALID;
          const fields = { username: s('Username'), enabled: pick(p, 'Enabled') === true, systemAdmin: pick(p, 'SystemAdmin') === true };
          if (fields.username === old.username && fields.enabled === old.enabled && fields.systemAdmin === old.systemAdmin) return INVALID;
          Object.assign(old, fields, { revision: expected + 1 });
          return;
        }
        const next = {
          id,
          username: s('Username'),
          enabled: pick(p, 'Enabled') === true,
          systemAdmin: pick(p, 'SystemAdmin') === true,
          revision: expected + 1,
          // 브라우저 키 목업(loadKeys)에 있는 키는 거기서 붙으므로 여기 두 번 넣지 않는다
          credentials: ((pick(p, 'Credentials') as Payload[] | null) ?? [])
            .filter((c) => !loadKeys().keys.some((k) => k.user === id && k.id === String(pick(c, 'ID'))))
            .map((c) => {
              const pk = pick(c, 'PublicKey') as number[] | undefined;
              return { id: String(pick(c, 'ID')), method: String(pick(c, 'Method')), enabled: pick(c, 'Enabled') !== false, ...(pk ? { publicKey: pk.map((b) => b.toString(16).padStart(2, '0')).join('') } : {}) };
            }),
        };
        fx.users.push({ ...next, password: '' });
      };
    case 'revoke-session':
    case 'set-node-cli-policy':
      return () => (user.systemAdmin ? undefined : FORBIDDEN);
    case 'isolate-node':
    case 'restore-node':
      return () => {
        if (!user.systemAdmin) return FORBIDDEN;
        const m = fx.members.find((x) => x.id === s('Node'));
        if (!m) return INVALID;
        const iso = action === 'isolate-node';
        m.phase = iso ? 'isolated' : 'active';
        m.admitsWork = !iso;
        m.revision++;
        const sum = fx.summaries.find((x) => x.node === m.id);
        if (sum) sum.status = iso ? 'isolated' : 'ready';
      };
    case 'add-credential':
      // 본인 키, 또는 시스템 관리자가 다른 계정에 더하는 키(동작 상한 Operations 가능)
      return () => {
        const own = s('User') === user.id;
        if (!own && !user.systemAdmin) return FORBIDDEN;
        const target = own ? user : (fx.users.find((x) => x.id === s('User')) as User | undefined);
        if (!target) return INVALID;
        if (expected !== accountRevision(target)) return CAS;
        const c = (pick(p, 'Credential') ?? {}) as Payload;
        const pk = pick(c, 'PublicKey');
        const bytes = Array.isArray(pk) ? (pk as number[]) : [];
        if (String(pick(c, 'Method')) !== 'private-key' || bytes.length !== 32 || !String(pick(c, 'ID'))) return INVALID;
        const ks = loadKeys();
        const publicKey = hex(Uint8Array.from(bytes));
        if (credentialsOf(target).some((k) => k.id === pick(c, 'ID') || k.publicKey === publicKey)) return CAS;
        // 본인 추가는 새 키로 서명한 증명이 있어야 한다(시스템 관리자는 없어도 통과, #642). 증명이 오면 누구든 sfcd처럼 검사한다
        const sentProof = pick(p, 'Proof') !== undefined || pick(p, 'Challenge') !== undefined;
        if ((own && !user.systemAdmin) || sentProof) {
          const ch = pick(p, 'Challenge');
          const proof = String(pick(p, 'Proof') ?? '');
          if (!Array.isArray(ch) || ch.length !== 32 || !proof) return FORBIDDEN;
          let good = false;
          try {
            const msg = credentialAdditionBytes(MOCK_CLUSTER_ID, expected, { user: target.id, id: String(pick(c, 'ID')), method: 'private-key', label: String(pick(p, 'Label') ?? ''), publicKey, challenge: Uint8Array.from(ch as number[]) });
            good = ed25519.verify(Uint8Array.from(atob(proof), (x) => x.charCodeAt(0)), msg, Uint8Array.from(bytes));
          } catch {
            good = false;
          }
          if (!good) return FORBIDDEN;
        }
        ks.keys.push({ user: target.id, id: String(pick(c, 'ID')), publicKey, enabled: true });
        ks.bumps[target.id] = (ks.bumps[target.id] ?? 0) + 1;
        saveKeys(ks);
      };
    case 'disable-credential':
      // 본인은 자기 개인키를, 시스템 관리자는 어느 계정의 어느 수단이든 끈다
      return () => {
        const own = s('User') === user.id;
        if (!own && !user.systemAdmin) return FORBIDDEN;
        const target = own ? user : (fx.users.find((x) => x.id === s('User')) as User | undefined);
        if (!target) return INVALID;
        if (expected !== accountRevision(target)) return CAS;
        const id = s('Credential');
        const ks = loadKeys();
        const k = ks.keys.find((x) => x.user === target.id && x.id === id);
        const fixed = target.credentials?.find((c) => c.id === id);
        if (!k && !fixed) return INVALID;
        if (k ? !k.enabled : !fixed!.enabled) return CAS;
        if (own && !user.systemAdmin && !k && fixed!.method !== 'private-key' && !id.startsWith('invite-')) return INVALID;
        if (credentialsOf(target).filter((c) => c.enabled).length <= 1) return INVALID; // 마지막 수단은 끌 수 없다
        if (k) k.enabled = false;
        if (fixed) fixed.enabled = false;
        ks.bumps[target.id] = (ks.bumps[target.id] ?? 0) + 1;
        saveKeys(ks);
      };
    case 'abort-app-upload':
      return () => {
        const t = s('Tenant');
        if (!user.systemAdmin && roleIn(user, t) !== 'manager') return FORBIDDEN;
        const i = fx.uploads.findIndex((u) => u.tenant === t && u.id === s('ID'));
        if (i < 0) return INVALID;
        fx.uploads.splice(i, 1);
      };
    case 'standalone-stop':
    case 'standalone-start':
    case 'standalone-restart':
    case 'standalone-remove':
    case 'standalone-pin':
    case 'standalone-extend':
      return () => saApply(user, action, expected, p);
    default:
      return err(501, 'unsupported', `목업이 아직 모르는 action: ${action}`);
  }
}

// ── 라우팅 ──────────────────────────────────────────────

type Handler = (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse | Promise<RawResponse>;
const routes: [string, RegExp, Handler][] = [];
const on = (method: string, pattern: string, h: Handler) => routes.push([method, new RegExp('^' + pattern.replace(/:([a-z]+)/g, '([^/]+)') + '$'), h]);

function sessionView(s: MockSession, u: User): D.DSession {
  return {
    user: { id: u.id, username: u.username, revision: u.revision, systemAdmin: u.systemAdmin },
    tenants: visibleTenants(u)
      .filter((t) => !fx.retiring[t])
      .map((t) => ({ id: t, revision: fx.tenantRev[t] ?? 1, role: roleIn(u, t) ?? 'manager' })),
    expiresAt: s.expiresAt,
    method: s.method,
    rootRevision: ROOT_REVISION,
  };
}
function startSession(u: User, method: MockSession['method']): RawResponse {
  const s: MockSession = { user: u.id, method, expiresAt: new Date(Date.now() + 3600_000).toISOString() };
  saveSession(s);
  return ok(sessionView(s, u));
}
const TICKET_SEC = 30;

// 인증
on('GET', '/auth/session', () => {
  const { session, user } = requireSession();
  return ok(sessionView(session, user));
});
// 세션 없이 읽는다 (#114). 키 로그인이 꺼져 있으면 key/* 가 403 key-login-disabled
on('GET', '/auth/methods', () => ok({ credential: true, key: fx.webState.settings.allowKeyLogin !== false }));
on('POST', '/auth/credential/challenge', (_m, body) => {
  const u = fx.users.find((x) => x.username === body.username);
  const id = randomUUID();
  const deadline = Date.now() + TICKET_SEC * 1000;
  // 없는 사용자도 ticket은 준다(사용자 존재 여부를 흘리지 않는다).
  tickets.set(id, { user: u?.id ?? '', kind: 'credential', method: String(body.method ?? 'password'), deadline });
  return ok({ ticketId: id, deadline: new Date(deadline).toISOString() });
});
on('POST', '/auth/credential/login', (_m, body) => {
  const t = tickets.get(String(body.ticketId));
  tickets.delete(String(body.ticketId));
  if (!t || t.kind !== 'credential' || t.deadline < Date.now()) return err(401, 'ticket-expired', '로그인 확인 시간이 지났습니다. 다시 시도해 주세요.');
  const u = fx.users.find((x) => x.id === t.user);
  if (!u || !u.enabled || !u.password || u.password !== body.secret) return err(403, 'denied', '인증에 실패했습니다. 사용자 이름과 비밀번호를 확인해 주세요.');
  return startSession(u, t.method === 'token' ? 'token' : 'password');
});
on('POST', '/auth/key/challenge', (_m, body) => {
  if (fx.webState.settings.allowKeyLogin === false) return err(403, 'key-login-disabled', 'private-key login is turned off');
  const username = String(body.username ?? '');
  const publicKey = String(body.publicKey ?? '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(publicKey)) return err(400, 'bad-request', '공개키는 hex 64자여야 합니다.');
  const u = fx.users.find((x) => x.username === username);
  const id = randomUUID();
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const deadline = Math.floor(Date.now() / 1000) + TICKET_SEC;
  const ticket: D.DTicket = { schema: 1, user: u?.id ?? '', username, userKey: publicKey, nonce: hex(nonce), issuer: fx.members[0].key, issuedAt: fx.nowSec(), deadline, authMethod: 'private-key' };
  const ticketBytes = new TextEncoder().encode('sfc-ticket-1\0' + JSON.stringify(ticket));
  const proof = new TextEncoder().encode('sfc-user-key-proof-1\0' + JSON.stringify({ ticket: hex(nonce), userKey: publicKey }));
  tickets.set(id, { user: u?.id ?? '', kind: 'key', publicKey, proof, deadline: deadline * 1000 });
  const reply: D.DKeyChallenge = { ticketId: id, ticket, ticketBytes: b64(ticketBytes), proof: b64(proof), deadline: new Date(deadline * 1000).toISOString() };
  return ok(reply);
});
on('POST', '/auth/key/login', async (_m, body) => {
  if (fx.webState.settings.allowKeyLogin === false) return err(403, 'key-login-disabled', 'private-key login is turned off');
  const t = tickets.get(String(body.ticketId));
  tickets.delete(String(body.ticketId));
  if (!t || t.kind !== 'key' || !t.proof || t.deadline < Date.now()) return err(401, 'ticket-expired', '로그인 확인 시간이 지났습니다. 다시 시도해 주세요.');
  const u = fx.users.find((x) => x.id === t.user);
  const reg = loadKeys().keys.find((k) => k.user === t.user && k.publicKey === t.publicKey && k.enabled);
  if (!reg || !u || !u.enabled) return err(403, 'denied', '이 키는 이 계정에 등록되지 않았거나 꺼져 있습니다.');
  try {
    if (!ed25519.verify(fromHex(String(body.signature ?? '')), t.proof, fromHex(t.publicKey!))) return err(403, 'denied', '서명이 맞지 않습니다.');
  } catch {
    return err(400, 'bad-request', '서명을 확인하지 못했습니다.');
  }
  // R02(데몬 #353): 세션은 아직 승인 전이다. 같은 키로 승인 바이트를 서명해 key/approve로 보내야 쿠키가 나온다.
  const sessionDigest = hex(crypto.getRandomValues(new Uint8Array(32)));
  const approval = new TextEncoder().encode('sfc-user-session-approval-1\0' + JSON.stringify({ Schema: 1, PublicKey: t.publicKey, Session: sessionDigest }));
  const id = randomUUID();
  const deadline = Date.now() + TICKET_SEC * 1000;
  tickets.set(id, { user: u.id, kind: 'approve', publicKey: t.publicKey, proof: approval, deadline });
  return ok({ approve: true, ticketId: id, sessionDigest, approval: b64(approval), deadline: new Date(deadline).toISOString() });
});
on('POST', '/auth/key/approve', async (_m, body) => {
  if (fx.webState.settings.allowKeyLogin === false) return err(403, 'key-login-disabled', 'private-key login is turned off');
  const t = tickets.get(String(body.ticketId));
  tickets.delete(String(body.ticketId));
  if (!t || t.kind !== 'approve' || !t.proof || t.deadline < Date.now()) return err(401, 'ticket-expired', '로그인 확인 시간이 지났습니다. 다시 시도해 주세요.');
  const u = fx.users.find((x) => x.id === t.user);
  if (!u || !u.enabled) return err(403, 'denied', '이 계정으로 들어갈 수 없습니다.');
  try {
    if (!ed25519.verify(fromHex(String(body.signature ?? '')), t.proof, fromHex(t.publicKey!))) return err(403, 'denied', '다른 키로 서명했습니다.');
  } catch {
    return err(400, 'bad-request', '서명을 확인하지 못했습니다.');
  }
  return startSession(u, 'private-key');
});
on('POST', '/auth/logout', () => {
  saveSession(null);
  return ok(null, 204);
});

// 내 계정
on('GET', '/me/credentials', () => {
  const { user } = requireSession();
  const rec: D.DOwnCredentials = { id: user.id, username: user.username, revision: user.revision, enabled: user.enabled, systemAdmin: user.systemAdmin, credentials: credentialsOf(user), accountRevision: accountRevision(user), clusterId: MOCK_CLUSTER_ID };
  return ok(rec);
});
// 계정별 화면 설정 JSON (마지막에 쓴 값이 이긴다)
const prefsBy = new Map<string, Record<string, unknown>>();
// 내 계정 › 열린 세션 · 최근 로그인 (#621). 목업은 지금 세션 + 다른 세션 둘
const otherSessions = new Map<string, { id: string; method: string; credential?: string; at: string; expiresAt: string; client?: string; address: string; source?: string; node: string }[]>();
const othersOf = (u: string) => {
  if (!otherSessions.has(u))
    otherSessions.set(u, [
      { id: 's-ff21a9', method: 'private-key', credential: 'office-firefox', at: new Date(Date.now() - 42 * 60_000).toISOString(), expiresAt: new Date(Date.now() + 18 * 60_000).toISOString(), client: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:132.0) Gecko/20100101 Firefox/132.0', address: '10.0.0.54', source: 'unix-uid:0', node: 'node-b' },
      { id: 's-cli77e', method: 'token', credential: 'tok-ci-deploy', at: new Date(Date.now() - 5 * 60_000).toISOString(), expiresAt: new Date(Date.now() + 55 * 60_000).toISOString(), address: '203.0.113.77', source: '203.0.113.77:51234', node: 'node-a' },
    ]);
  return otherSessions.get(u)!;
};
on('GET', '/me/sessions', () => {
  const { session, user } = requireSession();
  const cur = { id: 's-current', current: true, method: session.method === 'key' ? 'private-key' : session.method, at: new Date(Date.parse(session.expiresAt) - 3600_000).toISOString(), expiresAt: session.expiresAt, client: navigator.userAgent, address: '192.0.2.20', source: 'unix-uid:0', node: 'node-a' };
  return ok({ items: [cur, ...othersOf(user.id)], missing: [] });
});
on('DELETE', '/me/sessions/:id', (m, body) => {
  const { user } = requireSession();
  if (m[0] === 's-current') return invalid('id: 지금 세션은 로그아웃으로 끝냅니다');
  const list = othersOf(user.id);
  if (!list.some((x) => x.id === m[0])) return err(404, 'not-found', '그 세션이 없습니다.');
  return submit(user, { ...body, target: `session/${m[0]}` }, 'revoke-session', () => {
    otherSessions.set(user.id, othersOf(user.id).filter((x) => x.id !== m[0]));
  });
});
on('GET', '/me/logins', (_m, _b, query) => {
  requireSession();
  const t = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
  const all = [
    { at: t(5), count: 1, ok: true, method: 'token', credential: 'tok-ci-deploy', session: 's-cli77e', address: '203.0.113.77', source: '203.0.113.77:51234', node: 'node-a' },
    { at: t(31), lastAt: t(30), count: 7, ok: false, reason: 'throttled', method: 'password', credential: 'password', address: '198.51.100.9', source: 'unix-uid:0', node: 'node-a' },
    { at: t(42), count: 1, ok: true, method: 'private-key', credential: 'office-firefox', client: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:132.0) Gecko/20100101 Firefox/132.0', address: '10.0.0.54', source: 'unix-uid:0', node: 'node-b' },
    { at: t(60 * 26), count: 1, ok: true, method: 'password', credential: 'password', client: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 Safari/537.36', address: '192.0.2.20', source: 'unix-uid:0', node: 'node-a' },
  ];
  const after = query.get('after');
  return ok(after ? { items: [], missing: [] } : { items: all, next: 'p2', missing: ['node-c'], budgetLeft: 4, budgetMax: 5 });
});
// 클러스터 앱 경로 (PR #614): 시스템 관리자만. route 파일은 name: cluster-app/web + x-sfc.ingress만
const webRoutes = {
  revision: 1,
  removed: false,
  // yaml-formats.md 3.1: x-sfc.ingress는 route 목록, 항목마다 node
  file: `name: cluster-app/web\nx-sfc:\n  ingress:\n    - {node: node-a, host: sfc.example.com, prefix: /, gateway: local}\n`,
};
const webRoutesView = () => {
  const d = YAML.parse(webRoutes.file) as { 'x-sfc'?: { ingress?: Record<string, unknown>[] } };
  const ing = d['x-sfc']?.ingress ?? [];
  // #910: 모든 route가 같은 서버라 node는 위에 하나, 이름 없는 route는 route-N, listeners는 비어 있다
  return { app: 'web', revision: webRoutes.revision, removed: webRoutes.removed, node: ing[0]?.node, listeners: [], routes: ing.map((r, i) => ({ id: r.id ?? `route-${i + 1}`, host: r.host, prefix: r.prefix ?? '/', gateway: r.gateway ?? 'external' })), file: webRoutes.file };
};
on('GET', '/cluster-apps/:a/routes', (m) => {
  requireAdmin(requireSession().user);
  if (m[0] !== 'web') return err(404, 'not-found', '경로를 받는 클러스터 앱이 아닙니다.');
  return ok(webRoutesView());
});
on('PUT', '/cluster-apps/:a/routes', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  if (m[0] !== 'web') return err(404, 'not-found', '경로를 받는 클러스터 앱이 아닙니다.');
  const file = String(body.file ?? '');
  let d: Record<string, unknown>;
  try {
    d = YAML.parse(file) as Record<string, unknown>;
  } catch {
    return invalid('file: YAML을 읽지 못했습니다');
  }
  if (d?.name !== 'cluster-app/web') return invalid('file: name은 cluster-app/web이어야 합니다');
  if (Object.keys(d).some((k) => k !== 'name' && k !== 'x-sfc')) return invalid('file: x-sfc.ingress만 받습니다');
  const ing = (d['x-sfc'] as Record<string, unknown> | undefined)?.ingress;
  if (ing !== undefined && !Array.isArray(ing)) return invalid('file: x-sfc.ingress는 route 목록이어야 합니다');
  const routes = (ing ?? []) as Record<string, unknown>[];
  if (routes.some((r) => r && ('service' in r || 'port' in r || 'network' in r || 'health' in r))) return invalid('file: 클러스터 앱 경로에는 backend를 적지 않습니다');
  const listMsg = ing === undefined ? '' : ingressListProblem(ing, 'file: x-sfc.ingress', ['id', 'node', 'host', 'prefix', 'gateway', 'balance']);
  if (listMsg) return invalid(listMsg);
  const expected = Number(body.expected ?? webRoutes.revision);
  return submit(user, { ...body, target: 'cluster-app/web' }, 'put-cluster-app-route', () => {
    if (expected !== webRoutes.revision) return CAS;
    webRoutes.file = file;
    webRoutes.revision++;
    webRoutes.removed = false;
  });
});
on('GET', '/prefs', () => ok({ prefs: prefsBy.get(requireSession().user.username) ?? {} }));
on('PUT', '/prefs', (_m, body) => {
  const { user } = requireSession();
  const p = (body.prefs ?? {}) as Record<string, unknown>;
  if (JSON.stringify(p).length > 64 << 10) return invalid('prefs: at most 64 KiB');
  prefsBy.set(user.username, p);
  return ok({ prefs: p });
});

// 대시보드 · 서버
function nodesFor(u: User, tenant: string | null): string[] {
  if (u.systemAdmin && !tenant) return fx.members.map((m) => m.id);
  const ts = tenant ? [tenant] : visibleTenants(u);
  return [...new Set(ts.flatMap((t) => fx.tenantNodes[t] ?? []))];
}
on('GET', '/dashboard', (_m, _b, query) => {
  const { user } = requireSession();
  const tenant = query.get('tenant');
  if (tenant) requireTenant(user, tenant);
  const nodes = new Set(nodesFor(user, tenant));
  const ts = tenant ? [tenant] : visibleTenants(user);
  const d: D.DDashboard = { nodes: fx.summaries.filter((s) => nodes.has(s.node)).map((s) => tenantSummary(s, tenant)), apps: fx.apps.filter((a) => ts.includes(a.tenant)), asOf: nowIso() };
  return ok(d);
});
on('GET', '/nodes', () => {
  const { user } = requireSession();
  requireAdmin(user);
  const voters = fx.members.filter((m) => m.voter).length;
  const p: D.DMembersPage = { ...page(fx.members, 31), voters, quorum: Math.floor(voters / 2) + 1, runtimeRevision: 31, operationEpoch: 1, configurationIndex: fx.raft.configurationIndex, ledgerEpoch: ledgerState.epoch, ledgerRevision: ledgerState.revision };
  return ok(p);
});
// 새 배치 제외·이미지 캐시 정리
const cordonRoute = (on: boolean) => (m: string[], body: Record<string, unknown>) => {
  const { user } = requireSession();
  requireAdmin(user);
  const n = fx.members.find((x) => x.id === m[0]);
  if (!n) return err(404, 'not-found', 'no such node');
  if (!!n.cordoned === on) return err(409, 'unchanged', on ? 'already cordoned' : 'not cordoned');
  const reason = String(body.reason ?? '');
  if (!on && body.reason !== undefined) return invalid('reason: cordon only');
  if ([...reason].length > 256) return invalid('reason: at most 256 characters');
  const sch = n.scheduling ?? { enabled: false, revision: 0 };
  const expected = Number(body.expected ?? 0) || sch.revision;
  return submit(user, { ...body, target: n.id }, on ? 'cordon-node' : 'uncordon-node', () => {
    if (expected !== sch.revision) return CAS;
    const by = on ? user.username : undefined;
    const at = on ? new Date().toISOString() : undefined;
    Object.assign(n, { cordoned: on || undefined, cordonReason: on ? reason || undefined : undefined, cordonedBy: by, cordonedAt: at, scheduling: { enabled: on, revision: sch.revision + 1, cordonedBy: by, cordonedAt: at } });
  });
};
// 격리·복귀 (#133). 이미 그 상태면 409 unchanged
const isolateRoute = (iso: boolean) => (m: string[], body: Record<string, unknown>) => {
  const { user } = requireSession();
  requireAdmin(user);
  const extra = Object.keys(body).filter((k) => !['opId', 'operation', 'epoch', 'expected'].includes(k));
  if (extra.length) return err(400, 'bad-request', `unknown field ${extra[0]}`);
  const n = fx.members.find((x) => x.id === m[0]);
  if (!n || n.phase === 'removed') return err(n ? 409 : 404, n ? 'unchanged' : 'not-found', 'no such node');
  if ((n.phase === 'isolated') === iso) return err(409, 'unchanged', iso ? 'already isolated' : 'not isolated');
  const expected = Number(body.expected ?? 0) || n.revision;
  return submit(user, { ...body, target: n.id }, iso ? 'isolate-node' : 'restore-node', () => {
    if (expected !== n.revision) return CAS;
    n.phase = iso ? 'isolated' : 'active';
    n.admitsWork = !iso;
    n.revision++;
    const sum = fx.summaries.find((x) => x.node === n.id);
    if (sum) sum.status = iso ? 'isolated' : 'ready';
  });
};
on('POST', '/nodes/:n/isolate', isolateRoute(true));
on('POST', '/nodes/:n/restore', isolateRoute(false));
// 서버 제거 미리 보기
const removeBlockers = (n: D.DMember) => {
  const voters = fx.members.filter((x) => x.voter).length;
  const out: { code: string; detail?: string }[] = [];
  if (n.voter && voters <= 1) out.push({ code: 'LAST_VOTER' });
  else if (n.voter && voters - 1 < Math.floor(voters / 2) + 1) out.push({ code: 'QUORUM_LOSS' });
  const vols = fx.volumes.filter((v) => v.node === n.id);
  if (vols.length) out.push({ code: 'FIXED_VOLUME_PRESENT', detail: vols.map((v) => `${v.tenant}/${v.name}`).join(', ') });
  return out;
};
const planTask = (t: (typeof fx.tasks)[number], extra: Partial<D.DNodePlanTask> = {}): D.DNodePlanTask => ({ tenant: t.tenant, app: t.app, service: t.service, task: `${t.app}-${t.service}-${t.instance}`, node: t.node, generation: 1, revision: 1, movable: true, ...extra });
const removePlan = (n: D.DMember) => {
  const voters = fx.members.filter((x) => x.voter).length;
  const after = n.voter ? voters - 1 : voters;
  const blockers = removeBlockers(n);
  return {
    node: n.id,
    epoch: 1,
    expected: n.revision,
    removable: !blockers.length,
    blockers,
    votersBefore: voters,
    votersAfter: after,
    quorumAfter: Math.floor(after / 2) + 1,
    faultToleranceAfter: Math.max(0, Math.floor((after - 1) / 2)),
    tasks: fx.tasks.filter((t) => t.node === n.id).map((t) => planTask(t)),
    storage: [],
    volumes: fx.volumes.filter((v) => v.node === n.id).map((v) => ({ tenant: v.tenant, id: v.name, fixed: true, retained: false, generation: 1 })),
    activity: { resources: 0, flows: 0, writers: 0, leases: 0, cdJobs: 0 },
    nativeClosed: false,
  };
};
on('GET', '/nodes/:n/remove-plan', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const n = fx.members.find((x) => x.id === m[0]);
  if (!n) return err(404, 'not-found', 'no such node');
  return ok(removePlan(n));
});
// 서버 고급 동작 (REQ-51, 데몬 #335). plan은 상태에서 만든 64 hex, operation은 계획이 정하고 웹이 그대로 돌려보낸다
const hex64 = (key: string) => {
  let h = 0;
  for (const c of key) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h.toString(16).padStart(8, '0').repeat(8);
};
const memberOr404 = (id: string) => fx.members.find((x) => x.id === id);
const opName = (kind: string, q?: URLSearchParams) => q?.get('operation') || `${kind}-${randHex(4)}`;
const drains = new Map<string, D.DNodeDrainStatus>();
const drainPlan = (n: D.DMember, operation: string): D.DNodeDrainPlan => {
  const others = fx.members.filter((x) => x.id !== n.id && x.phase === 'active' && !x.cordoned).map((x) => x.id);
  const hasFixed = fx.volumes.some((v) => v.node === n.id);
  const tasks = fx.tasks
    .filter((t) => t.node === n.id)
    .map((t, i) => {
      const reason = hasFixed && /mysql|db/.test(`${t.app}-${t.service}`) ? 'FIXED_VOLUME' : !others.length ? 'NO_TARGET' : undefined;
      return planTask(t, reason ? { movable: false, reason } : { target: others[i % others.length] });
    });
  const apps = [...new Set(tasks.filter((t) => t.movable).map((t) => `${t.tenant}/${t.app}`))];
  const jobs = apps.map((k) => {
    const [tenant, app] = k.split('/');
    const ts = tasks.filter((t) => t.movable && t.tenant === tenant && t.app === app);
    return { tenant, app, operation: `${operation}-${app}`, target: ts[0].target!, services: [...new Set(ts.map((t) => t.service))], tasks: ts.length, moveVolume: false };
  });
  return { node: n.id, operation, expected: n.revision, plan: hex64(n.id + n.revision + operation + tasks.map((t) => t.task).join()), blockers: [], tasks, jobs };
};
const voterPlan = (n: D.DMember) => {
  const voters = fx.members.filter((x) => x.voter).length;
  const after = n.voter ? voters - 1 : voters;
  const quorumBefore = Math.floor(voters / 2) + 1;
  const code = !n.voter ? 'NOT_VOTER' : voters <= 1 ? 'LAST_VOTER' : after < quorumBefore ? 'QUORUM_LOSS' : undefined;
  const quorumAfter = Math.floor(after / 2) + 1;
  const tol = Math.max(0, Math.floor((after - 1) / 2));
  return { node: n.id, epoch: 1, expected: n.revision, demotable: !code, ...(code ? { code } : {}), blockers: code ? [{ code }] : [], votersBefore: voters, votersAfter: after, quorumAfter, faultToleranceAfter: tol, quorum: quorumAfter, tolerates: tol };
};
const forcePlan = (n: D.DMember, operation: string) => {
  const base = removePlan(n);
  const responding = n.phase === 'active';
  const code = responding ? 'NODE_RESPONDING' : undefined;
  const now = new Date().toISOString();
  return { ...base, blockers: code ? [{ code }] : [], operation, forceable: !code, ...(code ? { code } : {}), plan: hex64(n.id + n.revision + operation + 'force'), probe: { responding, startedAt: now, finishedAt: now } };
};
const advanced = (path: string, h: (n: D.DMember, user: User, body: Record<string, unknown>, q: URLSearchParams) => RawResponse, method: 'GET' | 'POST' = 'POST') =>
  on(method, `/nodes/:n/${path}`, (m, body, q) => {
    const { user } = requireSession();
    requireAdmin(user);
    const n = memberOr404(m[0]);
    if (!n) return err(404, 'not-found', 'no such server');
    return h(n, user, body ?? {}, q);
  });
advanced('drain-plan', (n, _u, _b, q) => ok(drainPlan(n, opName('drain', q))), 'GET');
advanced('drain-status', (n, _u, _b, q) => {
  const op = q.get('operation');
  const d = op ? drains.get(`${n.id}/${op}`) : [...drains.values()].reverse().find((x) => x.node === n.id);
  return d ? ok(d) : err(404, 'not-found', 'no such drain operation');
}, 'GET');
advanced('drain', (n, user, body) => {
  if (!body.operation) return invalid('operation: the operation from the drain plan');
  const p = drainPlan(n, String(body.operation));
  if (!/^[0-9a-f]{64}$/.test(String(body.plan ?? ''))) return invalid('plan: the plan digest as shown (64 hex)');
  if (body.plan !== p.plan) return err(409, 'plan-changed', 'the drain plan changed; read the plan again');
  const tasks = p.tasks ?? [];
  return submit(user, { ...body, target: n.id }, 'drain-node', () => {
    if (p.expected !== n.revision) return CAS;
    const blocked = tasks.filter((t) => !t.movable).length;
    if (blocked && !body.leaveBlocked) return INVALID;
    Object.assign(n, { cordoned: true, cordonReason: 'drain', cordonedBy: user.username, cordonedAt: new Date().toISOString(), scheduling: { enabled: true, revision: (n.scheduling?.revision ?? 0) + 1, cordonedBy: user.username, cordonedAt: new Date().toISOString() }, revision: n.revision + 1, drain: { operation: p.operation, state: 'Running' } });
    const st: D.DNodeDrainStatus = { node: n.id, operation: p.operation, state: 'Running', total: tasks.length, moved: 0, blocked, jobs: (p.jobs ?? []).map((j) => ({ tenant: j.tenant, app: j.app, operation: j.operation, state: 'running', total: j.tasks, moved: 0 })) };
    drains.set(`${n.id}/${p.operation}`, st);
    // 몇 초 뒤 옮김이 끝난다
    setTimeout(() => {
      for (const t of fx.tasks.filter((x) => x.node === n.id)) {
        const pt = tasks.find((y) => y.task === `${t.app}-${t.service}-${t.instance}`);
        if (pt?.target) t.node = pt.target;
      }
      Object.assign(st, { state: blocked ? 'Partial' : 'Succeeded', moved: tasks.length - blocked, jobs: (st.jobs ?? []).map((j) => ({ ...j, state: 'done', moved: j.total })) });
      if (n.drain?.operation === p.operation) n.drain = { operation: p.operation, state: blocked ? 'Partial' : 'Succeeded' };
    }, 4000);
  });
});
advanced('voter-plan', (n) => ok(voterPlan(n)), 'GET');
advanced('demote', (n, user, body) => {
  const expected = Number(body.expected ?? 0) || n.revision;
  return submit(user, { ...body, target: n.id }, 'demote-node', () => {
    if (expected !== n.revision) return CAS;
    const p = voterPlan(n);
    if (p.code) return { code: 3, errorCode: p.code };
    Object.assign(n, { voter: false, revision: n.revision + 1 });
  });
});
advanced('rotate-identity', (n, user, body) => {
  // sfcd처럼 멤버 항목 revision(joinRevision)으로 확인한다
  const expected = Number(body.expected ?? 0) || (n.joinRevision ?? 0);
  return submit(user, { ...body, target: n.id }, 'rotate-node-identity', () => {
    if (expected !== (n.joinRevision ?? 0)) return CAS;
    if (n.phase !== 'active') return { code: 3, errorCode: 'NODE_UNREACHABLE' };
    Object.assign(n, { key: randHex(32), identity: { operation: `rotate-${n.id}-${randHex(3)}`, phase: 'Installed' }, identityRotatedAt: new Date().toISOString(), joinRevision: (n.joinRevision ?? 0) + 1, revision: n.revision + 1 });
  });
});
advanced('force-remove-plan', (n, _u, _b, q) => ok(forcePlan(n, opName('force', q))), 'GET');
advanced('force-remove', (n, user, body) => {
  if (!body.operation) return invalid('operation: the operation from the force-remove plan');
  const p = forcePlan(n, String(body.operation));
  if (body.plan !== p.plan) return err(409, 'plan-changed', 'the plan changed; read the plan again');
  if (!p.forceable) return err(409, 'not-forceable', 'the server is responding');
  return submit(user, { ...body, target: n.id }, 'force-remove-node', () => {
    fx.members.splice(fx.members.indexOf(n), 1);
  });
});
// 서버 제거 (remove-node, #128). 거절 이유는 op 결과로 온다
on('POST', '/nodes/:n/remove', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const extra = Object.keys(body).filter((k) => !['opId', 'operation', 'epoch', 'expected'].includes(k));
  if (extra.length) return err(400, 'bad-request', `unknown field ${extra[0]}`);
  const n = fx.members.find((x) => x.id === m[0]);
  if (!n) return err(404, 'not-found', 'no such node');
  const expected = Number(body.expected ?? 0) || n.revision;
  return submit(user, { ...body, target: n.id }, 'remove-node', () => {
    if (expected !== n.revision) return CAS;
    const b = removeBlockers(n);
    if (b.length) return { code: 2, errorCode: b[0].code };
    fx.members.splice(fx.members.indexOf(n), 1);
  });
});
on('POST', '/nodes/:n/cordon', cordonRoute(true));
on('POST', '/nodes/:n/uncordon', cordonRoute(false));
type PruneImage = NonNullable<D.DNodeImagePrunePlan['images']>[number];
const PMiB = 1024 * 1024;
/** 미사용 이미지. 한 번에 8개까지 정리하고 나머지는 remaining (데몬 #384) */
const nodeImages = new Map<string, PruneImage[]>([
  ['node-a', [
    { ref: 'registry.shop.internal/shop/web:v4', aliases: ['registry.shop.internal/shop/web:v4', 'registry.shop.internal/shop/web:stable'], digest: 'sha256:' + 'a4'.repeat(32), bytes: 182 * PMiB },
    { ref: 'docker.io/library/php:8.2-fpm', aliases: ['docker.io/library/php:8.2-fpm'], digest: 'sha256:' + 'b2'.repeat(32), bytes: 471 * PMiB },
    { ref: '', aliases: [], digest: 'sha256:' + 'c7'.repeat(32), bytes: 64 * PMiB },
    ...Array.from({ length: 7 }, (_, i): PruneImage => ({ ref: `registry.shop.internal/shop/worker:v${i + 1}`, aliases: [`registry.shop.internal/shop/worker:v${i + 1}`], digest: 'sha256:' + (i + 10).toString(16).padStart(2, '0').repeat(32), bytes: (90 + i * 7) * PMiB })),
  ]],
]);
const IN_USE = 5;
const prunePlan = (node: string): D.DNodeImagePrunePlan => {
  const all = nodeImages.get(node) ?? [];
  const images = all.slice(0, 8);
  const key = images.map((x) => x.digest).join(',');
  let h = 0;
  for (const c of node + key) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return { node, images, bytes: images.reduce((a, x) => a + x.bytes, 0), plan: h.toString(16).padStart(8, '0').repeat(8), remaining: all.length - images.length, inUse: IN_USE, total: all.length + IN_USE };
};
const prunes = new Map<string, D.DImagePrune & { started: number }>();
on('GET', '/nodes/:n/image-prune-plan', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  if (!fx.members.some((x) => x.id === m[0])) return err(404, 'not-found', 'no such node');
  return ok(prunePlan(m[0]));
});
on('POST', '/nodes/:n/image-prune', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  if (!/^[0-9a-f]{64}$/.test(String(body.plan ?? ''))) return invalid('plan: the plan digest as shown (64 hex)');
  const p = prunePlan(m[0]);
  if (body.plan !== p.plan) return err(409, 'plan-changed', 'the image list changed; read the plan again');
  return submit(user, { ...body, target: m[0] }, 'prune-node-images', () => {
    const ids = (p.images ?? []).map((x) => x.digest);
    nodeImages.set(m[0], (nodeImages.get(m[0]) ?? []).filter((x) => !ids.includes(x.digest)));
    const operation = `op-${String(body.opId)}`;
    prunes.set(operation, { operation, user: user.id, state: 'queued', node: m[0], at: fx.nowSec(), revision: 1, images: ids, parts: [], started: Date.now() });
  });
});
// 접수 뒤 1초마다 한 장씩 지운다. 마지막 한 장은 이미 없음
on('GET', '/image-prunes/:op', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const r = prunes.get(m[0]);
  if (!r) return err(404, 'not-found', 'no such image prune');
  const ids = r.images ?? [];
  const n = Math.min(ids.length, Math.floor((Date.now() - r.started) / 1000));
  const parts = ids.slice(0, n).map((digest, i) => ({ digest, state: i === ids.length - 1 ? 'already-absent' : 'removed', at: fx.nowSec() }));
  const { started: _s, ...out } = r;
  return ok({ ...out, parts, state: n === 0 ? 'queued' : n < ids.length ? 'running' : 'done' });
});
// 서버 추가(UI-13). 목업은 초대 파일을 받으면 가입(learner), 다시 읽을 때 설치 확인(ready)으로 넘긴다
on('POST', '/nodes', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const id = String(body.id ?? '');
  const endpoint = String(body.endpoint ?? '');
  const key = String(body.publicKey ?? '');
  const joinId = String(body.joinId ?? '');
  const name = /^[a-z][a-z0-9-]{0,62}$/;
  if (!name.test(id) || !name.test(joinId) || joinId === 'genesis' || !/^[a-z0-9.-]+:\d{1,5}$/i.test(endpoint) || !/^[0-9a-f]{64}$/.test(key)) return invalid('id, endpoint, publicKey (64 hex) and joinId');
  if (fx.members.some((x) => x.id === id || x.key === key || x.endpoint === endpoint || (x.joinId ?? x.joinID) === joinId)) return err(409, 'exists', 'that node, key, endpoint or join ID already exists');
  return submit(user, { ...body, target: `node/${id}` }, 'invite-node', () => {
    fx.members.push({ id, key, endpoint, joinId, revision: 1, joinRevision: 1, phase: 'pending', voter: false, pendingOperation: `invite-${id}`, join: 'invited' });
  });
});
const invitable = (id: string) => fx.members.find((x) => x.id === id && ['invited', 'learner', 'ready'].includes(x.join ?? ''));
on('GET', '/nodes/:n/invitation/summary', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const n = invitable(m[0]);
  if (!n) return err(403, 'forbidden', 'no invitation for this node');
  if (n.join === 'learner') n.join = 'ready';
  const src = fx.members[0];
  return ok({ node: n.id, cluster: 'ef4b5ee492edeb0049e937e62cbfe111d2fcc9b95f96e76b13ed26280cfb01a2', joinId: n.joinId ?? n.joinID ?? '', approvalRevision: n.revision, source: { id: src.id, key: src.key, endpoint: src.endpoint }, target: { id: n.id, key: n.key, endpoint: n.endpoint } });
});
on('GET', '/nodes/:n/invitation', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const n = invitable(m[0]);
  if (!n) return err(403, 'forbidden', 'no invitation for this node');
  if (n.join === 'invited') n.join = 'learner';
  return ok({ version: 1, node: n.id, joinId: n.joinId ?? n.joinID, endpoint: n.endpoint, signature: '목업-서명' });
});
on('POST', '/nodes/:n/promote', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const n = fx.members.find((x) => x.id === m[0]);
  if (!n) return err(404, 'not-found', 'no such node');
  if (n.join !== 'ready') return err(409, 'not-ready', 'the node has not acknowledged its install yet');
  const expected = Number(body.expected ?? 0) || (n.joinRevision ?? 0);
  return submit(user, { ...body, target: `node/${n.id}` }, 'promote-node', () => {
    if (expected !== (n.joinRevision ?? 0)) return CAS;
    Object.assign(n, { join: 'active', phase: 'active', voter: true, admitsWork: true, scheduling: { enabled: false, revision: 1 }, pendingOperation: undefined, joinRevision: (n.joinRevision ?? 0) + 1, revision: n.revision + 1 });
  });
});
/** 데몬 #373: 작업 공간 보기는 role·cpu·총량 없이 containers와 memUsed만 */
function tenantSummary(s: D.DNodeSummary, tenant: string | null): D.DNodeSummary {
  if (!tenant) return s;
  return { node: s.node, build: s.build, status: s.status, state: s.state, ready: s.ready, stale: s.stale, memUsed: s.memUsed, containers: s.containers, observedAt: s.observedAt, observeLimitSeconds: s.observeLimitSeconds };
}
on('GET', '/nodes/summary', (_m, _b, query) => {
  const { user } = requireSession();
  const tenant = query.get('tenant');
  const nodes = new Set(nodesFor(user, tenant));
  return ok(page(fx.summaries.filter((s) => nodes.has(s.node)).map((s) => tenantSummary(s, tenant))));
});
on('GET', '/nodes/:id/tasks', (m, _b, query) => {
  const { user } = requireSession();
  const tenant = query.get('tenant');
  if (tenant) requireTenant(user, tenant);
  const ts = tenant ? [tenant] : visibleTenants(user);
  return ok(page(fx.tasks.filter((t) => t.node === m[0] && ts.includes(t.tenant))));
});
on('GET', '/nodes/:id/storage', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(page(fx.storageRoots.filter((r) => r.node === m[0] && !rootGone.has(`${r.node}/${r.id}`)).map(rootView), 8));
});
on('GET', '/storage', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(page(fx.storageRoots.map(rootView), 8));
});
// 저장 경로 바꾸기(UI-14). 데몬이 add/set-node-storage-policy/drain/remove-node-storage payload를 만든다.
const findRoot = (node: string, id: string) => fx.storageRoots.find((r) => r.node === node && r.id === id && !rootGone.has(`${node}/${id}`));
on('POST', '/nodes/:id/storage', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const node = m[0];
  const id = String(body.id ?? '');
  const path = String(body.path ?? '');
  const tenants = [...new Set((body.tenants as string[] | undefined) ?? [])].sort();
  const all = body.allTenants === true;
  const cap = Number(body.capacityBytes ?? 0);
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(id)) return invalid('id: [a-z][a-z0-9-]{0,62}');
  if (!/^\/(?:[^/\0]+\/?)*$/.test(path) || path.includes('/../') || path.endsWith('/..') || path === '/') return invalid('path: a clean absolute path, not /');
  if (!Number.isInteger(cap) || cap < 0 || cap > 2 ** 60) return invalid('capacityBytes: 0 (no limit) or a byte count up to 2^60');
  if (all && tenants.length) return invalid('allTenants and tenants cannot be used together');
  if (tenants.some((t) => !(t in fx.memberships))) return invalid('tenants: unknown workspace');
  return submit(user, { ...body, target: `${node}/${id}` }, 'add-node-storage', () => {
    if (fx.storageRoots.some((r) => r.node === node && (r.id === id || r.path === path))) return INVALID;
    const root: D.DStorageRoot = { node, id, path, tenants, generation: 1, revision: 1, draining: false, allTenants: all, capacityBytes: cap, attested: false };
    fx.storageRoots.push(root);
    // 서버가 경로를 확인하는 데 몇 초 걸리는 것을 흉내 낸다.
    setTimeout(() => (root.attested = true), 6000);
  });
});
on('PATCH', '/nodes/:id/storage/:sid', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const r = findRoot(m[0], m[1]);
  if (!r) return err(404, 'not-found', 'no such storage root');
  const add = [...new Set((body.addTenants as string[] | undefined) ?? [])];
  const remove = [...new Set((body.removeTenants as string[] | undefined) ?? [])];
  const cap = body.capacityBytes === undefined ? undefined : Number(body.capacityBytes);
  const all = body.allTenants === undefined ? undefined : body.allTenants === true;
  if (cap !== undefined && (!Number.isInteger(cap) || cap < 0 || cap > 2 ** 60)) return invalid('capacityBytes: 0 (no limit) or a byte count up to 2^60');
  if (add.length === 0 && remove.length === 0 && cap === undefined && all === undefined) return invalid('nothing to change');
  return submit(user, { ...body, target: `${r.node}/${r.id}` }, 'set-node-storage-policy', () => {
    if (Number(body.expected) !== r.revision || r.draining) return CAS;
    // sfcd nodestorage.ChangePolicy와 같은 규칙: 모든 작업 공간 중에는 목록을 고치지 못하고, 목록으로 돌아올 때는 addTenants로 새로 시작한다
    const wasAll = !!r.allTenants;
    const nowAll = all ?? wasAll;
    if (all !== undefined && all === wasAll) return CAS;
    if (nowAll && (add.length || remove.length)) return CAS;
    if (!nowAll && wasAll && remove.length) return CAS;
    const base = nowAll || wasAll ? [] : r.tenants;
    if (add.some((t) => base.includes(t)) || remove.some((t) => !base.includes(t))) return CAS;
    const limit = cap ?? r.capacityBytes ?? 0;
    const held = fx.volumes.filter((v) => v.node === r.node && v.storage === r.id).reduce((s, v) => s + (v.capacityBytes ?? 0), 0);
    if (limit && held > limit) return CAS;
    const tenants = nowAll ? [] : [...base.filter((t) => !remove.includes(t)), ...add].sort();
    Object.assign(r, { tenants, allTenants: nowAll, capacityBytes: limit, revision: r.revision + 1 });
  });
});
on('POST', '/nodes/:id/storage/:sid/drain', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const r = findRoot(m[0], m[1]);
  if (!r) return err(404, 'not-found', 'no such storage root');
  return submit(user, { ...body, target: `${r.node}/${r.id}` }, 'drain-node-storage', () => {
    if (Number(body.expected) !== r.revision || r.draining) return CAS;
    Object.assign(r, { draining: true, revision: r.revision + 1, closed: rootVolumes(r) === 0 });
  });
});
on('DELETE', '/nodes/:id/storage/:sid', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const r = findRoot(m[0], m[1]);
  if (!r) return err(404, 'not-found', 'no such storage root');
  return submit(user, { ...body, target: `${r.node}/${r.id}` }, 'remove-node-storage', () => {
    if (Number(body.expected) !== r.revision || !r.draining || !r.closed || rootVolumes(r) > 0) return CAS;
    rootGone.add(`${r.node}/${r.id}`);
  });
});
// 원장 교체. 데몬이 rotate-ledger payload {NextEpoch: expected+1}을 만든다.
on('POST', '/ledger/rotate', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const expected = Number(body.expected ?? 0);
  return submit(user, { ...body, target: `epoch ${expected + 1}` }, 'rotate-ledger', () => {
    if (expected !== ledgerState.epoch) return CAS;
    ledgerState.epoch++;
    ledgerState.revision++;
  });
});
// 작업 공간 서버 한도(UI-16). 데몬이 지금 한도의 나머지 필드를 지키며 set-node-quota payload를 만든다.
on('PUT', '/t/:t/limits/:node', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const [t, node] = m;
  const cpus = Number(body.cpus ?? 0);
  const mem = Number(body.memoryBytes ?? 0);
  const top = NODE_LIMIT[node];
  if (!top) return err(422, 'limit-over-node', 'this server has no node-wide limit yet', { max: { cpus: 0, memoryBytes: 0 } });
  if (!(cpus > 0) || !(mem > 0)) return invalid('cpus and memoryBytes must be positive');
  if (cpus > top.cpus || mem > top.memoryBytes) return err(422, 'limit-over-node', 'over the node-wide limit', { max: { cpus: top.cpus, memoryBytes: top.memoryBytes } });
  return submit(user, { ...body, tenant: t, target: `${t}/${node}` }, 'set-node-quota', () => {
    const e = fx.resources.find((x) => x.tenant === t && x.limit?.node === node);
    if ((e?.limit?.revision ?? 0) !== Number(body.expected ?? 0)) return CAS;
    if (e?.limit) Object.assign(e.limit, { cpus, memoryBytes: mem, revision: e.limit.revision + 1 });
    else fx.resources.push({ key: `limit/${t}/${node}`, tenant: t, limit: { node, cpus, memoryBytes: mem, maxContainers: 10, revision: 1 } });
  });
});
on('GET', '/nodes/:id/disks', (m, _b, q) => {
  const { user } = requireSession();
  const tenant = q.get('tenant');
  if (!tenant) {
    requireAdmin(user);
    // #689: 서버 하나를 물으면 첫 페이지에 장치 목록, 행에 그 파일 시스템의 디스크
    const dev = fx.devices[m[0]];
    const where = (mount: string) => dev?.disks?.find((d) => (d.parts ?? []).some((p) => (p.mounts ?? []).includes(mount) || (p.holders ?? []).some((h) => (h.mounts ?? []).includes(mount))));
    const rows = fx.disks.filter((d) => d.node === m[0]).map((d) => {
      const b = where(d.mount);
      return b ? { ...d, blockDevice: b.name, blockClass: b.class } : d;
    });
    return ok({ ...page(rows), ...(dev ? { devices: devicesView(m[0], dev) } : {}) });
  }
  requireTenant(user, tenant);
  // 작업 공간 보기: 시스템·런타임 경로와 장치 이름은 빼고 저장 경로만
  return ok(page(fx.disks.filter((d) => d.node === m[0] && d.purpose === 'storage-root').map((d) => ({ ...d, device: '' }))));
});
// #689 3단계: 디스크 포맷·마운트·마운트 풀기·기록 지우기. 실패도 200 + state failed + code
const diskOps = new Map<string, D.DDiskOp & { key: string; at: number }>();
const DISK_SYSTEM = ['/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/libx32', '/proc', '/root', '/run', '/sbin', '/snap', '/sys', '/tmp', '/usr', '/var/lib/docker', '/var/lib/sfe', '/var/lib/sfc', '/var/lib/containerd', '/var/log', '/var/cache', '/var/tmp'];
const diskPathOk = (p: string) =>
  p.startsWith('/') && p !== '/' && !/\/\/|\/\.\.?(\/|$)|\/$|\s/.test(p) && !DISK_SYSTEM.some((x) => p === x || p.startsWith(x + '/') || x.startsWith(p + '/')) && !['/var', '/var/lib', '/home', '/opt', '/srv', '/mnt', '/media'].includes(p);
/** 저장 경로는 마운트 지점 아래에 있으면 그 파티션 위로 본다 (/ 는 다른 마운트가 없는 경로만) */
function devicesView(node: string, dev: D.DNodeDevices): D.DNodeDevices {
  const roots = fx.storageRoots.filter((r) => r.node === node && !rootGone.has(`${r.node}/${r.id}`));
  const mounts = (dev.disks ?? []).flatMap((d) => (d.parts ?? []).flatMap((p) => p.mounts ?? [])).filter((x) => x !== '/');
  const under = (r: string, m: string) => r === m || r.startsWith(m + '/');
  const on = (m: string) => roots.filter((r) => (m === '/' ? !mounts.some((x) => under(r.path, x)) && !r.path.startsWith('/var/lib/sfc') : under(r.path, m))).map((r) => r.id);
  return {
    ...dev,
    observedAt: Math.floor(Date.now() / 1000) - 2,
    disks: (dev.disks ?? []).map((d) => ({ ...d, parts: (d.parts ?? []).map((p) => ({ ...p, storageRoots: [...new Set([...(p.storageRoots ?? []), ...(p.mounts ?? []).flatMap(on)])] })) })),
    bundles: (dev.bundles ?? []).map(bundleView),
  };
}
/** 묶음 미러 재동기화(목업): 교체한 뒤 20초에 걸쳐 0→100% */
const syncStart = new Map<string, number>();
function bundleView(b: D.DDiskBundle): D.DDiskBundle {
  const t0 = syncStart.get(b.name);
  if (t0 === undefined || b.state !== 'syncing') return b;
  const pc = Math.min(100, Math.floor((Date.now() - t0) / 200));
  if (pc >= 100) {
    syncStart.delete(b.name);
    Object.assign(b, { state: 'ok', syncPercent: 0 });
    b.members?.forEach((m) => (m.state = 'ok'));
    return b;
  }
  return { ...b, syncPercent: pc };
}
const diskOpView = (o: D.DDiskOp & { key: string; at: number }): D.DDiskOp => {
  const { key: _k, at, ...v } = o;
  if (v.action === 'bundle' && v.state === 'running') {
    const t = Date.now() - at;
    if (t < 1000) return { ...v, step: 'members' };
    if (t < 2000) return { ...v, step: 'create' };
    if (t < 4000) return { ...v, step: 'format' };
    if (t < 5000) return { ...v, step: 'mount' };
    Object.assign(o, { state: 'done', step: 'mount', finishedAt: Math.floor(Date.now() / 1000) });
    return diskOpView(o);
  }
  if (v.action === 'prepare-storage' && v.state === 'running') {
    const t = Date.now() - at;
    if (t < 1500) return { ...v, step: 'partition' };
    if (t < 4500) return { ...v, step: 'format' };
    if (t < 5500) return { ...v, step: 'record' };
    Object.assign(o, { state: 'done', step: 'directory', finishedAt: Math.floor(Date.now() / 1000) });
    return diskOpView(o);
  }
  if (v.action !== 'format' || v.state !== 'running') return v;
  const t = Date.now() - at;
  if (t < 1500) return { ...v, step: 'partition' };
  if (t < 4500) return { ...v, step: 'format' };
  o.state = 'done';
  o.step = 'format';
  o.finishedAt = Math.floor(Date.now() / 1000);
  return diskOpView(o);
};
on('POST', '/nodes/:id/disks/:disk/:action', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const [node, name, action] = m;
  const dev = fx.devices[node];
  const opId = String(body.opId ?? '');
  const part = String(body.part ?? '');
  const key = JSON.stringify({ node, name, action, ...body });
  const prev = diskOps.get(opId);
  if (prev) return prev.key === key ? ok(diskOpView(prev)) : ok({ ...diskOpView(prev), state: 'failed', code: 'operation-conflict', error: 'opId is used for another request' });
  const mountPath = body.mountPath === undefined ? undefined : String(body.mountPath);
  const uuid = body.uuid === undefined ? undefined : String(body.uuid);
  if (!opId || !part || !['format', 'mount', 'unmount', 'forget', 'prepare-storage'].includes(action)) return invalid('opId, part and action');
  const subPath = String(body.subPath ?? '');
  if (action === 'prepare-storage' && ((body.format ? !(Number(body.size) > 0 && (body.serial || body.wwn)) || part !== name || !!uuid : !uuid || !!body.label) || (subPath && (subPath.split('/').length > 8 || subPath.split('/').some((x) => !/^[A-Za-z0-9._-]+$/.test(x) || x === '.' || x === '..'))) || (mountPath !== undefined && !diskPathOk(mountPath))))
    return invalid('prepare-storage: format with serial or wwn and size on the whole disk, or uuid; subPath a relative path of plain names');
  if (action === 'format' && !(Number(body.size) > 0 && (body.serial || body.wwn))) return invalid('format: serial or wwn and size');
  if (action === 'mount' && (!uuid || (mountPath !== undefined && !diskPathOk(mountPath)))) return invalid('mount: uuid, mountPath a non-system absolute path');
  if (action === 'forget' && !uuid) return invalid('forget: uuid');
  if (!dev) return err(404, 'not-found', 'no device list for this server');
  const now = Math.floor(Date.now() / 1000);
  const o: D.DDiskOp & { key: string; at: number } = { key, at: Date.now(), operation: opId, node, action: action as D.DDiskOp['action'], user: user.id, disk: name, part, state: 'done', step: action, startedAt: now, finishedAt: now };
  const fail = (code: string, error: string) => (Object.assign(o, { state: 'failed', code, error }), diskOps.set(opId, o), ok(diskOpView(o)));
  dev.recorded ??= [];
  if (action === 'forget') {
    const i = dev.recorded.findIndex((r) => r.uuid === uuid && r.disk === name && r.reason === 'disk-not-found');
    if (i < 0) return fail('not-found', 'no such missing-disk record');
    dev.recorded.splice(i, 1);
    diskOps.set(opId, o);
    return ok(diskOpView(o));
  }
  const d = (dev.disks ?? []).find((x) => x.name === name);
  if (!d) return fail('not-found', 'no such disk');
  if (d.class === 'system' || d.locked) return fail('system-disk', 'the disk holds /');
  const parts = d.parts ?? [];
  const roots = (devicesView(node, dev).disks ?? []).find((x) => x.name === name)?.parts?.flatMap((p) => p.storageRoots ?? []) ?? [];
  if (action === 'prepare-storage') {
    const under = (mp: string) => (subPath ? `${mp}/${subPath}` : mp);
    const mountAt = (pt: D.DBlockPart, path: string) => {
      pt.mounts = [path];
      pt.space = { total: Math.round(pt.size * 0.98), used: Math.round(pt.size * 0.01), available: Math.round(pt.size * 0.92) };
      d.class = 'additional';
      dev.recorded!.push({ uuid: pt.uuid ?? '', path, disk: name, part: pt.name });
    };
    const taken = (path: string) => (dev.disks ?? []).flatMap((x) => (x.parts ?? []).flatMap((y) => y.mounts ?? [])).filter((x) => x !== '/').some((x) => x === path || path.startsWith(x + '/') || x.startsWith(path + '/')) || dev.recorded!.some((r) => r.path === path);
    if (body.format) {
      if (body.size !== d.size || (body.serial ?? '') !== (d.serial ?? '') || (body.wwn ?? '') !== (d.wwn ?? '') || (body.tableId ?? '') !== (d.tableID ?? '')) return fail('changed', 'the device no longer matches');
      if (parts.some((p) => (p.mounts ?? []).length || p.swap || (p.holders ?? []).length || p.busy)) return fail('busy', 'mounted, swap or held');
      const path = mountPath ?? `/var/lib/sfc-disks/${name}1`;
      if (taken(path)) return fail('mount-path', 'the mount point is inside another mount');
      const id = crypto.randomUUID();
      const label = body.label ? String(body.label) : undefined;
      const pn = `${name}1`;
      Object.assign(o, { state: 'running', step: 'partition', part: pn, uuid: id, device: `/dev/${pn}`, label, mountPath: path, rootPath: under(path), finishedAt: undefined });
      diskOps.set(opId, o);
      setTimeout(() => {
        const np: D.DBlockPart = { name: pn, number: 1, size: d.size - 16 * 1024 * 1024, fsType: 'ext4', uuid: id, label };
        Object.assign(d, { table: 'gpt', tableID: crypto.randomUUID(), parts: [np] });
        mountAt(np, path);
      }, 5500);
      return ok(diskOpView(o));
    }
    const p = parts.find((x) => x.uuid === uuid);
    if (!p) return fail('not-found', 'no such part');
    const rec = dev.recorded.find((r) => r.uuid === uuid && !r.reason);
    if ((p.mounts ?? []).length && !rec) return fail('not-managed', 'mounted by the operator');
    let path = rec?.path;
    if (!path) {
      path = mountPath ?? `/var/lib/sfc-disks/${p.name}`;
      if (taken(path)) return fail('mount-path', 'the mount point is inside another mount');
      mountAt(p, path);
    }
    Object.assign(o, { step: 'directory', part: p.name, uuid, device: `/dev/${p.name}`, mountPath: path, rootPath: under(path) });
    diskOps.set(opId, o);
    return ok(diskOpView(o));
  }
  if (action === 'format') {
    if (body.size !== d.size || (body.serial ?? '') !== (d.serial ?? '') || (body.wwn ?? '') !== (d.wwn ?? '') || (body.tableId ?? '') !== (d.tableID ?? '')) return fail('changed', 'the device no longer matches');
    if (roots.length) return fail('storage-root', 'a storage root is on it');
    if (parts.some((p) => (p.mounts ?? []).length || p.swap || (p.holders ?? []).length || p.busy)) return fail('busy', 'mounted, swap or held');
    const whole = part === name;
    if (!whole && !parts.some((p) => p.name === part)) return fail('not-found', 'no such part');
    const id = crypto.randomUUID();
    const label = body.label ? String(body.label) : undefined;
    const pn = whole ? `${name}1` : part;
    const size = whole ? d.size - 16 * 1024 * 1024 : (parts.find((p) => p.name === part)?.size ?? 0);
    Object.assign(o, { state: 'running', step: whole ? 'partition' : 'format', part: pn, uuid: id, device: `/dev/${pn}`, label, finishedAt: undefined });
    diskOps.set(opId, o);
    // 4.5초 뒤 포맷이 끝난 것으로 본다(상태 GET이 done을 돌려준다)
    setTimeout(() => {
      if (whole) Object.assign(d, { table: 'gpt', tableID: crypto.randomUUID(), parts: [{ name: pn, number: 1, size, fsType: 'ext4', uuid: id, label }] });
      else Object.assign(parts.find((p) => p.name === part) ?? {}, { fsType: 'ext4', uuid: id, label });
    }, 4500);
    return ok(diskOpView(o));
  }
  const p = parts.find((x) => x.name === part);
  if (!p) return fail('not-found', 'no such part');
  if (action === 'mount') {
    if (p.uuid !== uuid) return fail('changed', 'the device no longer matches');
    if (p.fsType !== 'ext4') return fail('not-ext4', 'only ext4 is mounted');
    if ((p.mounts ?? []).length || p.swap || (p.holders ?? []).length) return fail('busy', 'already mounted or held');
    const path = mountPath ?? `/var/lib/sfc-disks/${part}`;
    const taken = (dev.disks ?? []).flatMap((x) => (x.parts ?? []).flatMap((y) => y.mounts ?? [])).filter((x) => x !== '/');
    if (taken.some((x) => x === path || path.startsWith(x + '/') || x.startsWith(path + '/')) || dev.recorded.some((r) => r.path === path)) return fail('mount-path', 'the mount point is inside another mount');
    p.mounts = [path];
    p.space = { total: Math.round(p.size * 0.98), used: Math.round(p.size * 0.01), available: Math.round(p.size * 0.92) };
    d.class = 'additional';
    dev.recorded.push({ uuid: p.uuid ?? '', path, disk: name, part });
    Object.assign(o, { step: 'record', uuid: p.uuid, device: `/dev/${part}`, mountPath: path });
    diskOps.set(opId, o);
    return ok(diskOpView(o));
  }
  // unmount
  const rec = dev.recorded.find((r) => r.uuid === p.uuid && !r.reason);
  if (!rec) return fail('not-managed', 'unmount of a mount sfcd did not make');
  if (roots.length) return fail('storage-root', 'a storage root is on it');
  p.mounts = [];
  p.space = undefined;
  if (parts.every((x) => !(x.mounts ?? []).length)) d.class = 'unused';
  dev.recorded.splice(dev.recorded.indexOf(rec), 1);
  Object.assign(o, { step: 'record', uuid: p.uuid, mountPath: rec.path });
  diskOps.set(opId, o);
  return ok(diskOpView(o));
});
// fuse 묶음 (#819): 마운트된 파티션에 조각 파일을 두고 묶는다. 구성원 파티션은 포맷하지 않는다
function fuseBundle(dev: D.DNodeDevices, o: D.DDiskOp & { key: string; at: number }, name: string, body: Record<string, unknown>, members: Record<string, unknown>[], fail: (code: string, error: string) => RawResponse): RawResponse {
  const alloc = String(body.allocation ?? '');
  if (!['reserve', 'grow'].includes(alloc)) return invalid('allocation: reserve or grow');
  const used = new Set((dev.bundles ?? []).flatMap((b) => (b.members ?? []).map((x) => x.part ?? '')));
  const rows: { d: D.DBlockDisk; p: D.DBlockPart; bytes: number; copy: number }[] = [];
  for (const x of members) {
    const d = (dev.disks ?? []).find((y) => y.name === x.disk);
    const p = d?.parts?.find((y) => y.name === x.part);
    const bytes = Number(x.bytes);
    const copy = Number(x.copy);
    if (!d || !p) return fail('not-found', `no part ${String(x.part)}`);
    if (d.class === 'system' || d.locked) return fail('system-disk', 'a part of the system disk cannot be a bundle member');
    if (d.kind === 'bundle' || used.has(p.name)) return fail('busy', `${p.name} is part of a bundle`);
    if (!(p.mounts ?? []).length) return fail('not-mounted', `${p.name} is not mounted`);
    if (p.uuid !== x.uuid) return fail('changed', `the filesystem on ${p.name} is not the one shown`);
    if (!(bytes >= 64 * 2 ** 20)) return invalid('bytes: 64MiB or more');
    if ((body.mode === 'mirror') !== copy > 0) return invalid('copy: 1… for a mirror, none for linear');
    if (alloc === 'reserve' && bytes > (p.space?.available ?? 0)) return fail('too-small', `${p.name} has less room than ${bytes} bytes`);
    rows.push({ d, p, bytes, copy: body.mode === 'mirror' ? copy : 1 });
  }
  const copies = [...new Set(rows.map((r) => r.copy))].sort((a, b) => a - b);
  if (body.mode === 'mirror') {
    if (copies.length < 2 || copies.some((c, i) => c !== i + 1)) return fail('members', 'mirror copies must be numbered from 1 without gaps');
    for (const r of rows) if (rows.some((q) => q.d === r.d && q.copy !== r.copy)) return fail('members', 'two copies on the same disk');
  }
  const per = copies.map((c) => rows.filter((r) => r.copy === c).reduce((n, r) => n + r.bytes, 0));
  const size = body.mode === 'mirror' ? Math.min(...per) : per[0];
  const path = body.mountPath ? String(body.mountPath) : `/var/lib/sfc-disks/${name}`;
  const uuid = crypto.randomUUID();
  Object.assign(o, { state: 'running', step: 'members', uuid, device: '/dev/loop7', mountPath: path, label: body.label ? String(body.label) : undefined, finishedAt: undefined });
  diskOps.set(String(body.opId), o);
  setTimeout(() => {
    if (alloc === 'reserve') for (const r of rows) if (r.p.space) Object.assign(r.p.space, { used: r.p.space.used + r.bytes, available: Math.max(0, r.p.space.available - r.bytes) });
    dev.disks!.push({ name, class: 'additional', kind: 'bundle', bundle: name, size, parts: [{ name, number: 0, size, fsType: 'ext4', uuid, label: name.slice(0, 16), mounts: [path], space: { total: Math.round(size * 0.98), used: Math.round(size * 0.01), available: Math.round(size * 0.92) } }] });
    dev.bundles!.push({ name, backend: 'fuse', mode: String(body.mode), size, device: '/dev/loop7', state: 'ok', syncPercent: 0, members: rows.map((r) => ({ disk: r.d.name, part: r.p.name, size: r.bytes, state: 'ok' })) });
    dev.recorded!.push({ uuid, path, disk: name, part: name });
  }, 5000);
  return ok(diskOpView(o));
}
// 디스크 묶음 (#811 lvm, #819 fuse)
on('POST', '/nodes/:id/disk-bundles', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const node = m[0];
  const dev = fx.devices[node];
  const opId = String(body.opId ?? '');
  const name = String(body.name ?? '');
  const members = Array.isArray(body.members) ? (body.members as Record<string, unknown>[]) : [];
  const key = JSON.stringify({ node, ...body });
  const prev = diskOps.get(opId);
  if (prev) return prev.key === key ? ok(diskOpView(prev)) : ok({ ...diskOpView(prev), state: 'failed', code: 'operation-conflict', error: 'opId is used for another request' });
  if (!opId || !/^[a-z0-9-]{1,32}$/.test(name) || !['lvm', 'fuse'].includes(String(body.backend)) || !['linear', 'mirror'].includes(String(body.mode)) || members.length < 2 || members.length > 32 || (body.mountPath !== undefined && !diskPathOk(String(body.mountPath))))
    return invalid('opId, name, backend lvm or fuse, mode linear or mirror, 2–32 members');
  if (!dev) return err(404, 'not-found', 'no device list for this server');
  const now = Math.floor(Date.now() / 1000);
  const o: D.DDiskOp & { key: string; at: number } = { key, at: Date.now(), operation: opId, node, action: 'bundle', user: user.id, bundle: name, state: 'done', step: 'check', startedAt: now, finishedAt: now };
  const fail = (code: string, error: string) => (Object.assign(o, { state: 'failed', code, error }), diskOps.set(opId, o), ok(diskOpView(o)));
  dev.bundles ??= [];
  dev.recorded ??= [];
  if (dev.bundles.some((b) => b.name === name) || (dev.disks ?? []).some((d) => d.name === name)) return fail('invalid', 'a bundle or disk with that name exists');
  if (body.backend === 'fuse') return fuseBundle(dev, o, name, body, members, fail);
  const ds = members.map((x) => (dev.disks ?? []).find((d) => d.name === x.disk));
  for (let i = 0; i < members.length; i++) {
    const d = ds[i];
    const x = members[i];
    if (!d) return fail('not-found', `no such disk: ${String(x.disk)}`);
    if (d.class === 'system' || d.locked) return fail('system-disk', 'the disk holds /');
    if (d.class !== 'unused' || (d.parts ?? []).some((p) => (p.mounts ?? []).length || p.swap || (p.holders ?? []).length || p.busy)) return fail('busy', `${d.name} is in use`);
    if (x.size !== d.size || (x.serial ?? '') !== (d.serial ?? '') || (x.wwn ?? '') !== (d.wwn ?? '')) return fail('changed', 'the device no longer matches');
  }
  const mirror = body.mode === 'mirror';
  const size = mirror ? Math.min(...ds.map((d) => d!.size)) : ds.reduce((n, d) => n + d!.size, 0);
  const path = body.mountPath ? String(body.mountPath) : `/var/lib/sfc-disks/${name}`;
  const uuid = crypto.randomUUID();
  Object.assign(o, { state: 'running', step: 'members', uuid, device: '/dev/dm-8', mountPath: path, label: body.label ? String(body.label) : undefined, finishedAt: undefined });
  diskOps.set(opId, o);
  setTimeout(() => {
    for (const d of ds) Object.assign(d!, { class: 'bundle-member', bundle: name, parts: [], table: undefined, tableID: undefined });
    dev.disks!.push({ name, class: 'additional', kind: 'bundle', bundle: name, size, parts: [{ name, number: 0, size, fsType: 'ext4', uuid, label: name.slice(0, 16), mounts: [path], space: { total: Math.round(size * 0.98), used: Math.round(size * 0.01), available: Math.round(size * 0.92) } }] });
    dev.bundles!.push({ name, backend: 'lvm', mode: String(body.mode), size, device: '/dev/dm-8', state: 'ok', syncPercent: 0, members: ds.map((d) => ({ disk: d!.name, serial: d!.serial, wwn: d!.wwn, size: d!.size, state: 'ok' })) });
    dev.recorded!.push({ uuid, path, disk: name, part: name });
  }, 5000);
  return ok(diskOpView(o));
});
on('POST', '/nodes/:id/disk-bundles/:name/:action', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const [node, name, action] = m;
  const dev = fx.devices[node];
  const opId = String(body.opId ?? '');
  const key = JSON.stringify({ node, name, action, ...body });
  const prev = diskOps.get(opId);
  if (prev) return prev.key === key ? ok(diskOpView(prev)) : ok({ ...diskOpView(prev), state: 'failed', code: 'operation-conflict', error: 'opId is used for another request' });
  if (!['unbundle', 'replace-member'].includes(action)) return err(404, 'not-found', 'action: unbundle or replace-member');
  const nw = body.new as Record<string, unknown> | undefined;
  const old = body.old as Record<string, unknown> | undefined;
  if (!opId || (action === 'replace-member' && !(old?.disk && nw?.disk && Number(nw.size) > 0 && (nw.serial || nw.wwn)))) return invalid('opId; replace-member: old {disk, serial or wwn} and new {disk, serial or wwn, size}');
  const now = Math.floor(Date.now() / 1000);
  const o: D.DDiskOp & { key: string; at: number } = { key, at: Date.now(), operation: opId, node, action: action as D.DDiskOp['action'], user: user.id, bundle: name, state: 'done', step: 'done', startedAt: now, finishedAt: now };
  const fail = (code: string, error: string) => (Object.assign(o, { state: 'failed', code, error }), diskOps.set(opId, o), ok(diskOpView(o)));
  const b = dev?.bundles?.find((x) => x.name === name);
  if (!dev || !b) return fail('not-found', 'no such bundle');
  const view = devicesView(node, dev);
  const bd = (view.disks ?? []).find((d) => d.kind === 'bundle' && d.bundle === name);
  if (action === 'unbundle') {
    if ((bd?.parts ?? []).some((p) => (p.storageRoots ?? []).length)) return fail('storage-root', 'a storage root is on it');
    if (b.backend === 'fuse') {
      for (const mb of b.members ?? []) {
        const pt = (dev.disks ?? []).find((x) => x.name === mb.disk)?.parts?.find((x) => x.name === mb.part);
        if (pt?.space && mb.size) Object.assign(pt.space, { used: Math.max(0, pt.space.used - mb.size), available: pt.space.available + mb.size });
      }
      dev.disks = (dev.disks ?? []).filter((d) => !(d.kind === 'bundle' && d.bundle === name));
      dev.bundles = dev.bundles!.filter((x) => x !== b);
      dev.recorded = (dev.recorded ?? []).filter((r) => r.disk !== name);
      diskOps.set(opId, o);
      return ok(diskOpView(o));
    }
    for (const mb of b.members ?? []) {
      const d = (dev.disks ?? []).find((x) => x.name === mb.disk);
      if (d) Object.assign(d, { class: 'unused', bundle: undefined, parts: [] });
    }
    dev.disks = (dev.disks ?? []).filter((d) => !(d.kind === 'bundle' && d.bundle === name));
    dev.bundles = dev.bundles!.filter((x) => x !== b);
    dev.recorded = (dev.recorded ?? []).filter((r) => r.disk !== name);
    diskOps.set(opId, o);
    return ok(diskOpView(o));
  }
  if (b.backend === 'fuse') return fail('not-supported', 'a fuse bundle does not replace members; unbundle and bundle again');
  if (b.mode !== 'mirror') return fail('not-mirror', 'only a mirror replaces a member');
  if (bundleView(b).state === 'syncing') return fail('busy', 'a copy is running');
  const nd = (dev.disks ?? []).find((d) => d.name === nw!.disk);
  if (!nd || nd.class !== 'unused') return fail('not-found', 'no such unused disk');
  if (nd.size < b.size) return fail('too-small', 'the new disk is smaller than the bundle');
  const i = (b.members ?? []).findIndex((x) => x.disk === old!.disk);
  if (i < 0) return fail('not-found', 'no such member');
  Object.assign(nd, { class: 'bundle-member', bundle: name, parts: [] });
  const gone = (dev.disks ?? []).find((d) => d.name === old!.disk);
  if (gone) Object.assign(gone, { class: 'unused', bundle: undefined, parts: [] });
  b.members![i] = { disk: nd.name, serial: nd.serial, wwn: nd.wwn, size: nd.size, state: 'syncing' };
  Object.assign(b, { state: 'syncing', syncPercent: 0 });
  syncStart.set(name, Date.now());
  Object.assign(o, { step: 'record', disk: nd.name });
  diskOps.set(opId, o);
  return ok(diskOpView(o));
});
on('GET', '/nodes/:id/disk-operations/:op', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const o = diskOps.get(m[1]);
  return o && o.node === m[0] ? ok(diskOpView(o)) : err(404, 'not-found', 'no such disk operation');
});
on('GET', '/disks', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(page(fx.disks));
});
on('GET', '/raft', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok({ ...fx.raft, commitIndex: fx.raft.commitIndex + Math.floor((Date.now() / 1000) % 1000) });
});
// 기능 집합(UI-17): node-c는 0.1.0이라 network-transit을 알리지 않아 클러스터가 쓰지 못한다
on('GET', '/cluster/features', () => {
  const { user } = requireSession();
  requireAdmin(user);
  // 캔버스 v271 예시: transit은 v1을 쓰고, volume share는 node-c(0.1.1)가 알리지 않아 쓰지 않음. node-b는 끊겨 마지막 보고로 센다
  return ok({
    major: 0,
    groups: [
      {
        name: 'network',
        sets: [
          {
            name: 'network-transit',
            versions: [
              { name: 'network-transit-v1', version: 1, postfix: 'mainline', desc: '다른 서버를 거쳐 가는 연결 (SFCP purpose 25)' },
              { name: 'network-transit-v2-preview', version: 2, postfix: 'preview', desc: '거쳐 가는 연결 묶어 보내기 (시험)' },
            ],
            cluster: 1,
            behind: [],
          },
        ],
      },
      { name: 'volume', sets: [{ name: 'volume-share', versions: [{ name: 'volume-share-v1', version: 1, postfix: 'mainline', desc: '여러 서버에서 쓰기 (VolumeFS)' }], cluster: 0, behind: ['node-c'] }] },
    ],
    cluster: ['network-transit-v1'],
    nodes: [
      { node: 'node-a', major: 0, build: '0.1.2', features: ['network-transit-v1', 'network-transit-v2-preview', 'volume-share-v1'], seen: true, reportedAt: Math.floor(Date.now() / 1000) - 2 },
      { node: 'node-b', major: 0, build: '0.1.2', features: ['network-transit-v1', 'network-transit-v2-preview', 'volume-share-v1'], seen: false, reportedAt: Math.floor(Date.now() / 1000) - 180 },
      { node: 'node-c', major: 0, build: '0.1.1', features: ['network-transit-v1'], seen: true, reportedAt: Math.floor(Date.now() / 1000) - 2 },
    ],
  });
});
// 합의 로그 수동 압축. 서버마다 1.5초씩 차례로 스냅샷을 찍는다고 흉내 낸다.
let compactRun: { id: string; at: string; by: string; mode: 'keep' | 'minimal'; order: string[]; started: number; failed?: string; skipped: string[] } | undefined = {
  id: 'op-raft-compact-0019',
  at: new Date(Date.now() - 13 * 86400000).toISOString(),
  by: 'alice',
  mode: 'keep',
  order: ['node-c', 'node-b', 'node-a'],
  started: Date.now() - 13 * 86400000,
  skipped: [],
};
const compactView = () => {
  const entries: Record<string, number> = {};
  for (const s of fx.raft.servers ?? []) entries[s.node] = Math.max(0, Math.round((s.logBytes ?? 0) / 70000));
  if (!compactRun) return { retain: 20000, minimal: 1000, entries };
  const r = compactRun;
  const n = Math.floor((Date.now() - r.started) / 1500);
  const nodes = r.order.map((node, i) => {
    const srv = (fx.raft.servers ?? []).find((x) => x.node === node);
    const before = srv?.logBytes ?? 300 * 1048576;
    if (r.skipped.includes(node)) return { node, state: 'skipped' as const, error: '응답하지 않음' };
    if (i > n) return { node, state: 'queued' as const };
    if (i === n) return { node, state: 'running' as const, snapshotBytes: 41 * 1048576 };
    if (node === r.failed) return { node, state: 'failed' as const, error: '스냅샷 쓰기 실패: 디스크 남은 공간 부족(필요 41 MiB · 남음 18 MiB)' };
    return { node, state: 'done' as const, snapshotIndex: fx.raft.commitIndex + i * 12, snapshotBytes: 41 * 1048576, logBytesBefore: before, logBytesAfter: r.mode === 'minimal' ? 4 * 1048576 : 12 * 1048576, durationMs: 1800 + i * 300 };
  });
  const finished = n >= r.order.length;
  return { retain: 20000, minimal: 1000, entries, last: { operation: r.id.startsWith('op-') ? r.id : `op-${r.id}`, id: r.id.startsWith('op-') ? undefined : r.id, at: r.at, by: r.by, mode: r.mode, state: !finished ? 'running' : nodes.some((x) => x.state === 'failed') ? 'failed' : 'done', nodes } };
};
on('GET', '/raft/compact', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(compactView());
});
/** 미리보기 digest (데몬 #391). 대상·방식·투표 서버 구성이 같으면 같다 */
const compactPlanDigest = (order: string[], mode: string) => {
  let h = 0;
  for (const c of `${order.join(',')}|${mode}|${(fx.raft.servers ?? []).filter((s) => s.suffrage === 'voter').map((s) => s.node).join(',')}`) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h.toString(16).padStart(8, '0').repeat(8);
};
const compactOrder = (nodes: string[], serial: boolean) => {
  const leader = fx.raft.leader;
  return serial ? [...nodes.filter((n) => n !== leader), ...nodes.filter((n) => n === leader)] : nodes;
};
// 미리보기 (데몬 #387)
on('GET', '/raft/compact/plan', (_m, _b, q) => {
  const { user } = requireSession();
  requireAdmin(user);
  const all = (fx.raft.servers ?? []).filter((s) => s.suffrage === 'voter').map((s) => s.node);
  const asked = (q.get('nodes') ?? '').split(',').filter(Boolean);
  const nodes = (asked.length ? asked : all).filter((n) => all.includes(n));
  if (!nodes.length) return invalid('nodes: 압축할 서버를 하나 이상 고르세요.');
  const mode = q.get('mode') === 'minimal' ? 'minimal' : 'keep';
  const serial = q.get('serial') !== 'false';
  return ok({ mode, retain: mode === 'minimal' ? 1000 : undefined, parallel: !serial, total: nodes.length, nodes: compactOrder(nodes, serial), plan: compactPlanDigest(compactOrder(nodes, serial), mode) });
});
// 한 작업의 진행 (데몬 #387)
on('GET', '/raft/compactions/:op', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const last = compactView().last;
  if (!last || last.operation !== m[0]) return err(404, 'not-found', 'no such compaction');
  const count = (st: string) => last.nodes.filter((x) => x.state === st).length;
  return ok({ operation: last.operation, by: user.id, at: last.at, mode: last.mode, sequential: true, complete: last.state !== 'running', total: last.nodes.length, queued: count('queued'), running: count('running'), done: count('done'), failed: count('failed'), skipped: count('skipped'), nodes: last.nodes.map((x) => ({ node: x.node, state: x.state, code: x.state === 'failed' ? 'SNAPSHOT_WRITE_FAILED' : undefined, revision: 1 })) });
});
on('POST', '/raft/compact', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const v = compactView();
  if (v.last?.state === 'running') return err(409, 'in-progress', '이미 압축 중입니다. 끝난 뒤 다시 하세요.');
  const all = (fx.raft.servers ?? []).filter((s) => s.suffrage === 'voter').map((s) => s.node);
  const nodes = (Array.isArray(body.nodes) && body.nodes.length ? (body.nodes as string[]) : all).filter((n) => all.includes(n));
  if (!nodes.length) return invalid('압축할 서버를 하나 이상 고르세요.');
  const mode = body.mode === 'minimal' ? 'minimal' : 'keep';
  const leader = fx.raft.leader;
  const order = body.serial === false ? nodes : [...nodes.filter((n) => n !== leader), ...nodes.filter((n) => n === leader)];
  if (!/^[0-9a-f]{64}$/.test(String(body.plan ?? ''))) return invalid('plan: the preview plan (64 hex)');
  if (body.plan !== compactPlanDigest(order, mode)) return err(409, 'plan-changed', '읽는 사이 서버 구성이 바뀌었습니다.');
  return submit(user, { ...body, target: nodes.join(',') }, 'raft-compact', () => {
    compactRun = { id: String(body.opId), at: new Date().toISOString(), by: user.username, mode, order, started: Date.now(), skipped: [] };
  });
});
on('GET', '/mesh', (_m, _b, q) => {
  const { user } = requireSession();
  const tenant = q.get('tenant');
  if (!tenant) {
    requireAdmin(user);
    return ok(page(fx.mesh));
  }
  requireTenant(user, tenant);
  // 작업 공간 보기: 허용 서버 사이 연결만, 양쪽 관측값(rtt·손실)은 없다
  const ns = new Set(nodesFor(user, tenant));
  return ok(page(fx.mesh.filter((l) => ns.has(l.nodeA) && ns.has(l.nodeB)).map(({ rttMillis: _r, lossPercent: _l, ...l }) => l)));
});

// 작업 공간 · 사용자
on('GET', '/tenants', () => {
  const { user } = requireSession();
  return ok(page(visibleTenants(user).map((t): D.DTenantView => ({ id: t, revision: fx.tenantRev[t] ?? 1, role: roleIn(user, t) ?? 'manager' })), 22));
});
on('GET', '/tenants/:t', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return ok({ id: m[0], revision: fx.tenantRev[m[0]], role: roleIn(user, m[0]) ?? 'manager', nodes: fx.tenantNodes[m[0]] ?? [] });
});
on('GET', '/tenants/:t/members', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const rows = Object.entries(fx.memberships[m[0]] ?? {}).map(([id, role]): D.DTenantMember => {
    const u = fx.users.find((x) => x.id === id)!;
    return { tenant: m[0], user: id, username: u.username, role, revision: fx.tenantRev[m[0]], enabled: u.enabled };
  });
  return ok(page(rows, fx.tenantRev[m[0]]));
});
on('GET', '/tenants/:t/retirement', (m) => {
  const { user } = requireSession();
  requireAdmin(user);
  const r: D.DTenantRetirement = fx.retiring[m[0]] ?? { tenant: m[0], retiring: false, index: 0, rootRevision: ROOT_REVISION, targetCount: 0, ownerCount: 0, closedOwners: 0, remainingCount: 0, remaining: [], operation: '', phase: 'active' };
  return ok({ ...r, revision: fx.tenantRev[m[0]], ready: r.retiring && r.closedOwners >= r.ownerCount && r.remainingCount === 0 });
});
// 작업 공간 종료(UI-22). 데몬이 opId로 Operation 식별자를 만들고, 마치기는 상태의 operation을 넣는다.
const retireTimers: Record<string, number> = {};
on('POST', '/tenants/:t/retire', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const t = m[0];
  const expected = Number(body.expected ?? 0);
  return submit(user, { ...body, tenant: t, target: t }, 'begin-tenant-retirement', () => {
    if (!(t in fx.tenantRev) || fx.retiring[t]) return CAS;
    if (expected !== fx.tenantRev[t]) return CAS;
    fx.tenantRev[t]++;
    const left = ['app/web@node-a', 'network/shop-net@node-a', 'volume/shop-data@node-b'];
    const r: D.DTenantRetirement = { tenant: t, retiring: true, index: 5000, rootRevision: ROOT_REVISION, targetCount: 3, ownerCount: 2, closedOwners: 0, remainingCount: 3, remaining: left, operation: `retire-${String(body.opId)}`, revision: fx.tenantRev[t], phase: 'retiring' };
    fx.retiring[t] = r;
    // 서버들이 정리 보고를 하나씩 올리는 흉내.
    let step = 0;
    window.clearInterval(retireTimers[t]);
    retireTimers[t] = window.setInterval(() => {
      step++;
      const done = Math.min(step, 3);
      Object.assign(r, { remaining: left.slice(done), remainingCount: 3 - done, closedOwners: Math.min(2, Math.floor((done * 2) / 3)) });
      if (done === 3) window.clearInterval(retireTimers[t]);
    }, 4000);
  });
});
on('POST', '/tenants/:t/retire/finish', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const t = m[0];
  const expected = Number(body.expected ?? 0);
  if (!fx.retiring[t]?.retiring) return err(409, 'not-retiring', 'tenant is not retiring');
  return submit(user, { ...body, tenant: t, target: t }, 'finish-tenant-retirement', () => {
    const r = fx.retiring[t];
    if (!r?.retiring || expected !== fx.tenantRev[t]) return CAS;
    if (r.remainingCount > 0 || r.closedOwners < r.ownerCount) return INVALID;
    fx.tenantRev[t]++;
    Object.assign(r, { retiring: false, phase: 'deleted', operation: '', revision: fx.tenantRev[t], remaining: [] });
  });
});
on('GET', '/users', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(page(fx.users.map(({ password: _p, ...u }): D.DUserRecord => ({ ...u, credentials: credentialsOf(u as User), accountRevision: accountRevision(u as User), invite: inviteOf(u as User) })), 40));
});
on('GET', '/users/:u', (m) => {
  const { user } = requireSession();
  if (!user.systemAdmin && m[0] !== user.id) requireAdmin(user);
  const u = fx.users.find((x) => x.id === m[0] || x.username === m[0]);
  if (!u) return err(404, 'not-found', '사용자를 찾지 못했습니다.');
  const { password: _p, ...rest } = u;
  return ok({ ...rest, credentials: credentialsOf(u), accountRevision: accountRevision(u), invite: inviteOf(u) });
});

// 초대 링크 (UI-23A, 51-invite-links.md). 초대는 계정의 한 번 쓰는 자격 증명(invite-<만료>-<8hex>)이고,
// 코드는 목업 메모리에만 둔다. 만들면 있던 초대를 바꿔 끼운다
const invites = new Map<string, { code: string; cred: string; exp: number }>();
const inviteTickets = new Map<string, { user: string; deadline: number; rev: number }>();
const INVITE_SEC: Record<string, number> = { '1h': 3600, '24h': 86400, '7d': 7 * 86400 };
function inviteOf(u: User): D.DUserRecord['invite'] {
  const iv = invites.get(u.id);
  const c = iv && u.credentials?.find((x) => x.id === iv.cred && x.enabled);
  if (!iv || !c) return null;
  return { state: iv.exp * 1000 > Date.now() ? 'active' : 'expired', expiresAt: new Date(iv.exp * 1000).toISOString() };
}
const bumpAccount = (u: User) => {
  const ks = loadKeys();
  ks.bumps[u.id] = (ks.bumps[u.id] ?? 0) + 1;
  saveKeys(ks);
};
on('POST', '/users/:u/invites', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const target = fx.users.find((x) => x.username === m[0]);
  if (!target) return err(404, 'not-found', '사용자를 찾지 못했습니다.');
  const sec = INVITE_SEC[String(body.expires ?? '')];
  if (!sec) return err(400, 'bad-request', 'expires: 1h | 24h | 7d');
  const fresh = !findOp(String(body.opId ?? ''), user.id);
  let link: { link: string; expiresAt: string } | undefined;
  const res = submit(user, { ...body, target: target.username }, 'create-invite', () => {
    // 켜진 초대(만료 포함)가 있으면 실패한다. 먼저 revoke
    if (inviteOf(target)) return CAS;
    const exp = Math.floor(Date.now() / 1000) + sec;
    const cred = `invite-${exp}-${hex(crypto.getRandomValues(new Uint8Array(4)))}`;
    const old = invites.get(target.id);
    target.credentials = [...(target.credentials ?? []).filter((c) => c.id !== old?.cred), { id: cred, method: 'token', enabled: true }];
    const code = b64(crypto.getRandomValues(new Uint8Array(24))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    invites.set(target.id, { code, cred, exp });
    bumpAccount(target);
    link = { link: `/login/invite?u=${encodeURIComponent(target.username)}#${code}`, expiresAt: new Date(exp * 1000).toISOString() };
  });
  const j = res.json as { op?: D.DOp };
  return fresh && link && j.op?.state === 'applied' ? { ...res, json: { ...j, ...link } } : res;
});
on('POST', '/users/:u/invites/revoke', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const target = fx.users.find((x) => x.username === m[0]);
  if (!target) return err(404, 'not-found', '사용자를 찾지 못했습니다.');
  if (!inviteOf(target) && !findOp(String(body.opId ?? ''), user.id)) return err(409, 'no-invite', '취소할 초대가 없습니다.');
  return submit(user, { ...body, target: target.username }, 'revoke-invite', () => {
    if (Number(body.expected) !== accountRevision(target)) return CAS;
    const iv = invites.get(target.id);
    if (!iv) return INVALID;
    // 마지막 로그인 수단이면 취소할 수 없다(다시 만들기만)
    if (credentialsOf(target).filter((c) => c.enabled && c.id !== iv.cred).length === 0 && target.systemAdmin) return INVALID;
    target.credentials = (target.credentials ?? []).filter((c) => c.id !== iv.cred);
    invites.delete(target.id);
    bumpAccount(target);
  });
});
on('POST', '/login/invite/open', (_m, body) => {
  const u = fx.users.find((x) => x.username === body.username);
  const iv = u && invites.get(u.id);
  const live = u && iv && u.enabled && iv.code === body.code && iv.exp * 1000 > Date.now() && u.credentials?.some((c) => c.id === iv.cred && c.enabled);
  if (!u || !iv || !live) return err(410, 'invite-invalid', '이 초대 링크는 쓸 수 없습니다.');
  iv.code = ''; // 한 번만 연다
  const ticket = randomUUID();
  const deadline = Date.now() + 600_000;
  inviteTickets.set(ticket, { user: u.id, deadline, rev: accountRevision(u) });
  return ok({ ticket, userId: u.id, username: u.username, accountRevision: accountRevision(u), clusterId: MOCK_CLUSTER_ID, expiresAt: new Date(deadline).toISOString() });
});
on('POST', '/login/invite/finish', (_m, body) => {
  const t = inviteTickets.get(String(body.ticket));
  if (!t || t.deadline < Date.now()) return err(410, 'ticket-expired', '10분이 지났습니다.');
  const u = fx.users.find((x) => x.id === t.user)!;
  const c = (body.credential ?? {}) as { id?: string; publicKey?: string };
  const id = String(c.id ?? '');
  const publicKey = String(c.publicKey ?? '').toLowerCase();
  if (!id || id.startsWith('invite-') || !/^[0-9a-f]{64}$/.test(publicKey)) return err(400, 'bad-request', 'credential');
  const challenge = fromHex(String(body.challenge ?? ''));
  let good = false;
  try {
    const msg = credentialAdditionBytes(MOCK_CLUSTER_ID, t.rev, { user: u.id, id, method: 'private-key', label: String(body.label ?? ''), publicKey, challenge });
    good = challenge.length === 32 && ed25519.verify(Uint8Array.from(atob(String(body.proof ?? '')), (x) => x.charCodeAt(0)), msg, fromHex(publicKey));
  } catch {
    good = false;
  }
  if (!good) return err(403, 'denied', '증명이 맞지 않습니다.');
  if (credentialsOf(u).some((k) => k.id === id || k.publicKey === publicKey)) return err(409, 'exists', '같은 키가 이미 있습니다.');
  inviteTickets.delete(String(body.ticket));
  const ks = loadKeys();
  ks.keys.push({ user: u.id, id, publicKey, enabled: true });
  ks.bumps[u.id] = (ks.bumps[u.id] ?? 0) + 1;
  saveKeys(ks);
  return ok({ credential: id, username: u.username });
});

// 계정 동작 범위. 시스템 관리자 또는 본인이 읽고, 시스템 관리자만 바꾼다.
// revision은 계정 revision이다(#461): 범위를 바꾸면 계정 revision이 오른다
const accountScopes = new Map<string, { actions: string[]; keyOnly: boolean }>([['u-bob', { actions: ['deploy', 'cd-approve', 'observe'], keyOnly: false }]]);
on('GET', '/users/:u/scope', (m) => {
  const { user } = requireSession();
  if (m[0] !== user.id) requireAdmin(user);
  if (!fx.users.some((x) => x.id === m[0])) return err(404, 'not-found', 'no such user');
  const sc = accountScopes.get(m[0]) ?? { actions: [], keyOnly: false };
  return ok({ user: m[0], ...sc, revision: accountRevision(fx.users.find((x) => x.id === m[0])!) });
});
// PATCH: 읽은 revision 기준 변경분 {expected, add?, remove?, unlimited?, keyOnly?}
on('PATCH', '/users/:u/scope', (m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const u = fx.users.find((x) => x.id === m[0]);
  if (!u) return err(404, 'not-found', 'no such user');
  const extra = Object.keys(body).filter((k) => !['opId', 'expected', 'add', 'remove', 'unlimited', 'keyOnly'].includes(k));
  if (extra.length) return err(400, 'bad-request', `unknown field ${extra[0]}`);
  const add = (body.add as string[] | undefined) ?? [];
  const remove = (body.remove as string[] | undefined) ?? [];
  const unlimited = body.unlimited === true;
  const keyOnly = body.keyOnly as boolean | undefined;
  if (!add.length && !remove.length && !unlimited && keyOnly === undefined) return invalid('add, remove, unlimited or keyOnly: at least one change');
  if (unlimited && (add.length || remove.length)) return invalid('unlimited goes without add and remove');
  if ([add, remove].some((l) => l.length > 64 || l.some((a) => !a || a.length > 64))) return invalid('add, remove: at most 64 action names such as restart-task');
  if (!body.expected) return invalid('expected: the scope revision it was read at');
  if (Number(body.expected) !== accountRevision(u)) return err(409, 'stale', 'the account changed since it was read; read it again');
  const cur = accountScopes.get(m[0]) ?? { actions: [], keyOnly: false };
  const has = add.find((a) => cur.actions.includes(a));
  if (has) return err(422, 'exists', `the limit already allows ${has}`);
  const missing = remove.find((a) => !cur.actions.includes(a));
  if (missing) return err(422, 'no-such-action', `the limit has no ${missing}`);
  const actions = unlimited ? [] : [...cur.actions.filter((a) => !remove.includes(a)), ...add].sort();
  if (!unlimited && cur.actions.length && !actions.length) return invalid('the last action goes only with unlimited');
  return submit(user, { ...body, target: `user/${m[0]}` }, 'set-account-scope', () => {
    if ((keyOnly ?? cur.keyOnly) && !credentialsOf(u as User).some((c) => c.method === 'private-key' && c.enabled)) return { code: 2, errorCode: 'no-key' };
    accountScopes.set(m[0], { actions, keyOnly: keyOnly ?? cur.keyOnly });
    const ks = loadKeys();
    ks.bumps[u.id] = (ks.bumps[u.id] ?? 0) + 1;
    saveKeys(ks);
  });
});

// 자동 작업 계정 (REQ-9 웹 데몬). 개인키는 목업에도 두지 않고 공개키만 만든다
type Automation = { username: string; publicKey: string; fingerprint: string; createdBy: string; createdAt: string; userId?: string; lastCheck?: { at: string; ok: boolean; user?: string; error?: string } };
let automationState: Automation | undefined;
const randHex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const automationView = () => ({ configured: !!automationState, sealReady: fx.webState.seal.ready, ...(automationState ?? {}) });
on('GET', '/system/automation', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok(automationView());
});
on('PUT', '/system/automation', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const username = String(body.username ?? '');
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(username)) return err(422, 'invalid', 'username: lowercase letters, digits, . _ -');
  if (!fx.webState.seal.ready) return err(503, 'seal-unavailable', 'seal key not ready');
  if (!automationState || automationState.username !== username || body.rotate === true) {
    const pk = randHex(32);
    automationState = { username, publicKey: pk, fingerprint: `SHA256:${randHex(4)}…${randHex(4)}`, createdBy: user.username, createdAt: new Date().toISOString() };
  }
  return ok(automationView());
});
on('POST', '/system/automation/check', () => {
  const { user } = requireSession();
  requireAdmin(user);
  if (!automationState) return err(409, 'not-configured', 'automation account not configured');
  const a = automationState;
  const u = fx.users.find((x) => x.username === a.username);
  const keyOk = !!u && u.enabled && credentialsOf(u).some((c) => c.method === 'private-key' && c.enabled && c.publicKey === a.publicKey);
  const res = !u ? { ok: false, error: 'automation-account-missing' } : keyOk ? { ok: true, user: u.id, username: u.username, systemAdmin: u.systemAdmin } : { ok: false, error: 'denied' };
  a.lastCheck = { at: new Date().toISOString(), ok: res.ok, ...(res.ok ? { user: u!.id } : { error: res.error }) };
  if (res.ok) a.userId = u!.id;
  return ok(res);
});
on('DELETE', '/system/automation', () => {
  const { user } = requireSession();
  requireAdmin(user);
  automationState = undefined;
  return ok(null, 204);
});

// 작업 공간 자원
const byTenant = <T extends { tenant: string }>(xs: T[], t: string) => xs.filter((x) => x.tenant === t);
const tenantGet = (path: string, rows: (t: string) => unknown[]) =>
  on('GET', `/t/:t/${path}`, (m) => {
    const { user } = requireSession();
    requireTenant(user, m[0]);
    return ok(page(rows(m[0]), 12));
  });
tenantGet('resources', (t) => [
  ...byTenant(fx.resources, t).map((e) => (e.limit && NODE_LIMIT[e.limit.node] ? { ...e, limit: { ...e.limit, nodeCpus: NODE_LIMIT[e.limit.node].cpus, nodeMemoryBytes: NODE_LIMIT[e.limit.node].memoryBytes } } : e)),
  ...fx.bridges.filter((b) => b.a.tenant === t || b.b.tenant === t).map((b) => ({ key: `bridge/${b.owner}/${b.name}`, tenant: b.owner, bridge: { ...b, state: bridgeState(t, b) } })),
]);
// 가상 브릿지 (UI-5D, #704): 이 작업 공간 기준 state
function bridgeState(t: string, b: fx.MockBridge): D.DBridge['state'] {
  if (b.phase === 'open') return 'open';
  if (b.phase === 'closing') return 'closing';
  return b.approvals.some((a) => a.tenant === t) ? 'waiting-peer' : 'waiting-me';
}
const netRow = (t: string, n: string) => fx.resources.find((e) => e.tenant === t && e.network?.name === n)?.network;
// 다른 작업 공간이 브릿지를 받도록 연 망 (#728). 어느 작업 공간이든 관리할 수 있으면 읽는다
on('GET', '/t/:t/bridge-endpoints', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const pt = query.get('tenant') ?? '';
  if (!pt || pt === m[0]) return invalid('tenant: another workspace');
  const items = fx.resources.filter((e) => e.tenant === pt && e.network?.kind === 'tun' && e.network.toggles?.includes('bridge-inbound')).map((e) => ({ tenant: pt, network: e.network!.name }));
  return ok({ tenant: pt, items });
});
on('POST', '/t/:t/bridges', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  const peer = (body.peer ?? {}) as { tenant?: string; network?: string };
  const pt = peer.tenant || t;
  if (!validName(body.name) || !validName(body.network) || !validName(peer.network) || !validName(pt)) return invalid('name, network and peer.network');
  if (body.network === 'sfc-system' || peer.network === 'sfc-system') return invalid('the system network is never bridged');
  if (pt === t && body.network === peer.network) return invalid('peer: another network');
  if (body.direction !== undefined && !['both', 'a-to-b', 'b-to-a'].includes(String(body.direction))) return invalid('direction: both, a-to-b or b-to-a');
  const proto = String(body.protocol ?? 'all');
  const ports = (Array.isArray(body.ports) ? body.ports : []) as { first: number; last: number }[];
  if (!['all', 'tcp', 'udp'].includes(proto)) return invalid('protocol: all, tcp or udp');
  if (proto === 'all' && ports.length) return invalid('ports: needs protocol tcp or udp');
  if (ports.some((p) => !(p.first >= 1 && p.last <= 65535 && p.first <= p.last))) return invalid('ports: 1-65535 ranges');
  const own = netRow(t, String(body.network));
  if (!own) return err(404, 'not-found', 'no such network');
  const sameEnds = (b: fx.MockBridge) => {
    const x = `${b.a.tenant}/${b.a.network}`, y = `${b.b.tenant}/${b.b.network}`, p = `${t}/${String(body.network)}`, q2 = `${pt}/${String(peer.network)}`;
    return (x === p && y === q2) || (x === q2 && y === p);
  };
  if (fx.bridges.some(sameEnds)) return err(409, 'bridge-exists', 'a bridge already links these two networks');
  return submit(user, { ...body, tenant: t, target: `bridge/${String(body.name)}` }, 'create-virtual-bridge', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (fx.bridges.some((b) => b.owner === t && b.name === body.name)) return INVALID;
    if (fx.bridges.some(sameEnds)) return { code: 2, errorCode: 'bridge-exists' };
    const pn = netRow(pt, String(peer.network));
    if (!pn || (pt !== t && !pn.toggles?.includes('bridge-inbound'))) return { code: 2, errorCode: 'peer-closed' };
    const same = pt === t;
    fx.bridges.push({ kind: 'bridge', owner: t, name: String(body.name), a: { tenant: t, network: String(body.network) }, b: { tenant: pt, network: String(peer.network) }, direction: (body.direction as D.DBridge['direction']) ?? 'both', protocol: proto as D.DBridge['protocol'], ports, phase: same ? 'open' : 'pending', approvals: same ? [] : [{ tenant: t, user: user.username }], generation: 1, revision: 1 });
    networksRev++;
    return { code: 0 };
  });
});
on('POST', '/t/:t/bridges/:owner/:name/:verb', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, owner, name, verb] = m;
  const b = fx.bridges.find((x) => x.owner === owner && x.name === name && (x.a.tenant === t || x.b.tenant === t));
  if (!b || (verb !== 'approve' && verb !== 'close')) return err(404, 'not-found', 'no such bridge');
  if (b.phase === 'closing') return err(409, 'closing', 'this bridge is closing');
  if (verb === 'approve' && (b.phase !== 'pending' || b.b.tenant !== t)) return err(409, 'already-approved', 'this workspace has nothing to approve on the bridge');
  return submit(user, { ...body, tenant: t, target: `bridge/${name}` }, `${verb}-virtual-bridge`, () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (body.expected !== undefined && Number(body.expected) !== b.revision) return CAS;
    if (verb === 'approve') {
      if (!netRow(b.b.tenant, b.b.network)?.toggles?.includes('bridge-inbound')) return { code: 2, errorCode: 'peer-closed' };
      b.approvals = [...b.approvals, { tenant: t, user: user.username }];
      b.phase = 'open';
    } else if (b.phase === 'pending') {
      fx.bridges.splice(fx.bridges.indexOf(b), 1);
      return { code: 0 };
    } else {
      b.phase = 'closing';
      // 목업: 모든 서버가 정리를 보고한 것으로 보고 8초 뒤 사라진다
      setTimeout(() => fx.bridges.includes(b) && fx.bridges.splice(fx.bridges.indexOf(b), 1), 8000);
    }
    b.revision++;
    return { code: 0 };
  });
});
tenantGet('networks', (t) => byTenant(fx.resources, t).filter((e) => e.network).map((e) => ({ ...e, network: { ...e.network!, members: netMembers(e.tenant, e.network!).map((x, i) => ({ ...x, resolver: e.network!.dns?.enabled ? x.cidr.replace(/\.\d+\/\d+$/, '.1') : undefined, dns: e.network!.dns?.enabled ? { state: i === 1 && e.network!.dns.revision > 3 ? 'not-ready' : 'ready', ready: !(i === 1 && e.network!.dns.revision > 3), resolvers: [`${x.cidr.replace(/\.\d+\/\d+$/, '.1')}:53`] } : undefined })), ...userCounts(fx.networkUsers[`${e.tenant}/${e.network!.name}`]) } })));
function userCounts(us: D.DResourceUser[] | undefined) {
  const list = us ?? [];
  return { apps: new Set(list.filter((u) => u.kind === 'service').map((u) => u.app)).size, standalones: list.filter((u) => u.kind === 'standalone').length, total: list.length };
}
on('GET', '/t/:t/networks/:n/users', (m) => {
  const { user } = requireSession();
  if (!netFind(user, m[0], m[1])) return err(404, 'not-found', 'no such network');
  return ok({ tenant: m[0], network: m[1], users: fx.networkUsers[`${m[0]}/${m[1]}`] ?? [], ...userCounts(fx.networkUsers[`${m[0]}/${m[1]}`]) });
});
tenantGet('volumes', (t) => byTenant(fx.volumes, t));
tenantGet('volume-backups', (t) => byTenant(fx.volumeBackups, t));
tenantGet('vault', (t) => strip(byTenant(fx.vault, t)));
// 클러스터 보관함(데몬 #74): 처음에는 없다. POST /vault/init으로 최상위 묶음을 만든다
let clusterVaultReady = false;
on('GET', '/vault', () => {
  const { user } = requireSession();
  requireAdmin(user);
  return ok({ ...page(clusterVaultReady ? strip(byTenant(fx.vault, 'cluster')) : [], 12), initialized: clusterVaultReady, root: clusterVaultReady ? 'cluster' : '' });
});
on('POST', '/vault/init', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  if (clusterVaultReady) return err(409, 'exists', 'cluster vault already initialized');
  return submit(user, { ...body, target: 'vault/cluster' }, 'vault-init', () => {
    if (clusterVaultReady) return CAS;
    clusterVaultReady = true;
  });
});
// 쓰는 곳(데몬 #75·#76): 묶음이면 그 아래 비밀값까지. 클러스터는 id가 꼭 있어야 한다
const vaultUsing = (t: string, id: string) => {
  const ids = id ? new Set([id, ...vaultBelow(t, id)]) : undefined;
  return fx.vaultUsages.filter((u) => u.tenant === t && (!ids || (u.secrets ?? []).some((x) => ids.has(x))));
};
['/t/:t/vault/usages', '/vault/usages'].forEach((path) =>
  on('GET', path, (m, _b, query) => {
    const { t } = vaultAuth(m);
    const id = query.get('id') ?? '';
    if (!id && t === 'cluster') return err(400, 'invalid', 'id: required');
    if (id && !fx.vault.some((v) => v.tenant === t && v.id === id)) return err(404, 'not-found', 'no such vault object');
    return ok({ ...page(vaultUsing(t, id).map(({ tenant: _t, ...u }) => u), 12), next: '' });
  }),
);
// REQ-30 가정: 이 작업 공간에 허용된 저장 경로(작업 공간 구성원 누구나). 데몬에는 아직 없다.
// REQ-30·58 (#222): 한 쪽 8개, 관리 권한 필요. maxVolumes·attested 없이 allowed와 root 전체 참조
on('GET', '/t/:t/storage', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const rows = fx.storageRoots
    .filter((r) => (r.allTenants || r.tenants?.includes(m[0])) && !rootGone.has(`${r.node}/${r.id}`))
    .map((r): D.DTenantStorageRoot => ({
      node: r.node,
      id: r.id,
      generation: r.generation,
      revision: r.revision,
      draining: r.draining,
      allowed: r.attested !== false && !r.closed,
      root: { cluster: 'sfc', node: r.node, key: `${r.node}-key`, id: r.id, generation: r.generation, path: r.path },
      volumes: r.volumes,
      ...(r.archiveDefault ? { archiveDefault: true } : {}),
    }));
  const from = Number(query.get('after') || 0);
  const next = from + 8 < rows.length ? String(from + 8) : undefined;
  return ok({ ...page(rows.slice(from, from + 8)), next });
});

// 공유 자원 만들기(web-api.md "공유 자원 만들기"). 칸 검사는 웹 서버(422 invalid), 권한·겹침·중복은 sfcd(결과 코드).
const rootGone = new Set<string>();
const rootVolumes = (r: D.DStorageRoot) => fx.volumes.filter((v) => v.node === r.node && v.storage === r.id).length;
const rootView = (r: D.DStorageRoot): D.DStorageRoot => ({ capacityBytes: 0, allTenants: false, attested: true, closed: false, ...r, default: r.id === 'default', volumes: rootVolumes(r) });
const NODE_LIMIT: Record<string, { cpus: number; memoryBytes: number }> = { 'node-a': { cpus: 8, memoryBytes: 32 * 1024 ** 3 }, 'node-b': { cpus: 8, memoryBytes: 16 * 1024 ** 3 } };
const validName = (s: unknown) => typeof s === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s);
const invalid = (msg: string) => err(422, 'invalid', msg);
/** 시스템 망 대역(10.254.0.0/16)과 겹침: 실제 웹과 같은 422 system-range */
/** 서버마다 고정된 서버 주소(10.254.240.0/20). sfcd가 터널 주소로 채운다(#584) */
const nodeAddr = (node: string) => fx.members.find((x) => x.id === node)?.systemAddress ?? `10.254.240.${Math.max(0, fx.members.findIndex((x) => x.id === node)) + 11}`;
const systemRange = (field: 'cidr') => err(422, 'system-range', `${field}: 10.254.0.0/16 is the system network (sfc-system)`);
const canWrite = (u: User, t: string) => u.systemAdmin || roleIn(u, t) === 'manager';
on('POST', '/t/:t/networks', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  // bridge 망은 없다(#547). 서버 하나의 망도 멤버 하나인 tun 망이다
  if (body.kind !== 'tun') return invalid('kind: "tun" (a one-server network is a tun network with one member)');
  return createTun(user, t, body);
});
function createTun(user: User, t: string, body: Record<string, unknown>): RawResponse {
  if (!validName(body.name)) return invalid("name: lowercase letters, digits and '-'");
  const members = Array.isArray(body.members) ? (body.members as { node?: unknown; cidr?: unknown; tunnel?: unknown; gateway?: unknown }[]) : [];
  if (!members.length) return invalid('members: at least one server');
  const mtu = Number(body.mtu ?? 0) || 1500;
  if (mtu < 1280 || mtu > 9000) return invalid('mtu: 1280..9000');
  const cs: Cidr[] = [];
  for (const mb of members) {
    const c = parseCidr(String(mb.cidr ?? ''));
    if (!validName(mb.node) || !c || c.bits > 29) return invalid('members[].node and cidr (IPv4, at most /29)');
    if (cs.some((x) => overlaps(x, c))) return invalid('members[].cidr must not overlap');
    if (mb.tunnel !== undefined) return invalid('members[].tunnel is not accepted: sfcd uses the server address');
    if (inSystem(c)) return systemRange('cidr');
    if (mb.gateway && !hostIn(c, String(mb.gateway))) return invalid('members[].gateway must be a host address inside cidr');
    cs.push(c);
  }
  if (body.tunnelCidr !== undefined) return invalid('tunnelCidr is not accepted: sfcd uses the server address');
  const toggles = body.toggles && typeof body.toggles === 'object' ? (body.toggles as Record<string, unknown>) : {};
  if (Object.keys(toggles).some((k) => k !== 'local')) return invalid('toggles: one of [local]');
  if (toggles.local === true && members.length !== 1) return invalid('toggles.local: only with one server');
  const name = String(body.name);
  return submit(user, { ...body, tenant: t, target: name }, 'create-tun-network', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (fx.resources.some((e) => e.tenant === t && e.network?.name === name)) return INVALID;
    if (fx.resources.some((e) => e.network && cs.some((c) => e.network!.cidr.split(/,\s*/).some((x) => overlaps(c, parseCidr(x) ?? { base: 0, bits: 32 }))))) return INVALID;
    fx.resources.push({ key: `net/${t}/${name}`, tenant: t, network: { name, kind: 'tun', cidr: cs.map(cidrText).join(', '), nodes: members.map((mb) => String(mb.node)), revision: 1, ...(toggles.local === true ? { toggles: ['local'] } : {}) } });
    return { code: 0 };
  });
}
// 망 변경·폐기(UI-50·51). 멤버 행은 망 행에서 처음 한 번 만들고, 변경 상태를 그 위에 둔다.
// 막기(fence)와 bridge 폐기는 서버 정리 보고(closure)로 한다. 목업: 비운 멤버의 남은 끝점은 그 서버의 쓰는 곳에서 만들고, 몇 초마다 하나씩 떠난다.
const netState: Record<string, D.DNetworkMember[]> = {};
const closures: Record<string, D.DNetworkClosure> = {};
function closureOf(t: string, net: string, mb: D.DNetworkMember): D.DNetworkClosure {
  const k = `${t}/${net}@${mb.node}`;
  if (!closures[k]) {
    // 목업: 남은 컨테이너 수는 그 서버의 쓰는 곳에서 센다. 처음 몇 초는 sfcd가 아직 재지 않은 것(null)으로 보인다
    const left = (fx.networkUsers[`${t}/${net}`] ?? []).filter((u) => u.node === mb.node).reduce((n, u) => n + (u.kind === 'standalone' ? 1 : (u.selection ?? []).length), 0);
    closures[k] = { node: mb.node, state: left ? 'pending' : 'closed', closed: left === 0, unreachable: false, nativeGone: left ? null : true, pendingEndpoints: left ? null : 0, pendingFlows: left ? null : 0, pendingPins: left ? null : 0 };
    let remain = left;
    const tick = () => {
      const c = closures[k];
      if (!c || c.closed) return;
      remain = Math.max(0, remain - (c.pendingEndpoints === null ? 0 : 1));
      Object.assign(c, { pendingEndpoints: remain, pendingFlows: 0, pendingPins: 0, nativeGone: remain === 0, closed: remain === 0, state: remain === 0 ? 'closed' : 'pending' });
      if (!c.closed) window.setTimeout(tick, 7000);
    };
    if (left) window.setTimeout(tick, 4000);
  }
  return closures[k];
}
let networksRev = 120;
function netMembers(t: string, n: NonNullable<D.DResourceEntry['network']>): D.DNetworkMember[] {
  const k = `${t}/${n.name}`;
  if (!netState[k]) {
    const cidrs = n.cidr.split(/,\s*/);
    netState[k] = arr0(n.nodes).map((node, i) => ({ node, id: n.kind === 'tun' ? `${n.name}@${node}` : n.name, cidr: cidrs[i] ?? cidrs[0], tunnel: n.kind === 'tun' ? nodeAddr(node) : undefined, generation: 3, revision: n.revision, draining: false }));
  }
  return netState[k];
}
const arr0 = <T,>(x: T[] | null | undefined): T[] => x ?? [];
const activeChange = (c?: D.DNetworkChangeRef) => !!c && c.phase !== 'committed' && c.phase !== 'cancelled';
// 터널 다시 연결 (RQ4, 데몬 #307). shop-net의 node-a↔node-b는 끊긴 채, node-b↔node-c는 불안정하게 시작한다.
// 행은 PairID(정렬한 a/b)로 묶고 다시 연결 횟수는 없다. op applied는 접수일 뿐이고 진행은 /tunnel-reconnects/op-{opId}로 본다.
type TunState = { state: 'up' | 'degraded' | 'down' | 'pending'; since: number };
const tunnelState = new Map<string, TunState>([
  ['node-a/node-b', { state: 'down', since: fx.nowSec() - 420 }],
  ['node-b/node-c', { state: 'degraded', since: fx.nowSec() - 95 }],
]);
const pairOf = (x: string, y: string) => [x, y].sort().join('/');
const tunOf = (pair: string): TunState => tunnelState.get(pair) ?? { state: 'up', since: fx.nowSec() - 86400 * 3 };
const tunnelsOf = (t: string, e: { name: string; nodes?: string[] | null }): D.DTunnelLink[] => {
  const ns = [...(e.nodes ?? [])].sort();
  const out: D.DTunnelLink[] = [];
  for (let i = 0; i < ns.length; i++)
    for (let j = i + 1; j < ns.length; j++) {
      const pairId = pairOf(ns[i], ns[j]);
      const s = tunOf(pairId);
      out.push({ tenant: t, network: e.name, pairId, from: ns[i], to: ns[j], state: s.state, since: s.since });
    }
  return out;
};
type Reconnect = { operation: string; user: string; state: 'queued' | 'running' | 'done' | 'failed'; node: string; peer: string; pairId: string; at: number; revision: number; result?: string; code?: string; error?: string; handshakeAt?: number; keptExisting?: boolean };
const reconnects = new Map<string, Reconnect>();
function reconnectOp(user: User, body: Record<string, unknown>, node: string, peer: string, tenant?: string, target?: string): RawResponse {
  const pairId = pairOf(node, peer);
  if (tunOf(pairId).state !== 'down' && !findOp(String(body.opId ?? ''), user.id)) return err(409, 'not-down', 'the link is not down');
  return submit(user, { ...body, tenant, target: target ?? `tunnel/${pairId}` }, 'reconnect-tunnel', () => {
    // 실제 sfcd: 시스템 관리자만
    if (!user.systemAdmin) return FORBIDDEN;
    const operation = `op-${String(body.opId)}`;
    const r: Reconnect = { operation, user: user.id, state: 'queued', node, peer, pairId, at: fx.nowSec(), revision: 1 };
    reconnects.set(operation, r);
    // 목업: 1.5초 뒤 running, 4초 뒤 끝. 피어 이름에 'fail'이 있으면 실패
    window.setTimeout(() => Object.assign(r, { state: 'running', revision: 2 }), 1500);
    window.setTimeout(() => {
      if (/fail/.test(peer)) return Object.assign(r, { state: 'failed', revision: 3, result: 'failed', code: 'handshake-timeout', error: 'no handshake within 20s' });
      Object.assign(r, { state: 'done', revision: 3, result: 'reconnected', handshakeAt: Date.now() });
      tunnelState.set(pairId, { state: 'up', since: fx.nowSec() });
    }, 4000);
  });
}
on('GET', '/t/:t/networks/:n/tunnels', (m) => {
  const { user } = requireSession();
  const e = netFind(user, m[0], m[1]);
  if (!e) return err(404, 'not-found', 'no such network');
  if (e.net.kind !== 'tun') return ok({ items: [] });
  return ok({ items: tunnelsOf(m[0], e.net) });
});
on('POST', '/t/:t/networks/:n/tunnels/reconnect', (m, body) => {
  const { user } = requireSession();
  const e = netFind(user, m[0], m[1]);
  if (!e) return err(404, 'not-found', 'no such network');
  const from = String(body.from ?? '');
  const to = String(body.to ?? '');
  if (!tunnelsOf(m[0], e.net).some((x) => x.pairId === pairOf(from, to))) return err(404, 'not-found', 'no such server pair');
  return reconnectOp(user, body, from, to, m[0], `network/${m[1]}`);
});
on('POST', '/nodes/:n/tunnels/:p/reconnect', (m, body) => {
  const { user } = requireSession();
  return reconnectOp(user, body, m[0], m[1]);
});
on('GET', '/tunnel-reconnects/:op', (m) => {
  requireSession();
  const r = reconnects.get(m[0]);
  if (!r) return err(404, 'not-found', 'no such operation');
  return ok({ ...r });
});
function netFind(user: User, t: string, n: string) {
  requireTenant(user, t);
  const e = fx.resources.find((x) => x.tenant === t && x.network?.name === n);
  return e?.network ? { e, net: e.network, members: netMembers(t, e.network) } : undefined;
}
on('GET', '/t/:t/networks/:n/change', (m) => {
  const { user } = requireSession();
  const f = netFind(user, m[0], m[1]);
  if (!f) return err(404, 'not-found', 'no such network');
  const phases = new Set(f.members.filter((x) => activeChange(x.change)).map((x) => x.change!.phase));
  const view: D.DNetworkChange = {
    name: f.net.name,
    kind: f.net.kind,
    networksRevision: networksRev,
    dnsEnabled: !!f.net.dns?.enabled,
    members: f.members.map((x) => ({ node: x.node, id: x.id, cidr: x.cidr, tunnel: x.tunnel, revision: x.revision, draining: x.draining, phase: activeChange(x.change) ? (x.change!.phase as 'reserved') : 'none', target: activeChange(x.change) ? x.change!.targetCidr : x.cidr, change: x.change })),
    next: phases.has('reserved') ? 'drain' : phases.has('draining') ? 'fence' : phases.has('fenced') ? 'commit' : '',
    closure: f.members.filter((x) => x.draining).map((x) => closureOf(m[0], f.net.name, x)),
  };
  return ok(view);
});
const netStep = (path: string, action: string | ((kind: string) => string), h: (f: NonNullable<ReturnType<typeof netFind>>, body: Record<string, unknown>) => RawResponse | (() => Applied)) =>
  on('POST', `/t/:t/networks/:n${path}`, (m, body) => {
    const { user } = requireSession();
    const f = netFind(user, m[0], m[1]);
    if (!f) return err(404, 'not-found', 'no such network');
    const r = h(f, body);
    if (typeof r !== 'function') return r;
    return submit(user, { ...body, tenant: m[0], target: m[1] + (body.node ? `@${body.node}` : '') }, typeof action === 'string' ? action : action(f.net.kind), () => {
      if (!canWrite(user, m[0])) return FORBIDDEN;
      const code = r();
      if (code === undefined || code.code === 0) networksRev++;
      return code;
    });
  });
const memberOf = (f: NonNullable<ReturnType<typeof netFind>>, node: unknown) => f.members.find((x) => x.node === node);
netStep('/change', 'plan-network-change', (f, body) => {
  const mb = memberOf(f, body.node);
  if (!mb) return err(422, 'invalid', 'node: not a member of this network');
  const c = parseCidr(String(body.cidr ?? ''));
  if (!c || c.bits > 29) return invalid('cidr: an IPv4 network such as 10.40.0.0/24 (at most /29)');
  if (inSystem(c)) return systemRange('cidr');
  if (activeChange(mb.change)) return err(409, 'change-pending', 'a change is already in progress');
  return () => {
    const clash = fx.resources.some((e) => e.network && e.network.name !== f.net.name && overlaps(c, parseCidr(e.network.cidr) ?? { base: 0, bits: 32 }));
    if (clash || f.members.some((x) => x !== mb && overlaps(c, parseCidr(x.cidr) ?? { base: 0, bits: 32 }))) return INVALID;
    mb.change = { id: `chg-${String(body.opId)}`, generation: mb.generation + 1, revision: 1, targetRevision: mb.revision + 1, phase: 'reserved', targetCidr: cidrText(c) };
    return { code: 0 };
  };
});
netStep('/change/drain', 'drain-network', (f, body) => {
  const mb = memberOf(f, body.node);
  if (!mb) return err(422, 'invalid', 'node: not a member of this network');
  return () => {
    mb.draining = true;
    mb.revision++;
    if (mb.change?.phase === 'reserved') Object.assign(mb.change, { phase: 'draining', revision: mb.change.revision + 1 });
    delete closures[`${f.e.tenant}/${f.net.name}@${mb.node}`];
    return { code: 0 };
  };
});
netStep('/change/cancel', 'cancel-network-change', (f, body) => {
  const mb = memberOf(f, body.node);
  if (!mb) return err(422, 'invalid', 'node: not a member of this network');
  if (mb.change?.phase !== 'reserved') return err(409, 'not-reserved', 'only a planned (reserved) change can be cancelled');
  return () => {
    mb.change = { ...mb.change!, phase: 'cancelled' };
    return { code: 0 };
  };
});
const closedOrErr = (f: NonNullable<ReturnType<typeof netFind>>, mb: D.DNetworkMember) => {
  const c = closureOf(f.e.tenant, f.net.name, mb);
  if (c.unreachable) return err(409, 'unreachable', `the server of ${mb.node} does not answer`);
  if (!c.closed) return err(409, 'in-use', `${c.pendingEndpoints} containers on ${mb.node} still use the network`);
  return undefined;
};
netStep('/change/fence', 'fence-network-change', (f, body) => {
  const mb = memberOf(f, body.node);
  if (!mb) return err(422, 'invalid', 'node: not a member of this network');
  if (mb.change?.phase !== 'draining') return err(409, 'not-draining', 'the change is not draining');
  const e = closedOrErr(f, mb);
  if (e) return e;
  return () => {
    Object.assign(mb.change!, { phase: 'fenced', revision: mb.change!.revision + 1 });
    return { code: 0 };
  };
});
netStep('/change/commit', 'commit-network-change', (f, body) => {
  if (f.net.kind !== 'tun') return err(409, 'not-tun', 'only a tun network commits a change');
  if (!f.members.every((x) => x.change?.phase === 'fenced')) return err(409, 'not-fenced', 'every member must be fenced');
  return () => {
    if (Number(body.expected ?? 0) !== networksRev) return CAS;
    for (const x of f.members) {
      x.cidr = x.change!.targetCidr;
      x.change = { ...x.change!, phase: 'committed' };
      x.draining = false;
      x.generation++;
      x.revision++;
    }
    f.net.cidr = f.members.map((x) => x.cidr).join(', ');
    f.net.revision++;
    return { code: 0 };
  };
});
netStep('/reconfigure', 'reconfigure-tun-network', (f, body) => {
  if (f.net.kind !== 'tun') return err(409, 'not-tun', 'only a tun network has members to change');
  const want = Array.isArray(body.members) ? (body.members as { node?: string; cidr?: string; tunnel?: string }[]) : [];
  if (!f.members.every((x) => x.change?.phase === 'fenced')) return err(409, 'not-fenced', 'every member must be fenced');
  if (f.net.toggles?.includes('local') && want.length !== 1) return err(409, 'toggle-not-allowed', `turn local off before changing to ${want.length} servers`);
  for (const w of want) if (!memberOf(f, w.node) && (!parseCidr(String(w.cidr ?? '')) || !w.tunnel)) return invalid('members[]: a new server needs cidr and tunnel');
  for (const w of want) {
    const c = parseCidr(String(w.cidr ?? ''));
    if (c && inSystem(c)) return systemRange('cidr');
    if (w.tunnel !== undefined) return invalid('members[].tunnel is not accepted: sfcd uses the server address');
  }
  return () => {
    if (Number(body.expected ?? 0) !== networksRev) return CAS;
    const next = want.map((w, i): D.DNetworkMember => {
      const old = memberOf(f, w.node);
      return old ? { ...old, change: undefined, draining: false, generation: old.generation + 1, revision: old.revision + 1 } : { node: String(w.node), id: `${f.net.name}@${w.node}`, cidr: String(w.cidr), tunnel: nodeAddr(String(w.node)), generation: 1, revision: 1, draining: false };
      void i;
    });
    netState[`${f.e.tenant}/${f.net.name}`] = next;
    f.net.nodes = next.map((x) => x.node);
    f.net.cidr = next.map((x) => x.cidr).join(', ');
    f.net.revision++;
    return { code: 0 };
  };
});
netStep('/retire', 'reconfigure-tun-network', (f, body) => {
  if (f.net.dns?.enabled) return err(409, 'dns-enabled', 'turn the network DNS off first');
  if (!f.members.every((x) => x.change?.phase === 'fenced')) return err(409, 'not-fenced', 'every member must be fenced');
  return () => {
    if (Number(body.expected ?? 0) !== networksRev) return CAS;
    fx.resources.splice(fx.resources.indexOf(f.e), 1);
    delete netState[`${f.e.tenant}/${f.net.name}`];
    return { code: 0 };
  };
});
// 서버 하나 빼기(leave-tun-network). 비운 서버만, 쓰는 곳이 없어야 한다. 마지막 서버가 빠지면 망이 지워진다(DNS가 꺼져 있어야 함)
netStep('/members/leave', 'leave-tun-network', (f, body) => {
  const mb = memberOf(f, body.node);
  if (!mb) return err(422, 'invalid', 'node: not a member of this network');
  if (!mb.draining) return err(409, 'not-drained', 'drain the network first (POST …/change/drain)');
  if (f.members.length === 1 && f.net.dns?.enabled) return err(409, 'dns-enabled', 'turn the network DNS off first');
  const e = closedOrErr(f, mb);
  if (e) return e;
  return () => {
    f.members.splice(f.members.indexOf(mb), 1);
    delete closures[`${f.e.tenant}/${f.net.name}@${mb.node}`];
    if (!f.members.length) {
      fx.resources.splice(fx.resources.indexOf(f.e), 1);
      delete netState[`${f.e.tenant}/${f.net.name}`];
    } else {
      f.net.nodes = f.members.map((x) => x.node);
      f.net.cidr = f.members.map((x) => x.cidr).join(', ');
    }
    return { code: 0 };
  };
});
// 망 옵션 하나 켜기·끄기(set-network-toggle). local은 서버가 하나일 때만 켠다
netStep('/toggles', 'set-network-toggle', (f, body) => {
  const name = String(body.toggle);
  if (name !== 'local' && name !== 'bridge-inbound') return invalid('toggle: one of [local bridge-inbound]');
  const on = body.on === true;
  if (!!f.net.toggles?.includes(name) === on) return err(409, 'same-value', 'the toggle already has this value');
  if (name === 'local' && on && f.members.length !== 1) return err(409, 'toggle-not-allowed', `local cannot be true with ${f.members.length} servers`);
  if (name === 'local' && f.members.some((x) => x.draining || activeChange(x.change))) return err(409, 'member-changing', 'a server is draining or changing');
  return () => {
    const rest = (f.net.toggles ?? []).filter((x) => x !== name);
    f.net.toggles = on ? [...rest, name] : rest;
    return { code: 0 };
  };
});
on('POST', '/t/:t/networks/:n/dns', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, n] = m;
  const zone = String(body.zone ?? '');
  if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(zone)) return invalid('zone: a domain name such as shop.sfc.test');
  const net = fx.resources.find((e) => e.tenant === t && e.network?.name === n)?.network;
  if (net && net.kind !== 'tun') return invalid('network DNS is only for tun networks');
  return submit(user, { ...body, tenant: t, target: `${n}/dns` }, 'configure-network-dns', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    const e = fx.resources.find((x) => x.tenant === t && x.network?.name === n);
    if (!e?.network || e.network.kind !== 'tun') return INVALID;
    if (body.expected !== undefined && Number(body.expected) !== (e.network.dns?.revision ?? 0)) return CAS;
    const before = dnsSnap(t, n);
    const ttl = body.ttl !== undefined ? Number(body.ttl) : 10;
    e.network.dns = {
      zone: `${zone}.`,
      enabled: body.enabled !== false,
      revision: (e.network.dns?.revision ?? 0) + 1,
      upstreams: Array.isArray(body.upstreams) ? body.upstreams.map(String) : [],
      ttl,
      negativeTtl: body.negativeTtl !== undefined ? Number(body.negativeTtl) : Math.min(5, ttl),
      reverse: !!body.reverse,
      resolver: e.network.dns?.resolver ?? e.network.cidr.split(/[,/]/)[0].replace(/\.0$/, '.1'),
    };
    revertRecs.set(String(body.opId), { t, n, before, after: dnsSnap(t, n) });
    return { code: 0 };
  });
});
// 망 관리 DNS 이름 (#625)과 직접 더한 이름 (#631). 목업은 shop-net에 php-shop 이름
// 직접 더한 레코드(#636): name은 zone 아래 상대 이름(''은 zone 자체), value는 정규형
type MockDnsRow = { name: string; type: string; value: string; ttl?: number };
const dnsRecords = new Map<string, MockDnsRow[]>([
  [
    'shop/shop-net',
    [
      { name: 'www', type: 'CNAME', value: 'web.php-shop.shop.sfc.test.' },
      { name: 'legacy', type: 'AAAA', value: 'fd00:10:240::21' },
      { name: '_ldap._tcp', type: 'SRV', value: '10 50 389 ldap.shop.sfc.test.' },
      { name: '', type: 'TXT', value: '"v=spf1 -all"', ttl: 300 },
      { name: '', type: 'MX', value: '10 mail.shop.sfc.test.' },
    ],
  ],
]);
on('GET', '/t/:t/networks/:n/dns/names', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const e = fx.resources.find((x) => x.tenant === m[0] && x.network?.name === m[1]);
  if (!e?.network) return err(404, 'not-found', 'no such network');
  const dns = e.network.dns;
  if (!dns) return ok({ managed: false, enabled: false, revision: 0, names: [], servers: [] });
  const z = dns.zone;
  const names = m[1] === 'shop-net'
    ? [
        { name: `web.php-shop.${z}`, app: 'php-shop', service: 'web', task: 'web-1', family: 'ipv4', address: '10.40.0.12' },
        { name: `web.php-shop.${z}`, app: 'php-shop', service: 'web', task: 'web-2', family: 'ipv4', address: '10.40.4.14' },
        { name: `www.${z}`, app: 'php-shop', service: 'web', task: 'web-1', family: 'ipv4', address: '10.40.0.12' },
        { name: `worker.php-shop.${z}`, app: 'php-shop', service: 'worker', family: 'ipv4', address: '10.40.0.13' },
      ]
    : [];
  const servers = netMembers(e.tenant, e.network).map((x, i) => ({ node: x.node, state: i === 1 && dns.revision > 3 ? 'not-ready' : 'ready', ready: !(i === 1 && dns.revision > 3), resolvers: [`${x.cidr.replace(/\.\d+\/\d+$/, '.1')}:53`] }));
  const auto = new Set(names.map((x) => x.name));
  const zd = z.replace(/\.$/, '');
  const records = (dnsRecords.get(`${m[0]}/${m[1]}`) ?? []).map((r) => {
    const full = r.name ? `${r.name}.${zd}` : zd;
    return { name: `${full}.`, type: r.type, value: r.value, ...(r.ttl ? { ttl: r.ttl } : {}), served: !auto.has(`${full}.`) && !auto.has(full) };
  });
  return ok({ managed: true, enabled: dns.enabled, revision: dns.revision, zone: z, names, records, servers });
});
on('PATCH', '/t/:t/networks/:n/dns/records', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const e = fx.resources.find((x) => x.tenant === m[0] && x.network?.name === m[1]);
  if (!e?.network) return err(404, 'not-found', 'no such network');
  const dns = e.network.dns;
  if (!dns) return err(422, 'no-dns', '관리 DNS 정책이 없는 네트워크입니다.');
  if (body.expected === undefined) return invalid('expected: required');
  if (Number(body.expected) !== dns.revision) return err(409, 'stale', '목록을 읽은 뒤 정책이 바뀌었습니다. 다시 읽어 주세요.');
  const z = dns.zone.replace(/\.$/, '');
  type Row = MockDnsRow;
  const TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'];
  const norm = (r: Row): Row => {
    const n = String(r.name).toLowerCase();
    const name = n === '@' || n === z ? '' : n.replace(new RegExp(`\\.${z.replace(/\./g, '\\.')}$`), '');
    const type = String(r.type).toUpperCase();
    let value = String(r.value).trim();
    if (type === 'CNAME' && !value.endsWith('.')) value += '.';
    if (type === 'TXT' && !value.startsWith('"')) value = `"${value}"`;
    return { name, type, value, ...(r.ttl ? { ttl: Number(r.ttl) } : {}) };
  };
  const remove = ((Array.isArray(body.remove) ? body.remove : []) as Row[]).map(norm);
  const add = ((Array.isArray(body.add) ? body.add : []) as Row[]).map(norm);
  if (!remove.length && !add.length) return invalid('remove or add: one is required');
  const k = (r: Row) => `${r.name}/${r.type}/${r.value}`;
  const cur = dnsRecords.get(`${m[0]}/${m[1]}`) ?? [];
  const gone = remove.find((r) => !cur.some((c) => k(c) === k(r)));
  if (gone) return err(422, 'no-such-record', `${gone.name} ${gone.type} ${gone.value} 줄이 없습니다.`);
  const rest = cur.filter((c) => !remove.some((r) => k(r) === k(c)));
  const dup = add.find((r) => rest.some((c) => k(c) === k(r)));
  if (dup) return err(422, 'exists', `${dup.name} ${dup.type} ${dup.value} 줄이 이미 있습니다.`);
  const auto = m[1] === 'shop-net' ? ['web.php-shop', 'www', 'worker.php-shop'] : [];
  const before = new Set(cur.map((r) => r.name));
  const taken = add.find((r) => !before.has(r.name) && auto.includes(r.name));
  if (taken) return err(422, 'name-taken', `${taken.name}.${z}은 앱 서비스가 쓰는 이름입니다.`);
  const bad = add.find((r) => !TYPES.includes(r.type) || !r.value || /[\r\n]/.test(r.value) || (r.ttl !== undefined && (r.ttl < 1 || r.ttl > 3600)) || r.name === 'ns' || (r.type === 'CNAME' && !r.name));
  if (bad) return invalid(`records: ${bad.type} value is not valid`);
  const next = [...rest, ...add];
  if (next.length > 64) return invalid('records: at most 64');
  for (const r of next) {
    const at = next.filter((x) => x.name === r.name);
    const set = at.filter((x) => x.type === r.type);
    if ((r.type === 'CNAME' && at.length > 1) || set.length > 8 || set.some((x) => (x.ttl ?? 0) !== (r.ttl ?? 0)))
      return invalid('records: each name under the zone (not the zone or ns); a CNAME alone at its name; up to 8 of one type per name, with one ttl; at most 64');
  }
  return submit(user, { ...body, tenant: m[0], target: `${m[1]}/dns` }, 'configure-network-dns', () => {
    if (Number(body.expected) !== dns.revision) return CAS;
    const before = dnsSnap(m[0], m[1]);
    dnsRecords.set(`${m[0]}/${m[1]}`, next);
    dns.revision += 1;
    revertRecs.set(String(body.opId), { t: m[0], n: m[1], before, after: dnsSnap(m[0], m[1]) });
    // 뺀 줄은 지운 것에 남긴다(같은 이름·종류를 함께 더한 것은 고치기라 남기지 않음, 53-ops-trash.md)
    for (const r of remove.filter((r) => !add.some((a) => a.name === r.name && a.type === r.type))) trashDnsRow(user.username, m[0], m[1], r, String(body.opId));
  });
});
/** 망 DNS 지금 값(되돌리기 계획용) */
function dnsSnap(t: string, n: string): DnsSnap {
  const d = fx.resources.find((x) => x.tenant === t && x.network?.name === n)?.network?.dns;
  return {
    Enabled: !!d?.enabled,
    Zone: d?.zone ?? '',
    TTL: d?.ttl ?? 0,
    Upstreams: [...(d?.upstreams ?? [])],
    Records: (dnsRecords.get(`${t}/${n}`) ?? []).map((r) => ({ Name: r.name, Type: r.type, Value: r.value, ...(r.ttl ? { TTL: r.ttl } : {}) })),
  };
}
const rowKey = (r: { Name: string; Type: string; Value: string; TTL?: number }) => `${r.Name}/${r.Type}/${r.Value}/${r.TTL ?? 0}`;
function revertPlanOf(id: string, user: User): Record<string, unknown> {
  const o = findOp(id, user.id);
  if (!o) return { error: true };
  if (o.state === 'unknown') return { revert: 'no', reason: 'unsettled', action: o.action, target: o.target };
  if (o.state !== 'applied') return { revert: 'no', reason: 'not-applied', action: o.action, target: o.target };
  if (o.action === 'deploy') return { revert: 'link', link: { kind: 'app-revisions', tenant: o.tenant, app: o.target }, action: o.action, target: o.target };
  if (o.action === 'down-app') return { revert: 'link', link: { kind: 'archived-apps', tenant: o.tenant, app: o.target }, action: o.action, target: o.target };
  const rec = revertRecs.get(id);
  if (!rec) return { revert: 'no', reason: IRREVERSIBLE.has(o.action) ? 'irreversible' : 'unsupported', action: o.action, target: o.target };
  const net = fx.resources.find((x) => x.tenant === rec.t && x.network?.name === rec.n)?.network;
  if (!net?.dns) return { revert: 'here', reason: 'target-gone', action: o.action, target: o.target };
  const now = dnsSnap(rec.t, rec.n);
  const fields: Record<string, unknown>[] = [];
  for (const k of ['Enabled', 'Zone', 'TTL', 'Upstreams'] as const) {
    const b = JSON.stringify(rec.before[k]);
    const a = JSON.stringify(rec.after[k]);
    if (a !== b) fields.push({ path: `Policy.${k}`, kind: 'value', before: rec.before[k], after: rec.after[k], now: now[k], changedSince: JSON.stringify(now[k]) !== a });
  }
  const bk = new Set(rec.before.Records.map(rowKey));
  const ak = new Set(rec.after.Records.map(rowKey));
  const nk = new Set(now.Records.map(rowKey));
  const added = rec.after.Records.filter((r) => !bk.has(rowKey(r)));
  const removed = rec.before.Records.filter((r) => !ak.has(rowKey(r)));
  if (added.length || removed.length)
    fields.push({ path: 'Policy.Records', kind: 'set', before: rec.before.Records, after: rec.after.Records, now: now.Records, added, removed, changedSince: added.some((r) => !nk.has(rowKey(r))) || removed.some((r) => nk.has(rowKey(r))) });
  if (!fields.length) return { revert: 'here', reason: 'nothing', action: o.action, target: `${rec.n} 도메인 이름 설정` };
  return { revert: 'here', action: o.action, target: `${rec.n} 도메인 이름 설정`, expected: net.dns.revision, fields };
}
on('GET', '/ops/:id/revert', (m) => {
  const { user } = requireSession();
  const p = revertPlanOf(m[0], user);
  return p.error ? err(404, 'not-found', '이 작업을 찾지 못했습니다.') : ok(p);
});
on('POST', '/ops/:id/revert', (m, body) => {
  const { user } = requireSession();
  const p = revertPlanOf(m[0], user);
  if (p.error) return err(404, 'not-found', '이 작업을 찾지 못했습니다.');
  const picked = Array.isArray(body.fields) ? (body.fields as string[]) : [];
  if (!picked.length || body.expected === undefined) return err(400, 'bad-request', 'fields and expected are required');
  if (p.revert !== 'here' || p.reason) return err(422, 'not-revertible', String(p.reason ?? 'not revertible here'));
  const fields = p.fields as { path: string; kind: string; before: unknown; added?: DnsSnap['Records']; removed?: DnsSnap['Records'] }[];
  if (picked.some((f) => !fields.some((x) => x.path === f))) return invalid('fields: only the fields the operation changed');
  if (Number(body.expected) !== p.expected) return err(409, 'stale', '그사이 대상이 바뀌었습니다. 계획을 다시 읽어 주세요.');
  const rec = revertRecs.get(m[0])!;
  const opId = String(body.opId ?? '');
  const res = submit(user, { opId, tenant: rec.t, target: `${rec.n}/dns`, revertOf: m[0], fields: picked }, 'configure-network-dns', () => {
    const d = fx.resources.find((x) => x.tenant === rec.t && x.network?.name === rec.n)?.network?.dns;
    if (!d || d.revision !== Number(body.expected)) return CAS;
    const before = dnsSnap(rec.t, rec.n);
    for (const f of fields.filter((x) => picked.includes(x.path))) {
      const k = f.path.split('.').pop();
      if (k === 'Enabled') d.enabled = !!f.before;
      else if (k === 'Zone') d.zone = String(f.before);
      else if (k === 'TTL') d.ttl = Number(f.before);
      else if (k === 'Upstreams') d.upstreams = [...(f.before as string[])];
      else if (k === 'Records') {
        const gone = new Set((f.added ?? []).map(rowKey));
        const rows = before.Records.filter((r) => !gone.has(rowKey(r)));
        for (const r of f.removed ?? []) if (!rows.some((x) => rowKey(x) === rowKey(r))) rows.push(r);
        dnsRecords.set(`${rec.t}/${rec.n}`, rows.map((r) => ({ name: r.Name, type: r.Type, value: r.Value, ...(r.TTL ? { ttl: r.TTL } : {}) })));
      }
    }
    d.revision += 1;
    revertRecs.set(opId, { t: rec.t, n: rec.n, before, after: dnsSnap(rec.t, rec.n) });
  });
  const o = findOp(opId, user.id);
  if (o) {
    o.revertOf = m[0];
    return opReply(o);
  }
  return res;
});
/** 직접 더한 DNS 줄을 뺀 변경이 확정되면 지운 것에 남긴다 */
function trashDnsRow(by: string, t: string, n: string, r: MockDnsRow, op?: string, at?: number) {
  const zone = fx.resources.find((x) => x.tenant === t && x.network?.name === n)?.network?.dns?.zone ?? '';
  const full = (name: string) => (name ? `${name}.${zone}` : zone);
  addTrash(
    { kind: 'dns-record', tenant: t, name: `${full(r.name)} ${r.type}`, deletedBy: by, op, detail: { network: n, name: full(r.name), type: r.type, value: r.value, ttl: r.ttl ?? 0 } },
    {
      current: (nm) => {
        const name = nm ?? r.name;
        const cur = (dnsRecords.get(`${t}/${n}`) ?? []).filter((x) => x.name === name && x.type === r.type);
        return cur.length ? cur.map((x) => `${full(x.name)} ${x.type} ${x.value}`) : undefined;
      },
      apply: (nm, replace, opId, done) => {
        const { user } = requireSession();
        const d = fx.resources.find((x) => x.tenant === t && x.network?.name === n)?.network?.dns;
        if (!d) return err(422, 'target-gone', '망이나 관리 DNS가 없습니다.');
        const name = nm ?? r.name;
        return submit(user, { opId, tenant: t, target: `${n}/dns`, restore: name }, 'configure-network-dns', () => {
          const before = dnsSnap(t, n);
          const rows = (dnsRecords.get(`${t}/${n}`) ?? []).filter((x) => !(replace && x.name === name && x.type === r.type));
          rows.push({ ...r, name });
          dnsRecords.set(`${t}/${n}`, rows);
          d.revision += 1;
          revertRecs.set(opId, { t, n, before, after: dnsSnap(t, n) });
          done();
        });
      },
    },
    at,
  );
}
on('POST', '/t/:t/volumes', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  if (!validName(body.name) || !validName(body.node)) return invalid("name and node: lowercase letters, digits and '-'");
  const cap = Number(body.capacityBytes ?? 0);
  if (cap > 2 ** 40) return invalid('capacityBytes: at most 1 TiB');
  const name = String(body.name);
  const node = String(body.node);
  if (body.kind === 'managed') {
    if (!validName(body.app)) return invalid('app: the app namespace the data store belongs to');
    const uid = Number(body.uid ?? 0), gid = Number(body.gid ?? 0);
    if (!uid || !gid) return invalid('uid and gid must be non-root');
    if (body.mode && !['0700', '0750', '0770'].includes(String(body.mode))) return invalid('mode: 0700, 0750 or 0770');
    return submit(user, { ...body, tenant: t, target: name }, 'begin-volume-create', () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      if (fx.volumes.some((v) => v.tenant === t && v.name === name)) return INVALID;
      fx.volumes.push({ key: `vol/${t}/${name}`, tenant: t, name, kind: 'shared', node, app: String(body.app), revision: 1, consumers: 0, capacityBytes: cap || undefined, usedBytes: 0, usageObservedAt: Date.now(), retain: true });
      return { code: 0 };
    });
  }
  if (body.kind === 'fixed') {
    if (!validName(body.storage) || !body.path) return invalid('storage and path are required');
    const root = fx.storageRoots.find((r) => r.node === node && r.id === body.storage);
    const gen = Number(body.rootGeneration ?? 0);
    if (user.systemAdmin) {
      if (!root || root.draining || !(root.allTenants || root.tenants?.includes(t))) return invalid(`storage root ${String(body.storage)} on ${node} is not approved for this workspace`);
      if (gen && gen !== root.generation) return invalid('rootGeneration does not match the storage root');
    } else if (!gen) return err(422, 'storage-root-unknown', 'this account cannot read node-storage; pass rootGeneration');
    return submit(user, { ...body, tenant: t, target: name }, 'register-fixed-volume', () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      if (!root || root.draining || !(root.allTenants || root.tenants?.includes(t)) || (gen && gen !== root.generation)) return INVALID;
      // #684: 한도가 있는 저장 경로는 용량을 준 등록만, 예약 합이 한도 안일 때만 받는다
      if (root.capacityBytes) {
        const held = fx.volumes.filter((v) => v.node === root.node && v.storage === root.id).reduce((s, v) => s + (v.capacityBytes ?? 0), 0);
        if (!cap || held + cap > root.capacityBytes) return INVALID;
      }
      if (fx.volumes.some((v) => v.tenant === t && v.name === name)) return INVALID;
      fx.volumes.push({ key: `vol/${t}/${name}`, tenant: t, name, kind: 'fixed', node, storage: root.id, revision: 1, consumers: 0, capacityBytes: cap || undefined, usedBytes: 0, usageObservedAt: Date.now(), retain: true });
      return { code: 0 };
    });
  }
  return invalid('kind: "managed" or "fixed"');
});
// 상태 검사 스크립트·정책 (UI-90/91, 데몬 #60 계약). 작업 공간 관리자만 읽는다
const lcFind = (t: string, n: string) => fx.lifecycles.find((l) => l.tenant === t && l.name === n);
const lcView = (l: fx.MockLifecycle): D.DLifecycle => {
  const live = l.versions.filter((v) => !v.deleted);
  return { name: l.name, recordRevision: l.recordRevision, activeRevision: live.find((v) => v.active)?.revision ?? 0, latestRevision: live.length ? Math.max(...live.map((v) => v.revision)) : 0, versions: l.versions.map(({ source: _s, uses: _u, ...v }) => v) };
};
const lcManager = (m: string[]) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  if (!canWrite(user, m[0])) throw new Halt(err(403, 'denied', '상태 검사 스크립트는 작업 공간 관리자만 봅니다.'));
  return user;
};
const lcPolicy = (t: string) => fx.lifecyclePolicies[t];
on('GET', '/t/:t/lifecycle-scripts', (m) => {
  lcManager(m);
  const p = lcPolicy(m[0]);
  return ok({ items: fx.lifecycles.filter((l) => l.tenant === m[0] && l.versions.some((v) => !v.deleted)).map(lcView), policy: { configured: !!p, enabled: p?.enabled ?? true, revision: p?.revision ?? 0 } });
});
on('GET', '/t/:t/lifecycles/:n', (m, _b, query) => {
  lcManager(m);
  const l = lcFind(m[0], m[1]);
  if (!l) return err(404, 'not-found', 'no such lifecycle script');
  const view = lcView(l);
  const want = Number(query?.get('revision') ?? 0) || view.activeRevision || view.latestRevision;
  const v = l.versions.find((x) => x.revision === want && !x.deleted);
  if (!v) return err(404, 'not-found', 'no such revision');
  // 목업: legacy-tcp의 원문은 읽을 수 없는 것으로 둔다(REQ-40 전 모양)
  const hidden = l.name === 'legacy-tcp';
  return ok({ script: view, revision: v.revision, source: hidden ? null : v.source, sourceAvailable: !hidden, usedBy: l.versions.flatMap((x) => x.uses), usedByAvailable: true });
});
const lcProvided = new Set<string>();
on('PUT', '/t/:t/lifecycles/:n', (m, body) => {
  const user = lcManager(m);
  const [t, n] = m;
  if (!validName(n)) return invalid("name: lowercase letters, digits and '-'");
  const p = lcPolicy(t);
  if (!p || !p.enabled) return err(409, 'policy-disabled', 'the lifecycle policy is missing or disabled');
  const source = String(body.source ?? '');
  const lines = source.split('\n');
  const diags: { line: number; column: number; message: string }[] = [];
  if (!/^package checker\b/m.test(source)) diags.push({ line: 1, column: 1, message: 'package checker 가 필요합니다' });
  if (!/func Check\(ctx context\.Context, \w+ lifecycle\.Request, \w+ lifecycle\.Probe\) \(lifecycle\.Result, error\)/.test(source)) diags.push({ line: 0, column: 0, message: 'func Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) 가 필요합니다' });
  lines.forEach((x, i) => /lifecycle\.Result\{\s*\}/.test(x) && diags.push({ line: i + 1, column: x.indexOf('lifecycle') + 1, message: 'lifecycle.Result에 Schema·Status가 필요합니다' }));
  if (diags.length) return err(422, 'compile-error', 'the script does not compile', { diagnostics: diags });
  const lockIn = (Array.isArray(body.lock) ? body.lock : []) as { path: string; version: string; zip?: string }[];
  const allowed = arrOf(p.resolver.modules);
  if (lockIn.some((x) => !allowed.some((a) => a.path === x.path && a.version === x.version))) return invalid('lock: only modules the policy allows');
  // 데몬 #315: zip이 있는 모듈은 실행 서버에 먼저 올린다(목업: ZIP 머리 'PK'가 아니면 핀과 다름). 서버에 없는 모듈을 zip 없이 고르면 module-missing.
  // 목업의 실행 서버는 이미 쓰인 버전의 모듈을 가진 것으로 본다
  const provided = new Set([...lcProvided, ...byTenant(fx.lifecycles, t).flatMap((x) => x.versions.flatMap((v) => arrOf(v.modules).map((mm) => `${mm.path}@${mm.version}`)))]);
  for (const x of lockIn.filter((y) => y.zip)) {
    let head = '';
    try {
      head = atob(String(x.zip)).slice(0, 2);
    } catch {
      head = '';
    }
    if (head !== 'PK') return invalid(`lock: the ZIP of ${x.path}@${x.version} does not match its pin`);
  }
  if (lockIn.some((x) => !x.zip && !provided.has(`${x.path}@${x.version}`))) return err(422, 'module-missing', 'a module of the lock is not on the provider server; send its ZIP in lock[].zip');
  for (const x of lockIn.filter((y) => y.zip)) lcProvided.add(`${x.path}@${x.version}`);
  const lock = lockIn.map(({ path, version }) => ({ path, version }));
  const l0 = lcFind(t, n);
  const expected = Number(body.expected ?? l0?.recordRevision ?? 0);
  return submit(user, { ...body, tenant: t, target: `lifecycle/${n}` }, 'put-lifecycle-script', () => {
    const l = lcFind(t, n);
    if ((l?.recordRevision ?? 0) !== expected) return CAS;
    const rev = expected + 1;
    const cur = l ?? { tenant: t, name: n, recordRevision: 0, versions: [] };
    if (!l) fx.lifecycles.push(cur);
    cur.versions.push({ revision: rev, active: true, deleted: false, digest: Array.from(source).reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7).toString(16).padStart(8, '0').repeat(8), length: source.length, modules: lock, source, uses: [] });
    cur.recordRevision = rev;
    return { code: 0 };
  });
});
const lcStep = (method: string, path: string, action: string, check: (v: fx.MockLcVersion, l: fx.MockLifecycle) => RawResponse | undefined, apply: (v: fx.MockLcVersion) => void) =>
  on(method, path, (m, body) => {
    const user = lcManager(m);
    const l = lcFind(m[0], m[1]);
    if (!l) return err(404, 'not-found', 'no such lifecycle script');
    const v = l.versions.find((x) => x.revision === Number(body.revision));
    if (!v) return err(404, 'not-found', 'no such revision');
    const bad = check(v, l);
    if (bad) return bad;
    const expected = Number(body.expected ?? l.recordRevision);
    return submit(user, { ...body, tenant: m[0], target: `lifecycle/${m[1]}` }, action, () => {
      if (l.recordRevision !== expected) return CAS;
      apply(v);
      l.recordRevision++;
      return { code: 0 };
    });
  });
lcStep('POST', '/t/:t/lifecycles/:n/retire', 'retire-lifecycle-script', (v) => (v.active ? undefined : err(409, 'not-active', 'the revision is not active')), (v) => (v.active = false));
lcStep(
  'DELETE',
  '/t/:t/lifecycles/:n',
  'delete-lifecycle-script',
  (v) => (v.deleted ? err(409, 'deleted', 'already deleted') : v.active ? err(409, 'active', 'retire the revision first') : v.uses.length ? err(409, 'in-use', 'apps still use this revision') : undefined),
  (v) => (v.deleted = true),
);
on('GET', '/t/:t/lifecycle-policy', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const p = lcPolicy(m[0]);
  return ok({ configured: !!p, policy: p ?? fx.defaultLifecyclePolicy(m[0]) });
});
on('PUT', '/t/:t/lifecycle-policy', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  const build = body.build as D.DLifecyclePolicy['build'] | undefined;
  if (build && arrOf(build.nodes).length && (!build.image || !build.toolchain || !(build.maxJobs >= 1))) return err(422, 'invalid-policy', 'build: a build node needs image, toolchain and maxJobs');
  if (build && !arrOf(build.nodes).length && (build.image || build.toolchain)) return err(422, 'invalid-policy', 'build: image and toolchain need a build node');
  return submit(user, { ...body, tenant: t, target: 'lifecycle-policy' }, 'set-lifecycle-policy', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    const cur = lcPolicy(t) ?? fx.defaultLifecyclePolicy(t);
    if (Number(body.expected ?? cur.revision) !== cur.revision) return CAS;
    fx.lifecyclePolicies[t] = {
      ...cur,
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      ...(build ? { build } : {}),
      ...(typeof body.compiledCacheBytes === 'number' ? { compiledCacheBytes: body.compiledCacheBytes } : {}),
      revision: cur.revision + 1,
    };
    return { code: 0 };
  });
});
// 작업 공간 간 연결 (UI-53). docs/reference/web-api/30-ui-53.md
const routeView = (r: fx.MockRoute, t: string): D.DRoute => {
  const side = r.source.tenant === t ? 'source' : 'destination';
  const mine = r.approvals?.some((a) => a.tenant === t);
  // as the daemon: both sides carry the network name; only this tenant's side its cidr
  const end = (e: fx.MockRoute['source']) => (e.tenant === t ? e : { tenant: e.tenant, network: e.network, node: e.node, name: e.name });
  return { ...r, source: end(r.source), destination: end(r.destination), side, state: r.phase === 'revoking' ? 'revoking' : r.phase === 'active' ? 'active' : mine ? 'waiting-peer' : 'waiting-me' };
};
on('GET', '/t/:t/routes', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return ok({ items: fx.routes.filter((r) => r.source.tenant === m[0] || r.destination.tenant === m[0]).map((r) => routeView(r, m[0])), next: '', networksRevision: networksRev });
});
// 받는 쪽으로 연 망. 목업: 그 작업 공간의 망 전부를 서버마다 main 묶음으로 연다
const openEndpoints = (dt: string) => fx.resources.filter((e) => e.tenant === dt && e.network).flatMap((e) => arrOf(e.network!.nodes).map((node) => ({ tenant: dt, network: e.network!.name, node, pool: 'main' })));
on('GET', '/t/:t/route-endpoints', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const dt = query.get('tenant') ?? '';
  return ok({ tenant: dt, items: openEndpoints(dt) });
});
on('POST', '/t/:t/routes', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  const src = (body.source ?? {}) as { network?: string };
  const dst = (body.destination ?? {}) as { tenant?: string; network?: string };
  const ports = (Array.isArray(body.ports) ? body.ports : []) as { first: number; last: number }[];
  if (!validName(src.network) || !validName(dst.tenant) || !validName(dst.network)) return invalid('source.network, destination.tenant and destination.network are required');
  if (dst.tenant === t) return invalid('destination must be another workspace');
  if (!['tcp', 'udp'].includes(String(body.protocol))) return invalid('protocol: tcp or udp');
  if (!ports.length || ports.some((p) => !(p.first >= 1 && p.last <= 65535 && p.first <= p.last))) return invalid('ports: 1-65535 ranges');
  const net = fx.resources.find((e) => e.tenant === t && e.network?.name === src.network)?.network;
  if (!net) return invalid(`network ${String(src.network)} is not in this workspace`);
  const srcNodes = arrOf(net.nodes);
  const srcNode = (src as { node?: string }).node ?? (srcNodes.length === 1 ? srcNodes[0] : '');
  if (!srcNode) return err(422, 'node-required', 'the network spans several nodes; give source.node');
  // 받는 쪽은 그 작업 공간이 연 끝점에서 고른다
  const cands = openEndpoints(String(dst.tenant)).filter((x) => x.network === dst.network && (!(dst as { node?: string }).node || x.node === (dst as { node?: string }).node));
  if (!cands.length) return err(422, 'destination-not-open', 'the destination network is not open for routes');
  if (new Set(cands.map((x) => x.node)).size > 1) return err(422, 'destination-node-required', 'the destination network spans several nodes; give destination.node');
  const dstNode = cands[0].node;
  if (body.id !== undefined && !validName(body.id)) return invalid('id: lowercase letters, digits and -');
  const id = String(body.id ?? `rt-${String(body.opId).slice(0, 8)}`);
  const cidrAt = (n: { cidr?: string; nodes?: string[] | null }, node: string) => String(n.cidr ?? '').split(',').map((x) => x.trim())[arrOf(n.nodes).indexOf(node)];
  const dnet = fx.resources.find((e) => e.tenant === dst.tenant && e.network?.name === dst.network)?.network;
  return submit(user, { ...body, tenant: t, target: `route/${t}/${id}` }, 'propose-route', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (fx.routes.some((r) => r.sourceTenant === t && r.id === id)) return INVALID;
    fx.routes.push({ key: `route/${t}/${id}`, id, sourceTenant: t, source: { tenant: t, network: `${net.name}-${srcNode}`, node: srcNode, name: net.name, cidr: cidrAt(net, srcNode) }, destination: { tenant: String(dst.tenant), network: `${String(dst.network)}-${dstNode}`, node: dstNode, name: String(dst.network), cidr: dnet ? cidrAt(dnet, dstNode) : undefined }, protocol: body.protocol as 'tcp' | 'udp', ports, phase: 'pending', approvals: [], revision: 1 });
    return { code: 0 };
  });
});
on('POST', '/t/:t/routes/:src/:id/:verb', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, src, id, verb] = m;
  const r = fx.routes.find((x) => x.sourceTenant === src && x.id === id && (x.source.tenant === t || x.destination.tenant === t));
  if (!r) return err(404, 'not-found', 'no such route');
  if (verb !== 'approve' && verb !== 'withdraw') return err(404, 'not-found', 'unknown action');
  if (r.phase === 'revoking') return err(409, 'revoking', 'this route is being withdrawn');
  if (verb === 'approve' && r.approvals?.some((a) => a.tenant === t)) return err(409, 'already-approved', 'this workspace already approved the route');
  return submit(user, { ...body, tenant: t, target: `route/${src}/${id}` }, `${verb}-route`, () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (body.expected !== undefined && Number(body.expected) !== r.revision) return CAS;
    if (verb === 'approve') {
      if (r.phase !== 'pending') return INVALID;
      r.approvals = [...(r.approvals ?? []), { tenant: t, user: user.username }];
      if (r.approvals.some((a) => a.tenant === r.source.tenant) && r.approvals.some((a) => a.tenant === r.destination.tenant)) r.phase = 'active';
    } else {
      if (r.phase === 'revoking') return INVALID;
      r.phase = 'revoking';
      setTimeout(() => fx.routes.splice(fx.routes.indexOf(r), 1), 6000);
    }
    r.revision++;
    return { code: 0 };
  });
});
// 데이터 저장소 백업·복원·용량·삭제 (데몬 #47 계약)
const volFind = (t: string, name: string) => fx.volumes.find((v) => v.tenant === t && v.name === name);
const volGet = (m: string[]) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return { user, t: m[0], v: volFind(m[0], m[1]) };
};
on('GET', '/t/:t/volumes/:n', (m) => {
  const { t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  return ok({
    volume: v,
    backups: fx.volumeBackups.filter((b) => b.tenant === t && b.volume === v.name),
    restores: fx.volumeRestores.filter((r) => r.tenant === t && r.volume === v.name),
    archives: fx.volumeArchives.filter((a) => a.tenant === t && a.volume === v.name).map(({ tenant: _t, volume: _v, ...a }) => a),
    archiveReady: fx.archiveKeys.cluster && fx.archiveKeys.admin,
  });
});
// 내린 앱 저장소 보관(#920). 목업은 서버 일을 시간으로 흉내 낸다: 묶기 6초 → 비우기 3초 → 보관됨, 되살리기 6초
const archiveOf = (t: string, v: D.DVolume) => (v.archiveID ? fx.volumeArchives.find((a) => a.tenant === t && a.volume === v.name && a.id === v.archiveID) : undefined);
const archiveStep = (a: D.DVolumeArchive, v: D.DVolume, phase: string, extra: Partial<D.DVolumeArchive> = {}) => {
  Object.assign(a, { phase, revision: a.revision + 1, ...extra });
  v.revision++;
  if (['Restored', 'Cancelled', 'Discarded', 'Failed'].includes(phase)) {
    delete v.archiveID;
    delete v.archivePhase;
    delete v.phase;
  } else v.archivePhase = phase;
};
on('POST', '/t/:t/volumes/:n/archive', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  if (v.kind === 'fixed' || !v.app) return err(409, 'no-app', 'only app volumes can be archived');
  if (!fx.archiveKeys.cluster || !fx.archiveKeys.admin) return err(409, 'archive-keys', 'cluster key and admin key are both needed');
  const id = String(body.id ?? `a-${String(body.opId)}`);
  if (!/^[a-z][a-z0-9-]{0,60}$/.test(id)) return invalid('id: lowercase letter first, lowercase letters, digits and -, up to 61');
  const store = String(body.store ?? '') || (fx.storageRoots.find((r) => r.node === v.node && r.archiveDefault)?.id ?? 'default');
  if (!fx.storageRoots.some((r) => r.node === v.node && r.id === store)) return invalid('store: a storage root on the same server');
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'archive-volume', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (v.archiveID || v.consumers > 0 || v.movePhase) return INVALID;
    const used = v.usedBytes ?? 0;
    const compress = body.compress !== false;
    for (let i = fx.volumeArchives.length - 1; i >= 0; i--) if (fx.volumeArchives[i].tenant === t && fx.volumeArchives[i].volume === v.name) fx.volumeArchives.splice(i, 1);
    const a = { tenant: t, volume: v.name, id, node: v.node ?? 'node-a', store, phase: 'Packing', compression: compress ? 'zstd' : 'none', maxBytes: Number(body.maxBytes ?? 64 * 1024 ** 3), revision: 1 };
    fx.volumeArchives.push(a);
    Object.assign(v, { archiveID: id, archivePhase: 'Packing', phase: 'Archived', revision: v.revision + 1 });
    setTimeout(() => {
      if (a.phase !== 'Packing') return;
      archiveStep(a, v, 'Clearing', { tarBytes: used, dataBytes: compress ? Math.round(used / 3) : used });
      setTimeout(() => {
        archiveStep(a, v, 'Archived');
        v.usedBytes = 0;
      }, 3000);
    }, 6000);
    return { code: 0 };
  });
});
on('POST', '/t/:t/volumes/:n/unarchive', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  const a = body.id ? fx.volumeArchives.find((x) => x.tenant === t && x.volume === v.name && x.id === body.id) : archiveOf(t, v);
  if (!a) return err(404, 'not-found', 'no such archive');
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'unarchive-volume', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (a.phase !== 'Archived') return INVALID;
    archiveStep(a, v, 'Restoring');
    setTimeout(() => {
      v.usedBytes = a.tarBytes;
      archiveStep(a, v, 'Restored', { failure: undefined });
    }, 6000);
    return { code: 0 };
  });
});
const archiveVerb = (verb: 'POST' | 'DELETE', action: string, from: string, mid: string, to: string) =>
  on(verb, verb === 'DELETE' ? '/t/:t/volumes/:n/archives/:id' : '/t/:t/volumes/:n/archives/:id/cancel', (m, body) => {
    const { user, t, v } = volGet(m);
    const a = fx.volumeArchives.find((x) => x.tenant === t && x.volume === m[1] && x.id === m[2]);
    if (!v || !a) return err(404, 'not-found', 'no such archive');
    return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, action, () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      if (a.phase !== from) return INVALID;
      archiveStep(a, v, mid);
      setTimeout(() => archiveStep(a, v, to), 3000);
      return { code: 0 };
    });
  });
archiveVerb('POST', 'cancel-volume-archive', 'Packing', 'Cancelling', 'Cancelled');
archiveVerb('DELETE', 'discard-volume-archive', 'Archived', 'Discarding', 'Discarded');
on('POST', '/t/:t/volumes/:n/backups', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  if (v.kind === 'fixed' || !v.app) return err(409, 'no-app', 'only app volumes can be backed up');
  const id = String(body.id ?? `b-${String(body.opId)}`);
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'begin-volume-backup', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (fx.volumeBackups.some((b) => b.tenant === t && b.id === id)) return INVALID;
    const b: D.DVolumeBackup = { key: `${t}/${v.name}/${id}`, tenant: t, volume: v.name, id, node: v.node ?? 'node-a', phase: 'Reserved', revision: 1, bytes: 0, createdAt: Math.floor(Date.now() / 1000) };
    fx.volumeBackups.push(b);
    setTimeout(() => {
      if (b.phase === 'Reserved') Object.assign(b, { phase: 'Ready', bytes: v.usedBytes ?? 2 ** 30, revision: b.revision + 1 });
    }, 6000);
    return { code: 0 };
  });
});
const backupStep = (verb: string, action: string, from: string, mid: string, to: string) =>
  on(verb as 'POST', verb === 'DELETE' ? '/t/:t/volumes/:n/backups/:id' : '/t/:t/volumes/:n/backups/:id/cancel', (m, body) => {
    const { user, t, v } = volGet(m);
    const b = fx.volumeBackups.find((x) => x.tenant === t && x.volume === m[1] && x.id === m[2]);
    if (!v || !b) return err(404, 'not-found', 'no such backup');
    return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, action, () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      if (b.phase !== from) return INVALID;
      if (action === 'delete-volume-backup' && fx.volumeRestores.some((r) => r.backup === b.id && r.phase === 'Reserved')) return INVALID;
      Object.assign(b, { phase: mid, revision: b.revision + 1 });
      setTimeout(() => Object.assign(b, { phase: to, revision: b.revision + 1 }), 3000);
      return { code: 0 };
    });
  });
backupStep('POST', 'cancel-volume-backup', 'Reserved', 'Cancelling', 'Cancelled');
backupStep('DELETE', 'delete-volume-backup', 'Ready', 'Deleting', 'Deleted');
on('POST', '/t/:t/volumes/:n/restore', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  const target = (body.target ?? {}) as { name?: string; existing?: boolean; app?: string };
  if (target.existing) return err(422, 'restore-new-only', 'restore goes to a new volume');
  if (!validName(target.name)) return invalid('target.name: lowercase letters, digits and -');
  const b = fx.volumeBackups.find((x) => x.tenant === t && x.volume === v.name && x.id === body.backup);
  if (!b) return err(404, 'not-found', 'no such backup');
  if (b.phase !== 'Ready') return err(409, 'backup-not-ready', 'backup is not Ready');
  const need = b.bytes + 64 * 8192;
  if (need > 2 ** 40) return err(422, 'restore-too-large', 'restore needs more than 1 TiB');
  const id = `r-${String(body.opId).slice(0, 8)}`;
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'begin-volume-restore', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (fx.volumes.some((x) => x.tenant === t && x.name === target.name)) return INVALID;
    const r: D.DVolumeRestore = { key: `${t}/${v.name}/${id}`, tenant: t, volume: v.name, backup: b.id, id, node: b.node, phase: 'Reserved', target: String(target.name), revision: 1, maxBytes: need };
    fx.volumeRestores.push(r);
    setTimeout(() => {
      if (r.phase !== 'Reserved') return;
      Object.assign(r, { phase: 'Restored', revision: 2 });
      fx.volumes.push({ key: `vol/${t}/${r.target}`, tenant: t, name: r.target, kind: 'shared', node: b.node, app: target.app ?? v.app, revision: 1, consumers: 0, capacityBytes: v.capacityBytes, usedBytes: b.bytes, usageObservedAt: Date.now(), retain: true });
    }, 6000);
    return { code: 0 };
  });
});
on('POST', '/t/:t/volumes/:n/restores/:id/cancel', (m, body) => {
  const { user, t, v } = volGet(m);
  const r = fx.volumeRestores.find((x) => x.tenant === t && x.volume === m[1] && x.id === m[2]);
  if (!v || !r) return err(404, 'not-found', 'no such restore');
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'cancel-volume-restore', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (r.phase !== 'Reserved') return INVALID;
    Object.assign(r, { phase: 'Cancelling', revision: r.revision + 1 });
    setTimeout(() => Object.assign(r, { phase: 'Cancelled', revision: r.revision + 1 }), 3000);
    return { code: 0 };
  });
});
on('PUT', '/t/:t/volumes/:n/capacity', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  const bytes = Number(body.bytes ?? 0);
  if (!(bytes > 0) || bytes > 2 ** 40) return invalid('bytes: 1 B to 1 TiB');
  if (bytes <= (v.capacityBytes ?? 0)) return err(422, 'capacity-grow-only', 'capacity can only grow');
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, 'set-volume-capacity', () => {
    if (!user.systemAdmin) return FORBIDDEN;
    v.capacityBytes = bytes;
    v.revision++;
    return { code: 0 };
  });
});
on('DELETE', '/t/:t/volumes/:n', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  return submit(user, { ...body, tenant: t, target: `volume/${v.name}` }, v.kind === 'fixed' ? 'unregister-fixed-volume' : 'delete-volume', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (v.consumers > 0 || v.archiveID) return INVALID;
    fx.volumes.splice(fx.volumes.indexOf(v), 1);
    return { code: 0 };
  });
});
// 데이터 저장소 옮기기 (UI-64, 데몬 #69). 목업은 서버 일을 시간으로 흉내 낸다: 접수 → 2초 전송 → 8초 확정 → 12초 끝(원본 보존)
const moveTimers = new Map<string, ReturnType<typeof setTimeout>[]>();
const moveCheck = (v: D.DVolume | undefined, body: Record<string, unknown>) => {
  if (!v) return err(404, 'not-found', 'no such volume');
  if (v.kind === 'fixed' || !v.app) return err(409, 'no-app', 'only app volumes can move');
  if (v.movePhase) return err(409, 'moving', 'this volume is already moving');
  const to = String(body.node ?? '');
  if (!to || to === v.node) return invalid('node: another server');
  return undefined;
};
const movePlanOf = (t: string, v: D.DVolume, to: string) => {
  const yaml = `name: ${v.app}\nvolumes:\n  ${v.name}:\n    x-sfc:\n      node: ${to}\n`;
  const digest = Array.from(yaml).reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7).toString(16).padStart(8, '0').repeat(8);
  const svc = (v.writer ?? `${v.app}/app`).split('/')[1];
  const cap = v.capacityBytes ?? 10 * 1024 ** 3;
  return { volume: v.name, app: v.app!, id: 'mv-plan', from: v.node ?? '', to, yaml, digest, capacityBytes: cap, maxBytes: cap, maxEntries: 100000, transferSeconds: 900, expiresAt: new Date(Date.now() + 900_000).toISOString(), cd: false, services: [{ name: svc, image: '', node: to, change: 'update' }], tenant: t };
};
on('POST', '/t/:t/volumes/:n/move-plan', (m, body) => {
  const { t, v } = volGet(m);
  const bad = moveCheck(v, body);
  if (bad) return bad;
  const { tenant: _t, ...p } = movePlanOf(t, v!, String(body.node));
  return ok(p);
});
on('POST', '/t/:t/volumes/:n/move', (m, body) => {
  const { user, t, v } = volGet(m);
  const existing = findOp(String(body.opId ?? ''), user.id);
  if (!existing) {
    const bad = moveCheck(v, body);
    if (bad) return bad;
    if (body.digest && body.digest !== movePlanOf(t, v!, String(body.node)).digest) return err(409, 'digest-mismatch', 'the app definition changed since the plan');
  }
  const id = String(body.id || `mv-${String(body.opId).slice(0, 8)}`);
  return submit(user, { ...body, tenant: t, target: v?.name }, 'volume-move', () => {
    if (!canWrite(user, t) || !v) return FORBIDDEN;
    if (v.movePhase) return CAS;
    const to = String(body.node);
    Object.assign(v, { phase: 'Moving', moveID: id, targetNode: to, movePhase: 'Prepared', revision: v.revision + 1 });
    const step = (ms: number, f: () => void) => setTimeout(() => v.moveID === id && f(), ms);
    moveTimers.set(id, [
      step(2000, () => Object.assign(v, { movePhase: 'Copying', revision: v.revision + 1 })),
      step(8000, () => Object.assign(v, { movePhase: 'OwnerCommitted', revision: v.revision + 1 })),
      step(12000, () => {
        const from = v.node ?? '';
        Object.assign(v, { phase: 'Ready', node: to, moveID: undefined, targetNode: undefined, movePhase: undefined, revision: v.revision + 1, retained: [...(v.retained ?? []), { moveID: id, node: from, state: 'retained' as const }] });
      }),
    ]);
    return { code: 0 };
  });
});
on('POST', '/t/:t/volumes/:n/move/cancel', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  if (!findOp(String(body.opId ?? ''), user.id) && (!v.movePhase || (body.id && body.id !== v.moveID))) return err(409, 'not-moving', 'this volume is not moving');
  return submit(user, { ...body, tenant: t, target: v.name }, 'cancel-volume-move', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (!v.movePhase || ['OwnerCommitted', 'Activating', 'Active', 'Completed'].includes(v.movePhase)) return INVALID;
    (moveTimers.get(v.moveID ?? '') ?? []).forEach(clearTimeout);
    Object.assign(v, { phase: 'Ready', moveID: undefined, targetNode: undefined, movePhase: undefined, revision: v.revision + 1 });
    return { code: 0 };
  });
});
on('DELETE', '/t/:t/volumes/:n/retained/:id', (m, body) => {
  const { user, t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  const r = (v.retained ?? []).find((x) => x.moveID === m[2]);
  if (!findOp(String(body.opId ?? ''), user.id) && r && r.state !== 'retained') return err(409, 'not-retained', 'this source copy is already being deleted or gone');
  return submit(user, { ...body, tenant: t, target: v.name }, 'delete-retained-volume', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (!r || r.state !== 'retained') return INVALID;
    r.state = 'deleting';
    setTimeout(() => (r.state = 'removed'), 3000);
    return { code: 0 };
  });
});
// 백업 한도. 서버 전체 행은 시스템 관리자에게만 값이 간다. node-b에는 작업 공간 행이 없어 백업이 막힌다.
type Limit = Omit<D.DBackupLimit, 'used' | 'hidden'>;
const limits: Limit[] = [
  { node: 'node-a', scope: 'server', count: 30, bytes: 500 * 1024 ** 3, stagingCount: 2, stagingBytes: 100 * 1024 ** 3, revision: 1 },
  { node: 'node-a', scope: 'workspace', count: 5, bytes: 200 * 1024 ** 3, stagingCount: 1, stagingBytes: 60 * 1024 ** 3, revision: 1 },
  { node: 'node-b', scope: 'server', count: 30, bytes: 500 * 1024 ** 3, stagingCount: 2, stagingBytes: 100 * 1024 ** 3, revision: 1 },
];
const limitKey = (t: string, l: Pick<Limit, 'node' | 'scope'>) => (l.scope === 'server' ? l.node : `${t}@${l.node}`);
const limitRows: Record<string, Limit> = {};
for (const l of limits) for (const t of ['shop', 'internal']) limitRows[limitKey(t, l)] ??= { ...l };
function limitUsed(t: string, l: Limit) {
  const bs = fx.volumeBackups.filter((b) => b.node === l.node && (l.scope === 'server' || b.tenant === t) && b.phase !== 'Deleted' && b.phase !== 'Cancelled' && b.phase !== 'Failed');
  const staging = bs.filter((b) => b.phase === 'Reserved');
  return { count: bs.length, bytes: bs.reduce((a, b) => a + b.bytes, 0), stagingCount: staging.length, stagingBytes: staging.reduce((a, b) => a + b.bytes, 0) };
}
on('GET', '/t/:t/backup-limits', (_m, _b, query) => {
  const { user } = requireSession();
  const t = _m[0];
  requireTenant(user, t);
  const node = query.get('node') ?? '';
  const rows = [limitRows[node], limitRows[`${t}@${node}`]].filter(Boolean) as Limit[];
  return ok({ items: rows.map((l) => (l.scope === 'server' && !user.systemAdmin ? { node: l.node, scope: l.scope, hidden: true, count: 0, bytes: 0, stagingCount: 0, stagingBytes: 0, revision: 0, used: { count: 0, bytes: 0, stagingCount: 0, stagingBytes: 0 } } : { ...l, hidden: false, used: limitUsed(t, l) })) });
});
on('PUT', '/t/:t/backup-limits/:node', (m, body) => {
  const { user } = requireSession();
  const [t, node] = m;
  requireTenant(user, t);
  const scope = body.scope === 'server' ? 'server' : 'workspace';
  const num = (k: string) => (typeof body[k] === 'number' && Number.isInteger(body[k]) && (body[k] as number) >= 0 ? (body[k] as number) : undefined);
  if (num('count') === undefined || num('bytes') === undefined) return invalid('count and bytes: non-negative integers');
  return submit(user, { ...body, tenant: t, target: `backup-limit/${node}` }, 'set-volume-backup-limit', () => {
    if (!user.systemAdmin) return FORBIDDEN;
    const k = limitKey(t, { node, scope });
    const cur = limitRows[k];
    if (Number(body.expected ?? cur?.revision ?? 0) !== (cur?.revision ?? 0)) return CAS;
    const next: Limit = { node, scope, count: num('count')!, bytes: num('bytes')!, stagingCount: num('stagingCount') ?? cur?.stagingCount ?? 1, stagingBytes: num('stagingBytes') ?? cur?.stagingBytes ?? 0, revision: (cur?.revision ?? 0) + 1 };
    const used = limitUsed(t, next);
    if (next.count < used.count || next.bytes < used.bytes) return INVALID;
    limitRows[k] = next;
    return { code: 0 };
  });
});
on('GET', '/t/:t/volumes/:n/users', (m) => {
  const { t, v } = volGet(m);
  if (!v) return err(404, 'not-found', 'no such volume');
  return ok({ tenant: t, volume: v.name, users: fx.volumeUsers[`${t}/${v.name}`] ?? [], ...userCounts(fx.volumeUsers[`${t}/${v.name}`]) });
});
// 보관함 쓰기(값 넣기·묶음 비밀번호). 값·비밀번호는 목업에서도 어디에도 남기지 않는다(작업 기록에는 path만).
// 같은 opId로 다시 보내면 멈춘 곳부터 잇는다. 첫 값이 'mock:needs-input' · 'mock:input-unknown' · 'mock:not-applied'면 그 상태를 흉내 낸다.
// 보관함 경로의 작업 공간. 클러스터 보관함(/vault)은 시스템 관리자만. 목업 안에서는 tenant 'cluster'로 모은다(realm은 "")
const vaultAuth = (m: RegExpMatchArray | string[]) => {
  const { user } = requireSession();
  if (m[0] === undefined) {
    requireAdmin(user);
    return { user, t: 'cluster' };
  }
  requireTenant(user, m[0]);
  return { user, t: m[0] };
};
const vaultSecretWrite = (path: string, action: string, field: 'values' | 'password') =>
  on('POST', path, (m, body) => {
    const { user, t } = vaultAuth(m);
    const p = String(body.path ?? '');
    const v = body[field];
    const opId = String(body.opId ?? '');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (!p) return invalid('path is required');
    const has = field === 'values' ? !!v && typeof v === 'object' && Object.keys(v as object).length > 0 : typeof v === 'string' && v.length > 0;
    const apply = (): Applied => {
      if (!canWrite(user, t)) return FORBIDDEN;
      const o = fx.vault.find((x) => x.tenant === t && x.path === p);
      if (!o || (o.status ?? 'active') !== 'active' || (field === 'values' && o.kind !== 'object') || (field === 'password' && o.kind !== 'group')) return { code: 2, errorCode: 'result-2' };
      // sfcd처럼 쓴 키가 그 비밀값의 새 키가 된다.
      if (field === 'values' && has) o.keys = Array.isArray(body.keys) && body.keys.length ? body.keys.map(String) : Object.keys(v as object);
      if (field === 'password') o.protected = true;
      o.revision++;
      return { code: 0 };
    };
    const cur = findOp(opId, user.id);
    if (cur) {
      if (cur.target !== p || cur.action !== action) return err(409, 'op-conflict', '같은 작업 ID에 다른 내용이 왔습니다.');
      if (cur.state === 'applied' || cur.state === 'failed') return opReply(cur);
      if (cur.errorCode === 'needs-input' && !has) return err(400, 'bad-request', '값을 다시 넣어 보내 주세요.');
      settle(cur, apply()); // needs-input: 값으로 잇기, input-unknown: 값 없이 결과 확인(목업에서는 닿았다고 본다)
      return opReply(cur);
    }
    if (!has) return err(400, 'bad-request', field === 'values' ? 'values: {key: value}' : 'password is required');
    // 처음 정하는 비밀번호는 검증값 프로필이 있어야 한다(없으면 sfcd가 403).
    if (field === 'password' && !fx.vault.find((x) => x.tenant === t && x.path === p)?.protected && !body.profile) return err(403, 'forbidden', 'profile is required for the first password');
    if (field === 'password' && String(v).length > 1024) return invalid('password: at most 1024 bytes');
    const first = field === 'values' ? String(Object.values(v as object)[0]) : String(v);
    const op = newOp(user, opId, action, t, p, '');
    fx.ops.unshift(op);
    (op as fx.MockOp & { steps?: number }).steps = 4;
    if (first === 'mock:needs-input') Object.assign(op, { state: 'running', errorCode: 'needs-input', step: 2 });
    else if (first === 'mock:input-unknown') Object.assign(op, { state: 'unknown', errorCode: 'input-unknown', step: 2 });
    else if (first === 'mock:not-applied') Object.assign(op, { state: 'failed', errorCode: 'write-not-applied', resultFound: true });
    else settle(op, apply());
    return opReply(op);
  });
for (const base of ['/t/:t/vault', '/vault']) {
  vaultSecretWrite(`${base}/value`, 'vault-value', 'values');
  vaultSecretWrite(`${base}/password`, 'vault-password', 'password');
}
const vaultCreate: Handler = (m, body) => {
  const { user, t } = vaultAuth(m);
  const realm = t === 'cluster' ? '' : t;
  if (t === 'cluster' && !clusterVaultReady) return err(409, 'not-initialized', 'initialize the cluster vault first');
  if (body.realm && body.realm !== realm) return invalid('realm must be this workspace');
  const id = String(body.id ?? '');
  const parent = String(body.parent ?? '');
  if (!validName(id)) return invalid("id: lowercase letters, digits and '-'");
  const keys = Array.isArray(body.keys) ? (body.keys as unknown[]).map(String) : [];
  if (body.kind === 'group') {
    if (body.profile || body.object || keys.length) return invalid('a group has no profile, object or keys');
  } else if (body.kind === 'secret') {
    if (!keys.length || keys.length > 64) return invalid('keys: 1..64 names');
  } else return invalid('kind: "secret" or "group"');
  // parent는 묶음 ID, 최상위는 작업 공간 이름(데몬 #58)
  if (!parent) return invalid('parent: a group ID or the workspace');
  const pg = parent === t ? undefined : fx.vault.find((v) => v.tenant === t && v.kind === 'group' && v.id === parent);
  const full = pg ? `${pg.path}/${id}` : id;
  return submit(user, { ...body, tenant: t, target: `${parent}/${id}` }, 'vault-create', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (parent !== t && (!pg || pg.status !== 'active')) return INVALID;
    if (fx.vault.some((v) => v.tenant === t && (v.path === full || v.id === id))) return INVALID;
    const base = { tenant: t, realm, path: full, revision: 1, id, parent, status: 'active' as const, acl: { users: [], services: [], denyUsers: [], denyServices: [] }, group: pg?.id };
    if (body.kind === 'group') fx.vault.push({ ...base, kind: 'group', profile: '', keys: [] });
    else fx.vault.push({ ...base, kind: 'object', profile: String(body.profile || 'file'), keys: [...keys].sort() });
    return { code: 0 };
  });
};
on('POST', '/t/:t/vault', vaultCreate);
on('POST', '/vault', vaultCreate);
// 비밀값 객체 정책(UI-70, 데몬 #58). expected 기본은 객체 revision. 상태 판단은 secrets.Tree 규칙을 흉내 낸다.
type MockVault = (typeof fx.vault)[number];
const vaultBelow = (t: string, id: string) => {
  const out = new Set([id]);
  for (let grew = true; grew; ) {
    grew = false;
    for (const v of fx.vault) if (v.tenant === t && out.has(v.parent ?? '') && !out.has(v.id ?? '')) (out.add(v.id ?? ''), (grew = true));
  }
  return out;
};
const vaultPolicy = (method: 'POST' | 'PUT' | 'PATCH', sub: string, action: string, check: (o: MockVault, body: Record<string, unknown>, t: string) => RawResponse | undefined, apply: (o: MockVault, body: Record<string, unknown>, t: string) => Applied) =>
  ['/t/:t/vault', '/vault'].forEach((base) => on(method, `${base}/${sub}`, (m, body) => {
    const { user, t } = vaultAuth(m);
    const o = fx.vault.find((x) => x.tenant === t && x.id === String(body.id ?? ''));
    if (!o) return err(404, 'not-found', 'no such vault object');
    const pre = check(o, body, t);
    if (pre) return pre;
    const expected = Number(body.expected ?? 0) || o.revision;
    return submit(user, { ...body, tenant: t, target: `vault/${o.path}` }, action, () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      if (o.revision !== expected) return CAS;
      const r = apply(o, body, t);
      if (r) return r;
      o.revision = Math.max(...fx.vault.map((v) => v.revision)) + 1;
    });
  }));
const notActive = (o: MockVault) => ((o.status ?? 'active') !== 'active' ? err(409, 'not-active', `the object is ${o.status}`) : undefined);
// 바뀐 이름만 받는다(R17). 이미 있는 이름을 더하거나 없는 이름을 빼면 실패한다.
const aclKeys = ['users', 'services', 'denyUsers', 'denyServices'] as const;
const aclPart = (b: Record<string, unknown>, side: 'add' | 'remove', k: string) => ((b[side] as Record<string, unknown> | undefined)?.[k] ?? []) as unknown;
vaultPolicy('PATCH', 'acl', 'vault-acl', (o, b) => {
  const lists = aclKeys.flatMap((k) => [aclPart(b, 'add', k), aclPart(b, 'remove', k)]);
  if (lists.some((l) => !Array.isArray(l) || l.length > 256 || l.some((n) => typeof n !== 'string' || !n || n.length > 200))) return invalid('acl: lists of 1..200 character names');
  if (lists.every((l) => (l as string[]).length === 0)) return invalid('acl: nothing to change');
  return notActive(o);
}, (o, b) => {
  const next = { users: [] as string[], services: [] as string[], denyUsers: [] as string[], denyServices: [] as string[], ...o.acl };
  for (const k of aclKeys) {
    const add = aclPart(b, 'add', k) as string[];
    const remove = aclPart(b, 'remove', k) as string[];
    const cur = new Set(o.acl?.[k] ?? []);
    if (remove.some((n) => !cur.has(n) || add.includes(n)) || add.some((n) => cur.has(n))) return CAS;
    next[k] = [...[...cur].filter((n) => !remove.includes(n)), ...new Set(add)].sort();
  }
  o.acl = next;
});
vaultPolicy('POST', 'move', 'vault-move', (o, b) => (!b.parent || b.parent === o.parent ? invalid('parent: another group') : notActive(o)), (o, b, t) => {
  const to = String(b.parent);
  const pg = to === t ? undefined : fx.vault.find((v) => v.tenant === t && v.kind === 'group' && v.id === to);
  if ((to !== t && (!pg || pg.status !== 'active')) || vaultBelow(t, o.id ?? '').has(to)) return CAS;
  const oldPath = o.path;
  o.parent = to;
  o.path = pg ? `${pg.path}/${o.id}` : (o.id ?? o.path);
  for (const v of fx.vault) if (v.tenant === t && v.path.startsWith(`${oldPath}/`)) v.path = o.path + v.path.slice(oldPath.length);
  if (o.kind === 'object') o.group = pg?.id;
});
vaultPolicy('PUT', 'approval-age', 'vault-approval-age', (o, b) => {
  if (o.kind !== 'group') return err(409, 'not-group', 'only a group has an approval age');
  const n = Number(b.seconds);
  return !Number.isInteger(n) || n < 0 || n > 366 * 86400 ? invalid('seconds: 0 (no limit) .. 366 days') : undefined;
}, (o, b) => {
  if ((o.status ?? 'active') !== 'active') return CAS;
  o.maxApprovalAge = Number(b.seconds);
});
vaultPolicy('POST', 'revoke', 'vault-revoke', () => undefined, (o) => {
  if (o.status === 'retired') return CAS;
  o.status = 'revoking';
});
vaultPolicy('POST', 'retire', 'vault-retire', (o) => (o.status !== 'revoking' ? err(409, 'not-revoking', 'revoke the object first') : undefined), (o, _b, t) => {
  const kids = fx.vault.some((v) => v.tenant === t && v.parent === o.id && v.status !== 'retired');
  if (kids || o.pendingWrite || vaultUsing(t, o.id ?? '').some((u) => u.live)) return INVALID;
  o.status = 'retired';
});
tenantGet('registries', (t) => byTenant(fx.registries, t).map((r) => ({ ...r, maintenance: maintSummary(t, r.id) })));
// 내장 저장소 정의(web-api.md '내장 저장소 (UI-80)'). 정의 검사·권한은 sfcd 몫이라 목업은 최소만 본다.
const regFind = (t: string, id: string) => fx.registries.find((r) => r.tenant === t && r.id === id);
on('PUT', '/t/:t/registries/:id', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const cur = regFind(t, id);
  if (cur?.deleted) return err(409, 'deleted', 'this registry ID was deleted; use another ID');
  // 서버는 모르는 필드를 거절한다(인증서는 authority 호스트로 보관함에서 찾는다)
  if ('certificate' in body) return err(400, 'bad-request', 'json: unknown field "certificate"');
  if (cur && body.volume && body.volume !== cur.volume) return invalid('volume: a registry keeps its Volume');
  let vol: D.DVolume | undefined;
  if (!cur) {
    if (!body.authority || !body.volume) return invalid('a new registry needs authority and volume');
    vol = fx.volumes.find((v) => v.tenant === t && v.name === body.volume);
    if (!vol) return err(404, 'not-found', 'no such volume');
  }
  const authority = String(body.authority ?? cur?.endpoint ?? '');
  const port = /:(\d+)$/.exec(authority)?.[1] ?? '443';
  const address = String(body.address ?? (cur && !body.authority ? cur.address : `0.0.0.0:${port}`));
  if ((/:(\d+)$/.exec(address)?.[1] ?? '') !== port) return invalid('address: port must match the authority port');
  const expected = Number(body.expected ?? 0) || (cur?.revision ?? 0);
  return submit(user, { ...body, tenant: t, target: `registry/${id}` }, 'put-registry', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (cur) {
      if (expected !== cur.revision) return CAS;
      if (authority !== cur.endpoint) cur.certificateID = undefined; // 새 호스트의 인증서는 노드가 다시 보고한다
      Object.assign(cur, {
        endpoint: authority,
        address,
        node: String(body.node ?? cur.node),
        limits: (body.limits as D.DRegistryLimits | undefined) ?? cur.limits,
        revision: cur.revision + 1,
        generation: cur.generation + 1,
      });
      if (cur.enabled) (cur.status = 'pending'), (cur.observedAt = 0);
      return;
    }
    if (vol!.kind !== 'fixed' || !vol!.retain) return INVALID;
    fx.registries.push({ tenant: t, id, name: id, endpoint: authority, revision: 1, generation: 1, active: false, repositories: 0, node: String(body.node ?? vol!.node), address, volume: vol!.name, enabled: true, status: 'pending', limits: fx.registryLimits(Math.round((vol!.capacityBytes ?? 50 * 2 ** 30) / 2 ** 30)) });
  });
});
// 저장소 이미지와 정리(UI-84·8A, #242 mock). 쪽마다 8행. 삭제·GC·정리 op의 applied는 수락이고, 진행은 registry-maintenance/web-<opId>
const imgsOf = (t: string, id: string, external = false) => fx.registryImages.filter((i) => i.tenant === t && i.registry === id && !!i.external === external);
const globRe = (pat: string) => new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
const CAT_PAGE = 8;
const secIso = (v: string | number) => (typeof v === 'string' ? v : v ? new Date(v * 1000).toISOString() : undefined);
const catRow = (im: fx.MockRegistryImage, reference: string): D.DCatalogRow => ({
  repository: im.repository,
  reference,
  digest: im.digest,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  manifestBytes: 1200 + (im.bytes % 900),
  imageBytes: im.bytes,
  uploadedAt: im.external ? undefined : secIso(im.pushedAt),
});
/** 한 이미지의 목록 행: 태그마다 한 행, 내장 저장소는 digest 자체 행도 */
const catRows = (im: fx.MockRegistryImage) => [...(im.tags ?? []).map((tg) => catRow(im, tg)), ...(im.external && im.tags?.length ? [] : [catRow(im, im.digest)])];
/** 목록을 읽을 수 있는지: 내장은 지우지 않은 정의, 외부는 읽는 서버가 있는 켜진 정의 */
function catSource(t: string, id: string, external: boolean): RawResponse | { authority: string } {
  if (external) {
    const x = fx.externalRegistries.find((r) => r.tenant === t && r.id === id);
    if (!x || x.deleted) return err(404, 'not-found', 'no such external registry');
    if (!x.enabled || !x.reader) return err(409, 'not-bound', 'no node reads this source');
    return { authority: x.authority };
  }
  const r = regFind(t, id);
  return !r || r.deleted ? err(404, 'not-found', 'no such registry') : { authority: r.endpoint };
}
const catCache = new Map<string, number>();
on('GET', '/t/:t/registries/:id/images', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const external = query.get('external') === '1';
  const src = catSource(t, id, external);
  if ('status' in src) return src;
  const ck = `${user.id}/${t}/${external}/${id}`;
  if (query.get('refresh') || !catCache.has(ck) || Date.now() - catCache.get(ck)! > 10 * 60_000) catCache.set(ck, Date.now());
  const base = { kind: external ? 'external' : 'managed', id, authority: src.authority, live: external, untaggedComplete: !external, asOf: nowIso(), cachedAt: new Date(catCache.get(ck)!).toISOString() };
  const repository = query.get('repository') ?? '';
  const from = Number(query.get('after') || 0);
  const list = imgsOf(t, id, external);
  if (!repository) {
    const repos = [...new Set(list.map((i) => i.repository))].sort();
    const pg = repos.slice(from, from + CAT_PAGE);
    return ok({ ...base, repositories: pg, items: [], next: from + CAT_PAGE < repos.length ? String(from + CAT_PAGE) : '' });
  }
  const rows = list
    .filter((i) => i.repository === repository)
    .sort((a, b) => Number(b.pushedAt) - Number(a.pushedAt))
    .flatMap(catRows);
  if (!rows.length) return ok({ ...base, repository, code: 'not-found', repositories: [], items: [], next: '' });
  return ok({ ...base, repository, repositories: [], items: rows.slice(from, from + CAT_PAGE), next: from + CAT_PAGE < rows.length ? String(from + CAT_PAGE) : '' });
});
// 외부 저장소(UI-83, #232 mock). 시각은 Unix 초. 자격이 보호 묶음이면 연결(bind)에 묶음 승인이 필요하다(비밀번호 'late'는 늦은 승인 거절)
const extOf = (t: string) => fx.externalRegistries.filter((r) => r.tenant === t);
const extPublic = ({ tenant: _t, test: _x, users: _u, ...r }: fx.MockExternalRegistry) => r;
const extFind = (t: string, id: string) => extOf(t).find((x) => x.id === id);
const EXT_GONE = () => err(404, 'not-found', 'no such external registry');
on('GET', '/t/:t/external-registries', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return ok({ items: extOf(m[0]).map(extPublic), next: '', revision: ROOT_REVISION + fx.ops.length, asOf: nowIso() });
});
on('GET', '/t/:t/external-registries/:id/users', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const r = extFind(m[0], m[1]);
  if (!r) return EXT_GONE();
  const from = Number(query.get('after') || 0);
  const page = r.users.slice(from, from + 50);
  return ok({ items: page, next: from + 50 < r.users.length ? String(from + 50) : '', asOf: nowIso() });
});
on('POST', '/t/:t/external-registries/:id/test', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  if (!canWrite(user, m[0])) return err(403, 'forbidden', 'needs registry management permission');
  const r = extFind(m[0], m[1]);
  if (!r || r.deleted) return EXT_GONE();
  if (!r.reader || r.reader.draining) return err(409, 'not-bound', 'no node reads this source; bind one first');
  const image = body.image ? String(body.image) : '';
  const c = r.credential;
  const credOk = !c || fx.vault.some((v) => v.realm === c.realm && v.id === c.id && v.keys?.includes(c.usernameKey) && v.keys?.includes(c.passwordKey));
  const repo = image.replace(/^[^/]*[.:][^/]*\//, '').replace(/[:@][^/]*$/, '');
  const scoped = !image || r.repository === '**' || globRe(r.repository.replace(/\*\*/g, '*')).test(repo);
  const code: D.LoginTestCode = !credOk ? 'invalid-credential' : r.test === 'ok' && !scoped ? 'denied' : r.test;
  const at = fx.nowSec();
  const digest = 'sha256:' + '4e1c0b7a'.repeat(8);
  const res: D.DLoginTest = { id: r.id, generation: r.reader.generation, owner: r.reader.owner, at, code };
  if (code === 'ok' && image) {
    res.image = { normalized: `${r.authority}/${repo}${image.slice(image.lastIndexOf(repo) + repo.length) || ':latest'}`, registry: r.authority, repository: repo, pinned: `${r.authority}/${repo}@${digest}`, digest, mediaType: 'application/vnd.oci.image.index.v1+json', manifestBytes: 1843, platforms: ['linux/amd64', 'linux/arm64'] };
    res.pull = { manifestDigest: digest, platform: 'linux/amd64', blobs: 7, compressedBytes: 48_300_000 };
  }
  return ok(res);
});
on('PUT', '/t/:t/external-registries/:id', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const cur = extFind(t, id);
  const authority = String(body.authority ?? '');
  const repository = String(body.repository ?? '') || '**';
  const auth = body.auth === 'password' || body.auth === 'token' || body.auth === 'none' ? body.auth : '';
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/.test(authority)) return invalid('authority: lowercase host[:port]');
  if (byTenant(fx.registries, t).some((r) => r.endpoint === authority)) return invalid('authority: a built-in registry address');
  if (!/^(\*\*|[a-z0-9]+([._/-][a-z0-9]+)*(\/\*\*)?)$/.test(repository)) return invalid('repository: exact path, prefix/** or **');
  if (!auth) return invalid('auth: none, password or token');
  if ((auth !== 'none') !== !!body.credential) return invalid('credential: required for password/token, not allowed for none');
  if (cur && !cur.deleted && (cur.authority !== authority || cur.repository !== repository)) return err(409, 'scope-fixed', 'authority and repository cannot change; delete and register again');
  const expected = Number(body.expected ?? 0) || (cur?.revision ?? 0);
  return submit(user, { ...body, tenant: t, target: `external-registry/${id}` }, 'put-external-registry', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (expected !== (cur?.revision ?? 0)) return CAS;
    const next = { authority, repository, enabled: body.enabled !== false, auth: auth as D.DExternalRegistry['auth'], credential: body.credential as D.DRegistrySecretRef | undefined, ca: body.ca as D.DRegistryCARef | undefined, deleted: false };
    // 정의를 바꾸면 읽던 서버는 멈춘다. 다시 연결해야 한다
    if (cur) Object.assign(cur, next, { revision: cur.revision + 1, reader: undefined });
    else fx.externalRegistries.push({ tenant: t, id, ...next, revision: 1, pulls: [], test: 'ok', users: [] });
  });
});
on('DELETE', '/t/:t/external-registries/:id', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const cur = extFind(t, id);
  if (!cur || cur.deleted) return EXT_GONE();
  const expected = Number(body.expected ?? 0) || cur.revision;
  return submit(user, { ...body, tenant: t, target: `external-registry/${id}` }, 'delete-external-registry', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (expected !== cur.revision) return CAS;
    Object.assign(cur, { deleted: true, enabled: false, reader: undefined, revision: cur.revision + 1 });
  });
});
type BindWait = { tenant: string; source: string; node: string; approvals: D.DGroupApproval[]; op: fx.MockOp; go: () => RawResponse };
const bindWaits = new Map<string, BindWait>();
const extBound = (r: fx.MockExternalRegistry, node: string) => () => {
  r.reader = { node, owner: `reader-${node}`, generation: (r.reader?.generation ?? 0) + 1, draining: false };
  r.revision += 1;
};
on('POST', '/t/:t/external-registries/:id/bind', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const r = extFind(t, id);
  if (!r) return EXT_GONE();
  const opId = String(body.opId ?? '');
  const w = bindWaits.get(opId);
  if (w) return ok({ op: publicOp(w.op) }, 202);
  const node = String(body.node ?? '');
  if (!fx.members.some((n) => n.id === node)) return invalid('node: no such node');
  if (r.deleted || !r.enabled) return err(409, 'not-bindable', 'the source is deleted or disabled');
  const go = () =>
    submit(user, { ...body, tenant: t, target: `external-registry/${id}` }, 'bind-external-registry', () => {
      if (!canWrite(user, t)) return FORBIDDEN;
      extBound(r, node)();
    });
  const c = r.credential;
  const group = c && fx.vault.find((v) => v.tenant === t && v.kind === 'object' && v.id === c.id)?.group;
  const now = fx.nowSec();
  const need = group && fx.vault.some((v) => v.tenant === t && v.kind === 'group' && v.id === group && v.protected) && !fx.grantedApprovals.some((a) => a.tenant === t && a.group === group && a.app === `registry:${id}` && !a.revoking && (!a.expiresAt || a.expiresAt > now));
  if (!need) return go();
  const op = newOp(user, opId, 'bind-external-registry', t, `external-registry/${id}`, '');
  Object.assign(op, { state: 'running', errorCode: 'approval-required', approvals: [{ realm: t, group, services: [], state: 'required' }] });
  fx.ops.unshift(op);
  bindWaits.set(opId, { tenant: t, source: id, node, approvals: op.approvals as D.DGroupApproval[], op, go });
  return ok({ op: publicOp(op) }, 202);
});
on('POST', '/t/:t/external-registries/:id/bind/:op/approve', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const bad = checkPassword(body);
  if (bad) return bad;
  const w = bindWaits.get(m[2]);
  if (!w || w.tenant !== m[0] || w.source !== m[1]) return err(404, 'not-found', 'no such bind job');
  const realm = String(body.realm || m[0]);
  const a = w.approvals.find((x) => x.realm === realm && x.group === String(body.group ?? ''));
  if (w.op.errorCode !== 'approval-required' || !a) return err(409, 'not-required', 'this bind does not wait for that Group');
  if (a.state === 'approved') return err(409, 'already-approved', 'this Group is already approved');
  const pw = String(body.password);
  const k = approvalKind(pw);
  a.state = k === 'ok' ? 'approved' : k === 'denied' ? 'required' : 'unknown';
  w.op.approvals = w.approvals.map((x) => ({ ...x }));
  if (k === 'denied') return err(403, 'approval-denied', 'the password was not accepted for this Group');
  if (k === 'unknown') return err(502, 'approval-unknown', "the approver's answer was lost; send the password again");
  grant(user, m[0], `registry:${w.source}`, a.group, []);
  if (w.approvals.some((x) => x.state !== 'approved')) return opReply(w.op);
  bindWaits.delete(m[2]);
  if (pw === 'late') {
    Object.assign(w.op, { state: 'failed', errorCode: 'approval-rejected', updatedAt: nowIso() });
    return opReply(w.op);
  }
  fx.ops.splice(fx.ops.indexOf(w.op), 1);
  return w.go();
});
on('POST', '/t/:t/external-registries/:id/unbind', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const r = extFind(t, id);
  if (!r) return EXT_GONE();
  if (!r.reader) return err(409, 'not-bound', 'no node reads this source');
  const expected = Number(body.expected ?? 0) || r.revision;
  return submit(user, { ...body, tenant: t, target: `external-registry/${id}` }, 'unbind-external-registry', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (expected !== r.revision) return CAS;
    r.reader = undefined;
    r.revision += 1;
  });
});
on('POST', '/t/:t/image-usage', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const refs = Array.isArray(body.refs) ? body.refs.map(String) : [];
  if (!refs.length || refs.length > 32) return invalid('refs: 1..32');
  return ok({ items: refs.map((ref) => imageUseRow(m[0], ref)) });
});
/** usedBy 'php-shop/web' = 앱 실행, 'php-shop'(서비스 없음) = 자동 배포 후보. 태그로 물으면 match가 repository-unknown */
function imageUseRow(t: string, ref: string) {
  const all = fx.registryImages.filter((i) => i.tenant === t);
  const byDigest = /^sha256:[0-9a-f]{64}$/.test(ref) || ref.includes('@sha256:');
  const im = all.find((i) => i.digest === ref || ref.endsWith('@' + i.digest) || (i.tags ?? []).some((tg) => ref.endsWith(`${i.repository}:${tg}`)));
  const host = im ? (im.external ? fx.externalRegistries.find((x) => x.tenant === t && x.id === im.registry)?.authority : regFind(t, im.registry)?.endpoint) : '';
  const rows = (im?.usedBy ?? []).map((u, k) => {
    const [app, service] = u.split('/');
    return { id: `${app}/${service ?? 'cd'}/${k}`, app, service, deployment: service ? 'main' : undefined, node: service ? 'node-a' : undefined, instance: service ? `${service}-1` : undefined, kind: service ? 'app-execution' : 'cd-candidate', match: byDigest ? 'digest' : 'repository-unknown', image: `${host}/${im!.repository}@${im!.digest}` };
  });
  return { ref, rows, truncated: false, archived: (im?.archived ?? []).map((app) => ({ key: `${app}-1`, app, image: `${host}/${im!.repository}@${im!.digest}`, downAt: new Date(Date.now() - 86400_000 * 20).toISOString() })) };
}
// 정리 작업: 수락하면 queued → running → done(목업은 읽을 때 시간으로 진행). 같은 저장소에 끝나지 않은 작업이 있으면 409 busy
type MaintJob = D.DMaintenanceStatus & { tenant: string; created: number; run: () => D.DMaintenanceResult; items?: D.DPruneRow[] };
const maintJobs = new Map<string, MaintJob>();
const maintKey = (t: string, id: string) => `${t}/${id}`;
const maintOf = (t: string, id: string) => (fx.registryMaint[maintKey(t, id)] ??= { unref: 0, reclaimed: 0 });
function settleJob(j: MaintJob) {
  if (j.state === 'done' || j.state === 'failed' || j.state === 'unknown') return j;
  const age = Date.now() - j.created;
  if (age < 1200) j.state = 'queued';
  else if (age < 3500) j.state = 'running';
  else {
    j.result = j.run();
    j.state = j.result.code === 'ok' || j.result.code === 'already-absent' || j.result.code === 'image-in-use' || j.result.code === 'reference-changed' ? 'done' : j.result.code === 'partial' ? 'done' : 'failed';
  }
  return j;
}
const pendingJob = (t: string, id: string) => [...maintJobs.values()].map(settleJob).find((j) => j.tenant === t && j.registry === id && (j.state === 'queued' || j.state === 'running'));
function maintSummary(t: string, id: string): D.DRegistryMaintenance | undefined {
  const p = pendingJob(t, id);
  const st = fx.registryMaint[maintKey(t, id)];
  if (!p && !st) return undefined;
  return { pendingOperation: p?.operation, pendingState: p?.state, lastGCOperation: st?.lastGCOperation, lastGCAt: st?.lastGCAt, reclaimedBytes: st?.reclaimed ?? 0 };
}
function newJob(user: User, t: string, id: string, external: boolean, action: string, opId: string, x: Partial<MaintJob>, run: () => D.DMaintenanceResult) {
  const j: MaintJob = { tenant: t, operation: `web-${opId}`, action, user: user.id, state: 'queued', revision: ROOT_REVISION + fx.ops.length, at: nowIso(), registry: id, external, created: Date.now(), run, ...x };
  maintJobs.set(j.operation, j);
  return j;
}
const resultOk = (code: string, reclaimedBytes = 0): D.DMaintenanceResult => ({ code, at: nowIso(), reclaimedBytes });
on('GET', '/t/:t/registry-maintenance/:op', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const j = maintJobs.get(m[1]);
  if (!j || j.tenant !== m[0]) return err(404, 'not-found', 'no such maintenance operation');
  const { tenant: _t, created: _c, run: _r, items: _i, ...pub } = settleJob(j);
  return ok(pub);
});
on('GET', '/t/:t/registry-maintenance/:op/items', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const j = maintJobs.get(m[1]);
  if (!j || j.tenant !== m[0] || !j.items) return err(404, 'not-found', 'no such prune operation');
  settleJob(j);
  const from = Number(query.get('after') || 0);
  const rows = j.items.slice(from, from + CAT_PAGE);
  return ok({ conditions: {}, operation: j.operation, items: j.items.length, retained: 0, imageBytes: 0, estimatedReclaimedBytes: 0, estimateKnown: false, live: j.external, part: 'items', total: j.items.length, processed: j.items.filter((x) => x.code).length, rows, retainedRows: [], next: from + CAT_PAGE < j.items.length ? String(from + CAT_PAGE) : '' });
});
on('POST', '/t/:t/registries/:id/images/delete', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const external = !!body.external;
  const src = catSource(t, id, external);
  if ('status' in src) return src;
  const repository = String(body.repository ?? '');
  const reference = String(body.reference ?? '');
  const digest = String(body.digest ?? '');
  if (!repository || !reference || !/^sha256:[0-9a-f]{64}$/.test(digest)) return invalid('payload: repository, reference and sha256 digest');
  const whole = reference === digest;
  const im = imgsOf(t, id, external).find((x) => x.repository === repository && x.digest === digest);
  if (whole && im?.usedBy.length) return err(409, 'image-in-use', 'the maintenance plan reports the image in use');
  if (pendingJob(t, id)) return err(409, 'busy', 'the registry has an unfinished maintenance operation');
  const opId = String(body.opId ?? '');
  return submit(user, { ...body, tenant: t, target: `registry/${id}/${repository}` }, 'delete-registry-image', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    newJob(user, t, id, external, 'delete-registry-image', opId, { repository, reference, digest }, () => {
      const cur = imgsOf(t, id, external).find((x) => x.repository === repository && x.digest === digest);
      if (!cur) return resultOk('already-absent');
      if (external && !whole) return resultOk('unsupported');
      if (!whole) {
        if (!(cur.tags ?? []).includes(reference)) return resultOk('reference-changed');
        cur.tags = (cur.tags ?? []).filter((x) => x !== reference);
        return resultOk('ok');
      }
      if (cur.usedBy.length) return resultOk('image-in-use');
      fx.registryImages.splice(fx.registryImages.indexOf(cur), 1);
      if (!external) maintOf(t, id).unref += cur.bytes;
      return resultOk('ok');
    });
  });
});
on('POST', '/t/:t/registries/:id/gc', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const src = catSource(t, id, false);
  if ('status' in src) return src;
  if (pendingJob(t, id)) return err(409, 'busy', 'the registry has an unfinished maintenance operation');
  const opId = String(body.opId ?? '');
  return submit(user, { ...body, tenant: t, target: `registry/${id}` }, 'gc-registry', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    newJob(user, t, id, false, 'gc-registry', opId, {}, () => {
      const st = maintOf(t, id);
      const got = st.unref;
      Object.assign(st, { unref: 0, reclaimed: got, lastGCAt: Date.now(), lastGCOperation: `web-${opId}` });
      return resultOk('ok', got);
    });
  });
});
// 미리 보기 토큰: 조건·저장소 상태의 해시와 만료. 내린 앱이 쓰는 digest는 첫 쪽에서 protectedDigests에 더한다
const previews = new Map<string, { key: string; expires: number }>();
const fnv = (x: string) => Array.from(x).reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261).toString(16).padStart(8, '0');
const stateKey = (t: string, id: string, external: boolean, c: D.DPruneConditions) => fnv(JSON.stringify([t, id, external, c, imgsOf(t, id, external).map((i) => `${i.digest}:${(i.tags ?? []).join(',')}`)]));
function regPrunePlan(t: string, id: string, external: boolean, c: D.DPruneConditions) {
  const items: D.DPruneRow[] = [];
  const retained: D.DPruneRetained[] = [];
  const byRepo = new Map<string, fx.MockRegistryImage[]>();
  for (const im of imgsOf(t, id, external)) byRepo.set(im.repository, [...(byRepo.get(im.repository) ?? []), im]);
  for (const repo of [...byRepo.keys()].sort()) {
    let tagged = 0;
    for (const im of [...byRepo.get(repo)!].sort((a, b) => Number(b.pushedAt) - Number(a.pushedAt))) {
      const row = catRow(im, im.tags?.[0] ?? im.digest);
      const keep = (code: string) => retained.push({ image: row, code });
      if (c.repositories?.length && !c.repositories.includes(repo)) keep('repository-filter');
      else if ((c.protectedDigests ?? []).includes(im.digest)) keep('protected');
      else if (im.usedBy.length) keep('image-in-use');
      else if (!im.tags?.length && !c.includeUntagged) keep('untagged-excluded');
      else if (im.tags?.length && ++tagged <= c.keepRecentPerRepository) keep('recent');
      else if ((im.tags ?? []).some((tg) => (c.excludeTags ?? []).some((p) => globRe(p).test(tg)))) keep('excluded-tag');
      else if (c.before && !Number(im.pushedAt)) keep('upload-time-unknown');
      else if (c.before && Number(im.pushedAt) > c.before) keep('too-recent');
      else items.push({ id: `${repo}@${im.digest}`, image: row, aliases: Math.max(1, im.tags?.length ?? 0), aliasDigest: im.digest });
    }
  }
  return { items, retained };
}
on('POST', '/t/:t/registries/:id/prune/preview', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const external = !!body.external;
  const src = catSource(t, id, external);
  if ('status' in src) return src;
  if (!canWrite(user, t)) return err(403, 'forbidden', 'needs registry management permission');
  const c0 = (body.conditions ?? {}) as D.DPruneConditions;
  if ((c0.excludeTags ?? []).some((x) => x.includes('/')) || (c0.excludeTags ?? []).length > 32 || (c0.repositories ?? []).length > 256) return invalid('conditions: at most 256 repositories, 32 tag patterns (no /)');
  if (external && c0.gc) return invalid('conditions: gc only for a managed registry');
  let c = c0;
  let token = String(body.preview ?? '');
  if (!token) {
    const prot = imgsOf(t, id, external).filter((i) => i.archived?.length).map((i) => i.digest);
    c = { ...c0, repositories: c0.repositories ?? [], excludeTags: c0.excludeTags ?? [], protectedDigests: [...new Set([...(c0.protectedDigests ?? []), ...prot])].sort() };
    token = `pv-${fnv(String(Math.random()))}`;
    previews.set(token, { key: stateKey(t, id, external, c), expires: Date.now() + 10 * 60_000 });
  } else {
    const pv = previews.get(token);
    if (!pv || pv.expires < Date.now() || pv.key !== stateKey(t, id, external, c)) return err(409, 'preview-expired', 'the preview expired or the registry changed');
  }
  const plan = regPrunePlan(t, id, external, c);
  const part = body.part === 'retained' ? 'retained' : 'items';
  const from = Number(body.after || 0);
  const all = part === 'items' ? plan.items : plan.retained;
  const bytes = plan.items.reduce((a, x) => a + x.image.imageBytes, 0);
  return ok({
    conditions: c,
    preview: token,
    items: plan.items.length,
    retained: plan.retained.length,
    imageBytes: bytes,
    estimatedReclaimedBytes: Math.floor((bytes * 7) / 10),
    estimateKnown: !external,
    live: external,
    expiresAt: new Date(previews.get(token)!.expires).toISOString(),
    part,
    total: all.length,
    processed: Math.min(all.length, from + CAT_PAGE),
    rows: part === 'items' ? plan.items.slice(from, from + CAT_PAGE) : [],
    retainedRows: part === 'retained' ? plan.retained.slice(from, from + CAT_PAGE) : [],
    next: from + CAT_PAGE < all.length ? String(from + CAT_PAGE) : '',
  });
});
on('POST', '/t/:t/registries/:id/prune', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const external = !!body.external;
  const src = catSource(t, id, external);
  if ('status' in src) return src;
  const c = (body.conditions ?? {}) as D.DPruneConditions;
  const pv = previews.get(String(body.preview ?? ''));
  const opId = String(body.opId ?? '');
  // 같은 opId로 다시 보내면 저장된 op(미리 보기 검사보다 먼저)
  if (!findOp(opId, user.id)) {
    if (!pv || pv.expires < Date.now() || pv.key !== stateKey(t, id, external, c)) return err(409, 'preview-expired', 'the preview expired or the registry changed');
    if (pendingJob(t, id)) return err(409, 'busy', 'the registry has an unfinished maintenance operation');
  }
  return submit(user, { ...body, tenant: t, target: `registry/${id}` }, 'prune-registry-images', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    const plan = regPrunePlan(t, id, external, c);
    const items = plan.items.map((x) => ({ ...x }));
    newJob(user, t, id, external, 'prune-registry-images', opId, { items }, () => {
      let deleted = 0;
      let skipped = 0;
      let bytes = 0;
      for (const it of items) {
        const cur = imgsOf(t, id, external).find((x) => x.digest === it.image.digest && x.repository === it.image.repository);
        it.at = nowIso();
        if (!cur) it.code = 'already-absent';
        else if (cur.usedBy.length) ((it.code = 'image-in-use'), skipped++);
        else {
          fx.registryImages.splice(fx.registryImages.indexOf(cur), 1);
          bytes += cur.bytes;
          it.code = 'ok';
          deleted++;
        }
      }
      const st = maintOf(t, id);
      if (!external) st.unref += bytes;
      let gcCode: string | undefined;
      let reclaimed = 0;
      if (c.gc && !external) {
        reclaimed = st.unref;
        Object.assign(st, { unref: 0, reclaimed, lastGCAt: Date.now(), lastGCOperation: `web-${opId}` });
        gcCode = 'ok';
      }
      return { code: skipped ? 'partial' : 'ok', at: nowIso(), reclaimedBytes: reclaimed, prune: { processed: items.length, deleted, skipped, failed: 0, gcCode, gcAt: gcCode ? nowIso() : undefined } };
    });
  });
});
// 접근 자격(web-api.md 'UI-81'): 저장하지 않고 한 번만 돌려준다
on('POST', '/t/:t/registries/:id/credential', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id] = m;
  const cur = regFind(t, id);
  if (!cur || cur.deleted) return err(404, 'not-found', 'no such registry');
  const repository = String(body.repository ?? '');
  if (!/^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/.test(repository)) return invalid('repository: not a valid repository path');
  const access = String(body.access ?? 'pull');
  if (!['pull', 'push', 'pull,push'].includes(access)) return invalid('access: pull, push or pull,push');
  if (!cur.enabled || cur.status === 'stopped') return err(403, 'forbidden', 'registry is stopped');
  if (access.includes('push') && !canWrite(user, t)) return err(403, 'forbidden', 'push needs registry management permission');
  const token = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, '0')).join('');
  return ok({ registry: id, authority: cur.endpoint, username: user.username, token, repository, access: access.split(','), expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() });
});
on('POST', '/t/:t/registries/:id/(start|stop|delete)', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const [t, id, act] = m;
  const cur = regFind(t, id);
  if (!cur) return err(404, 'not-found', 'no such registry');
  if (!['start', 'stop', 'delete'].includes(act)) return err(404, 'not-found', 'no such API endpoint');
  if (act === 'delete' && cur.status !== 'stopped') return err(409, 'not-stopped', 'stop the registry first');
  const expected = Number(body.expected ?? 0) || cur.revision;
  return submit(user, { ...body, tenant: t, target: `registry/${id}` }, `${act}-registry`, () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    if (expected !== cur.revision) return CAS;
    cur.revision++;
    if (act === 'start') Object.assign(cur, { enabled: true, status: 'pending', active: true });
    if (act === 'stop') Object.assign(cur, { enabled: false, status: 'stopped', active: false, observedAt: 0 });
    if (act === 'delete') Object.assign(cur, { deleted: true, status: 'deleted' });
  });
});
// 신뢰 출처(web-api.md '이미지 신뢰 출처 (UI-82)')
type TrustUse = { app?: string; deployment?: string; service?: string; standalone?: string; image: string; rules: number[] };
function trustUses(t: string, rules: { registry: string; repository: string }[]): TrustUse[] {
  const reg = (name: string) => byTenant(fx.registries, t).find((r) => r.name === name)?.endpoint ?? ({ dockerhub: 'docker.io', ghcr: 'ghcr.io' } as Record<string, string>)[name] ?? name;
  const out: Omit<TrustUse, 'rules'>[] = [];
  for (const i of byTenant(fx.images, t)) for (const app of i.usedBy) out.push({ app, deployment: 'main', image: `${reg(i.registry)}/${i.repo}:${i.tag}` });
  for (const s of fx.standalone.filter((x) => x.tenant === t)) out.push({ standalone: s.name, image: s.image.includes('/') && /[.:]/.test(s.image.split('/')[0]) ? s.image : `docker.io/${s.image}` });
  return out.map((u) => ({ ...u, rules: rules.flatMap((r, i) => (matchRule(r, u.image) ? [i] : [])) }));
}
on('GET', '/t/:t/image-trust', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const cur = (fx.imageTrust[m[0]] ??= { revision: 1, rules: [{ registry: 'docker.io', repository: '**' }] });
  const uses = trustUses(m[0], cur.rules);
  const builtin = new Set(byTenant(fx.registries, m[0]).map((r) => r.endpoint));
  return ok({
    tenant: m[0],
    revision: cur.revision,
    rules: cur.rules.map((r, i) => {
      const us = uses.filter((u) => u.rules.includes(i));
      return { index: i, ...r, origin: builtin.has(r.registry) ? 'builtin' : r.registry === 'docker.io' && r.repository === '**' ? 'default' : 'direct', pull: builtin.has(r.registry) ? 'registry-credential' : 'anonymous', uses: us, only: us.filter((u) => u.rules.length === 1).length };
    }),
    uses,
    untrusted: uses.filter((u) => !u.rules.length),
  });
});
const trustRulesOf = (body: Record<string, unknown>, field: 'add' | 'remove') => ((body[field] as { registry?: string; repository?: string }[] | undefined) ?? []).map((r) => ({ registry: String(r.registry ?? ''), repository: String(r.repository ?? '') }));
const sameRule = (a: { registry: string; repository: string }, b: { registry: string; repository: string }) => a.registry === b.registry && a.repository === b.repository;
on('POST', '/t/:t/image-trust/preview', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const cur = fx.imageTrust[m[0]] ?? { revision: 1, rules: [] };
  const remove = trustRulesOf(body, 'remove');
  // 새로 더한 규칙은 계산에 넣지 않는다(넉넉히 알린다)
  const kept = cur.rules.filter((c) => !remove.some((r) => sameRule(r, c)));
  return ok({ affected: trustUses(m[0], cur.rules).filter((u) => u.rules.length && !kept.some((r) => matchRule(r, u.image))) });
});
on('PATCH', '/t/:t/image-trust', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  const add = trustRulesOf(body, 'add');
  const remove = trustRulesOf(body, 'remove');
  if (!add.length && !remove.length) return invalid('add or remove: at least one rule');
  if ([...add, ...remove].some((r) => !/^[a-z0-9.-]+(:\d{1,5})?$/.test(r.registry) || !/^(\*\*|[a-z0-9._-]+(\/[a-z0-9._-]+)*)$/.test(r.repository))) return invalid('rules: registry host[:port] (lowercase) and repository path or **, no duplicates');
  const cur = (fx.imageTrust[t] ??= { revision: 1, rules: [] });
  const expected = Number(body.expected ?? 0) || cur.revision;
  return submit(user, { ...body, tenant: t, target: `tenant/${t}` }, 'set-trust', () => {
    if (!canWrite(user, t)) return FORBIDDEN;
    // 낡은 목록에서 만든 delta(이미 있는 것 더하기, 없는 것 빼기)는 CAS 실패
    if (expected !== cur.revision || add.some((r) => cur.rules.some((c) => sameRule(r, c))) || remove.some((r) => !cur.rules.some((c) => sameRule(r, c)))) return CAS;
    cur.rules = [...cur.rules.filter((c) => !remove.some((r) => sameRule(r, c))), ...add];
    cur.revision++;
  });
});
tenantGet('images', (t) => byTenant(fx.images, t).map(({ tenant: _t, ...x }) => x));
tenantGet('uploads', (t) => byTenant(fx.uploads, t).map(({ tenant: _t, ...x }) => x));
tenantGet('apps', (t) => byTenant(fx.apps, t));
tenantGet('tasks', (t) => byTenant(fx.tasks, t));
tenantGet('archived', (t) => byTenant(fx.archived, t).map(({ yaml: _y, ...a }) => a));

// 앱
const sourceKey = (t: string, a: string) => `${t}/${a}`;
const findApp = (t: string, a: string) => fx.apps.find((x) => x.tenant === t && x.app === a);
on('GET', '/t/:t/apps/:a/tasks', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return ok(page(fx.tasks.filter((x) => x.tenant === m[0] && x.app === m[1])));
});
on('GET', '/t/:t/apps/:a/source', async (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const app = findApp(m[0], m[1]);
  const list = fx.sources[sourceKey(m[0], m[1])] ?? [];
  const v = Number(query.get('version') ?? 0) || app?.revision;
  const s = list.find((x) => x.version === v);
  if (!s) return err(404, 'not-found', '이 버전의 원문이 없습니다(이력 정리로 지워졌을 수 있습니다).');
  const r: D.DAppSource = { tenant: m[0], app: m[1], version: s.version, yaml: s.yaml, digest: await sha256hex(s.yaml), submitter: s.submitter, operation: s.operation, acceptedAt: new Date(s.acceptedAt * 1000).toISOString() };
  return ok(r);
});
on('GET', '/t/:t/apps/:a/revisions', async (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const list = fx.sources[sourceKey(m[0], m[1])] ?? [];
  const rows: D.DAppRevision[] = await Promise.all([...list].reverse().map(async (s) => ({ version: s.version, digest: await sha256hex(s.yaml), submitter: s.submitter, operation: s.operation, status: s.status, acceptedAt: s.acceptedAt })));
  return ok(page(rows));
});
on('GET', '/t/:t/apps/:a/operations/:id', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const a = findApp(m[0], m[1]);
  return a && a.operation.id === m[2] ? ok(a.operation) : err(404, 'not-found', '이 작업을 찾지 못했습니다.');
});
const layouts = new Map<string, unknown>();
on('GET', '/t/:t/apps/:a/layout', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  return ok({ layout: layouts.get(`${m[0]}/${m[1]}/${query.get('deployment') ?? ''}`) ?? null });
});
on('PUT', '/t/:t/apps/:a/layout', (m, body, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  layouts.set(`${m[0]}/${m[1]}/${query.get('deployment') ?? ''}`, body.layout ?? null);
  return ok(null, 204);
});

interface ParsedApp {
  name: string;
  services: { name: string; image: string; node: string }[];
  doc: Record<string, unknown>;
}
function parseApp(tenant: string, text: string): ParsedApp | RawResponse {
  let doc: Record<string, unknown>;
  try {
    doc = YAML.parse(text) as Record<string, unknown>;
  } catch (e) {
    return err(422, 'invalid', `app.yaml 문법 오류: ${(e as Error).message}`, { inputCode: 'yaml' });
  }
  if (!doc || typeof doc !== 'object') return err(422, 'invalid', 'app.yaml이 비어 있습니다.', { inputCode: 'yaml' });
  const name = typeof doc.name === 'string' ? doc.name : '';
  const xm = (doc['x-sfc'] ?? {}) as Record<string, unknown>;
  if (!name) return err(422, 'invalid', 'name이 없습니다.', { inputCode: 'name' });
  // app.yaml 새 형식(CLI 재설계 4b): 작업 공간은 요청 범위, 배포 구성 ID는 서버가 앱 이름으로 정한다
  for (const k of ['schema', 'tenant', 'deployment_id']) if (k in xm) return err(422, 'invalid', `x-sfc.${k}: 이제 쓰지 않습니다. 지우세요.`, { inputCode: k });
  const svc = (doc.services ?? {}) as Record<string, Record<string, unknown>>;
  const oldKeys = appYamlOldKeys(doc);
  if (oldKeys) return err(422, 'invalid', oldKeys, { inputCode: 'x-sfc' });
  if (!Object.keys(svc).length) return err(422, 'invalid', 'services가 비어 있습니다.', { inputCode: 'services' });
  const refs: [string, Set<string>, string][] = [
    ['networks', new Set(byTenant(fx.resources, tenant).flatMap((e) => (e.network ? [e.network.name] : []))), '망'],
    ['volumes', new Set(byTenant(fx.volumes, tenant).map((v) => v.name)), '데이터 저장소'],
    ['secrets', new Set(byTenant(fx.vault, tenant).map((v) => v.path)), '비밀값'],
  ];
  for (const [key, have, label] of refs)
    for (const [n, v] of Object.entries((doc[key] ?? {}) as Record<string, Record<string, unknown> | null>)) {
      if (v?.external !== true) return err(422, 'invalid', `${label} ${n}: 공유 자원은 external: true인 이름 참조만 됩니다.`, { inputCode: key });
      if (!have.has(n)) return err(422, 'invalid', `${label} ${n}이(가) 작업 공간 ${tenant}에 없습니다.`, { inputCode: key });
    }
  const services = Object.entries(svc).map(([s, v]) => ({ name: s, image: String(v?.image ?? ''), node: String(((v?.['x-sfc'] ?? {}) as Record<string, unknown>).node ?? '') }));
  const allowed = fx.tenantNodes[tenant] ?? [];
  for (const s of services) {
    if (!s.image) return err(422, 'invalid', `서비스 ${s.name}에 image가 없습니다.`, { inputCode: 'image' });
    if (s.node && !allowed.includes(s.node)) return err(422, 'invalid', `서비스 ${s.name}: 서버 ${s.node}은(는) 이 작업 공간에 허용되지 않았습니다.`, { inputCode: 'node' });
  }
  return { name, services, doc };
}
const currentYaml = (t: string, a: string) => {
  const app = findApp(t, a);
  return fx.sources[sourceKey(t, a)]?.find((s) => s.version === app?.revision)?.yaml ?? '';
};

on('POST', '/t/:t/apps/plan', async (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const text = String(body.yaml ?? '');
  const p = parseApp(m[0], text);
  if ('status' in p) return p;
  const before = currentYaml(m[0], p.name);
  const prev = before ? parseApp(m[0], before) : undefined;
  const prevSvc = prev && !('status' in prev) ? prev.services : [];
  const changes = [
    ...p.services.map((s) => {
      const o = prevSvc.find((x) => x.name === s.name);
      const change: 'add' | 'update' | 'keep' = !o ? 'add' : JSON.stringify((p.doc.services as Record<string, unknown>)[s.name]) === JSON.stringify(((prev as ParsedApp).doc.services as Record<string, unknown>)[s.name]) ? 'keep' : 'update';
      return { ...s, change };
    }),
    ...prevSvc.filter((o) => !p.services.some((s) => s.name === o.name)).map((o) => ({ ...o, change: 'remove' as const })),
  ];
  const diff = body.diff ? `--- 실행 중\n+++ 새 원문\n${lineDiff(before, text).map((l) => l.op + l.text).join('\n')}\n` : undefined;
  // 바뀐 항목(Z9): 목업은 서비스 하나를 Task 하나로 본다. 끊김 까닭은 서비스 모양(ports · 쓰기 Volume · 복제본 수)으로 정한다
  const svcDoc = (name: string) => ((p.doc.services as Record<string, Record<string, unknown>>)[name] ?? {}) as { ports?: unknown[]; volumes?: unknown[]; deploy?: { replicas?: number } };
  const why = (name: string) => {
    const d = svcDoc(name);
    if (d.ports?.length) return 'HOST_PORT';
    if (d.volumes?.some((v) => typeof v === 'string' && !v.endsWith(':ro') && !v.startsWith('/'))) return 'VOLUME_WRITER';
    if ((d.deploy?.replicas ?? 1) <= 1) return 'SINGLE_INSTANCE';
    return undefined;
  };
  const ACTION = { add: 'Create', keep: 'Keep', remove: 'Remove', update: 'Replace' } as const;
  const rows: D.DPlanChange[] | undefined = body.diff
    ? changes.map((c) => {
        const r: D.DPlanChange = { action: ACTION[c.change], key: `task/${c.name}/1` };
        if (c.change === 'update') {
          r.reason = 'original native closure and new generation required';
          const i = why(c.name);
          if (i) r.interruption = i;
        }
        return r;
      })
    : undefined;
  const plan: D.DAppPlan = { app: p.name, digest: await sha256hex(text), length: new TextEncoder().encode(text).length, services: changes, diff, changes: rows };
  return ok(plan);
});

/** 배포 묶음. 단계: begin-app-upload → put-app-part×n → begin-app */
interface DeployJob {
  tenant: string;
  app: string;
  yaml: string;
  parts: number;
  /** 다음에 보낼 단계(0부터, 데몬과 같음) */
  step: number;
  /** 비밀번호로 보호된 묶음 승인(begin-app 앞에서 기다림) */
  approvals: D.DGroupApproval[];
}
const jobs = new Map<string, DeployJob>();
const stepName = (j: DeployJob, n: number) => (n === 0 ? 'begin-app-upload' : n === j.parts + 1 ? 'begin-app' : 'put-app-part');

function finishDeploy(user: User, j: DeployJob, opId: string) {
  const list = (fx.sources[sourceKey(j.tenant, j.app)] ??= []);
  const version = (list[list.length - 1]?.version ?? 0) + 1;
  list.push({ version, yaml: j.yaml, submitter: user.username, operation: opId, status: 'running', acceptedAt: fx.nowSec() });
  const opsum: D.DOperationSummary = { id: opId, status: 'running', submitter: user.username, epoch: 1 };
  const a = findApp(j.tenant, j.app);
  if (a) Object.assign(a, { revision: version, operation: opsum, observedAt: fx.nowSec() });
  else fx.apps.push({ tenant: j.tenant, app: j.app, deployment: 'main', revision: version, operation: opsum, claims: 0, health: 'unknown', observedAt: fx.nowSec() });
  // 목업: 몇 초 뒤 진행 완료로 바꾼다.
  setTimeout(() => {
    const s = list.find((x) => x.version === version);
    if (s) s.status = 'succeeded';
    const cur = findApp(j.tenant, j.app);
    if (cur?.operation.id === opId) Object.assign(cur, { operation: { ...opsum, status: 'succeeded', completedAt: fx.nowSec() }, health: 'healthy', observedAt: fx.nowSec() });
  }, 6000);
}

/** 남은 단계를 차례로 보낸다. 단계 하나가 불명·실패면 멈춘다. */
function runDeploy(user: User, parent: fx.MockOp, j: DeployJob, failure: MockFailure) {
  const steps = j.parts + 2;
  parent.steps = steps;
  while (j.step < steps) {
    const id = `${parent.id}.${j.step}`;
    let child = findOp(id, user.id);
    if (child?.state === 'unknown') {
      parent.state = 'unknown';
      parent.errorCode = 'step-unknown';
      parent.step = j.step;
      return;
    }
    if (!child && j.step === steps - 1 && j.approvals.some((a) => a.state !== 'approved')) {
      parent.state = 'running';
      parent.errorCode = 'approval-required';
      parent.step = j.step;
      parent.approvals = j.approvals.map((a) => ({ ...a }));
      parent.updatedAt = nowIso();
      return;
    }
    if (!child) {
      child = newOp(user, id, stepName(j, j.step), j.tenant, j.app, '', parent.id);
      fx.ops.unshift(child);
      const last = j.step === steps - 1;
      // 실패 주입은 마지막 단계(begin-app)에 건다.
      execute(child, last ? failure : 'none', () => (last ? finishDeploy(user, j, parent.id) : undefined));
    }
    if (child.state === 'unknown') {
      parent.state = 'unknown';
      parent.errorCode = 'step-unknown';
      parent.step = j.step;
      return;
    }
    if (child.state !== 'applied') {
      parent.state = child.state;
      parent.errorCode = child.errorCode;
      parent.resultCode = child.resultCode;
      parent.resultFound = child.resultFound;
      parent.step = j.step;
      return;
    }
    j.step++;
  }
  parent.state = 'applied';
  parent.errorCode = undefined;
  parent.resultFound = true;
  parent.resultCode = 0;
  parent.step = steps;
  if (j.approvals.length) parent.approvals = j.approvals.map((a) => ({ ...a }));
  parent.updatedAt = nowIso();
}

on('POST', '/t/:t/apps/deploy', async (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const opId = String(body.opId ?? '');
  if (!/^[0-9a-f-]{36}$/.test(opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
  const text = String(body.yaml ?? '');
  const digest = await sha256hex(text);
  if (body.digest && body.digest !== digest) return err(409, 'digest-mismatch', '미리보기 뒤 app.yaml이 바뀌었습니다. 다시 미리보기 해 주세요.');
  const fp = JSON.stringify({ t: m[0], digest, deployment: body.deployment, node: body.node, prune: body.prune });
  const existing = findOp(opId, user.id);
  if (existing) {
    if (fingerprints.get(opId) !== fp) return err(409, 'op-conflict', '같은 작업 ID에 다른 내용이 왔습니다.');
    const j = jobs.get(opId);
    if (j && existing.state !== 'applied') runDeploy(user, existing, j, 'none');
    return opReply(existing);
  }
  const p = parseApp(m[0], text);
  if ('status' in p) return p;
  const failure = takeFailure();
  if (failure === 'disconnected') return err(503, 'disconnected', 'sfcd 연결이 끊겼습니다(목업 주입).');
  if (failure === 'denied') return err(403, 'denied', '이 작업 공간의 배포 권한이 없습니다(목업 주입).');
  const parent = newOp(user, opId, 'deploy', m[0], p.name, fp);
  fingerprints.set(opId, fp);
  fx.ops.unshift(parent);
  const j: DeployJob = { tenant: m[0], app: p.name, yaml: text, parts: Math.max(1, Math.ceil(text.length / (1 << 20))), step: 0, approvals: protectedUses(m[0], p.doc) };
  jobs.set(opId, j);
  runDeploy(user, parent, j, failure);
  return opReply(parent);
});

// ── 묶음 승인 (UI-72) ──
// 서비스의 x-sfc.secrets.from: [group/Y]가 비밀번호가 걸린 묶음이면 begin-app 앞에서 승인을 기다린다(데몬 가짜와 같음).
// 목업은 비밀번호를 저장하지 않는다: 'wrong'은 틀린 비밀번호, 'mock:unknown'은 답 유실, 그 밖은 맞는 것으로 본다.
function protectedUses(tenant: string, doc: Record<string, unknown>): D.DGroupApproval[] {
  const by = new Map<string, string[]>();
  for (const [svc, v] of Object.entries((doc.services ?? {}) as Record<string, Record<string, unknown> | null>)) {
    // secrets.from: [X, group/Y, cluster/X, cluster/group/Y]. cluster/는 작업 공간 묶음이 아니다
    const src = ((((v?.['x-sfc'] ?? {}) as Record<string, unknown>).secrets as Record<string, unknown> | undefined)?.from ?? []) as unknown[];
    for (const x of Array.isArray(src) ? src : []) {
      const m = /^group\/(.+)$/.exec(String(x));
      if (!m) continue;
      const g = fx.vault.find((r) => r.tenant === tenant && r.kind === 'group' && r.id === m[1] && r.protected);
      if (g) by.set(g.id!, [...(by.get(g.id!) ?? []), svc]);
    }
  }
  return [...by].map(([group, services]) => ({ realm: tenant, group, services, state: 'required' as const }));
}
const approvalKind = (pw: string) => (pw === 'wrong' ? 'denied' : pw === 'mock:unknown' ? 'unknown' : 'ok');
const checkPassword = (body: Record<string, unknown>) => {
  const pw = typeof body.password === 'string' ? body.password : '';
  return !pw || pw.length > 1024 || /[\r\n\0]/.test(pw) ? err(400, 'bad-request', 'password: one line, 1 to 1024 bytes') : undefined;
};
const grant = (user: User, t: string, app: string, group: string, services: string[]) => {
  const g = fx.vault.find((r) => r.tenant === t && r.id === group);
  const now = fx.nowSec();
  fx.grantedApprovals.unshift({ tenant: t, id: `approval-${Math.random().toString(16).slice(2, 10)}`, realm: t, group, user: user.id, app, deployment: 'main', services, nodes: ['node-a'], approvedAt: now, expiresAt: g?.maxApprovalAge ? now + g.maxApprovalAge : undefined, issuer: 'node-a', revoking: false, consumers: 1 });
  fx.approvalCollection[t] = (fx.approvalCollection[t] ?? 0) + 1;
};
type SaWait = { tenant: string; name: string; approvals: D.DGroupApproval[]; op: fx.MockOp; go: () => RawResponse };
const saWaits = new Map<string, SaWait>();
on('POST', '/t/:t/apps/deploy/:op/approve', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const bad = checkPassword(body);
  if (bad) return bad;
  const sw = saWaits.get(m[1]);
  if (sw && sw.tenant === m[0] && sw.op.user === user.id) {
    const a = sw.approvals.find((x) => x.realm === String(body.realm || m[0]) && x.group === String(body.group ?? ''));
    if (sw.op.errorCode !== 'approval-required' || !a) return err(409, 'not-required', 'this standalone job does not wait for that Group');
    if (a.state === 'approved') return err(409, 'already-approved', 'this Group is already approved');
    const k = approvalKind(String(body.password));
    a.state = k === 'ok' ? 'approved' : k === 'denied' ? 'required' : 'unknown';
    sw.op.approvals = sw.approvals.map((x) => ({ ...x }));
    if (k === 'denied') return err(403, 'approval-denied', 'the password was not accepted for this Group');
    if (k === 'unknown') return err(502, 'approval-unknown', "the approver's answer was lost; send the password again");
    grant(user, m[0], `standalone:${sw.name}`, a.group, arrOf(a.services));
    if (sw.approvals.some((x) => x.state !== 'approved')) return opReply(sw.op);
    saWaits.delete(m[1]);
    fx.ops.splice(fx.ops.indexOf(sw.op), 1);
    return sw.go();
  }
  const parent = findOp(m[1], user.id);
  const j = jobs.get(m[1]);
  if (!parent || !j || j.tenant !== m[0]) return err(404, 'not-found', 'no such deploy job');
  const realm = String(body.realm || m[0]);
  const a = j.approvals.find((x) => x.realm === realm && x.group === String(body.group ?? ''));
  if (parent.errorCode !== 'approval-required' || !a) return err(409, 'not-required', 'this deploy job does not wait for that Group');
  if (a.state === 'approved') return err(409, 'already-approved', 'this Group is already approved');
  const k = approvalKind(String(body.password));
  a.state = k === 'ok' ? 'approved' : k === 'denied' ? 'required' : 'unknown';
  parent.approvals = j.approvals.map((x) => ({ ...x }));
  if (k === 'denied') return err(403, 'approval-denied', 'the password was not accepted for this Group');
  if (k === 'unknown') return err(502, 'approval-unknown', "the approver's answer was lost; send the password again");
  grant(user, m[0], j.app, a.group, arrOf(a.services));
  runDeploy(user, parent, j, 'none');
  return opReply(parent);
});
// 빌드 비밀값 묶음 승인(#226). 승인 전에는 원본을 sfcd에 보내지 않는다. 비밀번호 'late'는 늦은 승인으로 거절(approval-rejected)
type BuildWait = { tenant: string; context: string; build: string; approvals: D.DGroupApproval[]; op: fx.MockOp; go: () => RawResponse };
const buildWaits = new Map<string, BuildWait>();
const buildGate = (t: string, context: string, build: string, secrets: D.DBuildSecret[], body: Record<string, unknown>, go: () => RawResponse): RawResponse => {
  const { user } = requireSession();
  const opId = String(body.opId ?? '');
  const w = buildWaits.get(opId);
  if (w) return ok({ op: publicOp(w.op) }, 202);
  const now = fx.nowSec();
  const groups = [...new Set(secrets.map((x) => fx.vault.find((v) => v.tenant === t && v.kind === 'object' && v.id === x.secret)?.group).filter((g): g is string => !!g))].filter(
    (g) => fx.vault.some((v) => v.tenant === t && v.kind === 'group' && v.id === g && v.protected) && !fx.grantedApprovals.some((a) => a.tenant === t && a.group === g && a.app === `build:${context}` && !a.revoking && (!a.expiresAt || a.expiresAt > now)),
  );
  if (!groups.length) return go();
  const op = newOp(user, opId, 'begin-image-build', t, `build/${build}`, '');
  Object.assign(op, { state: 'running', errorCode: 'approval-required', approvals: groups.map((g) => ({ realm: t, group: g, services: [], state: 'required' })) });
  fx.ops.unshift(op);
  buildWaits.set(opId, { tenant: t, context, build, approvals: op.approvals as D.DGroupApproval[], op, go });
  return ok({ op: publicOp(op) }, 202);
};
on('POST', '/t/:t/build-approvals/:op/approve', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const bad = checkPassword(body);
  if (bad) return bad;
  const w = buildWaits.get(m[1]);
  if (!w || w.tenant !== m[0]) return err(404, 'not-found', 'no such build job');
  const realm = String(body.realm || m[0]);
  const a = w.approvals.find((x) => x.realm === realm && x.group === String(body.group ?? ''));
  if (w.op.errorCode !== 'approval-required' || !a) return err(409, 'not-required', 'this build job does not wait for that Group');
  if (a.state === 'approved') return err(409, 'already-approved', 'this Group is already approved');
  const pw = String(body.password);
  const k = approvalKind(pw);
  a.state = k === 'ok' ? 'approved' : k === 'denied' ? 'required' : 'unknown';
  w.op.approvals = w.approvals.map((x) => ({ ...x }));
  if (k === 'denied') return err(403, 'approval-denied', 'the password was not accepted for this Group');
  if (k === 'unknown') return err(502, 'approval-unknown', "the approver's answer was lost; send the password again");
  grant(user, m[0], `build:${w.context}`, a.group, []);
  if (w.approvals.some((x) => x.state !== 'approved')) return opReply(w.op);
  buildWaits.delete(m[1]);
  if (pw === 'late') {
    Object.assign(w.op, { state: 'failed', errorCode: 'approval-rejected', updatedAt: nowIso() });
    return opReply(w.op);
  }
  // 다 승인됨: 같은 opId로 원본을 보낸다(기다리던 op는 그 결과로 바뀐다)
  fx.ops.splice(fx.ops.indexOf(w.op), 1);
  return w.go();
});
on('GET', '/t/:t/vault/approvals', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const items = [...jobs].flatMap(([opId, j]) => {
    const op = findOp(opId, user.id);
    if (!op || j.tenant !== m[0] || op.errorCode !== 'approval-required') return [];
    return j.approvals.map((a) => ({ kind: 'deploy', opId, app: j.app, ...a, updatedAt: op.updatedAt }));
  });
  for (const [opId, w] of buildWaits) {
    if (w.tenant !== m[0] || w.op.user !== user.id) continue;
    items.push(...w.approvals.map((a) => ({ kind: 'build', opId, app: '', context: w.context, build: w.build, ...a, updatedAt: w.op.updatedAt })));
  }
  for (const [opId, w] of saWaits) {
    if (w.tenant !== m[0] || w.op.user !== user.id) continue;
    items.push(...w.approvals.map((a) => ({ kind: 'standalone', opId, app: '', standalone: w.name, ...a, updatedAt: w.op.updatedAt })));
  }
  for (const [opId, w] of bindWaits) {
    if (w.tenant !== m[0] || w.op.user !== user.id) continue;
    items.push(...w.approvals.map((a) => ({ kind: 'registry-bind', opId, app: '', source: w.source, node: w.node, ...a, updatedAt: w.op.updatedAt })));
  }
  return ok({ items });
});
const cdKey = (t: string, app: string, q: string) => `${t}/${app}/${q}`;
on('GET', '/t/:t/apps/:a/cd/approvals', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const cand = query.get('candidate') ?? '';
  if (!/^[0-9a-f]{64}$/.test(cand)) return invalid('candidate: 64 hex characters');
  const c = fx.cdCandidateGroups[cdKey(m[0], m[1], cand)];
  if (c && c.registrant !== user.id) return err(403, 'denied', '');
  return ok({ app: m[1], approvals: (c?.groups ?? []).map((g) => ({ realm: g.realm, group: g.group, services: g.services, state: g.approved ? 'approved' : 'required' })) });
});
on('POST', '/t/:t/apps/:a/cd/approvals', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const bad = checkPassword(body);
  if (bad) return bad;
  const c = fx.cdCandidateGroups[cdKey(m[0], m[1], String(body.candidate ?? ''))];
  if (c && c.registrant !== user.id) return err(403, 'denied', '');
  const g = c?.groups.find((x) => x.realm === String(body.realm || m[0]) && x.group === String(body.group ?? ''));
  if (!g) return err(409, 'not-required', 'this candidate does not need that Group');
  if (g.approved) return err(409, 'already-approved', 'this Group is already approved');
  const k = approvalKind(String(body.password));
  if (k === 'denied') return err(403, 'approval-denied', 'the password was not accepted for this Group');
  if (k === 'unknown') return err(502, 'approval-unknown', "the approver's answer was lost; send the password again");
  g.approved = true;
  grant(user, m[0], m[1], g.group, g.services);
  return ok({ app: m[1], approvals: c!.groups.map((x) => ({ realm: x.realm, group: x.group, services: x.services, state: x.approved ? 'approved' : 'required' })) });
});
// 자동 배포 상태·동작·정책·고정값(web-api.md "자동 배포", PR #83). 상태는 앱 목록의 cd에서 시작한다.
const cdStates = new Map<string, D.DCdState>();
function cdState(t: string, a: string): D.DCdState | undefined {
  const app = findApp(t, a);
  if (!app?.cd) return undefined;
  const k = `${t}/${a}`;
  let s = cdStates.get(k);
  if (!s) {
    const c = app.cd;
    s = {
      ...c,
      sync: c.candidate ? 'OutOfSync' : 'InSync',
      effectiveSync: c.candidate ? 'OutOfSync' : 'InSync',
      operation: c.candidate ? 'Planned' : 'Succeeded',
      health: app.health === 'healthy' ? 'Healthy' : 'Degraded',
      source: 'Ready',
      lastSuccessCommit: c.running,
      changeCount: c.candidate ? 1 : 0,
      policyRevision: 1,
      principal: 'u-alice',
      policy: { enabled: true, source: { kind: 'git', repository: c.repository, ref: `refs/heads/${c.branch}`, path: 'app.yaml', credential: '' }, poll: 60, sync: { mode: c.mode, drift: 'report', prune: false, allowEmpty: false }, runtime: { mode: 'require-explicit-override', expiry: 'manual-release' }, limits: { fetch: 30, bytes: 4 << 20, queued: 1, active: 1 } },
      overrideRevision: 0,
      overrideCount: 0,
      overridePaths: [],
    };
    cdStates.set(k, s);
  }
  return s;
}
const cdOr404 = (t: string, a: string) => cdState(t, a) ?? err(404, 'not-cd', 'this app is not managed by CD');
const isRaw = (x: unknown): x is RawResponse => !!x && typeof x === 'object' && 'status' in x && !('revision' in x);
on('GET', '/t/:t/apps/:a/cd', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const gate = cdGateOf(m[0], m[1], s.candidate);
  return ok({ app: m[1], deployment: findApp(m[0], m[1])!.deployment, cd: { ...s, ...gate } });
});
on('POST', '/t/:t/apps/:a/cd/(sync|recover|replan|pause|resume|abandon)', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const act = m[2];
  if (!['sync', 'recover', 'replan', 'pause', 'resume', 'abandon'].includes(act)) return err(404, 'not-found', 'no such API endpoint');
  if (act === 'sync' || act === 'recover') {
    if (!s.candidate) return err(409, 'no-candidate', 'there is no candidate to sync');
    if (body.candidate && body.candidate !== s.candidateDigest) return err(409, 'candidate-changed', 'the candidate changed; read it again');
  }
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, `cd-${act}`, () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    s.revision++;
    if (act === 'pause') s.paused = true;
    if (act === 'resume') s.paused = false;
    if (act === 'replan') s.operation = s.candidate ? 'Planned' : s.operation;
    if (act === 'abandon') (s.activeOperation = undefined, s.transition = undefined, s.operation = 'Abandoned');
    if (act === 'sync' || act === 'recover') {
      s.running = s.candidate;
      s.lastSuccessCommit = s.candidate;
      s.candidate = undefined;
      s.candidateDigest = undefined;
      s.sync = s.effectiveSync = 'InSync';
      s.operation = 'Succeeded';
      s.changeCount = 0;
    }
  });
});
on('PUT', '/t/:t/apps/:a/cd/policy', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  // CD가 없는 앱에 처음 보내면 등록한다(sfcd configure-app-cd, PolicyRevision 0). 그때 expected는 앱 revision
  const app = findApp(m[0], m[1]);
  if (!app) return err(404, 'not-cd', 'this app is not managed by CD');
  const fresh = !app.cd;
  const s = fresh ? undefined : cdOr404(m[0], m[1]);
  if (s && isRaw(s)) return s;
  const p = body.policy as D.DCdPolicy | undefined;
  if (!p || typeof p !== 'object') return invalid('policy: required');
  const known = ['enabled', 'source', 'poll', 'sync', 'runtime', 'limits'];
  const extra = Object.keys(p).find((k) => !known.includes(k));
  if (extra) return invalid(`policy.${extra}: unknown field`);
  if (!(p.poll >= 1 && p.poll <= 86400)) return invalid('policy.poll: 1..86400');
  if (!['report', 'reconcile'].includes(p.sync?.drift)) return invalid('policy.sync.drift: report or reconcile');
  if (p.runtime?.mode && p.runtime.mode !== 'require-explicit-override') return invalid('policy.runtime.mode: require-explicit-override');
  if (!p.source?.repository) return invalid('policy.source.repository: required');
  const lim = p.limits;
  if (!lim || !(lim.fetch >= 1 && lim.fetch <= 300) || !(lim.bytes >= 1 && lim.bytes <= 4 << 20) || lim.queued !== 1 || lim.active !== 1) return invalid('policy.limits: fetch 1..300, bytes 1..4MiB, queued 1, active 1 (INVALID_CD_POLICY)');
  if (!/^https:\/\/[^\s@?#]+$/.test(p.source.repository)) return invalid('policy.source.repository: https:// only (INVALID_GIT_SOURCE)');
  // expected는 CD revision(모든 동작과 같다), 처음 등록이면 앱 revision. 없으면 지금 값
  const expected = Number(body.expected ?? 0) || (s ? s.revision : app.revision);
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, 'cd-policy', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    if (!s) {
      if (expected !== app.revision) return CAS;
      const branch = p.source.ref.replace(/^refs\/heads\//, '');
      app.cd = { revision: 1, repository: p.source.repository, branch, mode: p.sync.mode as 'manual', paused: false, running: '', candidate: 'c0ffee1', candidateDigest: 'c0ffee1'.padEnd(64, '0') };
      const n = cdState(m[0], m[1])!;
      n.policy = structuredClone(p);
      return;
    }
    if (expected !== s.revision) return CAS;
    s.policy = structuredClone(p);
    s.mode = p.sync.mode;
    s.policyRevision++;
    s.revision++;
  });
});
// 이력·값·변경점. 목업은 상태에서 지어낸다(가짜 어댑터와 같은 모양)
const cdHist = new Map<string, D.DCdHistory[]>();
function cdHistoryOf(t: string, a: string, s: D.DCdState): D.DCdHistory[] {
  const k = `${t}/${a}`;
  let h = cdHist.get(k);
  if (!h) {
    h = [{ commit: s.running ?? '', candidateDigest: ''.padEnd(64, '5'), plannedAt: fx.nowSec() - 86400, result: 'succeeded', operation: 'cd-77aa', finishedAt: fx.nowSec() - 86000 }];
    cdHist.set(k, h);
  }
  if (s.candidate && !h.some((x) => x.commit === s.candidate)) h.unshift({ commit: s.candidate, candidateDigest: s.candidateDigest ?? '', plannedAt: fx.nowSec() - 180, result: fx.cdCandidateGroups[`${t}/${a}/${s.candidateDigest}`]?.groups.some((g) => !g.approved) ? 'blocked' : 'candidate', reason: fx.cdCandidateGroups[`${t}/${a}/${s.candidateDigest}`]?.groups.some((g) => !g.approved) ? 'group-approval' : undefined });
  for (const x of h) if ((x.result === 'candidate' || x.result === 'blocked') && x.commit === s.running) Object.assign(x, { result: 'succeeded', reason: undefined, operation: `sync-${x.commit}`, finishedAt: fx.nowSec() });
  // 데몬 #168: 이력 행에 그 후보의 웹훅 확인
  const g = cdGateOf(t, a, s.candidate).checks;
  return h.map((x) => {
    const c = { ...(g?.['pre-sync']?.candidate === x.commit ? { 'pre-sync': g['pre-sync'] } : {}), ...(g?.['post-sync']?.candidate === x.commit ? { 'post-sync': g['post-sync'] } : {}) };
    return Object.keys(c).length ? { ...x, checks: c } : x;
  });
}
// 웹이 더한 서비스. REQ-25: 후보 승인·반려, 승인 담당
const cdLocals = new Map<string, { revision: number; document: string; actor?: string }>([['shop/worker-batch', { revision: 2, actor: 'alice', document: 'services:\n  report:\n    image: registry.shop.internal/shop/report@sha256:9c0' + 'd'.repeat(61) + '\n    x-sfc:\n      node: node-b\n' }]]);
const cdApproverSets = new Map<string, string[]>([['shop/worker-batch', ['bob']]]);
const gitServicesOf = (t: string, a: string) => [...new Set(fx.tasks.filter((x) => x.tenant === t && x.app === a).map((x) => x.service))];
on('GET', '/t/:t/apps/:a/cd/local', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const l = cdLocals.get(`${m[0]}/${m[1]}`) ?? { revision: 0, document: '' };
  // #466: revision은 CD revision, localRevision은 로컬 부분의 revision
  const services = Object.keys((l.document ? (YAML.parse(l.document) as { services?: object })?.services : undefined) ?? {});
  const git = gitServicesOf(m[0], m[1]);
  return ok({ tenant: m[0], app: m[1], revision: s.revision, localRevision: l.revision, ...(l.actor ? { actor: l.actor } : {}), document: l.document, services, gitServices: git, conflicts: services.filter((x) => git.includes(x)) });
});
on('PUT', '/t/:t/apps/:a/cd/local', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const k = `${m[0]}/${m[1]}`;
  const cur = cdLocals.get(k) ?? { revision: 0, document: '' };
  // #466: {opId, document, expected?}. operation은 없어졌다. 지금 배포하지 않고 다음 sync·승인 때 더한다
  if ('operation' in body) return err(400, 'bad-request', 'unknown field operation');
  const doc = String(body.document ?? '');
  if (doc.length > 1 << 20) return invalid('document: at most 1 MiB');
  if (!doc && !cur.document) return err(409, 'unchanged', 'there are no web services to clear');
  const expected = Number(body.expected ?? 0) || s.revision;
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, doc ? 'put-app-local-services' : 'clear-app-local-services', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    if (expected !== s.revision) return CAS;
    let v: { services?: Record<string, { depends_on?: unknown }> } | null = null;
    try {
      v = doc ? YAML.parse(doc) : null;
    } catch {
      return { code: 2, errorCode: 'invalid' };
    }
    if (v && Object.keys(v).some((x) => x !== 'services')) return { code: 2, errorCode: 'invalid' };
    const git = gitServicesOf(m[0], m[1]);
    const names = Object.keys(v?.services ?? {});
    if (names.some((n) => git.includes(n))) return { code: 2, errorCode: 'invalid' };
    if (names.some((n) => [v!.services![n].depends_on].flat().some((d) => typeof d === 'string' && git.includes(d)))) return { code: 2, errorCode: 'invalid' };
    if (names.length > 128) return { code: 2, errorCode: 'invalid' };
    cdLocals.set(k, { revision: cur.revision + 1, document: doc, actor: user.username });
    s.revision++;
  });
});
const cdDecide = (approve: boolean) => (m: string[], body: Record<string, unknown>) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  // #464: operation 필드는 없어졌고, reason은 한 줄 512자까지(작업 원본에 서명됨), expected는 cd.revision과 같아야 한다
  if ('operation' in body) return err(400, 'bad-request', 'unknown field operation');
  if ([...String(body.reason ?? '')].length > 512) return invalid('reason: at most 512 characters');
  if (/[\r\n]/.test(String(body.reason ?? ''))) return invalid('reason: a single line');
  if (String(body.candidate ?? '').length !== 64) return invalid('candidate: cd.candidateDigest as shown');
  if (!s.candidate || !s.candidateDigest) return err(409, 'no-candidate', 'there is no source candidate to decide on');
  if (body.candidate !== s.candidateDigest) return err(409, 'candidate-changed', 'the source candidate changed; read the app again');
  const k = `${m[0]}/${m[1]}`;
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, approve ? 'approve-app-cd' : 'reject-app-cd', () => {
    if (!canWrite(user, m[0]) && !(cdApproverSets.get(k) ?? []).includes(user.username)) return FORBIDDEN;
    if (body.expected !== undefined && Number(body.expected) !== s.revision) return CAS;
    if ((s.policy?.sync.mode ?? s.mode) !== 'manual' || s.paused) return { code: 2, errorCode: 'invalid' };
    if (fx.cdCandidateGroups[`${k}/${s.candidateDigest}`]?.groups.some((g) => !g.approved)) return { code: 2, errorCode: 'approval-required' };
    const h = cdHistoryOf(m[0], m[1], s);
    const row = h.find((x) => x.commit === s.candidate);
    if (approve) {
      s.running = s.candidate;
      s.lastSuccessCommit = s.candidate;
      s.sync = s.effectiveSync = 'InSync';
      s.operation = 'Succeeded';
    } else if (row) Object.assign(row, { result: 'rejected', reason: String(body.reason ?? '') || undefined, finishedAt: fx.nowSec() });
    s.candidate = undefined;
    s.candidateDigest = undefined;
    s.changeCount = 0;
    s.revision++;
  });
};
on('POST', '/t/:t/apps/:a/cd/candidate/approve', cdDecide(true));
on('POST', '/t/:t/apps/:a/cd/candidate/reject', cdDecide(false));
on('GET', '/t/:t/apps/:a/cd/approvers', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  return ok({ app: m[1], approvers: cdApproverSets.get(`${m[0]}/${m[1]}`) ?? [] });
});
const cdApprover = (add: boolean) => (m: string[], body: Record<string, unknown>) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  // #464: {user}(구성원 username) 또는 {userId} 중 하나. 구성원이 아니면 404, 이미 있는데 더하거나 없는데 빼면 op failed
  if ((body.user === undefined) === (body.userId === undefined)) return invalid('user or userId: exactly one');
  const target = fx.users.find((x) => (body.user !== undefined ? x.username === String(body.user) : x.id === String(body.userId)));
  if (!target || !fx.memberships[m[0]]?.[target.id]) return err(404, 'not-found', 'not a member of this tenant');
  const u = target.username;
  const expected = Number(body.expected ?? 0) || s.revision;
  const k = `${m[0]}/${m[1]}`;
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, add ? 'grant-cd-approver' : 'revoke-cd-approver', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    if (expected !== s.revision) return CAS;
    const cur = cdApproverSets.get(k) ?? [];
    if (add === cur.includes(u)) return { code: 2, errorCode: add ? 'already-approver' : 'not-approver' };
    cdApproverSets.set(k, add ? [...cur, u] : cur.filter((x) => x !== u));
    s.revision++;
  });
};
on('POST', '/t/:t/apps/:a/cd/approvers', cdApprover(true));
on('DELETE', '/t/:t/apps/:a/cd/approvers', cdApprover(false));
// REQ-56 읽기 확인(목업): 'private'이 든 주소는 접속 정보가 있어야 하고, .yaml이 아닌 경로는 파일 없음
on('POST', '/t/:t/apps/:a/cd/probe', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const repo = String(body.repository ?? '');
  if (!/^(https:\/\/|ssh:\/\/|git@)\S+$/.test(repo)) return err(422, 'invalid', 'repository');
  if (repo.includes('missing')) return err(422, 'no-repository', 'repository not found');
  if (repo.includes('private') && !body.credential) return err(422, 'auth-failed', 'authentication required');
  if (body.credential && body.credential !== 'git-readonly') return err(422, 'no-credential', 'no such credential');
  if (String(body.branch) !== 'main' && String(body.branch) !== 'release') return err(422, 'no-branch', 'branch not found');
  if (!/\.ya?ml$/.test(String(body.path ?? ''))) return err(422, 'no-file', 'path not found');
  if (/huge/.test(String(body.path))) return err(422, 'too-large', 'file too large');
  if (repo.includes('broken')) return err(422, 'source-error', 'source read failed');
  const h = [...repo + body.branch].reduce((x, c) => (x * 31 + c.charCodeAt(0)) >>> 0, 7);
  return ok({ commit: (h.toString(16) + 'a3f9c0d12e4b5a6978c0d1e2f3a4b5c6d7e8f901').slice(0, 40), size: 1200 + (h % 2400), node: 'node-a' });
});
on('GET', '/t/:t/apps/:a/cd/history', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  return ok({ items: cdHistoryOf(m[0], m[1], s), next: '', revision: s.revision, asOf: new Date().toISOString() });
});
on('GET', '/t/:t/apps/:a/cd/changes', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const svc = fx.tasks.find((x) => x.tenant === m[0] && x.app === m[1])?.service ?? 'web';
  const services = s.candidate ? [{ service: svc, fields: [{ path: ['services', svc, 'image'], before: `registry.shop.internal/shop/${svc}:v5`, after: `registry.shop.internal/shop/${svc}:v6` }] }] : [];
  return ok({ tenant: m[0], app: m[1], running: s.running, candidate: s.candidate ?? s.running, services, added: [], removed: [], count: services.length });
});
on('GET', '/t/:t/apps/:a/cd/values', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const path = query.getAll('path');
  if (path[0] !== 'services' || !path[1] || path.length < 3) return invalid('path: services.<svc>.<field>');
  const over = (s.overridePaths ?? []).some((x) => x.join('.') === path.join('.'));
  if (/PASSWORD|SECRET|TOKEN/.test(path[3] ?? '')) return ok({ tenant: m[0], app: m[1], path, running: s.running, candidate: s.candidate, overridden: over, secrets: [{ realm: m[0], id: 'db-cred' }] });
  const git = path[2] === 'image' ? `registry.shop.internal/shop/${path[1]}:v5` : path[2] === 'cpus' ? 0.5 : path[2] === 'mem_limit' ? '256m' : path[2] === 'environment' ? 'production' : undefined;
  return ok({ tenant: m[0], app: m[1], path, running: s.running, candidate: s.candidate, gitRunning: git, gitCandidate: path[2] === 'image' && s.candidate ? `registry.shop.internal/shop/${path[1]}:v6` : git, current: over ? cdOverrideValues.get(`${m[0]}/${m[1]}/${path.join('.')}`) : git, overridden: over });
});
const cdOverrideValues = new Map<string, unknown>();
const cdServiceOf = (t: string, a: string, svc: string) => fx.tasks.some((x) => x.tenant === t && x.app === a && x.service === svc);
on('GET', '/t/:t/apps/:a/cd/field', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const path = query.getAll('path');
  if (path[0] !== 'services' || !path[1] || path.length < 3) return invalid('path: services.<svc>.<field>');
  if (!cdServiceOf(m[0], m[1], path[1])) return err(409, 'no-ref', 'this service has no deployed object yet');
  const has = (s.overridePaths ?? []).find((x) => x.join('.') === path.join('.'));
  return ok({ target: `${m[0]}/${m[1]}/${path[1]}`, revision: s.overrideRevision, path, ...(has ? { override: { revision: s.overrideRevision, actor: user.id, anchors: null } } : {}) });
});
on('PUT', '/t/:t/apps/:a/cd/overrides', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const path = (body.path as string[] | undefined) ?? [];
  if (path[0] !== 'services' || !path[1] || path.length < 3) return invalid('path: services.<svc>.<field>');
  if (body.value === undefined) return invalid('value: required');
  if (!cdServiceOf(m[0], m[1], path[1])) return err(409, 'no-ref', 'this service has no deployed object yet');
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, 'cd-override-set', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    const ps = s.overridePaths ?? [];
    if (!ps.some((x) => x.join('.') === path.join('.'))) ps.push(path);
    cdOverrideValues.set(`${m[0]}/${m[1]}/${path.join('.')}`, body.value);
    s.overridePaths = ps;
    s.overrideCount = ps.length;
    s.overrideRevision++;
  });
});
on('DELETE', '/t/:t/apps/:a/cd/overrides', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const s = cdOr404(m[0], m[1]);
  if (isRaw(s)) return s;
  const path = ((body.path as string[] | undefined) ?? []).join('.');
  if (!(s.overridePaths ?? []).some((x) => x.join('.') === path)) return err(409, 'no-override', 'this field is not overridden');
  return submit(user, { ...body, tenant: m[0], target: `app/${m[1]}` }, 'cd-override-release', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    s.overridePaths = (s.overridePaths ?? []).filter((x) => x.join('.') !== path);
    s.overrideCount = s.overridePaths.length;
    s.overrideRevision++;
  });
});
on('GET', '/t/:t/vault/approvals/granted', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const app = query.get('app');
  // 가짜와 같이: 작업 공간 관리자는 전부, 그 밖에는 자기 것만
  const rows = byTenant(fx.grantedApprovals, m[0]).filter((g) => (!app || g.app === app) && (canWrite(user, m[0]) || g.user === user.id));
  return ok({ items: rows.map((g) => ({ ...g })), next: '', total: rows.length, collection: fx.approvalCollection[m[0]] ?? 0 });
});
on('POST', '/t/:t/vault/approvals/granted/:id/revoke', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const t = m[0];
  const expected = Number(body.expected ?? 0) || (fx.approvalCollection[t] ?? 0);
  return submit(user, { ...body, tenant: t, target: `approval/${m[1]}` }, 'vault-revoke-approval', () => {
    const g = fx.grantedApprovals.find((x) => x.tenant === t && x.id === m[1]);
    if (!g || g.revoking) return INVALID;
    if (!canWrite(user, t) && g.user !== user.id) return FORBIDDEN;
    if ((fx.approvalCollection[t] ?? 0) !== expected) return CAS;
    // 데몬 #298: 철회는 revoking으로 쓰는 곳을 돌려받고, 끝나면 목록에서 빠진다(목업: 5초 뒤)
    g.revoking = true;
    fx.approvalCollection[t] = expected + 1;
    window.setTimeout(() => {
      const i = fx.grantedApprovals.indexOf(g);
      if (i >= 0) fx.grantedApprovals.splice(i, 1);
    }, 5000);
  });
});
on('POST', '/t/:t/apps/:a/down', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const a = findApp(m[0], m[1]);
  if (!a) return err(404, 'not-found', '이 앱이 없거나 볼 권한이 없습니다.');
  const yaml = currentYaml(m[0], m[1]);
  if (!yaml) return err(503, 'unavailable', '실행 중 app.yaml을 읽지 못해 내리지 않았습니다.');
  const expected = Number(body.expected ?? -1);
  return submit(user, { ...body, tenant: m[0], target: m[1] }, 'down-app', () => {
    if (expected !== a.revision) return CAS;
    const at = fx.nowSec();
    fx.archived.unshift({ key: `${m[0]}~${m[1]}~${at}`, tenant: m[0], app: m[1], digest: '', version: a.revision, volumes: (body.volumes as string[] | undefined) ?? [], downBy: user.username, downAt: nowIso(), downOp: String(body.opId), yaml });
    fx.apps.splice(fx.apps.indexOf(a), 1);
    for (let i = fx.tasks.length - 1; i >= 0; i--) if (fx.tasks[i].tenant === m[0] && fx.tasks[i].app === m[1]) fx.tasks.splice(i, 1);
  });
});
on('GET', '/t/:t/archived/:key', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const a = fx.archived.find((x) => x.tenant === m[0] && x.key === m[1]);
  return a ? ok(a) : err(404, 'not-found', '보관된 앱을 찾지 못했습니다.');
});
on('POST', '/t/:t/archived/:key/purge', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  const a = fx.archived.find((x) => x.tenant === m[0] && x.key === m[1]);
  if (!a) return err(404, 'not-found', '보관된 앱을 찾지 못했습니다.');
  if (body.confirm !== a.app) return err(400, 'confirm-mismatch', '확인용으로 입력한 앱 이름이 다릅니다.');
  fx.archived.splice(fx.archived.indexOf(a), 1);
  return ok(null, 204);
});

// 단독 컨테이너 (REQ-29, UI-3E·3F) ─ 데몬 스레드와 합의한 가정 계약(정의는 평평한 원문)
const SA_MINE_MAX = 8;
const SA_TENANT_MAX = 32;
const SA_ENDED_KEEP = 3600;
const saFind = (t: string, n: string) => fx.standalone.find((x) => x.tenant === t && x.name === n && x.state !== 'removed');
const canManage = (u: User, t: string) => u.systemAdmin || roleIn(u, t) === 'manager';
const saEnd = (x: fx.MockStandalone, exitCode?: number) => Object.assign(x, { state: 'removed', endedAt: fx.nowSec(), connections: 0, exitCode: exitCode ?? x.exitCode, expiresAt: undefined, disconnectedAt: undefined });
/** 임시는 수명이 지나거나 끊긴 뒤 유예가 지나면 끝낸다. 끝난 기록은 1시간 남긴다(목업: 읽을 때 정리). */
function saSweep() {
  const now = fx.nowSec();
  for (let i = fx.standalone.length - 1; i >= 0; i--) {
    const x = fx.standalone[i];
    if (x.state === 'removed') {
      if (now - (x.endedAt ?? 0) > SA_ENDED_KEEP) fx.standalone.splice(i, 1);
      continue;
    }
    if (x.lifetime !== 'temp') continue;
    const graceOver = x.mode === 'shell' && x.disconnectedAt && x.connections === 0 && x.graceSeconds !== undefined && now - x.disconnectedAt > x.graceSeconds;
    if ((x.expiresAt && x.expiresAt <= now) || graceOver) saEnd(x);
  }
}
const saPublic = (x: fx.MockStandalone): D.DStandalone & { tenant: string } => ({ ...x, generation: x.revision });
const durSec = (v: unknown): number | undefined => {
  const t = String(v ?? '').trim();
  if (/^\d+$/.test(t)) return Number(t);
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(t);
  return m && t ? Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0) : undefined;
};

function saApply(user: User, action: string, expected: number, p: Payload): Applied {
  const x = saFind(String(pick(p, 'Tenant') ?? ''), String(pick(p, 'Name') ?? ''));
  if (!x) return INVALID;
  if (!canManage(user, x.tenant)) return FORBIDDEN;
  if (expected !== x.revision) return CAS;
  const now = fx.nowSec();
  switch (action) {
    case 'standalone-remove':
      if (x.lifetime === 'temp') saEnd(x, 137);
      else fx.standalone.splice(fx.standalone.indexOf(x), 1);
      return;
    case 'standalone-stop':
      // 임시는 멈추면 끝난다(지운다).
      if (x.lifetime === 'temp') {
        saEnd(x, 137);
        return;
      }
      Object.assign(x, { state: 'exited', exitCode: 137, connections: 0, observedAt: now });
      break;
    case 'standalone-start':
    case 'standalone-restart':
      if (action === 'standalone-start' && x.state === 'running') return INVALID;
      Object.assign(x, { state: 'created', exitCode: undefined, connections: 0, observedAt: now, restarts: x.restarts + (action === 'standalone-restart' ? 1 : 0) });
      setTimeout(() => x.state === 'created' && Object.assign(x, { state: 'running', observedAt: fx.nowSec() }), 1500);
      break;
    case 'standalone-pin': {
      if (x.lifetime !== 'temp') return INVALID;
      const restart = String(pick(p, 'Restart') ?? 'on-failure');
      if (!['no', 'on-failure', 'always'].includes(restart)) return INVALID;
      const newName = String(pick(p, 'NewName') ?? '') || x.name;
      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(newName)) return INVALID;
      if (newName !== x.name && saFind(x.tenant, newName)) return INVALID;
      const doc = YAML.parse(x.yaml) as Record<string, unknown>;
      delete doc.ttl;
      delete doc.grace;
      Object.assign(doc, { name: newName, lifetime: 'fixed', restart });
      Object.assign(x, { name: newName, lifetime: 'fixed', restartPolicy: restart, expiresAt: undefined, graceSeconds: undefined, disconnectedAt: undefined, yaml: YAML.stringify(doc, { lineWidth: 0 }) });
      break;
    }
    case 'standalone-extend': {
      if (x.lifetime !== 'temp' || !x.expiresAt) return INVALID;
      // 데몬 #291: ttlSeconds는 서명 시각부터의 새 남은 수명. 옛 /ops payload의 TTL은 더하는 값.
      const ttl = Number(pick(p, 'TtlSeconds') ?? NaN);
      const add = Number.isFinite(ttl) ? undefined : durSec(pick(p, 'TTL'));
      if (Number.isFinite(ttl) ? ttl < 60 : !add || add < 60) return INVALID;
      const next = Number.isFinite(ttl) ? now + ttl : Math.max(x.expiresAt, now) + add!;
      if (next <= x.expiresAt) return INVALID;
      if (next - x.createdAt > 24 * 3600) return INVALID;
      x.expiresAt = next;
      break;
    }
  }
  x.revision++;
}

interface ParsedSa {
  name: string;
  lifetime: 'temp' | 'fixed';
  mode: 'shell' | 'entrypoint';
  image: string;
  node: string;
  ttl: number;
  grace: number;
  restart: 'no' | 'on-failure' | 'always';
  doc: Record<string, unknown>;
}
function parseSa(tenant: string, text: string): ParsedSa | RawResponse {
  let doc: Record<string, unknown>;
  try {
    doc = YAML.parse(text) as Record<string, unknown>;
  } catch (e) {
    return err(422, 'invalid', `정의 문법 오류: ${(e as Error).message}`, { inputCode: 'yaml' });
  }
  if (!doc || typeof doc !== 'object') return err(422, 'invalid', '정의가 비어 있습니다.', { inputCode: 'yaml' });
  const name = typeof doc.name === 'string' ? doc.name : '';
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name)) return err(422, 'invalid', '이름은 소문자·숫자·-로 63자까지입니다.', { inputCode: 'name' });
  const lifetime = doc.lifetime === 'fixed' ? 'fixed' : doc.lifetime === 'temp' ? 'temp' : undefined;
  if (!lifetime) return err(422, 'invalid', 'lifetime은 temp 또는 fixed입니다.', { inputCode: 'lifetime' });
  const ttl = lifetime === 'temp' ? durSec(doc.ttl ?? '1h') : 0;
  const grace = lifetime === 'temp' ? durSec(doc.grace ?? '10m') : 0;
  if (ttl === undefined || (lifetime === 'temp' && (ttl < 60 || ttl > 24 * 3600))) return err(422, 'invalid', '임시 수명(ttl)은 1분~24시간입니다.', { inputCode: 'ttl' });
  if (grace === undefined) return err(422, 'invalid', 'grace를 읽지 못했습니다.', { inputCode: 'grace' });
  const restart = String(doc.restart ?? 'on-failure');
  if (!['no', 'on-failure', 'always'].includes(restart)) return err(422, 'invalid', 'restart는 no / on-failure / always입니다.', { inputCode: 'restart' });
  const mode = doc.mode === 'entrypoint' ? 'entrypoint' : doc.mode === 'shell' || doc.mode === undefined ? 'shell' : undefined;
  if (!mode) return err(422, 'invalid', 'mode는 shell 또는 entrypoint입니다.', { inputCode: 'mode' });
  if (doc.services) return err(422, 'invalid', '단독 컨테이너는 services 없이 서비스 칸 하나만 씁니다.', { inputCode: 'service' });
  if (doc.depends_on) return err(422, 'invalid', '단독 컨테이너에는 depends_on을 쓸 수 없습니다.', { inputCode: 'depends_on' });
  const image = String(doc.image ?? '');
  if (!image) return err(422, 'invalid', 'image가 없습니다.', { inputCode: 'image' });
  const allowed = fx.tenantNodes[tenant] ?? [];
  const xm = (doc['x-sfc'] ?? {}) as Record<string, unknown>;
  const node = String(xm.node ?? '') || allowed[0] || '';
  if (!allowed.includes(node)) return err(422, 'invalid', `서버 ${node || '(없음)'}은(는) 이 작업 공간에 허용되지 않았습니다.`, { inputCode: 'node' });
  const nets = Array.isArray(doc.networks) ? (doc.networks as string[]) : Object.keys((doc.networks ?? {}) as object);
  const haveNets = new Set(byTenant(fx.resources, tenant).flatMap((e) => (e.network ? [e.network.name] : [])));
  for (const n of nets) if (!haveNets.has(n)) return err(422, 'invalid', `망 ${n}이(가) 작업 공간 ${tenant}에 없습니다.`, { inputCode: 'networks' });
  const haveVols = new Set(byTenant(fx.volumes, tenant).map((v) => v.name));
  for (const v of (doc.volumes ?? []) as unknown[]) {
    const n = typeof v === 'string' ? v.split(':')[0] : '';
    if (n && !n.startsWith('/') && !n.startsWith('.') && !haveVols.has(n)) return err(422, 'invalid', `데이터 저장소 ${n}이(가) 작업 공간 ${tenant}에 없습니다.`, { inputCode: 'volumes' });
  }
  const haveSecs = new Set(byTenant(fx.vault, tenant).map((v) => v.path));
  for (const x of (doc.secrets ?? []) as unknown[]) {
    const n = typeof x === 'string' ? x : String((x as { source?: string })?.source ?? '');
    if (n && !haveSecs.has(n)) return err(422, 'invalid', `비밀값 ${n}이(가) 작업 공간 ${tenant}에 없습니다.`, { inputCode: 'secrets' });
  }
  return { name, lifetime, mode, image, node, ttl, grace, restart: restart as ParsedSa['restart'], doc };
}
const SA_NODE_MAX = 64;
const saLimits = (user: User, t: string, node: string) => ({
  mine: fx.standalone.filter((x) => x.tenant === t && x.state !== 'removed' && x.lifetime === 'temp' && x.owner === user.id).length,
  mineMax: SA_MINE_MAX,
  tenant: fx.standalone.filter((x) => x.tenant === t && x.state !== 'removed').length,
  tenantMax: SA_TENANT_MAX,
  node: fx.standalone.filter((x) => x.node === node && x.state !== 'removed').length,
  nodeMax: SA_NODE_MAX,
});
/** 데몬 #291: 상한은 plan·up 모두 HTTP 409로 거절한다. */
function saLimitErr(lim: ReturnType<typeof saLimits>, create: boolean, lifetime: string): RawResponse | undefined {
  if (!create) return undefined;
  if (lifetime === 'temp' && lim.mine >= lim.mineMax) return err(409, 'limit-user-temp', `temporary standalone limit ${lim.mineMax} per user reached`);
  if (lim.tenant >= lim.tenantMax) return err(409, 'limit-tenant', `tenant standalone limit ${lim.tenantMax} reached`);
  if (lim.node >= lim.nodeMax) return err(409, 'limit-node', `node standalone limit ${lim.nodeMax} reached`);
  return undefined;
}
/** 목업 신뢰 정책: 내장 저장소와 docker.io 공식 이미지만 신뢰(ghcr 등 외부 저장소는 신뢰 출처 아님) */
function imageTrust(t: string, image: string): { registry?: D.DRegistry; trusted: boolean } {
  const host = image.includes('/') && /[.:]/.test(image.split('/')[0]) ? image.split('/')[0] : 'docker.io';
  const registry = byTenant(fx.registries, t).find((r) => r.endpoint === host);
  // 신뢰는 작업 공간의 신뢰 출처 규칙(UI-82)으로 판단한다
  const ref = image.includes('/') && /[.:]/.test(image.split('/')[0]) ? image : `docker.io/${image.includes('/') ? image : `library/${image}`}`;
  return { registry, trusted: (fx.imageTrust[t]?.rules ?? []).some((r) => matchRule(r, ref)) };
}
const trustedImage = (t: string, image: string) => imageTrust(t, image).trusted;
on('POST', '/t/:t/images/resolve', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  const ref = String(body.ref ?? '').trim();
  if (!ref || /\s/.test(ref) || /[A-Z]/.test(ref.split('@')[0].split('/').slice(1).join('/'))) return err(422, 'invalid-ref', 'the image reference is empty or malformed');
  const { registry, trusted } = imageTrust(m[0], ref);
  const pinned = /@(sha256:[0-9a-f]{64})$/.exec(ref);
  const bare = ref.replace(/@sha256:[0-9a-f]{64}$/, '');
  const known = byTenant(fx.images, m[0]).find((i) => bare.endsWith(`${i.repo}:${i.tag}`) || (pinned && i.digest === pinned[1]));
  const host = ref.includes('/') && /[.:]/.test(ref.split('/')[0]) ? ref.split('/')[0] : 'docker.io';
  const repo = ref.replace(/^[^/]*[.:][^/]*\//, '').replace(/@sha256:[0-9a-f]{64}$/, '').replace(/:[^/:]*$/, '');
  const ext = registry ? undefined : extOf(m[0]).find((x) => x.authority === host && (x.repository === '**' || globRe(x.repository.replace(/\*\*/g, '*')).test(repo)));
  const ok2 = trusted && known?.trusted !== false;
  // 목업: 목록에 없으면 참조 글자로 digest를 지어낸다(실제는 저장소에 묻는다). ':missing'은 not-found, ':locked'는 denied
  const fake = async () => 'sha256:' + (await sha256hex(ref));
  const code = !ok2 ? 'untrusted' : ext && (ext.deleted || !ext.enabled) ? 'source-revoked' : ext && !ext.reader ? 'source-not-ready' : ref.endsWith(':missing') ? 'not-found' : ref.endsWith(':locked') ? 'denied' : ext && ext.test !== 'ok' ? ext.test : undefined;
  return fake().then((d) => {
    const digest = code ? undefined : (pinned?.[1] ?? known?.digest ?? d);
    const multi = !code && /php|nginx|alpine/.test(ref);
    return ok({
      ref,
      input: String(body.ref ?? ''),
      registry: registry?.endpoint ?? host,
      registryKind: registry ? 'builtin' : ext ? 'external' : 'unknown',
      source: registry?.name ?? ext?.id,
      digest,
      pinned: digest ? `${host}/${repo.includes('/') || host !== 'docker.io' ? repo : `library/${repo}`}@${digest}` : undefined,
      mediaType: digest ? (multi ? 'application/vnd.oci.image.index.v1+json' : 'application/vnd.oci.image.manifest.v1+json') : undefined,
      platforms: multi ? [{ platform: 'linux/amd64', digest: 'sha256:' + 'a1'.repeat(32) }, { platform: 'linux/arm64', digest: 'sha256:' + 'b2'.repeat(32) }] : [],
      trusted: ok2,
      rules: ok2 ? [] : (fx.imageTrust[m[0]]?.rules ?? []),
      reason: ok2 ? undefined : `${host}/${repo}가 신뢰 규칙에 없음`,
      code,
    });
  });
});

on('GET', '/t/:t/standalone', (m, _b, query) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  saSweep();
  const all = query.get('all') === '1' && canManage(user, m[0]);
  const rows = fx.standalone.filter((x) => x.tenant === m[0] && (x.lifetime === 'fixed' || all || x.owner === user.id));
  return ok(page(rows.map(saPublic), 20));
});
on('GET', '/t/:t/standalone/:n', (m) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  saSweep();
  const x = fx.standalone.find((s) => s.tenant === m[0] && s.name === m[1]);
  if (!x || (x.lifetime === 'temp' && x.owner !== user.id && !canManage(user, m[0]))) return err(404, 'not-found', '단독 컨테이너를 찾지 못했습니다.');
  return ok({ item: saPublic(x) });
});
on('POST', '/t/:t/standalone/plan', async (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0]);
  // 데몬처럼 모르는 필드는 거절한다(standalone_real.go: { yaml }만)
  const extra = Object.keys(body ?? {}).find((k) => k !== 'yaml');
  if (extra) return err(400, 'bad-request', `invalid JSON body: json: unknown field "${extra}"`);
  saSweep();
  const text = String(body.yaml ?? '');
  const p = parseSa(m[0], text);
  if ('status' in p) return p;
  const cur = saFind(m[0], p.name);
  const d = p.doc;
  // 목업: node-a의 web-1이 127.0.0.1:18080을 쓴다. 같은 서버에 고정 18080을 적으면 계획이 거절한다
  if (p.node === 'node-a' && ((d.ports ?? []) as unknown[]).some((x) => /(^|:)18080:/.test(typeof x === 'string' ? x : `${(x as { published?: unknown }).published}:`))) return err(409, 'host-port-conflict', 'ports: 18080 is already published on node-a');
  const lim = saLimits(user, m[0], p.node);
  const limErr = saLimitErr(lim, !cur, p.lifetime);
  if (limErr) return limErr;
  type Imp = { kind: string; name: string; level: 'info' | 'warn' | 'block'; text: string };
  const impact: Imp[] = [];
  if (!trustedImage(m[0], p.image)) impact.push({ kind: 'image', name: p.image, level: 'block', text: `이미지 ${p.image}는 작업 공간 신뢰 출처가 아닙니다 (image-untrusted).` });
  const nets = Array.isArray(d.networks) ? (d.networks as string[]) : Object.keys((d.networks ?? {}) as object);
  for (const n of nets) impact.push({ kind: 'network', name: n, level: 'info', text: `망 ${n}에 별칭 ${p.name} 추가` });
  for (const v of (d.volumes ?? []) as unknown[]) {
    const [n, , ro] = typeof v === 'string' ? v.split(':') : [];
    const vol = byTenant(fx.volumes, m[0]).find((x) => x.name === n);
    if (!vol) continue;
    if (vol.node !== p.node) impact.push({ kind: 'volume', name: n, level: 'block', text: `데이터 저장소 ${n}은(는) ${vol.node}에 있어 ${p.node}에서 쓸 수 없습니다.` });
    else if (ro !== 'ro' && vol.consumers > 0) impact.push({ kind: 'volume', name: n, level: 'block', text: `데이터 저장소 ${n}에는 이미 쓰는 쪽이 있습니다. 읽기 전용으로 붙이세요 (volume-writer-conflict).` });
    else impact.push({ kind: 'volume', name: n, level: 'info', text: `저장소 ${n} ${ro === 'ro' ? '읽는 쪽' : '쓰는 쪽'} 1` });
  }
  const ingList = xmOf(d).ingress;
  const routes = (Array.isArray(ingList) ? ingList : []) as { host?: string; prefix?: string }[];
  for (const r of routes) {
    const taken = byTenant(fx.resources, m[0]).find((e) => e.route && e.route.host === r.host && (e.route.path ?? '/') === (r.prefix ?? '/'));
    impact.push(taken ? { kind: 'ingress', name: String(r.host), level: 'block', text: `호스트 ${r.host}${r.prefix ?? '/'}는 앱 ${taken.route!.app}이 이미 씁니다.` } : { kind: 'ingress', name: String(r.host), level: 'info', text: `외부 접속 ${r.host}${r.prefix ?? '/'} 추가` });
  }
  if (cur && cur.lifetime === 'fixed' && p.lifetime === 'temp') impact.push({ kind: 'lifetime', name: p.name, level: 'block', text: '고정을 임시로 바꿀 수는 없습니다.' });
  if (cur && cur.lifetime === 'temp' && cur.owner !== user.id) impact.push({ kind: 'owner', name: cur.ownerName ?? cur.owner, level: canManage(user, m[0]) ? 'warn' : 'block', text: `${cur.ownerName}의 임시 컨테이너입니다.` });
  const prev = cur ? (YAML.parse(cur.yaml) as Record<string, unknown>) : {};
  const keys = new Set([...Object.keys(prev), ...Object.keys(d)]);
  const changes = cur ? [...keys].flatMap((k) => (JSON.stringify(prev[k]) === JSON.stringify(d[k]) ? [] : [{ field: k, before: prev[k], after: d[k] }])) : [];
  const diff = body.diff && cur ? `--- rev ${cur.revision}\n+++ 새 정의\n${lineDiff(cur.yaml, text).map((l) => l.op + l.text).join('\n')}\n` : undefined;
  const plan: D.DStandalonePlan = {
    name: p.name,
    digest: await sha256hex(text),
    revision: cur?.revision ?? 0,
    create: !cur,
    recreate: !!cur && changes.length > 0,
    changes,
    impact: impact.map((i) => ({ kind: i.kind, target: i.name, detail: i.text, blocking: i.level === 'block', code: /\(([a-z-]+)\)\.?$/.exec(i.text)?.[1] })),
    limits: lim,
    scope: `standalone-${m[0]}-${p.name}`,
    services: [p.name],
    diff,
  };
  return ok(plan);
});
const xmOf = (d: Record<string, unknown>) => (d['x-sfc'] ?? {}) as Record<string, unknown>;
on('POST', '/t/:t/standalone/up', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  saSweep();
  const text = String(body.yaml ?? '');
  const p = parseSa(m[0], text);
  if ('status' in p) return p;
  const expected = Number(body.expected ?? 0);
  {
    const cur = saFind(m[0], p.name);
    const limErr = saLimitErr(saLimits(user, m[0], p.node), !cur, p.lifetime);
    if (limErr && !findOp(String(body.opId ?? ''), user.id)) return limErr;
    const d = p.doc;
    if (p.node === 'node-a' && ((d.ports ?? []) as unknown[]).some((x) => /(^|:)18080:/.test(typeof x === 'string' ? x : `${(x as { published?: unknown }).published}:`))) return err(409, 'host-port-conflict', 'ports: 18080 is already published on node-a');
  }
  // 보호된 묶음(x-sfc.secrets.from의 group/Y)을 쓰면 승인을 기다린다. 승인은 배포 승인 끝점, 승인 목록의 kind는 standalone(#291)
  const opId = String(body.opId ?? '');
  const w = saWaits.get(opId);
  if (w) return opReply(w.op);
  const now0 = fx.nowSec();
  const need = protectedUses(m[0], { services: { [p.name]: p.doc } }).filter((a) => !fx.grantedApprovals.some((g) => g.tenant === m[0] && g.group === a.group && g.app === `standalone:${p.name}` && !g.revoking && (!g.expiresAt || g.expiresAt > now0)));
  const go = () => submit(user, { ...body, tenant: m[0], target: p.name }, 'standalone-up', () => {
    const cur = saFind(m[0], p.name);
    if ((cur?.revision ?? 0) !== expected) return CAS;
    if (!trustedImage(m[0], p.image)) return INVALID; // 다른 거절은 결과 코드 그대로(errorCode 없음)
    if (cur && cur.lifetime === 'fixed' && p.lifetime === 'temp') return INVALID;
    if (cur && cur.lifetime === 'temp' && cur.owner !== user.id && !canManage(user, m[0])) return FORBIDDEN;
    const now = fx.nowSec();
    const next: fx.MockStandalone = {
      tenant: m[0],
      name: p.name,
      lifetime: p.lifetime,
      mode: p.mode,
      image: p.image,
      digest: p.image.includes('@') ? p.image.slice(p.image.indexOf('@') + 1) : undefined,
      node: p.node,
      state: 'pending',
      restarts: 0,
      restartPolicy: p.lifetime === 'fixed' ? p.restart : undefined,
      expiresAt: p.lifetime === 'temp' ? now + p.ttl : undefined,
      graceSeconds: p.lifetime === 'temp' ? p.grace : undefined,
      connections: 0,
      owner: cur?.owner ?? user.id,
      ownerName: cur?.ownerName ?? user.username,
      revision: (cur?.revision ?? 0) + 1,
      yaml: text,
      createdAt: cur?.createdAt ?? now,
      observedAt: now,
      operation: String(body.opId),
      // 출처는 이 up이 applied일 때만 남고, 출처 없이 up하면 사라진다.
      importedFrom: body.importedFrom && typeof body.importedFrom === 'object' ? { ...(body.importedFrom as { app: string; deployment?: string; service: string; items: string[] }), by: user.id, at: now } : undefined,
    };
    // 같은 이름의 끝난 기록은 새 것으로 바꾼다.
    const old = fx.standalone.findIndex((x) => x.tenant === m[0] && x.name === p.name && x.state === 'removed');
    if (old >= 0) fx.standalone.splice(old, 1);
    if (cur) Object.assign(cur, next);
    else fx.standalone.push(next);
    const row = cur ?? next;
    // 목업: 이미지 받기·만들기에 1.5초. 쉘은 연결을 기다리며 유예를 시작한다.
    setTimeout(() => {
      if (row.state !== 'pending') return;
      Object.assign(row, { state: 'running', observedAt: fx.nowSec(), disconnectedAt: row.lifetime === 'temp' && row.mode === 'shell' ? fx.nowSec() : undefined });
    }, 1500);
  });
  if (!need.length || findOp(opId, user.id)) return go();
  const op = newOp(user, opId, 'standalone-up', m[0], p.name, '');
  Object.assign(op, { state: 'running', errorCode: 'approval-required', approvals: need.map((a) => ({ ...a })) });
  fx.ops.unshift(op);
  saWaits.set(opId, { tenant: m[0], name: p.name, approvals: op.approvals as D.DGroupApproval[], op, go });
  return opReply(op);
});

// 데몬 #291: 단독 컨테이너 동작 전용 끝점. body {opId, expected?, ...}; expected가 없으면 지금 revision.
on('POST', '/t/:t/standalone/:n/(pin|remove|extend|stop|start|restart)', (m, body) => {
  const { user } = requireSession();
  requireTenant(user, m[0], true);
  saSweep();
  const [t, name, verb] = m;
  const x = saFind(t, name);
  if (!x && !findOp(String(body.opId ?? ''), user.id)) return err(404, 'not-found', '단독 컨테이너를 찾지 못했습니다.');
  if (x && verb === 'start' && x.state === 'running' && !findOp(String(body.opId ?? ''), user.id)) return err(422, 'invalid', 'already running');
  const expected = body.expected === undefined ? (x?.revision ?? 0) : Number(body.expected);
  const p: Payload = { Tenant: t, Name: name, NewName: body.newName, Restart: body.restart, TtlSeconds: body.ttlSeconds };
  return submit(user, { ...body, tenant: t, target: `standalone/${name}` }, `standalone-${verb}`, () => saApply(user, `standalone-${verb}`, expected, p));
});

// 작업
// 관리 변경 (UI-A1) 동작 목록. 계약 초안 contracts/ops-actions.md 모양. 목업은 몇 동작만 싣는다
// sfcd 입력 형식에서 뽑은 동작 목록(데몬 #575 control.InputActions + ops_actions.go의 분류·offer·base)
const OP_ACTIONS = opActionCatalog as D.DOpAction[];
const opAction = (a: string) => OP_ACTIONS.find((x) => x.action === a);
/** 데몬처럼 payload를 칸과 맞춘다: 없는 칸이나 빠진 replace 칸이면 bad-payload */
function payloadFits(a: D.DOpAction, p: Record<string, unknown>): boolean {
  const names = new Set((a.fields ?? []).map((f) => f.name));
  if (Object.keys(p).some((k) => !names.has(k))) return false;
  return (a.fields ?? []).every((f) => !f.replace || (f.name in p && p[f.name] !== null));
}
on('GET', '/ops/actions', () => {
  requireSession();
  return ok({ items: OP_ACTIONS });
});
on('POST', '/ops/actions/:a/base', (m, body) => {
  requireSession();
  const p = (body.payload ?? {}) as Record<string, unknown>;
  const t = String(p.Tenant ?? '');
  switch (m[0]) {
    case 'create-tenant':
      return ok({ expected: 0, found: String(p.ID ?? '') in fx.memberships });
    case 'set-nodes':
      return t in fx.memberships ? ok({ expected: fx.tenantRev[t], found: true, current: { Tenant: t, Add: [], Remove: [] } }) : ok({ expected: 0, found: false });
    case 'set-membership':
      return t in fx.memberships ? ok({ expected: fx.tenantRev[t], found: true, current: { Tenant: t, Members: fx.memberships[t] } }) : ok({ expected: 0, found: false });
    default: {
      const a = opAction(m[0]);
      if (!a) return err(404, 'not-found', 'no such action');
      if (a.base !== 'current') return err(422, 'unsupported', "this action's base revision is entered by hand");
      // 목업에 지금 값이 없는 대상은 아직 없는 것으로 본다
      return ok({ expected: 0, found: false });
    }
  }
});
on('POST', '/ops', (_m, body) => {
  const { user } = requireSession();
  const action = String(body.action ?? '');
  if (action === 'down-app' || action === 'deploy') return err(400, 'bad-request', `${action}은(는) 전용 끝점으로 보냅니다.`);
  const known = opAction(action);
  if (known && !payloadFits(known, (body.payload ?? {}) as Record<string, unknown>)) return err(400, 'bad-payload', "the payload does not match this action's fields");
  let a = actionApply(user, action, Number(body.expected ?? 0), (body.payload ?? {}) as Payload);
  // 목업이 따로 흉내 내지 않는 동작은 확정만 한다
  if (typeof a !== 'function' && known && a.status === 501) a = () => undefined;
  if (typeof a !== 'function') return a;
  return submit(user, body, action, a);
});
on('GET', '/ops', (_m, _b, query) => {
  const { user } = requireSession();
  const state = query.get('state');
  const children = query.get('children') === '1';
  const limit = Number(query.get('limit') ?? 200);
  const batch = query.get('batch');
  return ok(page(fx.ops.filter((o) => o.user === user.id && (!state || o.state === state) && (children || !o.parent) && (!batch || o.batch === batch)).slice(0, limit).map(publicOp)));
});
on('GET', '/ops/:id', (m) => {
  const { user } = requireSession();
  const o = findOp(m[0], user.id);
  return o ? ok({ op: publicOp(o) }) : err(404, 'not-found', '이 작업을 찾지 못했습니다.');
});
on('POST', '/ops/:id/(result|resume)', (m) => {
  const { user } = requireSession();
  const o = findOp(m[0], user.id);
  if (!o) return err(404, 'not-found', '이 작업을 찾지 못했습니다.');
  if (o.action === 'deploy') return err(409, 'job', '배포 묶음에는 결과 조회·재개가 없습니다. 불명 단계를 정산한 뒤 같은 작업으로 배포를 다시 보내세요.');
  if (o.action === 'exec') {
    if (m[1] === 'resume') return err(409, 'exec', '터미널 작업은 재개하지 않습니다. 결과 조회로 상태를 보세요.');
    const finished = o.state === 'applied';
    return ok({ op: publicOp(o), exec: { receipt: { phase: finished ? 'finished' : 'started', exitCode: finished ? Number(o.errorCode?.replace('exit-', '') ?? 0) : undefined }, running: !finished, observedAt: nowIso() } });
  }
  if (o.state !== 'unknown') return m[1] === 'resume' ? err(409, 'settled', '이미 결과가 확정된 작업입니다.') : ok({ op: publicOp(o) });
  const apply = pendingApply.get(o.id);
  if (!apply) return ok({ op: publicOp(o) }); // 원 결과를 못 찾음: 불명 유지
  pendingApply.delete(o.id);
  // 목업: 결과 조회는 "실은 적용됐음", 재개는 "지금 적용함"으로 정산한다.
  settle(o, apply());
  return ok({ op: publicOp(o) });
});

// 알림 (UI-C0)
on('GET', '/notifications', (_m, _b, query) => {
  requireSession();
  const unread = fx.notifications.filter((n) => !n.readAt);
  const limit = Math.min(500, Math.max(1, Number(query.get('limit')) || 50));
  const items = (query.get('unread') === '1' ? unread : fx.notifications).slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limit);
  return ok({ items, unread: unread.length });
});
on('POST', '/notifications/read-all', () => {
  requireSession();
  for (const n of fx.notifications) n.readAt ??= nowIso();
  return ok(null, 204);
});
on('POST', '/notifications/:id/read', (m) => {
  requireSession();
  const n = fx.notifications.find((x) => x.id === m[0]);
  if (!n) return err(404, 'not-found', '알림을 찾지 못했습니다.');
  n.readAt ??= nowIso();
  return ok(null, 204);
});
on('GET', '/notify-prefs', () => (requireSession(), ok({ prefs: fx.notifyPrefs, kinds: fx.notifyKinds })));
on('PUT', '/notify-prefs', (_m, body) => {
  requireSession();
  const p = (body.prefs ?? {}) as Partial<D.DNotifyPrefs>;
  Object.assign(fx.notifyPrefs, { mutedKinds: p.mutedKinds ?? [], mutedTenants: p.mutedTenants ?? [], browser: !!p.browser });
  return ok({ prefs: fx.notifyPrefs });
});

// 웹 앱 설정 (UI-C1)
const SETTING_RANGE: Partial<Record<keyof D.DWebSettings, [number, number]>> = {
  maxSessionsPerUser: [0, 50],
  webhookDeliveryRetentionDays: [0, 3650],
  mcpCallRetentionDays: [0, 3650],
  trashRetentionDays: [0, 30],
  sessionMaxHours: [0, 720],
  sessionIdleMinutes: [0, 1440],
  opRetentionDays: [1, 3650],
  auditRetentionDays: [30, 3650],
  notificationRetentionDays: [1, 3650],
};
const settingsReply = (): D.DSettingsReply => ({
  settings: fx.webState.settings,
  defaults: fx.webDefaults,
  info: { version: 'mock', schema: 3, dbBytes: 2_621_440, restorePending: fx.webState.restorePending, dbPath: '/var/lib/sfc-web/web.db', socket: '/run/sfc/sfcdp.sock', connected: true, sfcdVersion: { version: '0.9.0-fake', commit: '11a0406', buildTime: '2026-11-24T01:50:00Z', protocol: '1' } },  // container는 아직 계약에 없음
  seal: fx.webState.seal,
});
const auditAdd = (user: User, area: string, action: string, target?: string, before?: unknown, after?: unknown) =>
  fx.audit.unshift({ id: 'a' + Date.now(), at: nowIso(), user: user.id, username: user.username, area, action, target, before, after });
// 공급자 진단 로그 (UI-C1, sfc-web 몫). 토큰은 목업에도 남기지 않는다(응답으로 한 번만)
const PL_IDLE_MS = 60 * 60_000;
const PL_LIMIT_MS = 24 * 60 * 60_000;
const plSeed = (): D.DProviderLogEntry[] => {
  const t = Date.now() - 90 * 60_000;
  const at = (s: number) => new Date(t + s * 1000).toISOString();
  const rows: D.DProviderLogEntry[] = [
    { seq: 1, at: at(0), provider: 'dns:hostinger', op: 'GetZone', level: 'error', error: 'Unauthenticated', http: { method: 'GET', url: 'https://developers.hostinger.com/api/dns/v1/zones/shop.example.com', status: 401, durationMs: 182, request: 'Authorization: [가림]', response: '{"message":"Unauthenticated"}', respBytes: 29 } },
    { seq: 2, at: at(17), provider: 'dns:hostinger', op: 'Apply', level: 'info', msg: '_acme-challenge TXT', http: { method: 'PUT', url: 'https://developers.hostinger.com/api/dns/v1/zones/shop.example.com', status: 200, durationMs: 240, request: '{"zone":[{"name":"_acme-challenge","type":"TXT","records":[{"content":"[가림]"}]}]}', reqBytes: 88 } },
    { seq: 3, at: at(31), provider: 'acme:letsencrypt', op: 'Challenge', level: 'info', http: { method: 'POST', url: 'https://acme-v02.api.letsencrypt.org/acme/chall/…/Yk2p', status: 200, durationMs: 310, request: '{"protected":"[가림]","payload":"{}","signature":"[가림]"}', response: '{"status":"valid"}' } },
  ];
  // 목록 넘기기를 볼 수 있게 오래된 항목을 더 둔다
  for (let k = 0; k < 60; k++) rows.unshift({ seq: 0, at: at(-60 * (k + 1)), provider: k % 3 ? 'dns:hostinger' : 'acme:letsencrypt-staging', op: k % 3 ? 'GetZone' : 'NewOrder', level: 'info', http: { method: k % 3 ? 'GET' : 'POST', url: k % 3 ? 'https://developers.hostinger.com/api/dns/v1/zones/shop.example.com' : 'https://acme-staging-v02.api.letsencrypt.org/acme/new-order', status: 200, durationMs: 150 + k } });
  return rows.map((r, n) => ({ ...r, seq: n + 1 }));
};
const pl: { enabled: boolean; enabledAt?: string; enabledBy?: string; lastActivity?: number; disabledAt?: string; disabledReason?: string; items: D.DProviderLogEntry[] } = { enabled: false, disabledAt: new Date(Date.now() - 80 * 60_000).toISOString(), disabledReason: 'idle', items: plSeed() };
const plTick = () => {
  if (!pl.enabled || pl.lastActivity === undefined) return;
  const limit = Date.parse(pl.enabledAt!) + PL_LIMIT_MS;
  const idle = pl.lastActivity + PL_IDLE_MS;
  const end = Math.min(limit, idle);
  if (Date.now() > end) Object.assign(pl, { enabled: false, disabledAt: new Date(end).toISOString(), disabledReason: end === limit ? 'limit' : 'idle', enabledAt: undefined, enabledBy: undefined });
};
const plState = (): D.DProviderLogState => {
  plTick();
  const n = { entries: pl.items.length, last: pl.items[pl.items.length - 1]?.seq ?? 0 };
  return pl.enabled
    ? { enabled: true, enabledAt: pl.enabledAt, enabledBy: pl.enabledBy, lastActivity: new Date(pl.lastActivity!).toISOString(), expiresAt: new Date(Math.min(pl.lastActivity! + PL_IDLE_MS, Date.parse(pl.enabledAt!) + PL_LIMIT_MS)).toISOString(), ...n }
    : { enabled: false, disabledAt: pl.disabledAt, disabledReason: pl.disabledReason, ...n };
};
on('GET', '/diag/provider-log/state', () => {
  requireAdmin(requireSession().user);
  return ok(plState());
});
on('POST', '/diag/provider-log/enable', () => {
  const { user } = requireSession();
  requireAdmin(user);
  plTick();
  const now = Date.now();
  // 켜져 있을 때 다시 켜면 토큰만 바뀐다
  if (!pl.enabled) Object.assign(pl, { enabled: true, enabledAt: new Date(now).toISOString(), enabledBy: user.username, disabledAt: undefined, disabledReason: undefined });
  pl.lastActivity = now;
  auditAdd(user, 'diag', 'provider-log-enable');
  return ok({ token: 'mpl_' + randHex(16), state: plState() });
});
on('POST', '/diag/provider-log/disable', () => {
  const { user } = requireSession();
  requireAdmin(user);
  plTick();
  if (pl.enabled) Object.assign(pl, { enabled: false, disabledAt: nowIso(), disabledReason: 'user', enabledAt: undefined, enabledBy: undefined });
  auditAdd(user, 'diag', 'provider-log-disable');
  return ok(plState());
});
on('GET', '/diag/provider-log', (_m, _b, query) => {
  requireAdmin(requireSession().user);
  const all = pl.items;
  const tail = Number(query.get('tail') ?? 0);
  const limit = Math.min(Math.max(Number(query.get('limit') ?? 100) || 100, 1), 1000);
  const after = Number(query.get('after') ?? 0);
  const entries = tail > 0 ? all.slice(-tail) : all.filter((x) => x.seq > after).slice(0, limit);
  const last = all[all.length - 1]?.seq ?? 0;
  const next = entries[entries.length - 1]?.seq ?? after;
  return ok({ page: { entries, next, last, oldest: all[0]?.seq ?? 0, more: next < last }, state: plState() });
});
on('GET', '/system/settings', () => {
  requireAdmin(requireSession().user);
  return ok(settingsReply());
});
on('PUT', '/system/settings', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const next = (body.settings ?? {}) as D.DWebSettings;
  for (const [k, [lo, hi]] of Object.entries(SETTING_RANGE) as [keyof D.DWebSettings, [number, number]][]) {
    const v = next[k] as number | undefined;
    if (v === undefined && k in fx.webState.settings === false) continue;
    if (!Number.isInteger(v) || v! < lo || v! > hi) return err(422, 'invalid', `${k}는 ${lo}..${hi} 사이여야 합니다.`);
  }
  if (next.allowKeyLogin !== undefined && typeof next.allowKeyLogin !== 'boolean') return err(422, 'invalid', 'allowKeyLogin: bool');
  auditAdd(user, 'web-settings', 'update', undefined, fx.webState.settings, next);
  fx.webState.settings = { ...fx.webState.settings, ...next };
  setTrashRetention(fx.webState.settings.trashRetentionDays ?? 0);
  return ok(settingsReply());
});
// 웹 데이터 자동 백업(UI-C1, REQ-28 웹 데몬 계약 요청 중)과 데이터 저장소 파일
const BACKUP_PREFIX = 'sfc-web-backups/';
const MiB = 1024 * 1024;
const backupName = (ms: number) => `${BACKUP_PREFIX}web-${new Date(ms).toISOString().slice(0, 16).replace(/:/g, '')}Z.db.gz.sealed`;
const volFiles = new Map<string, D.DVolumeFile[]>([
  [
    'shop/sfc-web-backup',
    Array.from({ length: 14 }, (_, i) => {
      const at = new Date();
      at.setHours(3, 0, 0, 0);
      const ms = at.getTime() - i * 86400_000 - (at.getTime() > Date.now() ? 86400_000 : 0);
      return { path: backupName(ms), bytes: Math.round((41.8 - i * 0.2) * MiB), modifiedAt: new Date(ms).toISOString() };
    }),
  ],
]);
const grants = new Set<string>(['shop/sfc-web-backup/sfc-web-backups/u-web-auto']);
const AUTO_ACCOUNT = { id: 'u-web-auto', username: 'sfc-web-auto' };
const autoState: Omit<D.DAutoBackup, 'granted' | 'prefix' | 'account' | 'next' | 'running'> = { enabled: true, at: '03:00', keep: 14, tenant: 'shop', volume: 'sfc-web-backup' };
let autoRunUntil = 0;
const autoView = (): D.DAutoBackup => {
  const files = volFiles.get(`${autoState.tenant}/${autoState.volume}`) ?? [];
  const last = autoState.last ?? (files[0] && { at: files[0].modifiedAt, ok: true, bytes: files[0].bytes, path: files[0].path });
  const [h, mi] = autoState.at.split(':').map(Number);
  const next = new Date();
  next.setHours(h, mi, 0, 0);
  if (next.getTime() <= Date.now()) next.setDate(next.getDate() + 1);
  return { ...autoState, sealed: true, sealReady: fx.webState.seal.ready, running: Date.now() < autoRunUntil, prefix: BACKUP_PREFIX, account: AUTO_ACCOUNT.username, accountId: AUTO_ACCOUNT.id, granted: autoState.tenant && autoState.volume ? grants.has(`${autoState.tenant}/${autoState.volume}/${BACKUP_PREFIX}${AUTO_ACCOUNT.id}`) : undefined, last, next: autoState.enabled ? next.toISOString() : undefined };
};
on('GET', '/system/auto-backup', () => (requireAdmin(requireSession().user), ok(autoView())));
on('PUT', '/system/auto-backup', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const at = String(body.at ?? '');
  const keep = Number(body.keep);
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(at)) return err(422, 'invalid', 'at: HH:MM');
  if (!Number.isInteger(keep) || keep < 1 || keep > 365) return err(422, 'invalid', 'keep: 1..365');
  const vol = fx.volumes.find((v) => v.tenant === body.tenant && v.name === body.volume);
  if (!vol) return err(404, 'not-found', 'no such volume');
  if (vol.kind !== 'fixed' || vol.app) return err(422, 'invalid', 'volume: a fixed volume that no app owns');
  const before = { ...autoState };
  Object.assign(autoState, { enabled: !!body.enabled, at, keep, tenant: String(body.tenant), volume: String(body.volume) });
  auditAdd(user, 'web-backup', 'auto-backup', undefined, before, { ...autoState, last: undefined });
  return ok(autoView());
});
on('POST', '/system/auto-backup/run', () => {
  const { user } = requireSession();
  requireAdmin(user);
  if (!fx.webState.seal.ready) return err(503, 'seal-unavailable', 'the web seal key is not ready');
  if (!autoState.tenant || !autoState.volume) return err(409, 'not-configured', 'choose a volume first');
  if (Date.now() < autoRunUntil) return err(409, 'running', 'a backup is running');
  autoRunUntil = Date.now() + 2000;
  const key = `${autoState.tenant}/${autoState.volume}`;
  setTimeout(() => {
    const files = volFiles.get(key) ?? [];
    const f = { path: backupName(Date.now()), bytes: Math.round(42.1 * MiB), modifiedAt: nowIso() };
    volFiles.set(key, [f, ...files.filter((x) => x.path !== f.path)].slice(0, autoState.keep));
    autoState.last = { at: f.modifiedAt, ok: true, bytes: f.bytes, path: f.path, by: user.username };
  }, 2000);
  return ok({ running: true }, 202);
});
on('POST', '/system/restore-from', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const f = (volFiles.get(`${body.tenant}/${body.volume}`) ?? []).find((x) => x.path === body.path);
  if (!fx.webState.seal.ready) return err(503, 'seal-unavailable', 'the web seal key is not ready');
  if (!f) return err(404, 'not-found', 'no such file');
  // 목업: 일주일보다 오래된 백업은 다른 봉인 키로 잠근 것으로 본다
  if (Date.now() - Date.parse(f.modifiedAt) > 7 * 86400_000) return err(422, 'seal-key', 'the backup was sealed with another key');
  fx.webState.restorePending = true;
  auditAdd(user, 'web-backup', 'restore-pending', String(body.path));
  return ok({ restorePending: true, bytes: f.bytes }, 202);
});
const fileVol = (t: string, name: string) => {
  const { user } = requireSession();
  requireTenant(user, t);
  return { user, vol: fx.volumes.find((v) => v.tenant === t && v.name === name) };
};
on('GET', '/t/:t/volumes/:n/files', (m, _b, query) => {
  const { vol } = fileVol(m[0], m[1]);
  if (!vol) return err(404, 'not-found', 'no such volume');
  const prefix = query.get('prefix') ?? '';
  const after = query.get('after') ?? '';
  // #270: 경로 순으로 한 쪽 64개, digest·revision·asOf 없음
  const all = (volFiles.get(`${m[0]}/${m[1]}`) ?? []).filter((f) => f.path.startsWith(prefix) && f.path > after).sort((a, b) => (a.path < b.path ? -1 : 1));
  const page = all.slice(0, 64);
  return ok({ items: page, next: all.length > 64 ? page[page.length - 1].path : '' });
});
on('DELETE', '/t/:t/volumes/:n/file', (m, body) => {
  const { user, vol } = fileVol(m[0], m[1]);
  if (!vol) return err(404, 'not-found', 'no such volume');
  const path = String(body.path ?? '');
  // #270: 없는 파일은 서명 전에 404, 응답은 {op, file:{path}}
  if (!findOp(String(body.opId ?? ''), user.id) && !(volFiles.get(`${m[0]}/${m[1]}`) ?? []).some((f) => f.path === path)) return err(404, 'not-found', 'no such file');
  const r = submit(user, { ...body, tenant: m[0], target: `volume/${m[1]}` }, 'volume-file-delete', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    const files = volFiles.get(`${m[0]}/${m[1]}`) ?? [];
    volFiles.set(`${m[0]}/${m[1]}`, files.filter((f) => f.path !== path));
  });
  return r.status < 300 && r.json && typeof r.json === 'object' ? { ...r, json: { ...(r.json as object), file: { path } } } : r;
});
const grantRoute = (revoke: boolean) => (m: string[], body: Record<string, unknown>) => {
  const { user, vol } = fileVol(m[0], m[1]);
  if (!vol) return err(404, 'not-found', 'no such volume');
  const prefix = String(body.prefix ?? '');
  if (!prefix.endsWith('/') || prefix.startsWith('/')) return err(422, 'invalid', 'prefix: a relative folder ending in /');
  return submit(user, { ...body, tenant: m[0], target: `volume/${m[1]}` }, revoke ? 'volume-file-revoke' : 'volume-file-grant', () => {
    if (!canWrite(user, m[0])) return FORBIDDEN;
    // #270: 받는 계정은 그 작업 공간의 구성원(보기 이상)이어야 한다
    if (!revoke && !fx.memberships[m[0]]?.[String(body.user)]) return { code: 4, errorCode: 'forbidden' };
    const k = `${m[0]}/${m[1]}/${prefix}${String(body.user)}`;
    if (revoke) grants.delete(k);
    else grants.add(k);
  });
};
on('POST', '/t/:t/volumes/:n/file-grants', grantRoute(false));
on('DELETE', '/t/:t/volumes/:n/file-grants', grantRoute(true));
on('GET', '/system/seal', () => (requireSession(), ok({ state: fx.webState.seal.state, ready: fx.webState.seal.ready, reason: fx.webState.seal.reason })));
on('POST', '/system/seal/reset', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  if (body.confirm !== 'reset') return err(422, 'invalid', 'confirm은 "reset"이어야 합니다.');
  if (fx.webState.seal.ready) return err(409, 'seal-ready', '봉인 파일이 정상이라 초기화하지 않습니다.');
  fx.webState.seal = { state: 'ready', ready: true, kinds: [] };
  auditAdd(user, 'seal', 'reset');
  return ok(fx.webState.seal);
});
on('POST', '/system/restore', (_m, body) => {
  const { user } = requireSession();
  requireAdmin(user);
  const file = body as unknown as Blob;
  if (!(file instanceof Blob) || file.size === 0) return err(422, 'invalid', '웹 데이터 백업 파일이 아닙니다.');
  fx.webState.restorePending = true;
  auditAdd(user, 'web-backup', 'restore-pending', undefined, undefined, { bytes: file.size });
  return ok({ restorePending: true, bytes: file.size }, 202);
});
on('DELETE', '/system/restore', () => {
  const { user } = requireSession();
  requireAdmin(user);
  fx.webState.restorePending = false;
  auditAdd(user, 'web-backup', 'restore-cancel');
  return ok(null, 204);
});

// 설정 변경 기록 (UI-A3)
on('GET', '/audit', (_m, _b, query) => {
  const { user } = requireSession();
  const tenant = query.get('tenant');
  const before = query.get('before');
  const limit = Math.min(1000, Math.max(1, Number(query.get('limit')) || 100));
  let rows = fx.audit.filter((a) => (user.systemAdmin ? true : !!a.tenant && !!roleIn(user, a.tenant)));
  if (tenant) rows = rows.filter((a) => a.tenant === tenant);
  if (before) {
    const i = rows.findIndex((a) => a.id === before);
    rows = i >= 0 ? rows.slice(i + 1) : rows;
  }
  const items = rows.slice(0, limit);
  return ok({ items, next: rows.length > limit ? items[items.length - 1].id : '' });
});

// ── 진입점 ──────────────────────────────────────────────

registerDns({ on, ok, err, user: () => requireSession().user, roleIn: (u, t) => roleIn(u as User, t) });
registerAcme({ on, ok, err, user: () => requireSession().user });
registerNodeShell({ on, ok, err, user: () => requireSession().user, submit });
registerVps({ on, ok, err, user: () => requireSession().user, submit });
registerFirewall({ on, ok, err, user: () => requireSession().user });
registerAi({
  on,
  ok,
  err,
  admin: () => {
    const { user } = requireSession();
    requireAdmin(user);
    return user;
  },
  sealReady: () => fx.webState.seal.ready,
});
registerCoordinator({
  on,
  ok,
  err,
  me: () => requireSession().user,
  submit: (body, action) => submit(requireSession().user, body, action, () => undefined),
});
registerIncidents({
  on,
  ok,
  err,
  me: () => requireSession().user,
  reader: (t) => requireTenant(requireSession().user, t),
  canWrite: (t) => canWrite(requireSession().user, t),
  submit: (body, action) => submit(requireSession().user, body, action, () => undefined),
  automation: () => (automationState ? { configured: true, username: automationState.username } : { configured: false }),
});
registerMcp({
  on,
  ok,
  err,
  admin: () => requireAdmin(requireSession().user),
});
registerWebhooks({
  on,
  ok,
  err,
  me: () => requireSession().user,
  canWrite: (t) => canWrite(requireSession().user, t),
  reader: (t) => requireTenant(requireSession().user, t),
  cdMode: (t, a) => {
    const s = cdState(t, a);
    return s ? (s.policy?.sync.mode ?? s.mode) : undefined;
  },
  automation: () => (automationState ? { configured: true, username: automationState.username } : { configured: false }),
});
registerTrash({
  on,
  ok,
  err,
  sees: (it) => {
    const u = requireSession().user;
    if (u.systemAdmin) return true;
    if (it.kind === 'mcp-server' || it.kind === 'cluster-app-route') return false;
    return !!it.tenant && visibleTenants(u).includes(it.tenant) && (it.kind === 'dns-record' || canWrite(u, it.tenant));
  },
  extra: () => {
    const u = requireSession().user;
    return fx.archived
      .filter((a) => u.systemAdmin || visibleTenants(u).includes(a.tenant))
      .map((a) => ({ id: `app:${a.key}`, kind: 'app', tenant: a.tenant, name: a.app, deletedBy: a.downBy, deletedAt: a.downAt, restore: 'link' as const, link: { kind: 'archived-apps', tenant: a.tenant, app: a.app } }));
  },
});
// 지운 것 보기용: 어제 alice가 뺀 shop-net의 cache CNAME
trashDnsRow('alice', 'shop', 'shop-net', { name: 'cache', type: 'CNAME', value: 'web.php-shop.shop.sfc.test.' }, undefined, Date.now() - 86400000);
registerIngress({
  on,
  ok,
  err,
  me: () => requireSession().user,
  tenants: () => visibleTenants(requireSession().user),
  canWrite: (t) => canWrite(requireSession().user, t),
});
registerGuides({
  on,
  ok,
  err,
  me: () => requireSession().user,
  reader: (t) => requireTenant(requireSession().user, t),
  canWrite: (t) => canWrite(requireSession().user, t),
});
registerBuilds({
  on,
  ok,
  err,
  reader: (t) => {
    const { user } = requireSession();
    requireTenant(user, t);
    return user;
  },
  canWrite: (t) => canWrite(requireSession().user, t),
  submit: (body, action, apply) => submit(requireSession().user, body, action, apply),
  vaultKeys: (t, object) => fx.vault.find((v) => v.tenant === t && v.kind === 'object' && v.id === object)?.keys ?? undefined,
  trust: (t) => fx.imageTrust[t]?.rules ?? [],
  builtinHost: (t) => regFind(t, 'builtin')?.endpoint ?? 'registry.local',
  pushImage: (t, repository, tag, digest, bytes) => {
    for (const im of fx.registryImages) if (im.tenant === t && im.repository === repository) im.tags = (im.tags ?? []).filter((x) => x !== tag);
    fx.registryImages.unshift({ tenant: t, registry: 'builtin', repository, digest, tags: [tag], bytes, pushedAt: Math.floor(Date.now() / 1000), inUse: 0, usedBy: [] });
  },
  roots: (t) => fx.storageRoots.filter((r) => r.tenants?.includes(t) && !rootGone.has(`${r.node}/${r.id}`)),
  revision: () => ROOT_REVISION + fx.ops.length,
  buildGate,
});

registerTasks({
  on,
  ok,
  err,
  reader: (t) => {
    const { user } = requireSession();
    requireTenant(user, t);
    return user;
  },
  canWrite: (t) => canWrite(requireSession().user, t),
  submit: (body, action, apply) => submit(requireSession().user, body, action, apply),
});

registerImageTools({
  on,
  ok,
  err,
  reader: (t) => {
    const { user } = requireSession();
    requireTenant(user, t);
    return user;
  },
  canWrite: (t) => canWrite(requireSession().user, t),
  registry: (t, id) => regFind(t, id),
  usage: (t, ref) => imageUseRow(t, ref),
});

/** 지금 처리하는 요청의 머리글(사유 등) */
let reqHeaders: Record<string, string> = {};
export async function mockFetch(method: string, rawPath: string, body: unknown, signal?: AbortSignal, headers?: Record<string, string>): Promise<RawResponse> {
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, mockControls.latencyMs * (0.6 + Math.random() * 0.8));
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new DOMException('aborted', 'AbortError'));
    });
  });
  const [path, qs] = rawPath.split('?');
  const query = new URLSearchParams(qs ?? '');
  for (const [mth, re, h] of routes) {
    if (mth !== method) continue;
    const match = path.match(re);
    if (!match) continue;
    try {
      reqHeaders = headers ?? {};
      const res = await h(match.slice(1).map(decodeURIComponent), (body ?? {}) as Record<string, unknown>, query);
      return structuredClone(res);
    } catch (e) {
      if (e instanceof Halt) return e.res;
      return err(500, 'transport', `목업 오류: ${(e as Error).message}`);
    }
  }
  return err(404, 'not-found', `목업에 없는 경로: ${method} ${path}`);
}

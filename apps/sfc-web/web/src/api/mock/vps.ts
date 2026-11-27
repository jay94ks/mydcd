// SPDX-License-Identifier: Apache-2.0

// 목업: 서버 › VPS 관리 (UI-12B, docs/reference/web-api/54-vps.md). 단계 바뀜은 몇 초 뒤 저절로 일어난다.
// 공급자 키는 받기만 하고 남기지 않는다(끝 네 글자만).
import type { RawResponse } from '../client';
import type { VpsAccount, VpsServer, VpsServerStatus, VpsAccountStatus, VpsOffer, VpsDnsPlan } from '../vps';
import { IWINV_TIERS } from '../vps';
import * as fx from './fixtures';

type Applied = { code: number; errorCode?: string } | void;
interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, q: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  user: () => fx.MockUser;
  submit: (user: fx.MockUser, body: Record<string, unknown>, action: string, apply: () => Applied) => RawResponse;
}

const now = () => Math.floor(Date.now() / 1000);
const H = 3600;
const st = {
  revision: 7,
  accounts: [
    { name: 'main', vendor: 'iwinv', overageKRWPerGB: 10, overageTiers: IWINV_TIERS, keyHint: '3F2A', sshPublic: 'ssh-ed25519 AAAAC3Nza…mock sfc-main', sshKeyID: 'key-1', addedBy: 'alice', addedAt: now() - 30 * 86400 },
    { name: 'test', vendor: 'iwinv', overageKRWPerGB: 10, overageTiers: IWINV_TIERS, keyHint: '91C0', sshPublic: 'ssh-ed25519 AAAAC3Nza…mock sfc-test', addedBy: 'alice', addedAt: now() - 20 * 86400 },
  ] as VpsAccount[],
  servers: [
    { name: 'vps-seoul-1', account: 'main', zone: 'KR1', image: 'ubuntu-2404', flavor: 'ss1-c2m4', script: 'sfc-enroll', capKRW: 30000, capAction: 'notify', voter: false, port: 7443, createdBy: 'alice', createdAt: now() - 24 * 86400, phase: 'running', phaseAt: now() - 24 * 86400, instanceID: 'i-seoul1', publicIP: '211.37.150.21' },
    { name: 'vps-seoul-2', account: 'main', zone: 'KR1', image: 'ubuntu-2404', flavor: 'ss1-c4m8', script: 'sfc-enroll', capKRW: 50000, capAction: 'stop', voter: true, port: 7443, createdBy: 'alice', createdAt: now() - 22 * 86400, phase: 'running', phaseAt: now() - 22 * 86400, instanceID: 'i-seoul2', publicIP: '211.37.150.48' },
    {
      name: 'vps-busan-1', account: 'main', zone: 'KR2', image: 'ubuntu-2404', flavor: 'ss1-c2m4', script: 'sfc-enroll', capKRW: 20000, capAction: 'stop', voter: false, port: 7443, createdBy: 'alice', createdAt: now() - 7 * 86400,
      phase: 'capped', phaseAt: now() - 8 * H, capStop: { at: now() - 8 * H, month: new Date().toISOString().slice(0, 7), capKRW: 20000, soFarKRW: 20000, projectedKRW: 31400, reason: 'traffic-soon' }, instanceID: 'i-busan', publicIP: '175.45.201.9',
      dnsHolds: [{ domain: 'example.com', at: new Date(Date.now() - 8 * H * 1000).toISOString(), sets: [{ name: 'shop', type: 'A', removed: ['175.45.201.9'] }, { name: '*', type: 'A', removed: ['175.45.201.9'] }], kept: [], blocked: [] }],
    },
    { name: 'vps-seoul-3', account: 'main', zone: 'KR1', image: 'ubuntu-2404', flavor: 'ss1-c1m2', script: 'sfc-enroll', capKRW: 15000, capAction: 'stop', voter: false, port: 7443, createdBy: 'alice', createdAt: now() - 600, phase: 'installing', joining: true, phaseAt: now() - 300, instanceID: 'i-seoul3', publicIP: '211.37.150.77' },
    { name: 'vps-test', account: 'test', zone: 'KR1', image: 'ubuntu-2404', flavor: 'ss1-c1m1', script: 'sfc-enroll', capKRW: 10000, capAction: 'stop', voter: false, port: 7443, createdBy: 'alice', createdAt: now() - 15 * 86400, phase: 'stopped', phaseAt: now() - 2 * 86400, instanceID: 'i-test' },
  ] as VpsServer[],
  status: new Map<string, Omit<VpsServerStatus, 'name' | 'updatedAt' | 'capKRW'>>([
    ['vps-seoul-1', { soFarKRW: 19800, projectedKRW: 24600, baseSoFarKRW: 19800, baseMonthKRW: 22000, trafficSoFarKRW: 0, trafficMonthKRW: 0, usedGB: 412, includedGB: 20, includedPeriod: 'DAY', includedMonthGB: 500, includedMaxGB: 600, todayMB: 14 * 1024, daily: [16, 18, 22, 19, 17, 21, 14].map((g, i) => ({ day: `2026-11-${21 + i}`, mb: g * 1024 })), projectedGB: 470, recentMB: 412, judgeable: true, guard: { at: now() - 30, rateMbps: 42, prevMbps: 38, averageMbps: 35, forecastGB: 6.6, patternGB: 4.1, patternDays: 12, patternUsed: true, monthGB: 412, remainingGB: 160 } }],
    ['vps-seoul-2', { soFarKRW: 38900, projectedKRW: 52700, baseSoFarKRW: 38900, baseMonthKRW: 44000, trafficSoFarKRW: 0, trafficMonthKRW: 8700, usedGB: 590, includedGB: 20, includedPeriod: 'DAY', includedMonthGB: 540, includedMaxGB: 600, todayMB: 23 * 1024, daily: [24, 19, 28, 22, 25, 26, 23].map((g, i) => ({ day: `2026-11-${21 + i}`, mb: g * 1024 })), projectedGB: 720, recentMB: 3100, judgeable: true, over: true, capBlocked: true, guard: { at: now() - 30, rateMbps: 310, prevMbps: 240, averageMbps: 180, forecastGB: 48.8, patternDays: 4, patternUsed: false, monthGB: 590, remainingGB: 31, soon: true, soonAt: now() + 12 * 60 } }],
    ['vps-busan-1', { soFarKRW: 20000, projectedKRW: 20000, baseSoFarKRW: 5100, baseMonthKRW: 22000, trafficSoFarKRW: 14900, trafficMonthKRW: 14900, usedGB: 610, includedGB: 20, includedPeriod: 'DAY', includedMonthGB: 160, includedMaxGB: 600, daily: [60, 80, 95, 110, 120, 145, 0].map((g, i) => ({ day: `2026-11-${21 + i}`, mb: g * 1024 })), projectedGB: 610, recentMB: 0, judgeable: false }],
    ['vps-test', { soFarKRW: 2100, projectedKRW: 2600, baseSoFarKRW: 2100, baseMonthKRW: 6600, trafficSoFarKRW: 0, trafficMonthKRW: 0, usedGB: 3, includedGB: 20, includedPeriod: 'DAY', includedMonthGB: 540, includedMaxGB: 600, daily: [1, 1, 0, 1, 0, 0, 0].map((g, i) => ({ day: `2026-11-${21 + i}`, mb: g * 1024 })), projectedGB: 3, recentMB: 0, judgeable: false }],
  ]),
  /** 공급자 키가 거부된 계정(목업) */
  rejected: new Set(['test']),
};
const TR = { gb: 20, period: 'DAY', maxGB: 600, estimated: true };
const FLAVORS: VpsOffer['flavors'] = [
  { id: 'ss1-c1m1', name: 'ss1.c1m1', vcpu: 1, memoryMiB: 1024, diskGB: 25, full: { krw: 6600, per: 'month' }, traffic: TR },
  { id: 'ss1-c1m2', name: 'ss1.c1m2', vcpu: 1, memoryMiB: 2048, diskGB: 25, full: { krw: 11000, per: 'month' }, traffic: TR },
  { id: 'ss1-c2m4', name: 'ss1.c2m4', vcpu: 2, memoryMiB: 4096, diskGB: 50, full: { krw: 22000, per: 'month' }, traffic: TR },
  { id: 'ss1-c4m8', name: 'ss1.c4m8', vcpu: 4, memoryMiB: 8192, diskGB: 100, full: { krw: 44000, per: 'month' }, traffic: TR },
];
export const vpsMockFlavor = (id: string) => FLAVORS.find((f) => f.id === id);

/** 단계를 몇 초 뒤에 바꾼다 */
function later(name: string, ms: number, f: (s: VpsServer) => void) {
  setTimeout(() => {
    const s = st.servers.find((x) => x.name === name);
    if (s) {
      f(s);
      s.phaseAt = now();
      st.revision++;
    }
  }, ms);
}

export function registerVps({ on, ok, err, user, submit }: Ctx) {
  const admin = () => user().systemAdmin;
  const deny = () => err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
  const rev = (b: Record<string, unknown>) => (b.expected === undefined ? st.revision : Number(b.expected));
  const cas = (b: Record<string, unknown>): Applied => (rev(b) !== st.revision ? { code: 1 } : undefined);
  const bump = () => void st.revision++;
  const statusOf = (s: VpsServer): VpsServerStatus | undefined => {
    const off = s.phase === 'stopping' || s.phase === 'stopped' || s.phase === 'capped';
    if (s.phase !== 'running' && !off) return undefined;
    if (off) {
      const y = st.status.get(s.name);
      return y ? { name: s.name, updatedAt: now() - 120, capKRW: s.capKRW, ...y, guard: undefined, over: false } : undefined;
    }
    const x = st.status.get(s.name) ?? { soFarKRW: 40, projectedKRW: 0, baseSoFarKRW: 40, baseMonthKRW: vpsMockFlavor(s.flavor)?.full?.krw ?? 0, trafficSoFarKRW: 0, trafficMonthKRW: 0, usedGB: 0, projectedGB: 0, recentMB: 0, judgeable: false };
    const over = x.judgeable ? x.projectedKRW > s.capKRW : x.soFarKRW > s.capKRW;
    return { name: s.name, updatedAt: now() - 120, capKRW: s.capKRW, ...x, over, capBlocked: over && s.voter && s.capAction !== 'notify' };
  };

  on('GET', '/system/vps', () => {
    if (!admin()) return deny();
    const accounts: VpsAccountStatus[] = st.accounts.map((a) => {
      const ours = st.servers.filter((s) => s.account === a.name).reduce((n, s) => n + (st.status.get(s.name)?.soFarKRW ?? (s.capStop?.soFarKRW ?? 0)), 0);
      return st.rejected.has(a.name) ? { name: a.name, billKRW: 0, oursKRW: ours, updatedAt: now() - H, failure: 'PROVIDER_AUTH' } : { name: a.name, billKRW: ours - 230, oursKRW: ours, updatedAt: now() - 120 };
    });
    return ok({ revision: st.revision, accounts: st.accounts, servers: st.servers, dnsAuto: true, status: { leader: 'node-a', servers: st.servers.map(statusOf).filter(Boolean), accounts } });
  });
  on('GET', '/system/vps/accounts/:a/offer', (m) => {
    if (!admin()) return deny();
    const a = st.accounts.find((x) => x.name === m[0]);
    if (!a) return err(404, 'not-found');
    if (st.rejected.has(a.name)) return err(503, 'unavailable', 'iwinv가 키를 거부했습니다(401).');
    const offer: VpsOffer = {
      account: a.name,
      at: now(),
      zones: [
        { id: 'KR1', name: '서울', usable: true },
        { id: 'KR2', name: '부산', usable: true },
      ],
      images: [
        { id: 'ubuntu-2404', name: 'Ubuntu 24.04 LTS', kind: 'os_linux', os: 'UBUNTU', linux: true, zones: ['KR1', 'KR2'] },
        { id: 'debian-12', name: 'Debian 12', kind: 'os_linux', os: 'DEBIAN', linux: true, zones: ['KR1'] },
        { id: 'win-2022', name: 'Windows Server 2022', kind: 'os_windows', os: 'WINDOWS', linux: false, zones: ['KR1'] },
      ],
      flavors: FLAVORS,
      sshKeys: a.sshKeyID ? [{ id: a.sshKeyID, name: `sfc-${a.name}` }] : [],
      scripts: [{ id: 'sfc-enroll', name: 'sfcli enroll' }],
    };
    return ok(offer);
  });

  // 공급자 계정
  on('POST', '/system/vps/accounts', (_m, b) => {
    if (!admin()) return deny();
    const name = String(b.name ?? '').trim();
    if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(name)) return err(422, 'invalid', 'name');
    if (!String(b.accessKey ?? '') || !String(b.secretKey ?? '')) return err(422, 'invalid', 'key');
    if (st.accounts.some((a) => a.name === name)) return err(409, 'exists', '같은 이름의 계정이 있습니다.');
    const hint = String(b.accessKey).slice(-4).toUpperCase();
    const reject = /bad|wrong/i.test(String(b.secretKey));
    return submit(user(), { ...b, accessKey: undefined, secretKey: undefined, target: name }, 'put-vps-account', () => {
      st.accounts.push({ name, vendor: 'iwinv', overageKRWPerGB: Number(b.trafficPrice ?? 10), overageTiers: IWINV_TIERS, keyHint: hint, sshPublic: `ssh-ed25519 AAAAC3Nza…mock sfc-${name}`, addedBy: user().username, addedAt: now() });
      if (reject) st.rejected.add(name);
      bump();
    });
  });
  on('POST', '/system/vps/accounts/:a/rotate-key', (m, b) => {
    if (!admin()) return deny();
    const a = st.accounts.find((x) => x.name === m[0]);
    if (!a) return err(404, 'not-found');
    const hint = String(b.accessKey ?? '').slice(-4).toUpperCase();
    const reject = /bad|wrong/i.test(String(b.secretKey ?? ''));
    return submit(user(), { ...b, accessKey: undefined, secretKey: undefined, target: a.name }, 'put-vps-account', () => {
      const c = cas(b);
      if (c) return c;
      Object.assign(a, { keyHint: hint, sshKeyID: undefined, updatedBy: user().username, updatedAt: now() });
      if (reject) st.rejected.add(a.name);
      else st.rejected.delete(a.name);
      bump();
    });
  });
  on('PATCH', '/system/vps/accounts/:a', (m, b) => {
    if (!admin()) return deny();
    const a = st.accounts.find((x) => x.name === m[0]);
    if (!a) return err(404, 'not-found');
    const price = b.trafficPrice === undefined ? a.overageKRWPerGB : Number(b.trafficPrice);
    const key = b.sshKeyId === undefined ? a.sshKeyID : String(b.sshKeyId) || undefined;
    const g = { ...(a.guard ?? {}) };
    if (b.guardWindowMin !== undefined) g.windowMin = Number(b.guardWindowMin) || undefined;
    if (b.guardAverageMin !== undefined) g.averageMin = Number(b.guardAverageMin) || undefined;
    if (b.guardPattern !== undefined) g.patternOff = b.guardPattern ? undefined : true;
    const w = g.windowMin || 5;
    const av = g.averageMin || 60;
    if (w < 1 || w > 60 || av < 2 * w || av > 1440) return err(400, 'invalid', 'guardWindowMin: 0 (5) to 60; guardAverageMin: 0 (60) or at least twice the window, up to 1440');
    const sameGuard = JSON.stringify(g) === JSON.stringify({ ...(a.guard ?? {}) });
    if (price === a.overageKRWPerGB && key === a.sshKeyID && sameGuard) return err(409, 'unchanged', '바뀌는 것이 없습니다.');
    return submit(user(), { ...b, target: a.name }, 'put-vps-account', () => {
      const c = cas(b);
      if (c) return c;
      Object.assign(a, { overageKRWPerGB: price, sshKeyID: key, guard: g, updatedBy: user().username, updatedAt: now() });
      bump();
    });
  });
  on('DELETE', '/system/vps/accounts/:a', (m, b) => {
    if (!admin()) return deny();
    const a = st.accounts.find((x) => x.name === m[0]);
    if (!a) return err(404, 'not-found');
    if (st.servers.some((s) => s.account === a.name)) return err(409, 'in-use', '이 계정으로 만든 VPS 서버가 남아 있습니다.');
    return submit(user(), { ...b, target: a.name }, 'remove-vps-account', () => {
      const c = cas(b);
      if (c) return c;
      st.accounts.splice(st.accounts.indexOf(a), 1);
      st.rejected.delete(a.name);
      bump();
    });
  });

  // VPS 서버
  on('POST', '/system/vps/servers', (_m, b) => {
    if (!admin()) return deny();
    const name = String(b.name ?? '').trim();
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name)) return err(422, 'invalid', 'name');
    if (st.servers.some((s) => s.name === name) || fx.members.some((x) => x.id === name)) return err(409, 'exists', '같은 이름의 서버가 있습니다.');
    if (!st.accounts.some((a) => a.name === b.account)) return err(422, 'invalid', 'account');
    return submit(user(), { ...b, target: name }, 'create-vps-node', () => {
      const c = cas(b);
      if (c) return c;
      st.servers.push({ name, account: String(b.account), zone: String(b.zone), image: String(b.image), flavor: String(b.flavor), script: b.script ? String(b.script) : undefined, capKRW: Number(b.capKRW), capAction: b.capAction === 'notify' ? 'notify' : 'stop', voter: b.voter === true, port: Number(b.port ?? 7443), createdBy: user().username, createdAt: now(), phase: 'creating', phaseAt: now() });
      bump();
      later(name, 3000, (s) => Object.assign(s, { phase: 'installing', instanceID: `i-${name}`, publicIP: `211.37.150.${100 + st.servers.length}` }));
      later(name, 5000, (s) => (s.joining = true));
      later(name, 7000, (s) => Object.assign(s, { phase: 'running', joining: undefined }));
    });
  });
  on('POST', '/system/vps/servers/:n/stop', (m, b) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    if (!s) return err(404, 'not-found');
    if (s.phase !== 'running') return err(409, 'phase', 'running이 아닙니다.');
    const wait = Math.min(3600, Math.max(0, Number(b.dnsWaitSeconds ?? 300)));
    return submit(user(), { ...b, target: s.name }, 'stop-vps-node', () => {
      const c = cas(b);
      if (c) return c;
      if (s.voter && st.servers.filter((x) => x.voter && x.phase === 'running').length + 3 <= 3) return { code: 2, errorCode: 'QUORUM_LOSS' };
      Object.assign(s, { phase: 'stopping', phaseAt: now(), stopAfter: now() + wait });
      bump();
      later(s.name, 4000, (x) => Object.assign(x, { phase: 'stopped', stopAfter: undefined }));
    });
  });
  on('POST', '/system/vps/servers/:n/start', (m, b) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    if (!s) return err(404, 'not-found');
    if (s.phase !== 'stopped' && s.phase !== 'capped') return err(409, 'phase', '중지된 서버만 켭니다.');
    return submit(user(), { ...b, target: s.name }, 'start-vps-node', () => {
      const c = cas(b);
      if (c) return c;
      if (s.phase === 'capped' && s.capStop && s.capStop.month === new Date().toISOString().slice(0, 7) && s.capKRW <= s.capStop.projectedKRW) return { code: 2, errorCode: 'CAP_REACHED' };
      Object.assign(s, { phase: 'starting', phaseAt: now() });
      bump();
      later(s.name, 4000, (x) => Object.assign(x, { phase: 'running', dnsHolds: [] }));
    });
  });
  on('POST', '/system/vps/servers/:n/cap', (m, b) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    if (!s) return err(404, 'not-found');
    const cap = b.capKRW === undefined ? s.capKRW : Number(b.capKRW);
    const act = b.capAction === undefined ? s.capAction : b.capAction === 'notify' ? 'notify' : 'stop';
    if (cap === s.capKRW && act === s.capAction) return err(409, 'unchanged', '바뀌는 것이 없습니다.');
    return submit(user(), { ...b, target: s.name }, 'set-vps-node-cap', () => {
      const c = cas(b);
      if (c) return c;
      Object.assign(s, { capKRW: cap, capAction: act });
      bump();
    });
  });
  on('DELETE', '/system/vps/servers/:n', (m, b) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    if (!s) return err(404, 'not-found');
    if (s.phase === 'deleting') return err(409, 'phase', '이미 삭제 중입니다.');
    return submit(user(), { ...b, target: s.name }, 'delete-vps-node', () => {
      const c = cas(b);
      if (c) return c;
      Object.assign(s, { phase: 'deleting', phaseAt: now() });
      bump();
      setTimeout(() => {
        const i = st.servers.indexOf(s);
        if (i >= 0) st.servers.splice(i, 1);
        st.revision++;
      }, 4000);
    });
  });
  on('GET', '/system/vps/servers/:n/dns-plan', (m) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    if (!s) return err(404, 'not-found');
    const ip = s.publicIP ?? '';
    const plan: VpsDnsPlan =
      s.name === 'vps-test'
        ? { rows: [], waitSeconds: 300, dnsAuto: true }
        : {
            rows: [
              { domain: 'example.com', name: 'shop', type: 'A', value: ip, ttl: 300, outcome: 'withdraw', others: 2 },
              { domain: 'example.com', name: '*', type: 'A', value: ip, ttl: 300, outcome: 'withdraw', others: 2 },
              { domain: 'example.net', name: 'blog', type: 'A', value: ip, ttl: 600, outcome: 'keep-last', others: 0 },
              { domain: 'other.kr', name: '', type: '', value: ip, ttl: 0, outcome: 'manual', others: 0 },
            ],
            waitSeconds: 300,
            dnsAuto: true,
          };
    return ok(plan);
  });
  on('DELETE', '/system/vps/servers/:n/dns-holds/:d', (m) => {
    if (!admin()) return deny();
    const s = st.servers.find((x) => x.name === m[0]);
    const h = s?.dnsHolds?.find((x) => x.domain === m[1]);
    if (!s || !h) return err(404, 'not-found');
    if (s.phase !== 'running') return err(409, 'held', '아직 중지 중입니다.');
    s.dnsHolds = s.dnsHolds!.filter((x) => x !== h);
    st.revision++;
    return ok(null, 204);
  });
}

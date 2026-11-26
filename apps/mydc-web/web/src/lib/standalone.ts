// SPDX-License-Identifier: Apache-2.0

/**
 * 단독 컨테이너 정의(REQ-29, 캔버스 UI-3F 미리보기와 같은 모양).
 * app.yaml 서비스 하나의 칸 + name·lifetime·restart(고정)·ttl·grace(임시)·mode. 작업 공간은 주소에서 온다.
 *
 *   name: report-cron
 *   lifetime: fixed          # temp | fixed
 *   restart: on-failure      # 고정만
 *   mode: entrypoint         # entrypoint | shell
 *   image: registry.local/shop/report:2.1
 *   command: [/app/report, --every, 1h]
 *   networks: [shop-back]
 *   x-mydc: { node: node-b, ingress: { routes: [...] } }
 */
import YAML from 'yaml';
import { parsePort, portText } from './ports';
import { splitArgs } from '../components/TerminalPane';

export type Lifetime = 'temp' | 'fixed';
export type RestartPolicy = 'no' | 'on-failure' | 'always';
export type RunMode = 'shell' | 'entrypoint';
export type Gateway = 'local' | 'external' | 'both';

export interface SaNet {
  name: string;
  alias: string;
}
export interface SaPort {
  port: string;
  proto: 'tcp' | 'udp';
  /** 서버 포트로 바로 공개. 끄면 ports에 쓰지 않는다(망 안에서만, 외부 접속 경로 고르기용) */
  expose: boolean;
  /** 받을 주소. 비우면 Docker 기본값 */
  host: string;
  /** 서버 포트(범위 가능). 비우면 서버가 고름 */
  publish: string;
}
/** ports 한 줄 글(공개하는 것만) */
export const saPortText = (p: SaPort) => `${p.host ? `${p.host.includes(':') ? `[${p.host}]` : p.host}:${p.publish}:` : p.publish ? `${p.publish}:` : ''}${p.port}/${p.proto}`;
export interface SaVolume {
  name: string;
  target: string;
  readOnly: boolean;
}
export interface SaSecret {
  name: string;
  target: string;
  mode: string;
}
export interface SaRoute {
  host: string;
  path: string;
  port: string;
  gateway: Gateway;
  cert: 'auto' | 'none';
}
export interface StandaloneForm {
  name: string;
  lifetime: Lifetime;
  ttl: string;
  grace: string;
  restart: RestartPolicy;
  mode: RunMode;
  /** 엔트리포인트에서 TTY를 붙일지(쉘은 항상) */
  tty: boolean;
  /** 쉘이면 실행 뒤 바로 터미널 */
  openTerminal: boolean;
  image: string;
  /** '' = 서버가 고름 */
  node: string;
  command: string;
  env: { key: string; value: string }[];
  workdir: string;
  user: string;
  networks: SaNet[];
  ports: SaPort[];
  routes: SaRoute[];
  volumes: SaVolume[];
  secrets: SaSecret[];
  health: 'none' | 'cmd' | 'http';
  healthCmd: string;
  healthUrl: string;
  healthInterval: string;
  logDriver: '' | 'local' | 'json-file';
  logMaxSize: string;
  logMaxFile: string;
  cpus: string;
  memory: string;
  /** 앱 서비스에서 가져왔으면 '앱 / 서비스'(표시만) */
  importedFrom?: ImportedFrom;
}

export const TTL_CHOICES: [string, string][] = [
  ['30m', '30분'],
  ['1h', '1시간'],
  ['4h', '4시간'],
  ['8h', '8시간'],
  ['24h', '24시간'],
];
export const GRACE_CHOICES: [string, string][] = [
  ['0s', '끊기면 바로'],
  ['5m', '끊긴 뒤 5분'],
  ['10m', '끊긴 뒤 10분'],
  ['30m', '끊긴 뒤 30분'],
  ['1h', '끊긴 뒤 1시간'],
];
export const RESTART_LABEL: Record<RestartPolicy, string> = { 'on-failure': '실패하면 다시 (on-failure)', always: '항상 (always)', no: '안 함 (no)' };
export const TTL_MAX_SEC = 24 * 3600;

export const emptyStandalone = (): StandaloneForm => ({
  name: '',
  lifetime: 'fixed',
  ttl: '1h',
  grace: '10m',
  restart: 'on-failure',
  mode: 'entrypoint',
  tty: false,
  openTerminal: true,
  image: '',
  node: '',
  command: '',
  env: [],
  workdir: '',
  user: '',
  networks: [],
  ports: [],
  routes: [],
  volumes: [],
  secrets: [],
  health: 'none',
  healthCmd: '',
  healthUrl: '',
  healthInterval: '30s',
  logDriver: '',
  logMaxSize: '10m',
  logMaxFile: '3',
  cpus: '',
  memory: '',
});

/** 임시 쉘 기본값(목록 '임시로 바로 쉘') */
export const quickShell = (image: string, network: string, node: string): StandaloneForm => ({
  ...emptyStandalone(),
  name: autoName(),
  lifetime: 'temp',
  mode: 'shell',
  command: '/bin/sh',
  image,
  node,
  networks: network ? [{ name: network, alias: '' }] : [],
});

export const autoName = () => `temp-${crypto.getRandomValues(new Uint16Array(1))[0].toString(16).padStart(4, '0')}`;

/** "1h30m", "90s", "10m" → 초. 못 읽으면 undefined */
export function parseDur(s: string): number | undefined {
  const t = s.trim();
  if (!t) return undefined;
  if (/^\d+$/.test(t)) return Number(t);
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(t);
  return m ? Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0) : undefined;
}
/** 초 → "48분", "1시간 5분" */
export function fmtDur(sec: number): string {
  if (sec < 60) return `${Math.max(0, Math.round(sec))}초`;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h && m ? `${h}시간 ${m}분` : h ? `${h}시간` : `${m}분`;
}
/** 메모리 표기 "256 MiB" → compose "256M" */
const memToCompose = (s: string) => s.trim().replace(/\s*(Mi?B?|M)$/i, 'M').replace(/\s*(Gi?B?|G)$/i, 'G');
const memFromCompose = (s: string) => s.replace(/^(\d+(?:\.\d+)?)M$/i, '$1 MiB').replace(/^(\d+(?:\.\d+)?)G$/i, '$1 GiB');

/** 폼 칸 검사. 빈 배열이면 통과 */
export function checkStandalone(f: StandaloneForm): string[] {
  const out: string[] = [];
  if (f.name && !/^[a-z0-9][a-z0-9-]{0,62}$/.test(f.name)) out.push('이름은 소문자·숫자·-로 63자까지입니다.');
  if (!f.name && f.lifetime === 'fixed') out.push('고정 컨테이너는 이름이 있어야 합니다.');
  if (!f.image) out.push('이미지를 골라 주세요.');
  if (f.lifetime === 'temp') {
    const ttl = parseDur(f.ttl);
    if (ttl === undefined || ttl < 60 || ttl > TTL_MAX_SEC) out.push('임시 수명은 1분~24시간입니다.');
  }
  for (const v of f.volumes) if (!v.target.startsWith('/')) out.push(`데이터 저장소 ${v.name}의 마운트 경로는 /로 시작해야 합니다.`);
  return out;
}

export function standaloneToObject(f: StandaloneForm): Record<string, unknown> {
  const doc: Record<string, unknown> = { name: f.name, lifetime: f.lifetime };
  if (f.lifetime === 'fixed') doc.restart = f.restart;
  else Object.assign(doc, { ttl: f.ttl, grace: f.grace });
  doc.mode = f.mode;
  doc.image = f.image || undefined;
  const cmd = splitArgs(f.command);
  if (f.mode === 'shell') {
    doc.command = cmd.length ? cmd : ['/bin/sh'];
    Object.assign(doc, { tty: true, stdin_open: true });
  } else {
    if (cmd.length) doc.command = cmd;
    if (f.tty) Object.assign(doc, { tty: true, stdin_open: true });
  }
  const env = f.env.filter((e) => e.key);
  if (env.length) doc.environment = Object.fromEntries(env.map((e) => [e.key, e.value]));
  if (f.workdir) doc.working_dir = f.workdir;
  if (f.user) doc.user = f.user;
  if (f.networks.length) doc.networks = f.networks.some((n) => n.alias) ? Object.fromEntries(f.networks.map((n) => [n.name, n.alias ? { aliases: [n.alias] } : {}])) : f.networks.map((n) => n.name);
  // ports에 적은 포트는 모두 서버에 공개된다(비운 서버 포트는 Docker가 고름). 망 안에서만 쓸 포트는 쓰지 않는다.
  const exposed = f.ports.filter((p) => p.expose);
  if (exposed.length) doc.ports = exposed.map(saPortText);
  if (f.secrets.length) doc.secrets = f.secrets.map((s) => ({ source: s.name, ...(s.target ? { target: s.target } : {}), ...(s.mode ? { mode: s.mode } : {}) }));
  if (f.volumes.length) doc.volumes = f.volumes.map((v) => `${v.name}:${v.target}${v.readOnly ? ':ro' : ''}`);
  if (f.health === 'cmd' && f.healthCmd.trim()) doc.healthcheck = { test: ['CMD', ...splitArgs(f.healthCmd)], interval: f.healthInterval || undefined };
  if (f.health === 'http' && f.healthUrl.trim()) doc.healthcheck = { test: ['CMD-SHELL', `wget -q -O /dev/null ${f.healthUrl.trim()} || exit 1`], interval: f.healthInterval || undefined };
  if (f.logDriver) doc.logging = { driver: f.logDriver, options: { ...(f.logMaxSize ? { 'max-size': f.logMaxSize } : {}), ...(f.logMaxFile ? { 'max-file': f.logMaxFile } : {}) } };
  if (f.cpus || f.memory) doc.deploy = { resources: { limits: { ...(f.cpus ? { cpus: f.cpus } : {}), ...(f.memory ? { memory: memToCompose(f.memory) } : {}) } } };
  const xm: Record<string, unknown> = {};
  if (f.node) xm.node = f.node;
  const routes = f.routes.filter((r) => r.host);
  if (routes.length) xm.ingress = { routes: routes.map((r) => ({ host: r.host, path: r.path || '/', port: Number(r.port) || undefined, gateway: r.gateway, ...(r.cert === 'auto' ? {} : { tls: false }) })) };
  if (Object.keys(xm).length) doc['x-mydc'] = xm;
  return doc;
}

const scalarList = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x !== 'object' || x === null);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/**
 * 폼 → 원문. original을 주면(정의 고치기) 그 문서를 고쳐 쓴다: 값이 같은 칸은 원래 모양(흐름 표기·주석)을 그대로 두고
 * 바뀐 칸만 바꿔 변경 검토에 바뀐 줄만 나오게 한다. 짧은 값 목록(command·networks 등)은 한 줄로 쓴다.
 */
export function standaloneToYaml(f: StandaloneForm, original?: string): string {
  const obj = standaloneToObject(f);
  let doc: YAML.Document;
  try {
    doc = original ? YAML.parseDocument(original) : new YAML.Document({});
    if (doc.errors.length || !YAML.isMap(doc.contents)) doc = new YAML.Document({});
  } catch {
    doc = new YAML.Document({});
  }
  const old = (doc.toJS() ?? {}) as Record<string, unknown>;
  for (const k of Object.keys(old)) if (!(k in obj) || obj[k] === undefined) doc.delete(k);
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || (k in old && same(old[k], v))) continue;
    const node = doc.createNode(v, { flow: scalarList(v) });
    doc.set(k, node);
  }
  return doc.toString({ lineWidth: 0, flowCollectionPadding: false });
}

const FORM_KEYS = new Set(['name', 'lifetime', 'restart', 'ttl', 'grace', 'mode', 'image', 'command', 'environment', 'working_dir', 'user', 'networks', 'ports', 'secrets', 'volumes', 'healthcheck', 'logging', 'deploy', 'x-mydc', 'tty', 'stdin_open']);

/** 원문 → 폼. 문법이 틀리면 error(줄 번호). 폼에 없는 칸 이름은 lost. */
export function standaloneFromYaml(text: string): { form: StandaloneForm; lost: string[] } | { error: string; line?: number } {
  let d: Record<string, any>;
  try {
    d = (YAML.parse(text) ?? {}) as Record<string, any>;
  } catch (e) {
    const linePos = (e as { linePos?: { line: number }[] }).linePos;
    return { error: (e as Error).message.split('\n')[0], line: linePos?.[0]?.line };
  }
  if (typeof d !== 'object' || Array.isArray(d)) return { error: '정의가 객체가 아닙니다.' };
  const f = emptyStandalone();
  f.name = typeof d.name === 'string' ? d.name : '';
  f.lifetime = d.lifetime === 'temp' ? 'temp' : 'fixed';
  f.restart = ['no', 'on-failure', 'always'].includes(d.restart) ? d.restart : 'on-failure';
  f.ttl = String(d.ttl ?? '1h');
  f.grace = String(d.grace ?? '10m');
  f.mode = d.mode === 'shell' ? 'shell' : 'entrypoint';
  f.tty = f.mode === 'entrypoint' && d.tty === true;
  f.image = typeof d.image === 'string' ? d.image : '';
  f.node = String(d['x-mydc']?.node ?? '');
  f.command = Array.isArray(d.command) ? d.command.map((c: unknown) => (/\s/.test(String(c)) ? `"${c}"` : String(c))).join(' ') : typeof d.command === 'string' ? d.command : '';
  const env = Array.isArray(d.environment) ? Object.fromEntries((d.environment as string[]).map((l) => [l.split('=')[0], l.slice(l.indexOf('=') + 1)])) : (d.environment ?? {});
  f.env = Object.entries(env as Record<string, unknown>).map(([key, value]) => ({ key, value: String(value ?? '') }));
  f.workdir = String(d.working_dir ?? '');
  f.user = String(d.user ?? '');
  f.networks = Array.isArray(d.networks)
    ? d.networks.map((n: string) => ({ name: String(n), alias: '' }))
    : Object.entries((d.networks ?? {}) as Record<string, { aliases?: string[] } | null>).map(([name, x]) => ({ name, alias: x?.aliases?.[0] ?? '' }));
  f.ports = (Array.isArray(d.ports) ? d.ports : []).flatMap((x: unknown) => {
    const q = parsePort(portText(x));
    return q ? [{ port: q.target, proto: q.proto === 'udp' ? 'udp' : 'tcp', expose: true, host: q.host, publish: q.published } as SaPort] : [];
  });
  f.secrets = (Array.isArray(d.secrets) ? d.secrets : []).map((s: unknown) => (typeof s === 'string' ? { name: s, target: '', mode: '' } : { name: String((s as any).source ?? ''), target: String((s as any).target ?? ''), mode: String((s as any).mode ?? '') }));
  f.volumes = (Array.isArray(d.volumes) ? d.volumes : []).flatMap((v: unknown) => {
    const [name, target, ro] = String(v).split(':');
    return name && target ? [{ name, target, readOnly: ro === 'ro' }] : [];
  });
  const test = d.healthcheck?.test;
  if (Array.isArray(test) && test[0] === 'CMD') {
    f.health = 'cmd';
    f.healthCmd = test.slice(1).join(' ');
  } else if (Array.isArray(test) && test[0] === 'CMD-SHELL') {
    const m = /^wget -q -O \/dev\/null (\S+) \|\| exit 1$/.exec(String(test[1] ?? ''));
    if (m) {
      f.health = 'http';
      f.healthUrl = m[1];
    } else {
      f.health = 'cmd';
      f.healthCmd = String(test[1] ?? '');
    }
  }
  if (d.healthcheck?.interval) f.healthInterval = String(d.healthcheck.interval);
  if (d.logging?.driver === 'local' || d.logging?.driver === 'json-file') {
    f.logDriver = d.logging.driver;
    f.logMaxSize = String(d.logging.options?.['max-size'] ?? '');
    f.logMaxFile = String(d.logging.options?.['max-file'] ?? '');
  }
  f.cpus = String(d.deploy?.resources?.limits?.cpus ?? '');
  f.memory = d.deploy?.resources?.limits?.memory ? memFromCompose(String(d.deploy.resources.limits.memory)) : '';
  f.routes = (Array.isArray(d['x-mydc']?.ingress?.routes) ? d['x-mydc'].ingress.routes : []).map((r: Record<string, unknown>) => ({
    host: String(r.host ?? ''),
    path: String(r.path ?? '/'),
    port: r.port ? String(r.port) : '',
    gateway: r.gateway === 'external' || r.gateway === 'both' ? r.gateway : 'local',
    cert: r.tls === false ? 'none' : 'auto',
  }));
  // 망 안에서만 쓰는 포트는 ports에 없으므로 외부 접속 경로가 가리키는 포트로 되살린다
  for (const r of f.routes) if (r.port && !f.ports.some((p) => p.port === r.port && p.proto === 'tcp')) f.ports.push({ port: r.port, proto: 'tcp', expose: false, host: '', publish: '' });
  const lost = Object.keys(d).filter((k) => !FORM_KEYS.has(k));
  if (d.deploy && Object.keys(d.deploy).some((k) => k !== 'resources')) lost.push('deploy');
  return { form: f, lost };
}

/** 앱 서비스 설정을 가져온 출처. up 본문의 importedFrom으로 보내 웹 서버가 보관한다. */
export interface ImportedFrom {
  app: string;
  deployment?: string;
  service: string;
  items: (keyof ImportParts)[];
}
export const IMPORT_ITEM_LABEL: Record<keyof ImportParts, string> = { imageCmd: '이미지·명령', netEnv: '망·환경 변수', volumes: '데이터 저장소', secrets: '비밀값', ingress: '외부 접속' };
export interface ImportParts {
  imageCmd: boolean;
  netEnv: boolean;
  volumes: boolean;
  secrets: boolean;
  ingress: boolean;
}
/**
 * 앱 원문의 서비스 하나를 폼에 채운다(복사만, 앱과 연결 없음).
 * 데이터 저장소는 읽기 전용으로, 외부 접속·포트는 고를 때만(앱과 겹치면 충돌).
 */
export function importAppService(base: StandaloneForm, appYaml: string, app: string, service: string, parts: ImportParts): StandaloneForm {
  const doc = (YAML.parse(appYaml) ?? {}) as Record<string, any>;
  const svc = (doc.services ?? {})[service] ?? {};
  const one = standaloneFromYaml(YAML.stringify({ ...svc, name: base.name || service, lifetime: base.lifetime }));
  if ('error' in one) return base;
  const s = one.form;
  const next: StandaloneForm = { ...base, name: base.name || (base.lifetime === 'fixed' ? service : ''), importedFrom: { app, service, items: (Object.keys(parts) as (keyof ImportParts)[]).filter((k) => parts[k]) } };
  if (parts.imageCmd) Object.assign(next, { image: s.image, command: s.command, mode: s.command || base.mode === 'entrypoint' ? 'entrypoint' : base.mode, node: s.node || base.node });
  if (parts.netEnv) Object.assign(next, { networks: s.networks, env: s.env, workdir: s.workdir, user: s.user });
  if (parts.volumes) next.volumes = s.volumes.map((v) => ({ ...v, readOnly: true }));
  if (parts.secrets) next.secrets = s.secrets;
  if (parts.ingress) {
    next.ports = s.ports;
    next.routes = (Array.isArray(doc['x-mydc']?.ingress?.routes) ? doc['x-mydc'].ingress.routes : [])
      .filter((r: Record<string, unknown>) => r.service === service)
      .map((r: Record<string, unknown>) => ({ host: String(r.host ?? ''), path: String(r.path ?? '/'), port: r.port ? String(r.port) : '', gateway: (r.gateway as Gateway) ?? 'local', cert: 'auto' as const }));
  }
  Object.assign(next, { health: s.health, healthCmd: s.healthCmd, healthUrl: s.healthUrl, healthInterval: s.healthInterval, logDriver: s.logDriver, logMaxSize: s.logMaxSize, logMaxFile: s.logMaxFile, cpus: s.cpus, memory: s.memory });
  return next;
}

// SPDX-License-Identifier: Apache-2.0

// 이미지 빌드 목업 (UI-85·86·87, REQ-19). 모양은 데몬 계약(web-api.md '이미지 빌드', PR #210·#212)을 따른다.
// 빌드는 시작 시각에서 흐른 시간으로 끝난다. 빌드 비밀값은 보관함 마운트뿐이고 값은 어디에도 없다(로그에는 «가림»).
import type { RawResponse } from '../client';
import type * as D from '../dto';
import { matchRule } from '../../lib/trust';
import { parseDockerfile } from '../../lib/dockerfile';

type Applied = { code: number; errorCode?: string } | void;
interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  /** 세션·작업 공간 읽기 권한을 확인하고 사용자를 돌려준다 */
  reader: (t: string) => { id: string; username: string };
  canWrite: (t: string) => boolean;
  submit: (body: Record<string, unknown>, action: string, apply: () => Applied) => RawResponse;
  vaultKeys: (t: string, object: string) => string[] | undefined;
  trust: (t: string) => { registry: string; repository: string }[];
  builtinHost: (t: string) => string;
  pushImage: (t: string, repository: string, tag: string, digest: string, bytes: number) => void;
  /** 이 작업 공간에 허용된 저장 경로 */
  roots: (t: string) => { node: string; id: string; generation: number; path: string }[];
  revision: () => number;
  /** 빌드 비밀값 묶음 승인(#226): 승인이 필요하면 기다리는 op를 돌려주고, 아니면 go()를 부른다 */
  buildGate: (t: string, context: string, build: string, secrets: D.DBuildSecret[], body: Record<string, unknown>, go: () => RawResponse) => RawResponse;
}
const CAS = { code: 1 };
const INVALID = { code: 2, errorCode: 'invalid' };
const FORBIDDEN = { code: 4 };
const now = () => Math.floor(Date.now() / 1000);
const iso = (s: number) => new Date(s * 1000).toISOString();
const KB = 1000;
const MB = 1000 * KB;
const MiB = 1 << 20;
const GiB = 1 << 30;
const LOG_PAGE = 24 * 1024;
const LOG_MAX = 8 * MiB;
/** 문자열에서 늘 같은 64자 hex */
function hex(seed: string) {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619) >>> 0;
  let out = '';
  for (let i = 0; out.length < 64; i++) {
    h ^= seed.charCodeAt(i % Math.max(1, seed.length)) + i;
    h = Math.imul(h, 16777619) >>> 0;
    out += h.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}
const rnd = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) => x.toString(16).padStart(2, '0')).join('');

type Files = Record<string, string>;
interface Ver {
  meta: D.DBuildVersion;
  files: Files;
  /** 목업 크기(내용 없이 크기만 큰 파일) */
  sizes?: Record<string, number>;
}
interface Ctx0 {
  tenant: string;
  row: Omit<D.DBuildContext, 'lastBuild' | 'version' | 'versions'>;
  /** 새 것부터 */
  versions: Ver[];
  draft?: { files: Files; exec: Set<string>; revision: number; initialized: boolean; sizes?: Record<string, number> };
  /** git: 저장소에 있는 최신 커밋과 파일(받기 흉내) */
  remote?: { commit: string; files: Files; fail?: boolean };
}
interface Rec {
  tenant: string;
  b: D.DBuild;
  /** 실행을 시작한(할) 때 */
  t0: number;
  dur: number;
  plan: { fail?: D.BuildCode; lines: string[] };
  cancelAt?: number;
  /** 씨앗처럼 결과가 이미 정해진 기록 */
  fixed?: boolean;
  log?: { text: string; truncated?: boolean; gap?: boolean; unclosed?: boolean };
  push?: { repository: string; tags: string[] };
}

const PHP = `# shop web · PHP 8.3 + Apache
FROM composer:2.7 AS deps
WORKDIR /app
COPY composer.json composer.lock ./
RUN --mount=type=secret,id=composer-token \\
    COMPOSER_AUTH=$(cat /run/secrets/composer-token) composer install --no-dev

FROM php:8.3-apache
ARG PHP_ENV=prod
COPY --from=deps /app/vendor /var/www/html/vendor
COPY . /var/www/html
RUN chown -R 10001:10001 /var/www/html
USER 10001:10001
EXPOSE 8080
HEALTHCHECK CMD curl -fsS http://localhost:8080/readyz || exit 1
`;
const webFiles = (): Files => ({
  Dockerfile: PHP,
  '.dockerignore': '.git\nnode_modules\n',
  'composer.json': '{\n  "name": "shop/web"\n}\n',
  'composer.lock': '{}\n',
  'public/index.php': '<?php require "../src/app.php";\n',
  'src/app.php': '<?php echo "shop";\n',
});
const workerFiles = (): Files => ({ ...webFiles(), 'worker/Dockerfile': 'FROM php:8.3-cli\nCOPY . /app\nCMD ["php", "/app/src/worker.php"]\n', 'src/worker.php': '<?php // worker\n' });
const reportFiles = (): Files => ({
  Dockerfile: 'FROM node:20-alpine AS build\nCOPY . /src\nRUN cd /src && npm ci && npm run build\nFROM ghcr.io/acme/base:1\nCOPY --from=build /src/dist /app\n',
  'package.json': '{"name":"report"}\n',
  'src/index.ts': 'export {};\n',
});
const nginxFiles = (): Files => ({
  Dockerfile: 'FROM nginx:1.27-alpine\nCOPY nginx.conf /etc/nginx/nginx.conf\nCOPY site/ /usr/share/nginx/html/\nEXPOSE 8080\nUSER 101\n',
  'nginx.conf': 'events {}\nhttp { server { listen 8080; root /usr/share/nginx/html; } }\n',
  'site/index.html': '<h1>edge</h1>\n',
});
const cronFiles = (): Files => ({
  Dockerfile: 'FROM debian:12-slim\nRUN apt-get update && apt-get install -y cron\nCOPY crontab /etc/cron.d/app\nCMD ["cron", "-f"]\n',
  crontab: '* * * * * root echo hi\n',
});

const BUILDER = 'registry.shop.internal/system/buildkit@sha256:7d1e4c0b9a8f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d';
const LIMITS = { zipBytes: 500 * MB, expandedBytes: 8 * GiB, fileReadBytes: 4 * MiB, logPageBytes: LOG_PAGE };
type Policy = Omit<D.DBuildPolicy, 'limits'>;
const policies: Record<string, Policy> = {
  shop: {
    exists: true,
    revision: 3,
    nodes: [{ node: 'node-c', root: { id: 'build-c', generation: 1, path: '/srv/mydc/build-c' } }],
    concurrency: 2,
    seconds: 1800,
    cpuMillis: 2000,
    memoryBytes: 4 * GiB,
    workspaceBytes: 8 * GiB,
    cacheBytes: 20 * GiB,
    registry: 'builtin',
    platforms: ['linux/amd64'],
    builderImage: BUILDER,
    cleanup: { highWaterPercent: 80, unusedDays: 14 },
  },
};
const emptyPolicy = (): Policy => ({
  exists: false,
  revision: 0,
  nodes: [],
  concurrency: 0,
  seconds: 0,
  cpuMillis: 0,
  memoryBytes: 0,
  workspaceBytes: 0,
  cacheBytes: 0,
  registry: 'builtin',
  platforms: [],
  builderImage: BUILDER,
  cleanup: { highWaterPercent: 80, unusedDays: 14 },
});

const ctxs: Ctx0[] = [];
const recs: Rec[] = [];
interface Scope {
  tenant: string;
  row: Omit<D.DBuildCacheScope, 'usage'>;
  /** undefined면 아직 관측 없음 */
  entries?: D.DBuildCacheEntry[];
  observedAt?: number;
  /** 서버가 응답하지 않음 */
  down?: boolean;
  /** 마지막 관측이 자동 정리 */
  byCleanup?: boolean;
}
const scopes: Scope[] = [];
interface Clean {
  tenant: string;
  row: D.DBuildCleaning;
  at: number;
  /** 씨앗: 상태를 움직이지 않는다 */
  fixed?: boolean;
}
const cleanings: Clean[] = [];
/** 초안 편집의 opId → 결과 revision(같은 opId는 같은 편집) */
const draftEdits = new Map<string, number>();

const bytesOf = (files: Files, sizes?: Record<string, number>) => Object.keys(files).reduce((n, p) => n + (sizes?.[p] ?? new TextEncoder().encode(files[p]).length), 0);
function mkVer(ctx: string, number: number, files: Files, at: number, commit?: string, sizes?: Record<string, number>): Ver {
  const bytes = bytesOf(files, sizes);
  return { meta: { number, id: hex(`${ctx}/v${number}`), bytes: Math.round(bytes * 0.42), expandedBytes: bytes, entries: Object.keys(files).length, at: iso(at), commit }, files, sizes };
}
function mkCtx(row: Omit<Ctx0['row'], 'revision' | 'node' | 'root'> & { node?: string }, versions: Ver[], extra: Partial<Ctx0> = {}): Ctx0 {
  return { tenant: 'shop', row: { node: 'node-c', root: 'build-c', revision: 2 + versions.length, ...row }, versions, ...extra };
}

function bigLog(): string {
  const head = [
    '#1 [internal] load build definition from Dockerfile',
    '#1 transferring dockerfile: 612B done',
    '#2 [internal] load metadata for docker.io/library/php:8.3-apache',
    '#3 [internal] load metadata for docker.io/library/composer:2.7',
    '#4 [deps 1/3] FROM docker.io/library/composer:2.7@sha256:0c2b5e1d…',
    '#7 [stage-1 1/4] FROM docker.io/library/php:8.3-apache@sha256:5be1a2c3…',
    '#8 [deps 2/3] COPY composer.json composer.lock ./',
    '#9 [deps 3/3] RUN --mount=type=secret,id=composer-token composer install --no-dev',
    '#9 secret composer-token «가림»',
  ];
  const body: string[] = [];
  for (let i = 0; body.join('\n').length < 400 * KB; i++) body.push(`#9 ${(i * 0.013).toFixed(3)}   - Installing vendor/package-${String(i).padStart(4, '0')} (v${1 + (i % 9)}.${i % 13}.${i % 7}): Extracting archive`);
  const tail = [
    '#9 48.2s done',
    '#10 [stage-1 2/4] COPY --from=deps /app/vendor /var/www/html/vendor',
    '#10 DONE 0.8s',
    '#11 [stage-1 3/4] COPY . /var/www/html',
    '#11 DONE 1.1s',
    '#12 [stage-1 4/4] RUN chown -R 10001:10001 /var/www/html',
    '#12 DONE 2.4s',
    '#13 exporting to oci layout',
    '#13 DONE 3.1s',
    '#14 pushing registry.shop.internal/shop/web:v41, main-4c1e9a2',
    '#14 DONE 6.0s',
  ];
  return [...head, ...body, ...tail].join('\n') + '\n';
}

function seed() {
  const t = now();
  const D1 = 86400;
  ctxs.push(
    mkCtx(
      {
        id: 'web',
        kind: 'git',
        git: { repository: 'https://git.shop.example/app.git', ref: 'main', path: '', credentialProfile: 'git-readonly', automatic: true },
        gitCheck: { code: 'OK', commit: '4c1e9a2', at: iso(t - 40), entries: 44 },
        dockerfile: 'Dockerfile',
        args: { PHP_ENV: 'prod' },
        secrets: [{ id: 'composer-token', realm: 'shop', secret: 'ghcr-shop', key: 'token' }],
        repository: 'shop/web',
        tags: ['v{version}', 'main-{commit}'],
        platforms: ['linux/amd64'],
      },
      [mkVer('web', 41, webFiles(), t - 900, '4c1e9a2'), mkVer('web', 40, webFiles(), t - 5 * D1, '9b02f11'), mkVer('web', 39, webFiles(), t - 9 * D1, '1d0e5aa')],
      { remote: { commit: '4c1e9a2', files: webFiles() } },
    ),
    mkCtx(
      {
        id: 'worker',
        kind: 'git',
        git: { repository: 'https://git.shop.example/app.git', ref: 'main', path: '', credentialProfile: 'git-readonly', automatic: true },
        gitCheck: { code: 'OK', commit: '4c1e9a2', at: iso(t - 40), entries: 46 },
        dockerfile: 'worker/Dockerfile',
        args: {},
        secrets: [],
        repository: 'shop/worker',
        tags: ['v{version}', 'main-{commit}'],
        platforms: ['linux/amd64'],
      },
      [mkVer('worker', 12, workerFiles(), t - 800, '4c1e9a2'), mkVer('worker', 11, workerFiles(), t - 2 * D1, '77ad310')],
      { remote: { commit: '4c1e9a2', files: workerFiles() } },
    ),
    mkCtx({ id: 'report', kind: 'upload', dockerfile: 'Dockerfile', args: {}, secrets: [{ id: 'db-password', realm: 'shop', secret: 'db-password', key: 'password' }], repository: 'shop/report', tags: ['v{version}'], platforms: ['linux/amd64'] }, [
      mkVer('report', 3, reportFiles(), t - 6 * D1),
      mkVer('report', 2, reportFiles(), t - 12 * D1),
      mkVer('report', 1, reportFiles(), t - 20 * D1),
    ]),
    mkCtx({ id: 'nginx-edge', kind: 'draft', dockerfile: 'Dockerfile', args: {}, secrets: [], repository: 'shop/nginx-edge', tags: ['v{version}'], platforms: ['linux/amd64'] }, [mkVer('nginx-edge', 3, nginxFiles(), t - 14 * D1)], {
      draft: { files: nginxFiles(), exec: new Set(), revision: 14, initialized: true },
    }),
    mkCtx({ id: 'legacy-cron', kind: 'upload', dockerfile: 'Dockerfile', args: {}, secrets: [], repository: 'shop/cron', tags: ['v{version}'], platforms: ['linux/amd64'] }, [
      mkVer('legacy-cron', 2, cronFiles(), t - 40 * D1, undefined, { crontab: 1_100_000 }),
      mkVer('legacy-cron', 1, cronFiles(), t - 60 * D1),
    ]),
  );
  const ver = (c: string, n: number) => ctxs.find((x) => x.row.id === c)!.versions.find((v) => v.meta.number === n)!.meta.id;
  const done = (id: number, c: string, v: number, start: number, dur: number, extra: Partial<D.DBuild> = {}, log?: Rec['log'], repo?: string): Rec => {
    const x = ctxs.find((y) => y.row.id === c)!;
    const phase = extra.phase ?? 'succeeded';
    return {
      tenant: 'shop',
      t0: start,
      dur,
      fixed: true,
      plan: { lines: [] },
      log: log ?? { text: `#1 [internal] load build definition from ${x.row.dockerfile}\n#2 context v${v}\n#9 DONE\n` },
      b: {
        id: `b${id}`,
        context: c,
        node: 'node-c',
        user: 'alice',
        phase,
        version: v,
        versionId: ver(c, v),
        number: id,
        revision: 3,
        createdAt: iso(start),
        closedAt: phase === 'unknown' ? undefined : iso(start + dur),
        result: phase === 'succeeded' ? { code: 'OK', image: `registry.shop.internal/${repo ?? x.row.repository}@sha256:${hex(`b${id}`)}`, bytes: 180 * MiB } : undefined,
        ...extra,
      },
    };
  };
  recs.push(
    done(212, 'web', 41, t - 720, 221, { result: { code: 'OK', image: 'registry.shop.internal/shop/web@sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8', bytes: 212 * MB } }, { text: bigLog() }),
    {
      tenant: 'shop',
      t0: t - 130,
      dur: 900,
      plan: {
        lines: [
          '#1 [internal] load build definition from worker/Dockerfile',
          '#4 [deps 1/3] FROM docker.io/library/composer:2.7@sha256:0c2b5e1d… CACHED',
          '#7 [stage-1 1/4] FROM docker.io/library/php:8.3-apache@sha256:5be1a2c3… CACHED',
          '#9 [deps 3/3] RUN composer install --no-dev',
          '#9 Installing laravel/framework (v11.31)…',
          '#9 Installing symfony/console (v7.1.8)…',
          '#9 48.2s done',
          '#11 [stage-1 3/4] COPY . /app',
          '#13 exporting to oci layout',
        ],
      },
      b: { id: 'b211', context: 'worker', node: 'node-c', user: 'alice', phase: 'running', version: 12, versionId: ver('worker', 12), number: 211, revision: 2, createdAt: iso(t - 130) },
    },
    done(210, 'web', 40, t - 5 * D1, 242),
    done(209, 'report', 3, t - 6 * D1, 52, { phase: 'failed', result: { code: 'UNTRUSTED_BASE', image: '', bytes: 0 } }, {
      text: '#1 [internal] load build definition from Dockerfile\n#2 FROM docker.io/library/node:20-alpine ✓ 신뢰 출처 docker.io/**\nerror: FROM ghcr.io/acme/base:1 is not a trusted source of shop\n',
    }),
    done(208, 'worker', 11, t - 2 * D1 - 600, 0, { phase: 'unknown' }, {
      text: '#1 [internal] load build definition from worker/Dockerfile\n#9 [deps 3/3] RUN composer install --no-dev\n#9 Installing laravel/framework (v11.31)…\n',
      gap: true,
      unclosed: true,
    }),
    done(207, 'worker', 11, t - 2 * D1, 230),
    done(198, 'nginx-edge', 3, t - 14 * D1, 60),
    done(190, 'legacy-cron', 2, t - 38 * D1, 75, {}, { text: '#1 load build definition\n#5 RUN apt-get update && apt-get install -y cron\n… (8 MiB에서 잘림)\n', truncated: true }),
    done(187, 'legacy-cron', 2, t - 39 * D1, 81),
  );

  // 캐시: 서버·컨텍스트마다 한 범위
  const kinds = ['regular', 'exec.cachemount', 'regular', 'regular', 'regular', 'source.git.checkout', 'source.local'];
  const fill = (scope: string, count: number, total: number, firsts: [string, string, number, number, number, boolean?, boolean?][], ago: number): D.DBuildCacheEntry[] => {
    const out: D.DBuildCacheEntry[] = firsts.map(([id, kind, bytes, agoS, uses, inUse, shared]) => ({
      id,
      kind,
      bytes,
      createdAt: iso(t - 30 * D1),
      lastUsedAt: iso(t - agoS),
      uses,
      inUse: !!inUse,
      mutable: kind === 'exec.cachemount',
      shared: !!shared,
    }));
    let left = total - out.reduce((n, e) => n + e.bytes, 0);
    for (let i = out.length; i < count; i++) {
      const b = i === count - 1 ? Math.max(0, left) : Math.max(1, Math.round(left / (count - i) / (1 + (i % 3))));
      left -= b;
      out.push({ id: hex(`${scope}/${i}`).slice(0, 25), kind: kinds[i % kinds.length], bytes: b, createdAt: iso(t - 20 * D1), lastUsedAt: iso(t - ago - (i % 11) * D1), uses: 1 + (i % 6), inUse: false, mutable: false, shared: i % 9 === 0 });
    }
    return out;
  };
  const sc = (node: string, context: string, job: string, entries: D.DBuildCacheEntry[] | undefined, observedAt: number | undefined, extra: Partial<Scope> = {}): Scope => ({
    tenant: 'shop',
    row: { cache: hex(`cache/${node}/${context}`), node, context, root: node === 'node-c' ? 'build-c' : 'build-d', builder: BUILDER, job, code: 'OK' },
    entries,
    observedAt,
    ...extra,
  });
  scopes.push(
    sc(
      'node-c',
      'web',
      'b212',
      fill(
        'web',
        92,
        3.0 * GiB,
        [
          ['k3f9e2c08d41b7a6e5f4c3b2a1', 'regular', 1.4 * GiB, 720, 14, true],
          ['7c2e41a0b9c8d7e6f5a4b3c209', 'exec.cachemount', 880 * MB, 720, 14, false, true],
          ['b51d07e6f5a4b3c2d1e0f9a83c', 'regular', 512 * MB, 720, 22],
          ['5d01aa9b8c7d6e5f4a3b2c1d7e', 'regular', 730 * MB, 21 * D1, 2],
          ['9a0c6f1e2d3c4b5a69788796a44', 'regular', 118 * MB, 21 * D1, 1],
          ['e41a90f8e7d6c5b4a3f2e1d03b', 'source.git.checkout', 96 * MB, 720, 9],
          ['22fdc17a6b5c4d3e2f1a0b9cc8', 'source.local', 22 * MB, 6 * D1, 1],
        ],
        9 * D1,
      ),
      t - 720,
    ),
    sc('node-c', 'worker', 'b207', fill('worker', 61, 1.6 * GiB, [], 2 * D1), t - 2 * D1),
    sc('node-c', 'legacy-cron', 'b190', fill('legacy-cron', 31, 0.85 * GiB, [], 30 * D1), t - D1, { byCleanup: true }),
    sc('node-c', 'report', 'b209', fill('report', 18, 0.4 * GiB, [], 6 * D1), t - 6 * D1),
    sc('node-c', 'nginx-edge', 'b198', fill('nginx-edge', 12, 0.25 * GiB, [], 14 * D1), t - 14 * D1),
    sc('node-c', 'api', '', undefined, undefined, { row: { cache: hex('cache/node-c/api'), node: 'node-c', context: 'api', root: 'build-c', builder: BUILDER, job: '', contextDeleted: true, code: 'OK' } }),
    sc('node-d', 'web', 'b150', fill('d-web', 40, 1.2 * GiB, [], 30 * D1), t - 30 * D1, { down: true }),
  );
  const cl = (id: string, context: string, user: string, filter: D.DBuildCacheFilter, state: string, agoS: number, extra: Partial<D.DBuildCleaning> = {}): Clean => ({
    tenant: 'shop',
    at: t - agoS,
    row: { id, node: 'node-c', context, cache: hex(`cache/node-c/${context}`), user, filter, state, acceptedAt: iso(t - agoS), ...extra },
  });
  cleanings.push(
    { ...cl('prune-r7', 'report', 'alice', { mode: 'unused', unusedDays: 7 }, 'queued', 180), fixed: true },
    { ...cl('prune-w3', 'worker', 'alice', { mode: 'entries', ids: ['a', 'b', 'c'] }, 'running', 60), fixed: true },
    cl('auto-lc', 'legacy-cron', '', { mode: 'unused', unusedDays: 14 }, 'succeeded', D1, { automatic: true, closedAt: iso(t - D1 + 40), removedCount: 22, reportedBytes: 0.6 * GiB }),
    cl('prune-wa', 'web', 'bob', { mode: 'all' }, 'failed', 5 * D1, { code: 'FAILED', closedAt: iso(t - 5 * D1 + 30) }),
  );
}
seed();

// ── 빌드 진행 흉내 ──
let hook: Ctx;
const ended = (p: D.BuildPhase) => p === 'succeeded' || p === 'failed' || p === 'cancelled';
const tagsOf = (c: Ctx0['row'], v: D.DBuildVersion) => (c.tags ?? []).map((x) => x.replace(/\{version\}/g, String(v.number)).replace(/\{commit\}/g, v.commit ?? ''));
function advance(r: Rec) {
  if (r.fixed) return;
  const n = now();
  if (n < r.t0) {
    r.b.phase = 'queued';
    return;
  }
  if (r.cancelAt) {
    r.b.cancel = true;
    if (n - r.cancelAt >= 4) {
      r.b.phase = 'cancelled';
      r.b.closedAt = iso(r.cancelAt + 4);
      r.b.result = { code: 'CANCELLED', image: '', bytes: 0 };
      r.fixed = true;
    } else r.b.phase = 'running';
    return;
  }
  if (n - r.t0 < r.dur) {
    r.b.phase = 'running';
    return;
  }
  r.b.closedAt = iso(r.t0 + r.dur);
  r.fixed = true;
  if (r.plan.fail) {
    r.b.phase = 'failed';
    r.b.result = { code: r.plan.fail, image: '', bytes: 0 };
    return;
  }
  const digest = 'sha256:' + rnd();
  const bytes = 180 * MiB;
  r.b.phase = 'succeeded';
  r.b.result = { code: 'OK', image: `${hook.builtinHost(r.tenant)}/${r.push?.repository}@${digest}`, bytes };
  for (const tag of r.push?.tags ?? []) hook.pushImage(r.tenant, r.push!.repository, tag, digest, bytes);
  // 성공한 빌드는 그 범위의 캐시를 관측한다
  const s = scopes.find((x) => x.tenant === r.tenant && x.row.node === r.b.node && x.row.context === r.b.context);
  if (s) {
    s.row.job = r.b.id;
    s.observedAt = r.t0 + r.dur;
    s.byCleanup = false;
    s.entries ??= [];
  }
}
function logOf(r: Rec): { text: string; truncated: boolean; gap: boolean; unclosed: boolean } {
  advance(r);
  if (r.log) return { text: r.log.text, truncated: !!r.log.truncated, gap: !!r.log.gap, unclosed: !!r.log.unclosed };
  if (r.b.phase === 'queued') return { text: '', truncated: false, gap: false, unclosed: false };
  const ls = r.plan.lines;
  const el = Math.min(1, (now() - r.t0) / Math.max(1, r.dur));
  const shown = ended(r.b.phase) ? ls : ls.slice(0, Math.max(1, Math.ceil(ls.length * el)));
  const end = r.b.phase === 'failed' ? [`error: build failed (${r.plan.fail})`] : r.b.phase === 'cancelled' ? ['build cancelled'] : [];
  return { text: [...shown, ...end].join('\n') + '\n', truncated: false, gap: false, unclosed: !ended(r.b.phase) };
}

// ── 캐시 ──
function usageOf(s: Scope): D.DBuildCacheUsage | undefined {
  if (s.down) return { recorded: true, available: false, lastAttemptAt: iso(now() - 60), lastAttemptCode: 'UNAVAILABLE', reportedBytes: 0, count: 0, kinds: [] };
  if (!s.entries || s.observedAt === undefined) return undefined;
  const by = new Map<string, D.DBuildCacheUsage['kinds'] extends (infer K)[] | null ? K : never>();
  for (const e of s.entries) {
    const k = by.get(e.kind) ?? { kind: e.kind, count: 0, inUse: 0, reportedBytes: 0, sharedBytes: 0 };
    k.count++;
    if (e.inUse) k.inUse++;
    k.reportedBytes += e.bytes;
    if (e.shared) k.sharedBytes += e.bytes;
    by.set(e.kind, k);
  }
  return {
    recorded: true,
    available: true,
    observedAt: iso(s.observedAt),
    lastAttemptAt: iso(s.observedAt),
    lastAttemptCode: 'OK',
    reportedBytes: s.entries.reduce((n, e) => n + e.bytes, 0),
    count: s.entries.length,
    kinds: [...by.values()],
    observedKind: s.byCleanup ? 'cache-prune' : '',
    ...(s.byCleanup ? { cleanup: { job: hex('cleanup'), steps: [] } } : {}),
  } as D.DBuildCacheUsage;
}
function advanceCleaning(c: Clean) {
  const r = c.row;
  if (c.fixed || r.state === 'succeeded' || r.state === 'failed') return;
  const busy = recs.some((x) => x.tenant === c.tenant && x.b.context === r.context && x.b.node === r.node && (advance(x), !ended(x.b.phase) && x.b.phase !== 'unknown'));
  const el = now() - c.at;
  if (busy) {
    r.state = 'queued';
    return;
  }
  if (el < 3) return;
  if (el < 7) {
    r.state = 'running';
    r.code = undefined;
    return;
  }
  const s = scopes.find((x) => x.tenant === c.tenant && x.row.cache === r.cache && x.row.node === r.node);
  const before = s?.entries ?? [];
  const cut = Date.now() - (r.filter.unusedDays ?? 0) * 86400_000;
  const hit = (e: D.DBuildCacheEntry) => !e.inUse && (r.filter.mode === 'all' || (r.filter.mode === 'entries' ? (r.filter.ids ?? []).includes(e.id) : Date.parse(e.lastUsedAt ?? '') < cut));
  const gone = before.filter(hit);
  if (s) {
    s.entries = before.filter((e) => !hit(e));
    s.observedAt = c.at + 7;
    s.byCleanup = true;
  }
  r.state = 'succeeded';
  r.closedAt = iso(c.at + 7);
  r.removedCount = gone.length;
  r.reportedBytes = gone.reduce((n, e) => n + e.bytes, 0);
}

export function registerBuilds(c: Ctx) {
  hook = c;
  const { on, ok, err, reader, canWrite, submit } = c;
  const find = (t: string, id: string) => ctxs.find((x) => x.tenant === t && x.row.id === id);
  const missingCtx = () => err(404, 'not-found', 'no such build context');
  const policyOf = (t: string) => policies[t] ?? emptyPolicy();
  const live = (t: string) => recs.filter((r) => r.tenant === t && (advance(r), r.b.phase === 'running' || r.b.phase === 'queued'));
  const lastBuild = (t: string, id: string) => recs.filter((r) => r.tenant === t && r.b.context === id).sort((a, b) => b.b.number - a.b.number)[0];
  const view = (x: Ctx0): D.DBuildContext => {
    const lb = lastBuild(x.tenant, x.row.id);
    if (lb) advance(lb);
    return { ...x.row, version: x.versions[0]?.meta.number ?? 0, versions: x.versions.map((v) => v.meta), lastBuild: lb?.b };
  };
  const bump = (x: Ctx0) => (x.row.revision += 1);
  const expectedOf = (body: Record<string, unknown>, cur: number) => Number(body.expected ?? 0) || cur;
  const verFiles = (x: Ctx0, v: number) => (v ? x.versions.find((y) => y.meta.number === v) : undefined);

  on('GET', '/t/:t/build-policy', (m) => {
    reader(m[0]);
    return ok({ ...policyOf(m[0]), limits: LIMITS });
  });
  on('PUT', '/t/:t/build-policy', (m, body) => {
    reader(m[0]);
    const t = m[0];
    const p = (body.policy ?? {}) as Record<string, unknown>;
    const cur = policyOf(t);
    const reqNodes = (p.nodes as { node: string; root: string }[] | undefined) ?? [];
    const nodes: Policy['nodes'] = [];
    for (const n of reqNodes) {
      const kept = cur.nodes?.find((x) => x.node === n.node && x.root.id === n.root);
      const r = kept?.root ?? c.roots(t).find((x) => x.node === n.node && x.id === n.root);
      if (!r) return err(422, 'root-unknown', `${n.node}/${n.root}: not a storage root of ${t}`);
      nodes.push({ node: n.node, root: { id: r.id, generation: r.generation, path: r.path } });
    }
    let builderImage = cur.builderImage;
    if (typeof p.builderImage === 'string' && p.builderImage && p.builderImage !== cur.builderImage) {
      const b = p.builderImage.trim();
      if (/@sha256:[0-9a-f]{64}$/.test(b)) builderImage = b;
      else if (/^[a-z0-9.-]+(:\d+)?(\/[a-z0-9._-]+)+:[\w.-]+$/.test(b) && !/unknown/.test(b)) builderImage = `${b.replace(/:[\w.-]+$/, '')}@sha256:${hex(b)}`;
      else return err(422, 'builder-digest', `${b}: could not resolve a digest`);
    }
    const num = (k: string) => Number(p[k]);
    const cl = (p.cleanup ?? {}) as { highWaterPercent?: number; unusedDays?: number };
    const platforms = (p.platforms as string[] | undefined) ?? [];
    if (
      !nodes.length ||
      new Set(nodes.map((n) => n.node)).size !== nodes.length ||
      !(num('concurrency') >= 1 && num('concurrency') <= 16) ||
      !(num('seconds') >= 60 && num('seconds') <= 86400) ||
      !(num('cpuMillis') > 0) ||
      !(num('memoryBytes') > 0) ||
      !(num('workspaceBytes') > 0) ||
      !(num('cacheBytes') > 0) ||
      !platforms.length ||
      !(Number(cl.highWaterPercent) >= 1 && Number(cl.highWaterPercent) <= 100) ||
      !(Number(cl.unusedDays) >= 0 && Number(cl.unusedDays) <= 3650)
    )
      return err(422, 'invalid', 'policy: nodes, concurrency 1..16, seconds 60..86400, sizes > 0, platforms, cleanup 1..100 % · 0..3650 days');
    const expected = expectedOf(body, cur.revision);
    return submit({ ...body, tenant: t, target: 'build-policy' }, 'set-image-build-policy', () => {
      if (!canWrite(t)) return FORBIDDEN;
      if (expected !== cur.revision) return CAS;
      policies[t] = {
        exists: true,
        revision: cur.revision + 1,
        nodes,
        concurrency: num('concurrency'),
        seconds: num('seconds'),
        cpuMillis: num('cpuMillis'),
        memoryBytes: num('memoryBytes'),
        workspaceBytes: num('workspaceBytes'),
        cacheBytes: num('cacheBytes'),
        registry: String(p.registry || 'builtin'),
        platforms,
        builderImage,
        cleanup: { highWaterPercent: Number(cl.highWaterPercent), unusedDays: Number(cl.unusedDays) },
      };
    });
  });

  on('GET', '/t/:t/build-contexts', (m) => {
    reader(m[0]);
    return ok({ items: ctxs.filter((x) => x.tenant === m[0]).map(view), next: '', revision: c.revision(), asOf: new Date().toISOString() });
  });
  on('PUT', '/t/:t/build-contexts/:id', (m, body) => {
    reader(m[0]);
    const [t, id] = m;
    const q = (body.context ?? {}) as Partial<D.DBuildContext>;
    const cur = find(t, id);
    const pol = policyOf(t);
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(id)) return err(422, 'invalid', 'id: lowercase letters, digits and -');
    if (!pol.exists) return err(409, 'no-policy', 'set the build policy first');
    const pn = pol.nodes?.find((n) => n.node === q.node);
    if (!pn) return err(422, 'node-not-in-policy', `${q.node}: not a build node of the policy`);
    const args = q.args ?? {};
    for (const k of Object.keys(args)) if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) return err(422, 'invalid', `args.${k}: a build argument name`);
    const expected = Number(body.expected ?? (cur ? cur.row.revision : 0));
    return submit({ ...body, tenant: t, target: `build-context/${id}` }, 'put-build-context', () => {
      if (!canWrite(t)) return FORBIDDEN;
      if ((cur?.row.revision ?? 0) !== expected) return CAS;
      if (!q.dockerfile || !q.repository || !q.tags?.length || !q.repository.startsWith(t + '/') || !q.platforms?.length || q.platforms.some((p) => !pol.platforms?.includes(p))) return INVALID;
      if (q.kind === 'git' ? !q.git?.repository || !q.git.ref : !!q.git) return INVALID;
      for (const s of q.secrets ?? []) if (!s.id || s.realm !== t || !c.vaultKeys(t, s.secret)?.includes(s.key)) return INVALID;
      if (cur && (cur.row.kind !== q.kind || cur.row.node !== q.node)) return { code: 2, errorCode: 'immutable' };
      const row = {
        id,
        kind: q.kind!,
        node: pn.node,
        root: pn.root.id,
        dockerfile: q.dockerfile,
        args,
        secrets: q.secrets ?? [],
        repository: q.repository,
        tags: q.tags,
        platforms: q.platforms,
        git: q.git,
      };
      if (cur) {
        Object.assign(cur.row, row);
        bump(cur);
      } else {
        const x: Ctx0 = { tenant: t, row: { ...row, revision: 1 }, versions: [] };
        if (q.kind === 'draft') x.draft = { files: {}, exec: new Set(), revision: 1, initialized: false };
        if (q.kind === 'git') {
          x.remote = /fail/.test(q.git!.repository) ? { commit: '', files: {}, fail: true } : { commit: Math.random().toString(16).slice(2, 9), files: webFiles() };
          if (!x.remote.fail) x.row.gitCheck = { code: 'OK', commit: x.remote.commit, at: iso(now()), entries: Object.keys(x.remote.files).length };
        }
        ctxs.push(x);
        scopes.push({ tenant: t, row: { cache: hex(`cache/${pn.node}/${id}`), node: pn.node, context: id, root: pn.root.id, builder: pol.builderImage, job: '', code: 'OK' } });
      }
    });
  });
  on('POST', '/t/:t/build-contexts/:id/delete', (m, body) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (x.versions.length) return err(409, 'versions-left', `versions ${x.versions.map((v) => v.meta.number).join(', ')} are kept`);
    const expected = expectedOf(body, x.row.revision);
    return submit({ ...body, tenant: m[0], target: `build-context/${m[1]}` }, 'delete-build-context', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      if (expected !== x.row.revision || x.versions.length) return CAS;
      ctxs.splice(ctxs.indexOf(x), 1);
      for (const s of scopes) if (s.tenant === m[0] && s.row.context === m[1]) s.row.contextDeleted = true;
    });
  });
  on('POST', '/t/:t/build-contexts/:id/versions/:v/delete', (m, body) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (!/^\d+$/.test(m[2])) return err(422, 'invalid', 'version: a number');
    const v = Number(m[2]);
    const ver = verFiles(x, v);
    if (!ver) return err(404, 'not-found', 'no such version');
    return submit({ ...body, tenant: m[0], target: `build-context/${m[1]}/v${v}` }, 'delete-build-version', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      if (recs.some((r) => r.tenant === m[0] && r.b.context === x.row.id && r.b.versionId === ver.meta.id)) return { code: 3, errorCode: 'version-in-use' };
      x.versions = x.versions.filter((y) => y !== ver);
      bump(x);
    });
  });
  const draftEntries = (d: NonNullable<Ctx0['draft']>) =>
    Object.keys(d.files)
      .sort()
      .map((p) => ({ path: p, directory: false, executable: d.exec.has(p), bytes: d.sizes?.[p] ?? new TextEncoder().encode(d.files[p]).length, digest: hex(d.files[p]) }));
  on('GET', '/t/:t/build-contexts/:id/tree', (m, _b, query) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    const v = Number(query.get('version') ?? 0);
    if (!v) {
      if (x.row.kind !== 'draft' || !x.draft) return err(404, 'not-found', 'no draft: only a draft context has one');
      if (!canWrite(m[0])) return err(403, 'forbidden', 'reading a draft needs manage permission');
      return ok({ version: 0, revision: x.draft.revision, digest: hex(JSON.stringify(x.draft.files)), initialized: x.draft.initialized, entries: draftEntries(x.draft), dockerfile: x.row.dockerfile });
    }
    const ver = verFiles(x, v);
    if (!ver) return err(404, 'not-found', 'no such version');
    const files = Object.keys(ver.files).sort();
    const dirs = [...new Set(files.flatMap((p) => p.split('/').slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join('/'))))];
    const entries = [
      ...dirs.map((p) => ({ path: p, directory: true, executable: false, bytes: 0, digest: '' })),
      ...files.map((p) => ({ path: p, directory: false, executable: false, bytes: ver.sizes?.[p] ?? new TextEncoder().encode(ver.files[p]).length, digest: hex(ver.files[p]) })),
    ].sort((a, b) => a.path.localeCompare(b.path));
    return ok({ version: v, id: ver.meta.id, tree: hex(`tree/${ver.meta.id}`), entries, dockerfile: x.row.dockerfile });
  });
  on('GET', '/t/:t/build-contexts/:id/file', (m, _b, query) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    const v = Number(query.get('version') ?? 0);
    const p = query.get('path') ?? '';
    const files = v ? verFiles(x, v)?.files : x.draft?.files;
    const sizes = v ? verFiles(x, v)?.sizes : x.draft?.sizes;
    if (!files || !(p in files)) return err(404, 'not-found', 'no such file');
    if ((sizes?.[p] ?? 0) > LIMITS.fileReadBytes) return err(413, 'too-large', `the file is larger than ${LIMITS.fileReadBytes} bytes`);
    return ok(files[p]);
  });
  on('POST', '/t/:t/build-contexts/:id/verify', (m) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (x.row.kind !== 'git' || !x.remote) return err(422, 'invalid', 'verify: Git contexts only');
    if (x.remote.fail) return ok({ context: x.row.id, code: 'SOURCE_FETCH' });
    const df = x.remote.files[x.row.dockerfile];
    const base = { context: x.row.id, commit: x.remote.commit, tree: hex(x.remote.commit), entries: Object.keys(x.remote.files).length, expandedBytes: bytesOf(x.remote.files) };
    if (!df) return ok({ ...base, code: 'INVALID_CONTEXT' });
    const from = parseDockerfile(df).from.map((f) => f.image);
    const bad = from.some((f) => !c.trust(m[0]).some((r) => matchRule(r, f)));
    return ok({ ...base, code: bad ? 'UNTRUSTED_BASE' : 'OK', baseSources: from });
  });

  // 올린 zip (옛 REQ-47 mock): 내용을 풀지 않고 같은 이름의 예시 파일로 새 버전을 만든다
  const newVersion = (x: Ctx0, files: Files, commit?: string) => {
    const v = Math.max(0, ...x.versions.map((y) => y.meta.number)) + 1;
    x.versions.unshift(mkVer(x.row.id, v, files, now(), commit));
    return v;
  };
  on('PUT', '/t/:t/build-contexts/:id/zip', (m, body, query) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    const file = body as unknown as Blob;
    if (!(file instanceof Blob) || !file.size) return err(422, 'invalid', 'body: the context zip');
    if (file.size > 8 * MiB) return err(413, 'too-large', 'the zip is larger than 8 MiB; upload it in chunks');
    // #215: expected는 쓰지 않는다. 같은 opId면 같은 업로드를 잇는다
    if (x.row.kind !== 'upload') return err(409, 'not-upload', 'only an upload context takes a zip');
    return submit({ opId: query.get('opId'), size: file.size, tenant: m[0], target: `build-context/${m[1]}` }, 'upload-build-zip', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      newVersion(x, { ...(x.versions[0]?.files ?? { Dockerfile: 'FROM docker.io/library/alpine:3.20\nCOPY . /app\n' }), [`uploaded-${x.versions.length + 1}.txt`]: `${file.size} bytes\n` });
      bump(x);
    });
  });
  const CHUNK = 4_177_920;
  type ZipUp = { upload: string; context: string; tenant: string; length: number; digest: string; chunks: number; got: Set<number>; at: number };
  const zipUps = new Map<string, ZipUp>();
  const zipView = (u: ZipUp) => ({
    upload: u.upload,
    context: u.context,
    length: u.length,
    digest: u.digest,
    revision: 1,
    partBytes: 24 * 1024,
    chunkBytes: CHUNK,
    chunks: u.chunks,
    missingChunks: [...Array(u.chunks).keys()].filter((n) => !u.got.has(n)),
    complete: u.got.size === u.chunks,
    expiresAt: iso(u.at + 24 * 3600),
  });
  const zipFind = (m: string[]) => {
    const u = zipUps.get(m[2]);
    return u && u.tenant === m[0] && u.context === m[1] ? u : undefined;
  };
  on('POST', '/t/:t/build-contexts/:id/zip-uploads', (m, body) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (x.row.kind !== 'upload') return err(409, 'not-upload', 'only an upload context takes a zip');
    const length = Number(body.length ?? 0);
    const digest = String(body.digest ?? '');
    if (!/^[0-9a-f]{64}$/.test(digest) || /^0+$/.test(digest)) return err(422, 'invalid', 'digest: sha256 of the whole zip (64 hex)');
    if (!(length > 0 && length <= LIMITS.zipBytes)) return err(422, 'invalid', 'length: 1 byte to 500 MB');
    const upload = `web-${String(body.opId)}`;
    return submit({ ...body, tenant: m[0], target: `build-context/${m[1]}` }, 'begin-build-zip-upload', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      if (!zipUps.has(upload)) zipUps.set(upload, { upload, context: m[1], tenant: m[0], length, digest, chunks: Math.ceil(length / CHUNK), got: new Set(), at: Date.now() / 1000 });
    });
  });
  on('GET', '/t/:t/build-contexts/:id/zip-uploads/:u', (m) => {
    reader(m[0]);
    const u = zipFind(m);
    return u ? ok(zipView(u)) : err(404, 'not-found', 'no such upload for this build context');
  });
  on('PUT', '/t/:t/build-contexts/:id/zip-uploads/:u/chunks/:n', (m, body) => {
    reader(m[0]);
    const u = zipFind(m);
    if (!u) return err(404, 'not-found', 'no such upload for this build context');
    const n = Number(m[3]);
    const blob = body as unknown as Blob;
    const want = n === u.chunks - 1 ? u.length - n * CHUNK : CHUNK;
    if (!(n >= 0 && n < u.chunks) || !(blob instanceof Blob) || blob.size !== want) return err(422, 'invalid', `chunk ${n}: exactly ${want} bytes`);
    u.got.add(n);
    return ok(zipView(u));
  });
  on('POST', '/t/:t/build-contexts/:id/zip-uploads/:u/finish', (m, body) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    const u = zipFind(m);
    if (!x || !u) return err(404, 'not-found', 'no such upload for this build context');
    if (u.got.size !== u.chunks) return err(409, 'incomplete', `${u.chunks - u.got.size} parts are still missing`);
    return submit({ opId: body.opId, tenant: m[0], target: `build-context/${m[1]}` }, 'upload-build-zip', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      newVersion(x, { ...(x.versions[0]?.files ?? { Dockerfile: 'FROM docker.io/library/alpine:3.20\nCOPY . /app\n' }), [`uploaded-${x.versions.length + 1}.txt`]: `${u.length} bytes\n` });
      zipUps.delete(u.upload);
      bump(x);
    });
  });
  on('DELETE', '/t/:t/build-contexts/:id/zip-uploads/:u', (m, body) => {
    reader(m[0]);
    const u = zipFind(m);
    if (!u) return err(404, 'not-found', 'no such upload for this build context');
    return submit({ ...body, tenant: m[0], target: `build-context/${m[1]}` }, 'abort-build-zip-upload', () => {
      zipUps.delete(u.upload);
    });
  });

  // 직접 작성 초안(build-draft, PR #212): op가 아니라 바로 끝나는 호출 → {code, revision}
  const draftEdit = (m: string[], body: Record<string, unknown>, change: (d: NonNullable<Ctx0['draft']>) => RawResponse | void) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (x.row.kind !== 'draft' || !x.draft) return err(409, 'conflict', 'not a draft context');
    if (!canWrite(m[0])) return err(403, 'forbidden', 'editing a draft needs manage permission');
    const opId = String(body.opId ?? '');
    if (!/^[0-9a-f-]{36}$/.test(opId)) return err(400, 'bad-request', 'opId: UUID');
    const key = `${m[0]}/${m[1]}/${opId}`;
    const seen = draftEdits.get(key);
    if (seen !== undefined) return ok({ code: 'OK', revision: seen });
    const d = x.draft;
    const expected = Number(body.expected ?? 0) || d.revision;
    if (expected !== d.revision) return err(409, 'conflict', `the draft is at revision ${d.revision}`);
    const r = change(d);
    if (r) return r;
    d.revision++;
    d.initialized = true;
    draftEdits.set(key, d.revision);
    return ok({ code: 'OK', revision: d.revision });
  };
  const okPath = (p: string) => !!p && !p.startsWith('/') && !p.split('/').some((s) => s === '..' || s === '' || s === '.');
  on('PUT', '/t/:t/build-contexts/:id/files', (m, body) => {
    const path = String(body.path ?? '');
    if (!okPath(path)) return err(422, 'invalid', 'path: a clean relative path inside the context');
    if ((body.text === undefined) === (body.data === undefined)) return err(422, 'invalid', 'one of text or data');
    const text = body.text !== undefined ? String(body.text) : atob(String(body.data));
    if (text.length > MiB) return err(422, 'invalid', 'a file is at most 1 MiB');
    return draftEdit(m, body, (d) => {
      d.files[path] = text;
      if (body.executable) d.exec.add(path);
      else d.exec.delete(path);
    });
  });
  on('DELETE', '/t/:t/build-contexts/:id/files', (m, body) => {
    const path = String(body.path ?? '').replace(/\/$/, '');
    return draftEdit(m, body, (d) => {
      const hit = Object.keys(d.files).filter((p) => p === path || p.startsWith(path + '/'));
      if (!hit.length) return err(404, 'not-found', 'no such file in the draft');
      for (const p of hit) {
        delete d.files[p];
        d.exec.delete(p);
      }
    });
  });
  on('POST', '/t/:t/build-contexts/:id/files/move', (m, body) => {
    const path = String(body.path ?? '').replace(/\/$/, '');
    const to = String(body.to ?? '').replace(/\/$/, '');
    if (!okPath(to)) return err(422, 'invalid', 'to: a clean relative path inside the context');
    return draftEdit(m, body, (d) => {
      const hit = Object.keys(d.files).filter((p) => p === path || p.startsWith(path + '/'));
      if (!hit.length) return err(404, 'not-found', 'no such file in the draft');
      for (const p of hit) {
        d.files[to + p.slice(path.length)] = d.files[p];
        delete d.files[p];
      }
    });
  });
  on('POST', '/t/:t/build-contexts/:id/commit', (m, body) => {
    reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    if (x.row.kind !== 'draft' || !x.draft) return err(409, 'conflict', 'not a draft context');
    const d = x.draft;
    if (!Object.keys(d.files).length) return err(409, 'empty-draft', 'the draft has no files');
    const expected = Number(body.expected ?? 0) || d.revision;
    if (expected !== d.revision) return err(409, 'conflict', `the draft is at revision ${d.revision}`);
    const frozen = { ...d.files };
    return submit({ ...body, tenant: m[0], target: `build-context/${m[1]}` }, 'publish-build-draft', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      newVersion(x, frozen);
      bump(x);
    });
  });

  on('POST', '/t/:t/build-contexts/:id/build', (m, body) => {
    const u = reader(m[0]);
    const x = find(m[0], m[1]);
    if (!x) return missingCtx();
    const t = m[0];
    // Git은 지금 브랜치의 최신 커밋을 받아 새 버전으로(목업은 빌드 요청 때)
    if (x.row.kind === 'git' && x.remote && !x.remote.fail && x.versions[0]?.meta.commit !== x.remote.commit) newVersion(x, { ...x.remote.files }, x.remote.commit);
    const want = Number(body.version ?? 0);
    const ver = want ? verFiles(x, want) : x.versions[0];
    if (!ver) return err(409, 'no-version', want ? `version ${want} is not kept` : 'the context has no version yet');
    const id = String(body.build || `build-${body.opId}`);
    return c.buildGate(t, x.row.id, id, x.row.secrets ?? [], body, () => submit({ ...body, tenant: t, target: `build/${id}` }, 'begin-image-build', () => {
      if (!canWrite(t)) return FORBIDDEN;
      const p = policyOf(t);
      if (!p.exists || !p.nodes?.some((n) => n.node === x.row.node) || recs.some((r) => r.tenant === t && r.b.id === id)) return CAS;
      const plan: Rec['plan'] = { lines: [] };
      const files = ver.files;
      const df = files[x.row.dockerfile];
      const lines = [`#1 [internal] load build definition from ${x.row.dockerfile}`, `#2 context v${ver.meta.number}: ${Object.keys(files).length} files`];
      if (x.row.kind === 'git' && x.remote?.fail) plan.fail = 'SOURCE_FETCH';
      else if (!df) plan.fail = 'BUILD_FAILED';
      else {
        const from = parseDockerfile(df).from.map((f) => f.image);
        const bad = from.find((f) => !c.trust(t).some((r) => matchRule(r, f)));
        lines.push(...from.filter((f) => f !== bad).map((f, i) => `#${3 + i} FROM ${f} ✓`));
        if (bad) {
          plan.fail = 'UNTRUSTED_BASE';
          lines.push(`error: FROM ${bad} is not a trusted source of ${t}`);
        } else {
          lines.push(...Object.entries(x.row.args ?? {}).map(([k, v]) => `#6 ARG ${k}=${v}`));
          lines.push(...(x.row.secrets ?? []).map((s) => `#7 secret ${s.id} «가림»`));
          lines.push('#8 RUN … done', '#9 exporting to oci layout', `#10 pushing ${tagsOf(x.row, ver.meta).join(', ')}`);
        }
      }
      plan.lines = lines;
      const running = live(t).length;
      const start = now() + (running >= p.concurrency ? 12 : 0);
      const number = Math.max(0, ...recs.filter((r) => r.tenant === t).map((r) => r.b.number)) + 1;
      const b: D.DBuild = { id, context: x.row.id, node: x.row.node, user: u.username, phase: start > now() ? 'queued' : 'running', version: ver.meta.number, versionId: ver.meta.id, number, revision: 1, createdAt: iso(now()) };
      recs.push({ tenant: t, b, t0: start, dur: plan.fail ? 8 : 24, plan, push: { repository: x.row.repository, tags: tagsOf(x.row, ver.meta) } });
    }));
  });
  on('GET', '/t/:t/builds', (m, _b, query) => {
    reader(m[0]);
    const cx = query.get('context');
    const items = recs
      .filter((r) => r.tenant === m[0] && (!cx || r.b.context === cx))
      .map((r) => (advance(r), r.b))
      .sort((a, b) => b.number - a.number);
    return ok({ items, next: '', revision: c.revision(), asOf: new Date().toISOString() });
  });
  on('GET', '/t/:t/builds/:id/log', (m, _b, query) => {
    reader(m[0]);
    const r = recs.find((x) => x.tenant === m[0] && x.b.id === m[1]);
    if (!r) return err(404, 'not-found', 'no such build');
    const lg = logOf(r);
    const after = query.get('after') ?? '';
    if (after && !/^o\d+$/.test(after)) return err(422, 'invalid', 'after: a cursor from next');
    const tail = query.get('tail') === '1';
    if (tail && after) return err(422, 'invalid', 'tail and after cannot be used together');
    const total = Math.min(lg.text.length, LOG_MAX);
    const off = tail ? Math.max(0, total - LOG_PAGE) : Math.min(after ? Number(after.slice(1)) : 0, total);
    const text = lg.text.slice(off, Math.min(total, off + LOG_PAGE));
    const end = off + text.length;
    const next = end < total ? `o${end}` : lg.unclosed ? `o${end}` : '';
    return ok({ text, offset: off, next, total, available: total > 0, truncated: lg.truncated, gap: lg.gap, unclosed: lg.unclosed, phase: r.b.phase, done: !lg.unclosed && next === '' });
  });
  on('POST', '/t/:t/builds/:id/cancel', (m, body) => {
    reader(m[0]);
    const r = recs.find((x) => x.tenant === m[0] && x.b.id === m[1]);
    if (!r) return err(404, 'not-found', 'no such build');
    return submit({ ...body, tenant: m[0], target: `build/${m[1]}` }, 'cancel-image-build', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      advance(r);
      if (ended(r.b.phase)) return CAS;
      r.fixed = false;
      r.cancelAt = now();
      if (r.b.id === 'b211') r.log = undefined;
      advance(r);
    });
  });
  on('POST', '/t/:t/builds/:id/delete', (m, body) => {
    reader(m[0]);
    const r = recs.find((x) => x.tenant === m[0] && x.b.id === m[1]);
    if (!r) return err(404, 'not-found', 'no such build');
    return submit({ ...body, tenant: m[0], target: `build/${m[1]}` }, 'delete-image-build-job', () => {
      if (!canWrite(m[0])) return FORBIDDEN;
      advance(r);
      if (!ended(r.b.phase)) return { code: 3, errorCode: 'build-running' };
      recs.splice(recs.indexOf(r), 1);
    });
  });

  // 캐시
  on('GET', '/t/:t/build-cache', (m) => {
    reader(m[0]);
    const t = m[0];
    const p = policyOf(t);
    for (const cl of cleanings) if (cl.tenant === t) advanceCleaning(cl);
    const mine = scopes.filter((s) => s.tenant === t);
    const caches = mine.map((s) => ({ ...s.row, usage: usageOf(s) }));
    const nodes = [...new Set(mine.map((s) => s.row.node))].sort().map((node) => {
      const rows = caches.filter((x) => x.node === node && x.usage?.available);
      return { node, reportedBytes: rows.reduce((n, x) => n + (x.usage?.reportedBytes ?? 0), 0), entries: rows.reduce((n, x) => n + (x.usage?.count ?? 0), 0), scopes: caches.filter((x) => x.node === node).length };
    });
    const cleaning = cleanings
      .filter((x) => x.tenant === t)
      .sort((a, b) => b.at - a.at)
      .map((x) => x.row);
    return ok({ cacheBytes: p.cacheBytes, cleanup: p.exists ? p.cleanup : undefined, nodes, caches, cleaning });
  });
  on('GET', '/t/:t/build-cache/entries', (m, _b, query) => {
    reader(m[0]);
    const node = query.get('node') ?? '';
    const cache = query.get('cache') ?? '';
    if (!/^[0-9a-f]{64}$/.test(cache) || !node) return err(422, 'invalid', 'node and cache (hex) of a cache scope');
    const s = scopes.find((x) => x.tenant === m[0] && x.row.node === node && x.row.cache === cache);
    if (!s) return err(404, 'not-found', 'no such cache scope');
    const u = usageOf(s);
    const after = query.get('after') ?? '';
    const off = after ? Number(after) || 0 : 0;
    const all = [...(s.entries ?? [])].sort((a, b) => b.bytes - a.bytes);
    const PAGE = 7;
    const page = s.down ? [] : all.slice(off, off + PAGE);
    return ok({
      available: !!u?.available,
      observedAt: u?.observedAt,
      lastAttemptAt: u?.lastAttemptAt,
      lastAttemptCode: u?.lastAttemptCode,
      reportedBytes: u?.reportedBytes ?? 0,
      count: u?.count ?? 0,
      offset: off,
      next: off + PAGE < all.length && !s.down ? String(off + PAGE) : '',
      entries: page,
    });
  });
  on('POST', '/t/:t/build-cache/prune', (m, body) => {
    const u = reader(m[0]);
    const t = m[0];
    const f = (body.filter ?? {}) as D.DBuildCacheFilter;
    const node = String(body.node ?? '');
    const cache = String(body.cache ?? '');
    const s = scopes.find((x) => x.tenant === t && x.row.node === node && x.row.cache === cache);
    const okFilter = f.mode === 'all' ? !f.ids?.length : f.mode === 'unused' ? Number(f.unusedDays) >= 1 : f.mode === 'entries' ? !!f.ids?.length && f.ids.length <= 64 : false;
    if (!s || !okFilter) return err(422, 'invalid', 'node, cache (hex) and filter: all | unused with unusedDays | entries with ids (at most 64)');
    const id = `prune-${String(body.opId).slice(0, 8)}`;
    return submit({ ...body, tenant: t, target: `build-cache/${node}/${s.row.context}` }, 'prune-build-cache', () => {
      if (!canWrite(t)) return FORBIDDEN;
      if (s.down) return { code: 3, errorCode: 'node-unavailable' };
      cleanings.push({ tenant: t, at: now(), row: { id, node, context: s.row.context, cache, user: u.username, filter: { mode: f.mode, ids: f.ids, unusedDays: f.unusedDays }, state: 'queued', acceptedAt: iso(now()) } });
    });
  });
}

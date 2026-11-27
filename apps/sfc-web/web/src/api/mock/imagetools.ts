// SPDX-License-Identifier: Apache-2.0

// 이미지 올리기·레이어 보기·태그 추가 목업 (UI-88·89). 실제로는 웹 데몬이 내장 저장소 API를 직접 쓴다.
// 레이어·파일 목록은 이미지 다이제스트에서 정해진 규칙으로 만들어 낸다(같은 저장소는 아래 레이어를 공유).
import type { RawResponse } from '../client';
import type * as D from '../dto';
import * as fx from './fixtures';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  reader: (t: string) => { id: string; username: string };
  canWrite: (t: string) => boolean;
  registry: (t: string, id: string) => { endpoint: string; deleted?: boolean } | undefined;
  usage: (t: string, ref: string) => unknown;
}

const MB = 1_000_000;
const CHUNK = 8 << 20;
const hex = (seed: string) => {
  let out = '';
  for (let k = 0; out.length < 64; k++) {
    let h = (2166136261 ^ Math.imul(k + 7, 2654435761)) >>> 0;
    for (const c of `${k}/${seed}`) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
    h = Math.imul(h ^ (h >>> 13), 0x5bd1e995) >>> 0;
    out += ((h ^ (h >>> 15)) >>> 0).toString(16).padStart(8, '0');
  }
  return 'sha256:' + out.slice(0, 64);
};

interface Layer {
  digest: string;
  bytes: number;
  createdBy: string;
  kind: 'base' | 'apt' | 'vendor' | 'app' | 'chown';
}
interface Step {
  createdBy: string;
  layer?: Layer;
}
/** 이미지 하나(플랫폼 하나)의 만든 순서 */
function stepsOf(im: fx.MockRegistryImage, platform: string): Step[] {
  const app = im.repository.split('/').pop() ?? 'app';
  const share = platform === 'linux/arm64' ? '-arm64' : '';
  const total = im.bytes;
  const L = (kind: Layer['kind'], createdBy: string, part: number, seed: string): Step => ({ createdBy, layer: { kind, createdBy, bytes: Math.round(total * part), digest: hex(seed + share) } });
  return [
    L('base', 'debian:12-slim 기본 (ADD rootfs.tar)', 0.353, 'base:debian12'),
    L('apt', 'RUN apt-get install -y apache2 libapache2-mod-php ca-certificates', 0.321, `apt:${im.repository}`),
    { createdBy: 'ENV PHP_INI_DIR=/usr/local/etc/php' },
    L('vendor', 'COPY --from=deps /app/vendor /var/www/html/vendor', 0.181, `vendor:${im.digest}`),
    L('app', 'COPY . /var/www/html', 0.114, `app:${im.digest}`),
    L('chown', `RUN chown -R 10001:10001 /var/www/html  # ${app}`, 0.031, `chown:${im.digest}`),
    { createdBy: 'USER 10001:10001' },
  ];
}
const multiArch = (im: fx.MockRegistryImage) => im.repository === 'shop/web';
/** 레이어 다이제스트 → 그 레이어(파일 목록을 만들 때 쓴다) */
const known = new Map<string, Layer>();

function filesOf(l: Layer): D.DLayerFile[] {
  const f = (path: string, bytes: number, type = 'file', extra: Partial<D.DLayerFile> = {}): D.DLayerFile => ({ path, bytes, mode: type === 'dir' ? '0755' : '0644', type, ...extra });
  switch (l.kind) {
    case 'base':
      return [f('bin/', 0, 'dir'), f('bin/bash', 1_265_648), f('bin/sh', 0, 'symlink', { link: 'dash', mode: '0777' }), f('etc/', 0, 'dir'), f('etc/os-release', 267), f('etc/passwd', 922), f('lib/x86_64-linux-gnu/libc.so.6', 1_922_136), f('usr/lib/', 0, 'dir'), f('var/lib/dpkg/status', 61_210)];
    case 'apt':
      return [f('etc/apache2/', 0, 'dir'), f('etc/apache2/apache2.conf', 7_224), f('usr/lib/apache2/modules/libphp8.2.so', 5_381_040), f('usr/sbin/apache2', 715_840), f('var/cache/apt/', 0, 'dir'), f('var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease', 0, 'file', { whiteout: true })];
    case 'vendor': {
      const out = [f('var/www/html/vendor/', 0, 'dir'), f('var/www/html/vendor/symfony/', 0, 'dir'), f('var/www/html/vendor/guzzlehttp/', 0, 'dir'), f('var/www/html/vendor/composer/autoload_classmap.php', 812_000)];
      for (let i = 0; i < 2914; i++) out.push(f(`var/www/html/vendor/symfony/pkg${Math.floor(i / 40)}/src/File${i}.php`, 1_000 + ((i * 7919) % 12_000)));
      return out;
    }
    case 'app':
      return [f('var/www/html/', 0, 'dir'), f('var/www/html/index.php', 2_410), f('var/www/html/index.html', 0, 'file', { whiteout: true }), f('var/www/html/public/app.js', 412_330), f('var/www/html/public/app.css', 88_120), f('var/www/html/config/app.php', 5_102)];
    case 'chown':
      return [f('var/www/html/', 0, 'dir', { mode: '0750' }), f('var/www/html/storage/', 0, 'dir', { mode: '0770' })];
  }
}

interface Upload {
  view: D.DImageUpload;
  owner: string;
  tenant: string;
  got: Set<number>;
  inspectAt?: number;
  pushAt?: number;
  applied?: boolean;
  overwrite?: boolean;
}
const uploads = new Map<string, Upload>();
let seq = 0;

export function registerImageTools({ on, ok, err, reader, canWrite, registry, usage }: Ctx) {
  const imgs = (t: string, id: string) => fx.registryImages.filter((i) => i.tenant === t && i.registry === id);
  const reg = (t: string, id: string) => {
    reader(t);
    const r = registry(t, id);
    return r && !r.deleted ? r : undefined;
  };
  const conflict = (t: string, id: string, repository: string, tag: string, cur: string): RawResponse => {
    const r = registry(t, id);
    return { status: 409, json: { error: { code: 'tag-exists', message: 'the tag already points at another image' }, current: cur, usage: usage(t, `${r?.endpoint}/${repository}:${tag}`) } };
  };
  const retag = (t: string, id: string, repository: string, tag: string, digest: string, bytes: number) => {
    for (const im of imgs(t, id)) if (im.repository === repository) im.tags = (im.tags ?? []).filter((x) => x !== tag);
    const same = imgs(t, id).find((i) => i.repository === repository && i.digest === digest);
    if (same) same.tags = [...(same.tags ?? []), tag];
    else fx.registryImages.unshift({ tenant: t, registry: id, repository, digest, tags: [tag], bytes, pushedAt: Math.floor(Date.now() / 1000), inUse: 0, usedBy: [] });
  };

  on('GET', '/t/:t/registries/:id/images/manifest', (m, _b, query) => {
    const [t, id] = m;
    if (!reg(t, id)) return err(404, 'not-found', 'no such registry');
    const repository = query.get('repository') ?? '';
    const ref = query.get('ref') ?? '';
    const platform = query.get('platform') ?? '';
    const im = imgs(t, id).find((i) => i.repository === repository && (i.digest === ref || (i.tags ?? []).includes(ref)));
    if (!im) return err(404, 'not-found', 'manifest unknown');
    const plats = multiArch(im) ? ['linux/amd64', 'linux/arm64'] : ['linux/amd64'];
    if (multiArch(im) && !platform)
      return ok({ repository, ref, digest: im.digest, mediaType: 'application/vnd.oci.image.index.v1+json', manifest: { schemaVersion: 2 }, platforms: plats.map((p) => ({ platform: p, digest: hex(im.digest + p) })), history: [], layers: [] });
    if (platform && !plats.includes(platform)) return err(404, 'not-found', 'no such platform in the index');
    const steps = stepsOf(im, platform || 'linux/amd64');
    const layers = steps.flatMap((s) => (s.layer ? [s.layer] : []));
    for (const l of layers) known.set(l.digest, l);
    const created = new Date(Number(im.pushedAt) * 1000).toISOString();
    return ok({
      repository,
      ref,
      digest: multiArch(im) ? hex(im.digest + platform) : im.digest,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      manifest: { schemaVersion: 2, layers: layers.map((l) => ({ digest: l.digest, size: l.bytes })) },
      config: { architecture: (platform || 'linux/amd64').split('/')[1], os: 'linux', created, config: { User: '10001:10001', Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'PHP_INI_DIR=/usr/local/etc/php', 'APP_ENV=production'], Cmd: ['apache2-foreground'], WorkingDir: '/var/www/html', ExposedPorts: { '8080/tcp': {} }, Labels: { 'org.opencontainers.image.source': `https://git.example/${repository}` } } },
      history: steps.map((s) => ({ created, createdBy: s.createdBy, ...(s.layer ? {} : { emptyLayer: true }) })),
      layers: layers.map((l) => ({ digest: l.digest, mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', bytes: l.bytes, createdBy: l.createdBy })),
    });
  });

  on('GET', '/t/:t/registries/:id/images/layer', (m, _b, query) => {
    const [t, id] = m;
    if (!reg(t, id)) return err(404, 'not-found', 'no such registry');
    const l = known.get(query.get('digest') ?? '');
    if (!l) return err(404, 'not-found', 'blob unknown');
    return ok({ digest: l.digest, files: filesOf(l), truncated: false });
  });

  on('POST', '/t/:t/registries/:id/images/tag', (m, body) => {
    const [t, id] = m;
    if (!reg(t, id)) return err(404, 'not-found', 'no such registry');
    if (!canWrite(t)) return err(403, 'forbidden', 'push credential refused');
    const repository = String(body.repository ?? '');
    const digest = String(body.digest ?? '');
    const tag = String(body.tag ?? '');
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) return err(422, 'invalid', 'tag: letters, digits, _ . - (at most 128, not starting with . or -)');
    const im = imgs(t, id).find((i) => i.repository === repository && i.digest === digest);
    if (!im) return err(404, 'not-found', 'manifest unknown');
    const cur = imgs(t, id).find((i) => i.repository === repository && (i.tags ?? []).includes(tag));
    if (cur && cur.digest !== digest && !body.overwrite) return conflict(t, id, repository, tag, cur.digest);
    if (cur?.digest !== digest) retag(t, id, repository, tag, digest, im.bytes);
    return ok({ repository, tag, digest });
  });

  // ── 올리기 ──
  const view = (u: Upload): D.DImageUpload => {
    const now = Date.now();
    const v = u.view;
    v.received = u.got.size;
    v.missing = Array.from({ length: v.chunks }, (_, i) => i).filter((i) => !u.got.has(i)).slice(0, 200);
    if (u.inspectAt && v.inspect?.state === 'running' && now - u.inspectAt > 1500) {
      if (/broken|fail/i.test(v.fileName)) v.inspect = { state: 'failed', error: 'manifest.json: unexpected end of JSON input' };
      else {
        const b = v.bytes;
        v.inspect = {
          state: 'done',
          items: [
            { index: 0, kind: 'image', refs: ['acme/billing-api:1.8.3'], platforms: ['linux/amd64'], bytes: Math.round(b * 0.42), layers: 7, digest: hex(v.id + ':0') },
            { index: 1, kind: 'image', refs: ['acme/billing-worker:1.8.3'], platforms: ['linux/amd64'], bytes: Math.round(b * 0.31), layers: 6, digest: hex(v.id + ':1') },
            { index: 2, kind: 'image', refs: null, platforms: ['linux/arm64'], bytes: Math.round(b * 0.27), layers: 5, digest: hex(v.id + ':2') },
          ],
        };
      }
    }
    const p = v.push;
    if (p && u.pushAt && (p.state === 'preparing' || p.state === 'pushing')) {
      const el = (now - u.pushAt) / 1000;
      const item = v.inspect?.items?.[p.item];
      const n = item?.layers ?? 5;
      const per = (item?.bytes ?? MB) / n;
      p.layers = Array.from({ length: n }, (_, i) => {
        const bytes = Math.round(per);
        const skipped = i < Math.min(4, n - 1) && i % 2 === 0;
        const start = 0.5 + i * 0.6;
        const done = skipped ? (el > start ? bytes : 0) : Math.max(0, Math.min(bytes, Math.round(((el - start) / 1.2) * bytes)));
        const state = el < start ? (el < 0.5 ? 'waiting' : 'checking') : skipped ? 'skipped' : done >= bytes ? 'uploaded' : 'uploading';
        return { digest: hex(`${v.id}:${p.item}:${i}`), bytes, done, state };
      });
      p.state = el < 0.5 ? 'preparing' : 'pushing';
      if (p.layers.every((l) => l.state === 'skipped' || l.state === 'uploaded')) {
        p.state = 'done';
        p.digest = item?.digest;
        p.finishedAt = new Date().toISOString();
        if (!u.applied && item?.digest) {
          u.applied = true;
          retag(u.tenant, v.registry, p.repository, p.tag, item.digest, item.bytes);
        }
      }
    }
    return structuredClone(v);
  };
  const mine = (m: string[]) => {
    const u = uploads.get(m[2]);
    const me = reader(m[0]).id;
    return u && u.owner === me && u.tenant === m[0] && u.view.registry === m[1] ? u : undefined;
  };

  on('POST', '/t/:t/registries/:id/uploads', (m, body) => {
    const [t, id] = m;
    if (!reg(t, id)) return err(404, 'not-found', 'no such registry');
    if (!canWrite(t)) return err(403, 'forbidden', 'creating an upload needs the tenant manager role');
    const me = reader(t).id;
    if ([...uploads.values()].filter((u) => u.owner === me).length >= 3) return err(409, 'too-many', 'at most 3 uploads per user; delete one first');
    const bytes = Number(body.bytes);
    const fileName = String(body.fileName ?? '');
    if (!fileName || !(bytes > 0) || bytes > 10 * 2 ** 30) return err(422, 'invalid', 'bytes: 1 … 10 GiB');
    if (!/\.(tar|tar\.gz|tgz)$/i.test(fileName)) return err(422, 'invalid', 'fileName: .tar, .tar.gz or .tgz');
    const uid = `up-${Date.now().toString(36)}-${++seq}`;
    const chunks = Math.ceil(bytes / CHUNK);
    const now = Date.now();
    const u: Upload = { owner: me, tenant: t, got: new Set(), view: { id: uid, registry: id, fileName, bytes, chunkBytes: CHUNK, chunks, received: 0, missing: [], createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 86400_000).toISOString() } };
    uploads.set(uid, u);
    return ok(view(u), 201);
  });
  on('GET', '/t/:t/registries/:id/uploads', (m) => {
    reader(m[0]);
    const me = reader(m[0]).id;
    return ok({ items: [...uploads.values()].filter((u) => u.owner === me && u.tenant === m[0] && u.view.registry === m[1]).map(view) });
  });
  on('GET', '/t/:t/registries/:id/uploads/:uid', (m) => {
    const u = mine(m);
    return u ? ok(view(u)) : err(404, 'not-found', 'no such upload');
  });
  on('DELETE', '/t/:t/registries/:id/uploads/:uid', (m) => {
    const u = mine(m);
    if (!u) return err(404, 'not-found', 'no such upload');
    if (u.view.push && (u.view.push.state === 'preparing' || u.view.push.state === 'pushing')) u.view.push.state = 'canceled';
    uploads.delete(m[2]);
    return { status: 204, json: null };
  });
  on('PUT', '/t/:t/registries/:id/uploads/:uid/chunks/:n', (m, body) => {
    const u = mine(m);
    if (!u) return err(404, 'not-found', 'no such upload');
    const n = Number(m[3]);
    const v = u.view;
    if (!Number.isInteger(n) || n < 0 || n >= v.chunks) return err(400, 'invalid', 'chunk out of range');
    const want = n === v.chunks - 1 ? v.bytes - n * CHUNK : CHUNK;
    const size = (body as unknown as Blob).size;
    if (size !== want) return err(400, 'invalid', `chunk ${n}: want ${want} bytes, got ${size}`);
    u.got.add(n);
    const x = view(u);
    return ok({ received: x.received, missing: x.missing });
  });
  on('POST', '/t/:t/registries/:id/uploads/:uid/inspect', (m) => {
    const u = mine(m);
    if (!u) return err(404, 'not-found', 'no such upload');
    if (u.got.size < u.view.chunks) return err(409, 'incomplete', 'chunks are missing');
    if (u.view.inspect?.state !== 'done') {
      u.inspectAt = Date.now();
      u.view.inspect = { state: 'running' };
    }
    return ok(view(u), 202);
  });
  on('POST', '/t/:t/registries/:id/uploads/:uid/push', (m, body) => {
    const u = mine(m);
    if (!u) return err(404, 'not-found', 'no such upload');
    const [t, id] = m;
    const v = view(u);
    const item = Number(body.item);
    const repository = String(body.repository ?? '');
    const tag = String(body.tag ?? '');
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) return err(422, 'invalid', 'tag: letters, digits, _ . - (at most 128, not starting with . or -)');
    const it = v.inspect?.state === 'done' ? v.inspect.items?.[item] : undefined;
    if (!it) return err(409, 'not-inspected', 'inspect the archive and choose one of its items');
    if (v.push && (v.push.state === 'preparing' || v.push.state === 'pushing')) return err(409, 'pushing', 'a push of this upload is running');
    if (!canWrite(t)) return err(403, 'forbidden', 'push credential refused');
    const cur = imgs(t, id).find((i) => i.repository === repository && (i.tags ?? []).includes(tag));
    if (cur && cur.digest !== it.digest && !body.overwrite) return conflict(t, id, repository, tag, cur.digest);
    u.pushAt = Date.now();
    u.applied = false;
    u.view.push = { item, repository, tag, state: 'preparing', layers: [], startedAt: new Date().toISOString() };
    return ok(view(u), 202);
  });
}

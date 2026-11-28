// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 빌드 › 새 빌드 컨텍스트 · 편집 (UI-86, 캔버스 ImageBuildNew · ImageBuildNewIx).
// 계약: docs/reference/web-api.md '이미지 빌드'(sfcd 실제 계약, 초안은 build-draft · PR #212). 저장은 여러 단계
// (컨텍스트 정의 op → 초안 편집(바로 끝나는 호출, expected = 초안 revision) → 게시 op)를 차례로 보낸다.
// 결과를 모르는 단계는 같은 작업 ID로 다시 보내고, 그 단계부터 이어 간다. 빌드 비밀값은 보관함 객체와 키만 고른다(값 입력 칸 없음).
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, ApiError, newOpId } from '../api/client';
import { BUILD_OFF_TEXT, buildBlocked, nodesOverview, buildContexts, buildFileText, buildPolicy, builds, buildTree, contextPath, imageTrust, toOp, vault, verifyBuildContext, type BuildContext } from '../api/endpoints';
import type { BuildKind, DBuildSecret, DOp } from '../api/dto';
import type { OpView } from '../api/types';
import type { SecretView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field } from '../components/ui';
import { Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { fmtBytes } from '../lib/format';
import { matchRule } from '../lib/trust';
import { usePoll } from '../lib/usePoll';
import { KIND, NEED, treeLines } from './ImageBuilds';
type Verify = Awaited<ReturnType<typeof verifyBuildContext>>;
type Arg = { name: string; value: string };
import { abortZip, chunkedZip, loadZipSaved, sameFile, ZIP_CHUNK_MAX, ZipPaused, type ZipProgress } from '../lib/zipUpload';

const mb = (b: number) => (b / 1e6).toFixed(0);
const pctOf = (p: ZipProgress) => (p.total ? Math.floor((p.sent / p.total) * 100) : 0);

const MiB = 1 << 20;
/** 한 번에 보내는 길(PUT …/zip)의 상한. 넘으면 조각 올리기(REQ-47, 500 MiB) */
const ZIP_ONE_MAX = 8 * MiB;
const FILE_MAX = MiB;
const ZIP_MAX = 16 * MiB;
const TEMPLATES: Record<string, [string, string]> = {
  php: [
    'PHP + Apache',
    `# PHP 8.3 + Apache
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
`,
  ],
  node: ['Node.js', `FROM node:20-alpine\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci --omit=dev\nCOPY . .\nUSER node\nEXPOSE 3000\nCMD ["node", "index.js"]\n`],
  go: [
    'Go (정적 바이너리)',
    `FROM golang:1.23 AS build\nWORKDIR /src\nCOPY go.mod go.sum ./\nRUN go mod download\nCOPY . .\nRUN CGO_ENABLED=0 go build -o /out/app .\n\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /out/app /app\nUSER nonroot\nENTRYPOINT ["/app"]\n`,
  ],
  nginx: ['정적 웹(nginx)', `FROM nginx:1.27-alpine\nCOPY nginx.conf /etc/nginx/nginx.conf\nCOPY site/ /usr/share/nginx/html/\nEXPOSE 8080\nUSER 101\n`],
  empty: ['빈 파일', 'FROM \n'],
};
const INSTR = new Set(['FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY', 'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL', 'MAINTAINER']);
const PLATFORMS = ['linux/amd64', 'linux/arm64'];
const okPath = (p: string) => !!p && !p.startsWith('/') && !p.split('/').some((s) => s === '..' || s === '' || s === '.');

/** Dockerfile 줄별 점검: FROM 신뢰 출처, 모르는 명령, COPY 원본 */
export function lintDockerfile(text: string, trust: { registry: string; repository: string }[], paths: string[]) {
  type Issue = { line: number; tone: 'ok' | 'wa' | 'er'; text: string };
  const out: Issue[] = [];
  const stages = new Set<string>();
  const copyOf: Record<string, number[]> = {};
  const missing: { line: number; src: string }[] = [];
  let cont = false;
  text.split('\n').forEach((raw, i) => {
    const line = i + 1;
    const l = raw.trim();
    const was = cont;
    cont = l.endsWith('\\');
    if (/^#\s*syntax\s*=/i.test(l)) return void out.push({ line, tone: 'er', text: '# syntax= 줄은 받지 않습니다(빌더에 고정된 문법만 씀). 지우세요' });
    if (/BUILDKIT_SYNTAX/.test(l) && !l.startsWith('#')) return void out.push({ line, tone: 'er', text: 'BUILDKIT_SYNTAX는 받지 않습니다(빌더에 고정된 문법만 씀)' });
    if (was || !l || l.startsWith('#')) return;
    const [w0, ...rest] = l.split(/\s+/);
    const ins = w0.toUpperCase();
    if (!INSTR.has(ins)) return void out.push({ line, tone: 'er', text: `알 수 없는 명령 ${w0}` });
    if (ins === 'FROM') {
      const img = rest.find((w) => !w.startsWith('--'));
      const as = rest.findIndex((w) => w.toLowerCase() === 'as');
      if (!img) return void out.push({ line, tone: 'er', text: 'FROM 뒤에 이미지가 없습니다' });
      if (!stages.has(img.toLowerCase()) && img !== 'scratch') {
        const rule = trust.find((r) => matchRule(r, img));
        if (!rule) out.push({ line, tone: 'er', text: `${img}는 신뢰 출처가 아닙니다. 빌드가 막힙니다` });
        else if (!img.includes('@'))
          out.push({ line, tone: 'wa', text: `${img}는 태그만 있습니다. 빌드 때 다이제스트로 고정되고 빌드 기록에 남습니다 · 신뢰 출처 ${rule.registry}/${rule.repository} ✓` });
        else out.push({ line, tone: 'ok', text: `${img} · 신뢰 출처 ${rule.registry}/${rule.repository}` });
      }
      if (as >= 0 && rest[as + 1]) stages.add(rest[as + 1].toLowerCase());
    }
    if ((ins === 'COPY' || ins === 'ADD') && !rest.some((w) => w.startsWith('--from='))) {
      const args = rest.filter((w) => !w.startsWith('--'));
      for (const s0 of args.slice(0, -1)) {
        const s = s0.replace(/^\.\//, '').replace(/\/$/, '');
        if (/^https?:/.test(s)) continue;
        const re = s.includes('*') ? new RegExp('^' + s.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '(/|$)') : undefined;
        const hit = paths.filter((p) => s === '.' || s === '' || p === s || p.startsWith(s + '/') || !!re?.test(p));
        if (!hit.length) missing.push({ line, src: s0 });
        for (const p of hit) if (s !== '.' && s !== '') (copyOf[p] ??= []).push(line);
      }
    }
    if ((ins === 'ARG' || ins === 'ENV') && /(PASS|SECRET|TOKEN|KEY)\w*=/i.test(l))
      out.push({ line, tone: 'wa', text: '비밀값은 ARG/ENV 대신 RUN --mount=type=secret 으로 받으세요(오른쪽 빌드 비밀값)' });
  });
  for (const m of missing) out.push({ line: m.line, tone: 'wa', text: `COPY ${m.src} · 컨텍스트에 ${m.src}가 없습니다. 빌드 전에 막습니다` });
  return { issues: out.sort((a, b) => a.line - b.line), copyOf, missing, from: out.filter((x) => x.text.includes('신뢰')).length };
}

interface LFile {
  path: string;
  /** 저장된 초안에서 온 경로(옮기면 다르다) */
  orig?: string;
  bytes: number;
  text: boolean;
  executable?: boolean;
  /** 고쳤거나 새로 넣은 내용. 없으면 저장된 내용 그대로 */
  data?: { text?: string; b64?: string };
}
interface Form {
  kind: BuildKind;
  id: string;
  node: string;
  repository: string;
  tags: string[];
  dockerfile: string;
  args: Arg[];
  secrets: DBuildSecret[];
  platforms: string[];
  git: { repository: string; ref: string; path: string; credentialProfile: string; automatic: boolean };
}
const blank = (tenant: string, kind: BuildKind, node: string): Form => ({
  kind,
  id: '',
  node,
  repository: `${tenant}/`,
  tags: kind === 'git' ? ['v{version}', 'main-{commit}'] : ['v{version}'],
  dockerfile: 'Dockerfile',
  args: [],
  secrets: [],
  platforms: ['linux/amd64'],
  git: { repository: '', ref: 'main', path: '', credentialProfile: '', automatic: false },
});
const fromCtx = (c: BuildContext): Form => ({
  kind: c.kind,
  id: c.id,
  node: c.node,
  repository: c.repository,
  tags: c.tags,
  dockerfile: c.dockerfile,
  args: Object.entries(c.args).map(([name, value]) => ({ name, value })),
  secrets: c.secrets,
  platforms: c.platforms.length ? c.platforms : ['linux/amd64'],
  git: { repository: c.git?.repository ?? '', ref: c.git?.ref ?? 'main', path: c.git?.path ?? '', credentialProfile: c.git?.credentialProfile ?? '', automatic: !!c.git?.automatic },
});
const formBody = (tenant: string, f: Form) => ({
  kind: f.kind,
  node: f.node,
  git:
    f.kind === 'git'
      ? {
          repository: f.git.repository.trim(),
          ref: f.git.ref.trim(),
          path: f.git.path.trim() || undefined,
          credentialProfile: f.git.credentialProfile.trim() || undefined,
          automatic: f.git.automatic,
        }
      : undefined,
  dockerfile: f.dockerfile.trim(),
  args: Object.fromEntries(f.args.map((a) => [a.name.trim(), a.value])),
  secrets: f.secrets.map((s) => ({ ...s, id: s.id.trim(), realm: tenant })),
  repository: f.repository.trim(),
  tags: f.tags,
  platforms: f.platforms,
});
const SECRETISH = /(PASS|SECRET|TOKEN|KEY)/i;

/** edit: 초안 편집(op가 아니라 {code, revision}을 바로 돌려줌). expected는 그때의 초안 revision */
type Step = { label: string; path: string; body?: Record<string, unknown>; blob?: Blob; method: 'PUT' | 'POST' | 'DELETE'; edit?: boolean; commit?: boolean; file?: string; run?: (opId: string) => Promise<{ op: DOp }> };
type Run = { steps: Step[]; at: number; opId: string; op?: OpView; error?: unknown; busy: boolean; done: boolean; edited?: boolean };

/** 여러 작업을 차례로. 결과를 모르는 단계는 같은 작업 ID로 다시 묻고, 실패한 단계는 새 ID로 그 단계부터 다시 낸다 */
function useSteps(onDone: () => void, rev: { current: number }) {
  const [run, setRun] = useState<Run>();
  const ref = useRef<Run>();
  const put = (r: Run | undefined) => ((ref.current = r), setRun(r ? { ...r } : undefined));
  const send = async (r: Run) => {
    const s = r.steps[r.at];
    r.busy = true;
    r.error = undefined;
    r.edited = false;
    put(r);
    if (s.edit) {
      try {
        const res = await api.raw<{ code: string; revision: number }>(s.method, s.path, { ...s.body, opId: r.opId, expected: rev.current });
        rev.current = res.revision;
        r.edited = true;
      } catch (e) {
        r.error = e;
      }
      r.busy = false;
      await settle(r);
      return;
    }
    try {
      const body = s.commit ? { ...s.body, expected: rev.current } : s.body;
      const res = s.run
        ? await s.run(r.opId)
        : s.blob
        ? await api.raw<{ op: DOp }>(s.method, `${s.path}${s.path.includes('?') ? '&' : '?'}opId=${r.opId}`, s.blob)
        : await api.raw<{ op: DOp }>(s.method, s.path, { ...body, opId: r.opId });
      r.op = toOp(res.op);
    } catch (e) {
      r.error = e;
    }
    r.busy = false;
    await settle(r);
  };
  const settle = async (r: Run) => {
    if (r.op?.state === 'applied' || r.edited) {
      if (r.at + 1 >= r.steps.length) {
        r.done = true;
        put(r);
        onDone();
        return;
      }
      r.at++;
      r.opId = newOpId();
      r.op = undefined;
      r.edited = false;
      put(r);
      await send(r);
      return;
    }
    put(r);
  };
  const start = (steps: Step[]) => {
    const r: Run = { steps, at: 0, opId: newOpId(), busy: false, done: false };
    if (!steps.length) {
      r.done = true;
      put(r);
      onDone();
      return;
    }
    void send(r);
  };
  const unsure = (r?: Run) => !!r && !r.done && (r.error !== undefined || (!!r.op && ['unknown', 'pending', 'running'].includes(r.op.state)));
  const failed = (r?: Run) => !!r && !!r.op && (r.op.state === 'failed' || r.op.state === 'rejected');
  /** 같은 단계를 다시: 결과를 모르면 같은 ID, 실패면 새 ID */
  const retry = () => {
    const r = ref.current;
    if (!r) return;
    if (failed(r)) r.opId = newOpId();
    r.op = undefined;
    void send(r);
  };
  const onOp = (o: OpView) => {
    const r = ref.current;
    if (!r) return;
    r.op = o;
    void settle(r);
  };
  return { run, start, retry, unsure: unsure(run), failed: failed(run), onOp, clear: () => put(undefined) };
}

export function BuildEditPage() {
  const { id } = useParams();
  const { tenant, canDeploy } = useTenantRole();
  const ctxQ = usePoll((s) => buildContexts(tenant, s), [tenant], 0);
  if (!canDeploy) return <Card title="빌드 컨텍스트">{NEED}</Card>;
  return (
    <Load q={ctxQ} what="빌드 컨텍스트를 불러오지 못했습니다">
      {(d) => {
        const cur = id ? d.items.find((c) => c.id === id) : undefined;
        if (id && !cur)
          return (
            <Card title="빌드 컨텍스트">
              <span>
                {id} 빌드 컨텍스트가 없습니다. <Link to="/images/builds">빌드 목록으로</Link>
              </span>
            </Card>
          );
        return <Editor key={cur ? `${cur.id}/${cur.revision}` : 'new'} cur={cur} taken={d.items.map((c) => c.id)} onSaved={ctxQ.refresh} />;
      }}
    </Load>
  );
}

function Editor({ cur, taken, onSaved }: { cur?: BuildContext; taken: string[]; onSaved: () => void }) {
  const { tenant } = useTenantRole();
  const navigate = useNavigate();
  const toast = useToast();
  const [params] = useSearchParams();
  const isNew = !cur;
  const polQ = usePoll((s) => buildPolicy(tenant, s), [tenant], 0);
  // 빌드하지 않는 서버(#693)는 새 컨텍스트의 빌드 서버로 고르지 못한다
  const nodesQ = usePoll((s) => nodesOverview(s, tenant).then((o) => new Map(o.nodes.map((n) => [n.id, n]))), [tenant], 0);
  const [f, setF] = useState<Form>(() => (cur ? fromCtx(cur) : blank(tenant, (['upload', 'git', 'draft'].includes(params.get('kind') ?? '') ? params.get('kind') : 'draft') as BuildKind, '')));
  const set = (p: Partial<Form>) => setF((x) => ({ ...x, ...p }));
  // 새 컨텍스트의 빌드 서버: 정책의 첫 서버
  useEffect(() => {
    if (!cur && !f.node && polQ.data?.nodes[0]) set({ node: polQ.data.nodes[0].node, platforms: f.platforms.filter((x) => polQ.data!.platforms.includes(x)).length ? f.platforms : polQ.data.platforms.slice(0, 1) });
  }, [polQ.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const trustQ = usePoll((s) => imageTrust(tenant, s), [tenant], 0);
  const vaultQ = usePoll((s) => vault(tenant, s), [tenant], 0);
  const secrets = useMemo(() => (vaultQ.data?.items ?? []).filter((v) => v.kind === 'object' && v.status === 'active'), [vaultQ.data]);
  const trust = trustQ.data?.rules ?? [];
  // 직접 작성: 초안 파일과 Dockerfile(내용은 file 끝점). revision이 편집의 expected
  const draftQ = usePoll(
    async (s) => {
      if (!cur || cur.kind !== 'draft') return undefined;
      // 트리와 파일 읽기 사이 초안이 바뀌면 409 conflict(#222): 한 번 더 읽는다. 비어 있으면 404
      for (let i = 0; ; i++) {
        const t = await buildTree(tenant, cur.id, 0, s);
        const has = t.files.some((x) => x.path === cur.dockerfile);
        try {
          return { ...t, text: has ? await buildFileText(tenant, cur.id, cur.dockerfile, 0, s) : undefined };
        } catch (e) {
          if (e instanceof ApiError && e.status === 404) return { ...t, text: undefined };
          if (!(e instanceof ApiError && e.status === 409) || i >= 1) throw e;
        }
      }
    },
    [tenant, cur?.id],
    0,
  );
  const rev = useRef(1);
  const [files, setFiles] = useState<LFile[]>();
  const [removed, setRemoved] = useState<string[]>([]);
  const [docker, setDocker] = useState<string>();
  useEffect(() => {
    if (files || (cur && cur.kind === 'draft' && !draftQ.data)) return;
    const t = draftQ.data;
    if (t) rev.current = t.revision;
    setFiles((t?.files ?? []).filter((x) => x.path !== (cur?.dockerfile ?? 'Dockerfile')).map((x) => ({ path: x.path, orig: x.path, bytes: x.bytes, text: true, executable: x.executable })));
    setDocker(t?.text ?? TEMPLATES.php[1]);
  }, [draftQ.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const [zip, setZip] = useState<File>();
  const [zipErr, setZipErr] = useState<string>();
  // 조각 올리기 진행·멈춤과 이어 올릴 업로드
  const [prog, setProg] = useState<ZipProgress>();
  const zipStop = useRef(false);
  const zipCancel = useRef(false);
  const [zipSaved, setZipSaved] = useState(() => (cur ? loadZipSaved(tenant, cur.id) : undefined));
  const [verify, setVerify] = useState<Verify | { error: unknown }>();
  const [conflict, setConflict] = useState<{ from: number; to?: number }>();
  const [verifying, setVerifying] = useState(false);
  const [leave, setLeave] = useState(false);
  const [missingDlg, setMissingDlg] = useState(false);
  const [tpl, setTpl] = useState<string>();
  const [folder, setFolder] = useState('');
  const [newFile, setNewFile] = useState<string>();
  const [moving, setMoving] = useState<LFile>();
  const [editing, setEditing] = useState<string>();
  // 저장이 끝난 뒤 할 일. 끝맺는 콜백이 옛 렌더를 잡아도 맞게 ref로 둔다
  const afterSave = useRef<'stay' | 'build' | 'leave'>('stay');
  const setAfterSave = (v: 'stay' | 'build' | 'leave') => (afterSave.current = v);
  const [frozenTaken] = useState(taken);
  const zipInput = useRef<HTMLInputElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);
  const loadInput = useRef<HTMLInputElement>(null);
  const replaceInput = useRef<HTMLInputElement>(null);
  const replaceTo = useRef('');

  const dockerPath = f.dockerfile.trim() || 'Dockerfile';
  const paths = [dockerPath, ...(files ?? []).map((x) => x.path)];
  const lint = useMemo(() => (f.kind === 'draft' && docker !== undefined ? lintDockerfile(docker, trust, paths) : undefined), [f.kind, docker, trust, paths.join('\n')]); // eslint-disable-line react-hooks/exhaustive-deps
  const total = (files ?? []).reduce((n, x) => n + x.bytes, 0) + new TextEncoder().encode(docker ?? '').length;
  const pol = polQ.data;

  const baseForm = useMemo(() => JSON.stringify(cur ? formBody(tenant, fromCtx(cur)) : null), [cur, tenant]);
  const formDirty = JSON.stringify(formBody(tenant, f)) !== baseForm;
  const filesDirty =
    f.kind === 'draft' && (isNew || removed.length > 0 || (files ?? []).some((x) => x.data || x.orig !== x.path) || (draftQ.data !== undefined && docker !== draftQ.data?.text));
  const dirty = formDirty || filesDirty || !!zip;

  const problems: string[] = [];
  if (isNew && !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(f.id)) problems.push('이름(ID)은 소문자·숫자·- 로 63자까지');
  if (isNew && frozenTaken.includes(f.id)) problems.push('이미 있는 이름입니다');
  if (!f.repository.startsWith(`${tenant}/`) || f.repository.trim().length <= tenant.length + 1) problems.push(`결과 이미지는 ${tenant}/이름 이어야 합니다`);
  if (!f.tags.length) problems.push('태그를 하나 이상 정하세요');
  if (f.kind !== 'git' && f.tags.some((t) => t.includes('{commit}'))) problems.push('{commit}은 Git 컨텍스트만 씁니다');
  if (pol && !pol.exists) problems.push('빌드 설정이 없습니다. 먼저 빌드 설정에서 빌드 서버를 정하세요');
  if (!f.node) problems.push('빌드 서버를 고르세요');
  if (isNew && f.node && buildBlocked(nodesQ.data?.get(f.node))) problems.push(`${f.node}: ${buildBlocked(nodesQ.data?.get(f.node))}. 다른 빌드 서버를 고르세요`);
  if (!okPath(dockerPath)) problems.push('Dockerfile 경로가 올바르지 않습니다');
  if (f.kind === 'git' && (!f.git.repository.trim() || !f.git.ref.trim())) problems.push('Git 저장소 주소와 브랜치를 적으세요');
  if (f.args.some((a) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(a.name))) problems.push('빌드 인자 이름을 확인하세요');
  if (f.secrets.some((s) => !/^[A-Za-z0-9_.-]+$/.test(s.id.trim()) || !s.secret || !s.key)) problems.push('빌드 비밀값의 ID와 보관함 참조를 확인하세요');
  if (new Set(f.secrets.map((s) => s.id)).size !== f.secrets.length) problems.push('같은 ID의 빌드 비밀값이 있습니다');
  if (new Set(f.args.map((a) => a.name)).size !== f.args.length) problems.push('같은 이름의 빌드 인자가 있습니다');
  if (!f.platforms.length) problems.push('대상 플랫폼을 하나 이상 고르세요');
  if (f.kind === 'upload' && isNew && !zip) problems.push('컨텍스트 .zip을 고르세요');

  const ctxId = isNew ? f.id : cur!.id;
  const steps = (commit: boolean): Step[] => {
    const out: Step[] = [];
    if (isNew || formDirty)
      out.push({ label: isNew ? '빌드 컨텍스트 만들기' : '빌드 설정 바꾸기', path: contextPath(tenant, ctxId), body: { context: formBody(tenant, f), expected: cur?.revision ?? 0 }, method: 'PUT' });
    if (f.kind === 'upload' && zip) {
      if (zip.size <= ZIP_ONE_MAX) out.push({ label: `${zip.name} 올리기`, path: contextPath(tenant, ctxId, '/zip'), blob: zip, method: 'PUT' });
      else
        out.push({
          label: `${zip.name} 올리기 (4 MiB 조각)`,
          path: '',
          method: 'POST',
          run: async (opId) => {
            zipStop.current = false;
            const old = loadZipSaved(tenant, ctxId);
            if (old && !sameFile(old, zip)) await abortZip(tenant, ctxId);
            try {
              return await chunkedZip({ tenant, ctx: ctxId, file: zip, opId, stop: () => zipStop.current, onProgress: setProg });
            } catch (e) {
              // 취소: 멈춘 뒤 서버 업로드를 버리고 저장 진행을 닫는다
              if (e instanceof ZipPaused && zipCancel.current) {
                zipCancel.current = false;
                await abortZip(tenant, ctxId).catch(() => undefined);
                setProg(undefined);
                setTimeout(() => s.clear(), 0);
                toast('zip 올리기를 취소했습니다.');
              }
              throw e;
            } finally {
              setZipSaved(loadZipSaved(tenant, ctxId));
            }
          },
        });
    }
    if (f.kind === 'draft') {
      const fp = contextPath(tenant, ctxId, '/files');
      for (const p of removed) out.push({ label: `${p} 지우기`, path: fp, body: { path: p }, method: 'DELETE', edit: true, file: p });
      for (const x of files ?? [])
        if (x.orig && x.orig !== x.path) out.push({ label: `${x.orig} → ${x.path}`, path: contextPath(tenant, ctxId, '/files/move'), body: { path: x.orig, to: x.path }, method: 'POST', edit: true, file: x.path });
      if (isNew || docker !== draftQ.data?.text || (cur && cur.dockerfile !== dockerPath)) out.push({ label: `${dockerPath} 저장`, path: fp, body: { path: dockerPath, text: docker ?? '' }, method: 'PUT', edit: true, file: dockerPath });
      for (const x of files ?? [])
        if (x.data)
          out.push({
            label: `${x.path} 저장`,
            path: fp,
            body: { path: x.path, ...(x.data.text !== undefined ? { text: x.data.text } : { data: x.data.b64 }), ...(x.executable ? { executable: true } : {}) },
            method: 'PUT',
            edit: true,
            file: x.path,
          });
      if (commit && (filesDirty || !cur?.version)) out.push({ label: `버전 v${nextVer}로 게시 (내 키로 서명)`, path: contextPath(tenant, ctxId, '/commit'), body: {}, method: 'POST', commit: true });
    }
    return out;
  };
  const buildAfter = async () => {
    try {
      const id = `build-${newOpId()}`;
      const r = await api.post<{ op: DOp }>(contextPath(tenant, ctxId, '/build'), { opId: newOpId(), build: id });
      const b = r.op.state === 'applied' ? (await builds(tenant, ctxId)).items.find((x) => x.id === id) : undefined;
      toast(
        r.op.state === 'applied'
          ? `◔ ${b?.label ?? '새'} 빌드를 대기열에 넣었습니다.`
          : r.op.errorCode === 'approval-required'
            ? '빌드가 비밀값 묶음의 비밀번호 승인을 기다립니다. 비밀값 보관함의 묶음 승인에서 승인하면 이어서 빌드합니다.'
            : `빌드를 보냈지만 결과가 ${r.op.state}입니다. 빌드 목록에서 확인하세요.`,
      );
    } catch (e) {
      toast(e instanceof ApiError && e.code === 'build-disabled' ? `저장했지만 빌드하지 않았습니다. ${BUILD_OFF_TEXT}` : `저장했지만 빌드를 보내지 못했습니다: ${e instanceof ApiError ? (e.body.message ?? e.body.code) : '연결 오류'}`);
    }
  };
  const nextVer = Math.max(0, ...(cur?.versions ?? []).map((v) => v.number)) + 1;
  const s = useSteps(() => {
    toast(`${ctxId} 빌드 컨텍스트를 저장했습니다.`);
    if (afterSave.current === 'build') void buildAfter().then(() => navigate(`/images/builds?context=${encodeURIComponent(ctxId)}`));
    else if (afterSave.current === 'leave') navigate('/images/builds');
    else navigate(`/images/builds?context=${encodeURIComponent(ctxId)}`);
  }, rev);
  const save = (mode: 'stay' | 'build' | 'leave', commit = true) => {
    setAfterSave(mode);
    setConflict(undefined);
    if (mode === 'build' && f.kind === 'draft' && lint?.missing.length) return setMissingDlg(true);
    s.start(steps(commit));
  };
  // 초안 충돌(409 conflict): 지금 revision을 읽어 띠로 알린다
  const runErr = s.run?.error;
  useEffect(() => {
    if (!(runErr instanceof ApiError) || runErr.code !== 'conflict' || !cur || cur.kind !== 'draft') return;
    const from = rev.current;
    setConflict({ from });
    void buildTree(tenant, cur.id, 0)
      .then((t) => setConflict({ from, to: t.revision }))
      .catch(() => undefined);
  }, [runErr]); // eslint-disable-line react-hooks/exhaustive-deps
  const step = s.run && !s.run.done ? s.run.steps[s.run.at] : undefined;
  const sending = s.run?.busy ? step?.file : undefined;
  const locked = !!s.run && !s.run.done && !s.failed;
  const zipRunning = !!s.run?.busy && !!s.run.steps[s.run.at]?.run;
  const cancelZip = async () => {
    if (zipRunning) {
      zipCancel.current = true;
      zipStop.current = true;
      return;
    }
    try {
      await abortZip(tenant, ctxId);
    } catch (e) {
      toast(`업로드를 취소하지 못했습니다: ${e instanceof ApiError ? (e.body.message ?? e.body.code) : '연결 오류'}`);
    }
    setZipSaved(undefined);
    setProg(undefined);
  };
  const dropZip = async () => {
    await cancelZip();
    s.clear();
  };

  const addLocal = async (list: FileList | File[], base = folder, at?: string) => {
    const next = [...(files ?? [])];
    const errs: string[] = [];
    for (const file of Array.from(list)) {
      const rel = ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name).replace(/^\/+/, '');
      const p = at ?? (base ? base.replace(/\/?$/, '/') : '') + rel;
      if (!okPath(p)) errs.push(`${rel}: 경로 밖 항목이라 뺍니다`);
      else if (file.size > FILE_MAX)
        errs.push(`${rel} (${fmtBytes(file.size)})를 올릴 수 없습니다. 파일 하나는 1 MiB까지이고, 컨텍스트 전체는 빌드 입력 예산${pol ? `(${fmtBytes(pol.workspaceBytes)})` : ''} 안이어야 합니다`);
      else {
        const buf = new Uint8Array(await file.arrayBuffer());
        let text: string | undefined;
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
        } catch {
          text = undefined;
        }
        const data = text !== undefined ? { text } : { b64: btoa(Array.from(buf, (b) => String.fromCharCode(b)).join('')) };
        const i = next.findIndex((x) => x.path === p);
        const row: LFile = { path: p, orig: i >= 0 ? next[i].orig : undefined, bytes: file.size, text: text !== undefined, executable: i >= 0 ? next[i].executable : undefined, data };
        if (i >= 0) next[i] = row;
        else next.push(row);
      }
    }
    setFiles(next);
    if (errs.length) toast(errs[0]);
  };
  /** zip은 브라우저에서 풀어 파일로 넣는다. 서버에는 풀린 파일만 간다. */
  const addZip = async (zip: File) => {
    if (zip.size > ZIP_MAX) return toast(`${zip.name} (${fmtBytes(zip.size)})는 너무 큽니다. 웹에서는 zip ${fmtBytes(ZIP_MAX)}까지 풉니다`);
    try {
      const { unzip } = await import('../lib/unzip');
      const r = await unzip(await zip.arrayBuffer(), FILE_MAX);
      const list = r.files.map((x) => {
        const f = new File([x.data as BlobPart], x.path.split('/').pop()!);
        Object.defineProperty(f, 'webkitRelativePath', { value: x.path });
        return f;
      });
      await addLocal(list);
      toast(`${zip.name}에서 ${list.length}개를 넣었습니다${r.skipped.length ? ` · ${r.skipped.length}개 뺌 (${r.skipped[0]})` : ''}. 저장해야 반영됩니다.`);
    } catch (e) {
      toast(`! ${e instanceof Error ? e.message : String(e)}`, 'er');
    }
  };
  const fileMenu = (x: LFile): MenuItem[] => [
    { label: '편집기 탭으로 열기', hint: '텍스트', disabledReason: x.text ? undefined : '텍스트 파일만 열 수 있습니다', onSelect: () => void openText(x) },
    { label: '다른 폴더로 옮기기(이름 바꾸기 포함)…', onSelect: () => setMoving(x) },
    { label: '같은 경로로 다시 올리기', onSelect: () => ((replaceTo.current = x.path), replaceInput.current?.click()) },
    { label: '내려받기', disabledReason: x.orig && !x.data ? undefined : '저장한 뒤 내려받을 수 있습니다', onSelect: () => void download(x) },
    { label: '', sep: true },
    { label: '지우기', danger: true, onSelect: () => (setFiles((fs) => (fs ?? []).filter((y) => y !== x)), x.orig && setRemoved((r) => [...r, x.orig!])) },
  ];
  const fetchFile = (p: string) => buildFileText(tenant, ctxId, p, 0);
  const readErr = (e: unknown) =>
    e instanceof ApiError && e.status === 413 ? '(읽을 수 있는 크기보다 큼)' : e instanceof ApiError && e.status === 409 ? '(그 사이 초안이 바뀜 · 새로 읽은 뒤 다시 여세요)' : e instanceof ApiError && e.status === 404 ? '(초안에 없음)' : '';
  const openText = async (x: LFile) => {
    if (!x.data && x.orig) {
      try {
        const text = await fetchFile(x.orig);
        setFiles((fs) => (fs ?? []).map((y) => (y === x ? { ...y, data: { text } } : y)));
      } catch (e) {
        return toast(`${x.path}를 읽지 못했습니다${readErr(e)}.`);
      }
    }
    setEditing(x.path);
  };
  const download = async (x: LFile) => {
    let text: string;
    try {
      text = await fetchFile(x.orig!);
    } catch (e) {
      return toast(`${x.path}를 내려받지 못했습니다${readErr(e)}.`);
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text]));
    a.download = x.path.split('/').pop()!;
    a.click();
  };
  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerify(await verifyBuildContext(tenant, ctxId));
    } catch (e) {
      setVerify({ error: e });
    } finally {
      setVerifying(false);
    }
  };
  const pickZip = (file?: File) => {
    setZipErr(undefined);
    if (!file) return;
    if (!/\.zip$/i.test(file.name)) return setZipErr('.zip 파일만 올릴 수 있습니다');
    if (file.size > ZIP_CHUNK_MAX) return setZipErr(`${file.name}(${fmtBytes(file.size)})를 올릴 수 없습니다. 웹에서는 500 MiB까지이고, 더 큰 컨텍스트는 CLI로 올립니다`);
    setZip(file);
  };
  const editingFile = editing ? (files ?? []).find((x) => x.path === editing) : undefined;

  return (
    <>
      <div className="row" style={{ gap: 12, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
        <a
          href="/images/builds"
          className="btn sm"
          onClick={(e) => {
            e.preventDefault();
            if (dirty && !s.run?.done) setLeave(true);
            else navigate('/images/builds');
          }}
        >
          ← 빌드
        </a>
        <b style={{ fontSize: 16 }}>{isNew ? '새 빌드 컨텍스트' : `${cur!.id} 편집`}</b>
        <span className="small muted">소스 방식</span>
        <div className="segmented" role="radiogroup" aria-label="소스 방식">
          {(['upload', 'git', 'draft'] as BuildKind[]).map((k) => (
            <button
              key={k}
              type="button"
              role="radio"
              aria-checked={f.kind === k}
              className={f.kind === k ? 'on' : ''}
              disabled={!isNew || locked}
              title={isNew ? undefined : '저장한 컨텍스트의 방식은 바꿀 수 없습니다'}
              onClick={() => set({ kind: k })}
            >
              {KIND[k][0]} {k === 'upload' ? 'Dockerfile 업로드' : k === 'git' ? 'Git에서 가져오기' : 'Dockerfile 직접 작성'}
            </button>
          ))}
        </div>
        <span className="small muted">{isNew ? '방식은 저장 전까지 바꿀 수 있습니다. 직접 작성도 컨텍스트 파일을 올릴 수 있어, 저장하면 Dockerfile과 파일이 함께 한 버전이 됩니다' : ''}</span>
      </div>
      <div className="main-side">
        <div className="col" style={{ gap: 16 }}>
          {f.kind === 'draft' && (
            <>
              <Card
                title={editingFile ? `${editingFile.path} (편집기 탭)` : 'Dockerfile'}
                actions={
                  <div className="row" style={{ gap: 6, alignItems: 'center' }}>
                    {editingFile ? (
                      <button type="button" className="btn sm" onClick={() => setEditing(undefined)}>
                        Dockerfile로 돌아가기
                      </button>
                    ) : (
                      <>
                        <span className="small muted">템플릿:</span>
                        {Object.entries(TEMPLATES).map(([k, [label]]) => (
                          <button type="button"
                            key={k}
                            className="btn sm"
                            disabled={locked}
                            onClick={() => (docker && docker !== TEMPLATES[k][1] && docker.trim() !== 'FROM' ? setTpl(k) : setDocker(TEMPLATES[k][1]))}
                          >
                            {label}
                          </button>
                        ))}
                        <button type="button" className="btn sm" disabled={locked} onClick={() => loadInput.current?.click()}>
                          파일에서 불러오기
                        </button>
                        <input
                          ref={loadInput}
                          type="file"
                          hidden
                          onChange={async (e) => {
                            const file = e.target.files?.[0];
                            e.target.value = '';
                            if (!file) return;
                            if (file.size > FILE_MAX) return toast('Dockerfile은 1 MiB까지입니다.');
                            setDocker(await file.text());
                          }}
                        />
                      </>
                    )}
                  </div>
                }
              >
                {docker === undefined ? (
                  <span className="small muted">초안을 불러오는 중…</span>
                ) : editingFile ? (
                  <LineEditor
                    value={editingFile.data?.text ?? ''}
                    onChange={(text) => setFiles((fs) => (fs ?? []).map((y) => (y.path === editingFile.path ? { ...y, bytes: new TextEncoder().encode(text).length, data: { text } } : y)))}
                    readOnly={locked}
                    label={editingFile.path}
                  />
                ) : (
                  <>
                    <LineEditor value={docker} onChange={setDocker} readOnly={locked} label="Dockerfile" marks={lint?.issues} />
                    <div className="col small" style={{ gap: 4 }}>
                      {(lint?.issues ?? []).map((x, i) => (
                        <span key={i} style={{ color: x.tone === 'er' ? 'var(--er)' : x.tone === 'wa' ? 'var(--wa)' : 'var(--ok)' }}>
                          {x.tone === 'ok' ? '✓' : '!'} {x.line}번 줄: {x.text}
                        </span>
                      ))}
                    </div>
                    <span className="small muted">
                      입력하는 동안 FROM 줄의 이미지를 신뢰 출처와 맞춰 보고, 문법 오류·알 수 없는 명령을 줄 옆에 표시합니다. # syntax= 줄과 BUILDKIT_SYNTAX는 받지 않습니다(빌더에 고정된 문법만 씀).
                      비밀값은 ARG/ENV에 쓰지 말고 RUN --mount=type=secret 으로 받으세요(오른쪽 '빌드 비밀값').
                    </span>
                  </>
                )}
              </Card>
              <Card
                title={`컨텍스트 파일 · 파일 ${(files?.length ?? 0) + 1}개 · ${fmtBytes(total)}${pol?.exists ? ` / 빌드 입력 예산 ${fmtBytes(pol.workspaceBytes)}` : ''}`}
                actions={
                  <div className="row" style={{ gap: 6 }}>
                    <button type="button" className="btn sm" disabled={locked} onClick={() => fileInput.current?.click()}>
                      ⇪ 파일 올리기
                    </button>
                    <button type="button" className="btn sm" disabled={locked} onClick={() => dirInput.current?.click()}>
                      ⇪ 폴더 올리기
                    </button>
                    <button type="button" className="btn sm" disabled={locked} title="브라우저에서 풀어 지금 폴더에 넣습니다" onClick={() => zipInput.current?.click()}>
                      .zip 풀어 넣기
                    </button>
                    <button type="button" className="btn sm" disabled={locked} onClick={() => setNewFile('')}>
                      ＋ 새 파일
                    </button>
                    <input ref={replaceInput} type="file" hidden onChange={(e) => (e.target.files?.[0] && void addLocal([e.target.files[0]], '', replaceTo.current), (e.target.value = ''))} />
                    <input ref={zipInput} type="file" accept=".zip,application/zip" hidden onChange={(e) => (e.target.files?.[0] && void addZip(e.target.files[0]), (e.target.value = ''))} />
                    <input ref={fileInput} type="file" multiple hidden onChange={(e) => (e.target.files && void addLocal(e.target.files), (e.target.value = ''))} />
                    <input ref={dirInput} type="file" multiple hidden {...{ webkitdirectory: '' }} onChange={(e) => (e.target.files && void addLocal(e.target.files), (e.target.value = ''))} />
                  </div>
                }
              >
                {conflict && (
                  <div className="note wa small row between wrap">
                    <span>
                      이 초안이 다른 곳에서 바뀌었습니다 (r{conflict.from}
                      {conflict.to ? ` → r${conflict.to}` : ''}). 방금 한 편집은 적용되지 않았습니다. 새로 읽기 뒤 다시 하세요.
                    </span>
                    <button type="button" className="btn sm" onClick={() => (s.clear(), onSaved())}>
                      새로 읽기
                    </button>
                  </div>
                )}
                <FileTree dockerPath={dockerPath} files={files ?? []} copyOf={lint?.copyOf ?? {}} folder={folder} setFolder={setFolder} menu={fileMenu} onOpen={(x) => void openText(x)} sending={sending} />
                {newFile !== undefined && (
                  <div className="row" style={{ gap: 6, alignItems: 'center' }}>
                    <span className="small muted">새 파일 {folder ? `(${folder} 안)` : ''}</span>
                    <input
                      autoFocus
                      className="mono"
                      placeholder="config/app.ini"
                      value={newFile}
                      onChange={(e) => setNewFile(e.target.value)}
                      onKeyDown={(e) => e.key === 'Escape' && setNewFile(undefined)}
                    />
                    <button type="button"
                      className="btn sm primary"
                      disabled={!okPath((folder ? folder.replace(/\/?$/, '/') : '') + newFile) || paths.includes((folder ? folder.replace(/\/?$/, '/') : '') + newFile)}
                      onClick={() => {
                        const p = (folder ? folder.replace(/\/?$/, '/') : '') + newFile;
                        setFiles((fs) => [...(fs ?? []), { path: p, bytes: 0, text: true, data: { text: '' } }]);
                        setNewFile(undefined);
                        setEditing(p);
                      }}
                    >
                      만들기
                    </button>
                    <span className="small muted">/ 로 폴더를 함께 만듭니다</span>
                  </div>
                )}
                <div
                  className="inset small muted"
                  style={{ textAlign: 'center', borderStyle: 'dashed' }}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (!locked && e.dataTransfer.files.length) void addLocal(e.dataTransfer.files);
                  }}
                >
                  여기에 파일을 끌어 놓으세요 · 고른 폴더({folder || '컨텍스트 루트'}) 안에 들어갑니다
                </div>
                {lint && lint.missing.length > 0 && (
                  <div className="note wa small">
                    {lint.missing.map((m) => (
                      <div key={`${m.line}${m.src}`}>
                        ! {m.line}번 줄 COPY {m.src} · 컨텍스트에 없습니다. 빌드 전에 막습니다.
                      </div>
                    ))}
                  </div>
                )}
                <span className="small muted">
                  .dockerignore에 걸리는 파일은 빌드에 들어가지 않습니다. 파일을 누르면 ⋯ 메뉴: 다른 폴더로 옮기기(이름 바꾸기 포함) · 같은 경로로 다시 올리기 · 내려받기 · 지우기. 텍스트 파일(설정 등)은 '편집기
                  탭으로 열기'로 Dockerfile 옆 탭에서 고칠 수 있습니다. 경로 밖(../)·링크·실행 장치 파일은 받지 않습니다. 파일 하나는 1 MiB까지입니다.
                </span>
              </Card>
            </>
          )}
          {f.kind === 'upload' && (
            <Card title="컨텍스트 .zip">
              <div
                className="inset col"
                style={{ gap: 8, alignItems: 'center', borderStyle: 'dashed', textAlign: 'center' }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (!locked) pickZip(e.dataTransfer.files[0]);
                }}
              >
                <b>컨텍스트 .zip을 끌어 놓거나 고르세요</b>
                <span className="small muted">Dockerfile과 빌드에 필요한 파일(COPY · ADD 대상) 전부를 .zip 하나로 (최대 500 MB · 4 MiB 조각으로 나눠 올리고 끊기면 이어 올림 · 낱개 파일은 하나 1 MiB). 압축을 푼 맨 위가 컨텍스트 루트입니다</span>
                <label className="btn sm">
                  파일 고르기
                  <input type="file" accept=".zip,application/zip" hidden disabled={locked} onChange={(e) => (pickZip(e.target.files?.[0]), (e.target.value = ''))} />
                </label>
              </div>
              {zipErr && <div className="note er small">{zipErr}</div>}
              {zipRunning && prog ? (
                <div className="inset col" style={{ gap: 6 }}>
                  <b>zip 올리는 중</b>
                  <span className="small">
                    {zip?.name} · {fmtBytes(prog.total)}
                  </span>
                  {prog.phase === 'hash' ? (
                    <span className="small muted">파일을 확인하는 중(sha256)…</span>
                  ) : (
                    <>
                      <div className="bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pctOf(prog)}>
                        <i style={{ width: `${pctOf(prog)}%` }} />
                      </div>
                      <span className="small">
                        {pctOf(prog)}% · {mb(prog.sent)} / {mb(prog.total)} MB{prog.phase === 'finish' ? ' · 서버가 확인하는 중' : ''}
                      </span>
                    </>
                  )}
                  <span className="small muted">4 MiB 조각으로 올립니다. 끊기거나 창을 닫아도 같은 파일을 다시 고르면 이어 올립니다. 다 올리면 서버가 풀어 파일 목록을 채웁니다.</span>
                  <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
                    <button type="button" className="btn sm" disabled={prog.phase !== 'send'} onClick={() => (zipStop.current = true)}>
                      멈춤
                    </button>
                    <button type="button" className="btn sm danger" disabled={prog.phase === 'finish'} onClick={() => void cancelZip()}>
                      취소
                    </button>
                  </div>
                </div>
              ) : (
                zipSaved &&
                (!zip || !sameFile(zipSaved, zip)) && (
                  <div className="note wa small row between wrap">
                    <span>
                      {zipSaved.name} {mb(zipSaved.sent)} / {mb(zipSaved.bytes)} MB까지 올리다 멈췄습니다. 같은 파일을 고르면 이어 올립니다.
                    </span>
                    <span className="row" style={{ gap: 6 }}>
                      <label className="btn sm">
                        파일 고르기
                        <input type="file" accept=".zip,application/zip" hidden disabled={locked} onChange={(e) => (pickZip(e.target.files?.[0]), (e.target.value = ''))} />
                      </label>
                      <button type="button" className="btn sm" disabled={locked} onClick={() => void dropZip()}>
                        버리기
                      </button>
                    </span>
                  </div>
                )
              )}
              {zip && (
                <span className="small">
                  고른 파일 <b>{zip.name}</b> · {fmtBytes(zip.size)} · 저장하면 새 버전(v{nextVer})이 됩니다
                </span>
              )}
              <Field label="Dockerfile 위치" hint="zip 안의 경로">
                <input className="mono" value={f.dockerfile} onChange={(e) => set({ dockerfile: e.target.value })} disabled={locked} />
              </Field>
              {cur && cur.versions.length > 0 && (
                <span className="small">
                  올린 파일 올린 zip v{cur.versions[0].number} (버전 {cur.versions.length}개) · {cur.versions.map((v) => `v${v.number} ${fmtBytes(v.expandedBytes)}`).join(', ')}
                </span>
              )}
              <span className="small muted">
                zip 안에 Dockerfile이 없으면 서버가 올리기를 거부합니다. 경로 밖으로 나가는 항목(../)·링크·장치 파일은 거부합니다. 500 MiB가 넘는 컨텍스트는 CLI로 올리세요.
              </span>
            </Card>
          )}
          {f.kind === 'git' && (
            <Card title="Git에서 가져오기">
              <fieldset disabled={locked} style={{ border: 0, padding: 0, margin: 0 }} className="col">
                <Field label="저장소 주소">
                  <input className="mono" placeholder="https://git.example.com/team/app.git" value={f.git.repository} onChange={(e) => set({ git: { ...f.git, repository: e.target.value } })} />
                </Field>
                <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 10 }}>
                  <Field label="브랜치 · 태그 · 커밋">
                    <input className="mono" value={f.git.ref} onChange={(e) => set({ git: { ...f.git, ref: e.target.value } })} />
                  </Field>
                  <Field label="접속 정보" hint="서버에 설치된 프로필 이름. 비우면 공개 저장소">
                    <input className="mono" placeholder="없음 (공개)" value={f.git.credentialProfile} onChange={(e) => set({ git: { ...f.git, credentialProfile: e.target.value } })} />
                  </Field>
                  <Field label="컨텍스트 폴더">
                    <input className="mono" placeholder="(저장소 루트)" value={f.git.path} onChange={(e) => set({ git: { ...f.git, path: e.target.value } })} />
                  </Field>
                  <Field label="Dockerfile 경로">
                    <input className="mono" value={f.dockerfile} onChange={(e) => set({ dockerfile: e.target.value })} />
                  </Field>
                </div>
                <label className="row small" style={{ gap: 6, alignItems: 'center' }}>
                  <input type="checkbox" checked={f.git.automatic} onChange={(e) => set({ git: { ...f.git, automatic: e.target.checked } })} /> 새 커밋이 올라오면 자동 빌드 (1분마다 확인)
                </label>
              </fieldset>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <button type="button"
                  className="btn"
                  disabled={isNew || formDirty || verifying}
                  title={isNew || formDirty ? '저장한 설정으로 받아 봅니다. 먼저 저장하세요' : undefined}
                  onClick={() => void runVerify()}
                >
                  {verifying ? '받는 중…' : '받아서 확인 (git clone)'}
                </button>
                {verify && 'code' in verify && (
                  <span className="small" style={{ color: verify.code === 'OK' ? 'var(--ok)' : 'var(--er)' }}>
                    {verify.code === 'OK'
                      ? `✓ ${f.git.ref}@${verify.commit?.slice(0, 7)} · Dockerfile 찾음 · FROM ${verify.baseSources.length}개 신뢰 출처`
                      : verify.code === 'SOURCE_FETCH'
                        ? `${f.git.repository}을 받지 못했습니다. 주소나 접속 정보(${f.git.credentialProfile || '공개'})를 확인하세요`
                        : verify.code === 'INVALID_CONTEXT'
                          ? `${f.git.ref}@${verify.commit?.slice(0, 7) ?? ''}의 컨텍스트가 올바르지 않습니다(${f.dockerfile}이 없거나 경로 밖 항목)`
                          : verify.code === 'UNTRUSTED_BASE'
                            ? `FROM 이미지 가운데 신뢰 출처가 아닌 것이 있습니다: ${verify.baseSources.join(', ')}`
                            : `확인 결과 ${verify.code}`}
                  </span>
                )}
                {verify && 'error' in verify && <MutationError error={verify.error} />}
              </div>
              <span className="small muted">
                Dockerfile은 Git이 기준이라 여기서는 읽기 전용으로 보여 줍니다. 받기는 빌드 서버가 하며, 접속 정보는 자동 배포와 같은 서버 설치 프로필(credential_profile)만 고를 수 있습니다.
              </span>
            </Card>
          )}
        </div>
        <Card title="빌드 설정">
          <fieldset disabled={locked} style={{ border: 0, padding: 0, margin: 0 }} className="col">
            <Field label="이름 (ID)" hint="영문 소문자·숫자·- · 저장 뒤 바꿀 수 없음 · 목록에 이 이름 그대로 보임">
              <input
                value={f.id}
                disabled={!isNew}
                onChange={(e) =>
                  set({
                    id: e.target.value.trim(),
                    repository: f.repository === `${tenant}/${f.id}` || f.repository === `${tenant}/` ? `${tenant}/${e.target.value.trim()}` : f.repository,
                  })
                }
              />
            </Field>
            <Field label="빌드 서버 (저장 위치)" hint="빌드 설정에 허용한 서버 중 하나 · 저장 뒤에는 바꿀 수 없음(복제해서 옮김)">
              <select value={f.node} disabled={!isNew} onChange={(e) => set({ node: e.target.value })}>
                {!f.node && <option value="">{pol && !pol.exists ? '빌드 설정이 없습니다' : '고르세요'}</option>}
                {cur && (!pol || !pol.nodes.some((n) => n.node === cur.node)) && (
                  <option value={cur.node}>
                    {cur.node} · {cur.root}{pol ? ' (지금 빌드 설정에 없음)' : ''}
                  </option>
                )}
                {(pol?.nodes ?? []).map((n) => {
                  const off = isNew ? buildBlocked(nodesQ.data?.get(n.node)) : undefined;
                  return (
                    <option key={n.node} value={n.node} disabled={!!off}>
                      {n.node} · {n.root.id}
                      {off ? ` (${off})` : ''}
                    </option>
                  );
                })}
              </select>
            </Field>
            <Field label="결과 이미지" hint="내장 저장소에 올릴 경로">
              <input className="mono" value={f.repository} onChange={(e) => set({ repository: e.target.value.trim() })} />
            </Field>
            <TagsField tags={f.tags} git={f.kind === 'git'} set={(tags) => set({ tags })} />
            <ArgsField
              args={f.args}
              set={(args) => set({ args })}
              toSecret={(a) => {
                set({ args: f.args.filter((x) => x !== a), secrets: [...f.secrets, { id: a.name.toLowerCase().replace(/_/g, '-'), realm: tenant, secret: '', key: '' }] });
                toast(`${a.name} 인자를 지웠습니다. 보관함 객체와 키를 고르고 Dockerfile에서 RUN --mount=type=secret,id=${a.name.toLowerCase().replace(/_/g, '-')} 로 받으세요.`);
              }}
            />
            <SecretsField items={f.secrets} set={(secrets) => set({ secrets })} secrets={secrets} />
            <Field label="대상 플랫폼">
              <div className="row" style={{ gap: 12 }}>
                {(pol?.platforms.length ? pol.platforms : PLATFORMS).map((p) => (
                  <label key={p} className="row small" style={{ gap: 4, alignItems: 'center' }}>
                    <input type="checkbox" checked={f.platforms.includes(p)} onChange={(e) => set({ platforms: e.target.checked ? [...f.platforms, p] : f.platforms.filter((x) => x !== p) })} /> {p}
                  </label>
                ))}
              </div>
            </Field>
            <Field label="언제 빌드">
              <span className="small">{f.kind === 'git' && f.git.automatic ? '새 커밋 때 자동 (1분마다 확인) · 수동' : '수동'}</span>
            </Field>
          </fieldset>
          {problems.length > 0 && (
            <span className="small" style={{ color: 'var(--er)' }}>
              {problems[0]}
            </span>
          )}
          {s.run && !s.run.done && (
            <div className="col" style={{ gap: 6 }}>
              {step?.commit ? (
                <div className="inset col small" style={{ gap: 4 }}>
                  <b>{ctxId} 저장 중</b>
                  <span className="row" style={{ gap: 8 }}>
                    <Badge tone="ok">끝남</Badge> 지금 초안 내용으로 고정 (r{rev.current} · 파일 {(files?.length ?? 0) + 1}개 · {fmtBytes(total)})
                  </span>
                  <span className="row" style={{ gap: 8 }}>
                    <Badge tone={s.failed ? 'er' : 'pr'}>{s.failed ? '실패' : '진행 중'}</Badge> {step.label}
                  </span>
                  <span className="muted">
                    고정한 뒤에 고친 내용은 이번 버전에 들어가지 않습니다. 게시는 고정 뒤 24시간 안에 끝나야 하며, 넘기면 다시 저장합니다. 결과가 불명하면 작업 기록에서 결과 조회·재개합니다.
                    {afterSave.current === 'build' ? " '저장하고 빌드'는 게시가 끝난 뒤 빌드를 시작합니다." : ''}
                  </span>
                </div>
              ) : (
                <span className="small">
                  {s.run.at + 1}/{s.run.steps.length} · {s.run.steps[s.run.at].label}
                </span>
              )}
              {s.run.error instanceof ZipPaused ? (
                <span className="small muted">멈췄습니다. ‘이어 올리기’를 누르면 빠진 조각만 보냅니다.</span>
              ) : conflict ? null : s.run.error instanceof ApiError && s.run.error.code === 'upload-refused' ? (
                <span className="small" style={{ color: 'var(--er)' }}>
                  서버가 zip 받기를 거절했습니다(빌드 설정·저장 경로가 바뀌었거나 빌드 입력 예산을 넘음). 빌드 설정을 확인한 뒤 다시 저장하세요.
                </span>
              ) : s.run.error instanceof ApiError && s.run.error.code === 'part-refused' ? (
                <span className="small" style={{ color: 'var(--er)' }}>
                  올린 zip을 빌드 컨텍스트로 쓸 수 없습니다(바깥을 가리키는 경로, Dockerfile 없음, 또는 풀면 빌드 입력 한도보다 큼).
                </span>
              ) : s.run.error instanceof ApiError && s.run.error.code === 'empty-draft' ? (
                <span className="small" style={{ color: 'var(--er)' }}>
                  초안에 파일이 없어 게시할 수 없습니다. Dockerfile을 먼저 넣으세요.
                </span>
              ) : (
                <MutationError error={s.run.error} />
              )}
              {s.run.op && <OpPanel op={s.run.op} onChange={s.onOp} />}
              {s.failed && (
                <span className="small" style={{ color: 'var(--er)' }}>
                  이 단계가 실패했습니다. 앞 단계는 이미 적용됐습니다. 고친 뒤 다시 저장하면 남은 단계부터 새로 보냅니다.
                </span>
              )}
            </div>
          )}
          <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
            {conflict ? (
              <button type="button" className="btn primary" onClick={() => (s.clear(), onSaved())}>
                새로 읽기
              </button>
            ) : s.unsure ? (
              s.run?.error instanceof ZipPaused ? (
                <button type="button" className="btn primary" disabled={s.run?.busy} onClick={s.retry}>
                  이어 올리기
                </button>
              ) : (
                <button type="button" className="btn primary" disabled={s.run?.busy} onClick={s.retry}>
                  같은 작업으로 다시 보내기
                </button>
              )
            ) : s.failed ? (
              <>
                <button type="button" className="btn" onClick={s.clear}>
                  고치기
                </button>
                <button type="button" className="btn primary" onClick={s.retry}>
                  이 단계부터 다시
                </button>
              </>
            ) : (
              <>
                <button type="button" className="btn" disabled={locked || problems.length > 0 || !dirty} onClick={() => save('stay')}>
                  저장
                </button>
                <button type="button"
                  className="btn primary"
                  disabled={locked || problems.length > 0 || (!dirty && !cur?.version) || !pol?.nodes.length}
                  title={pol && !pol.nodes.length ? '빌드 설정에 빌드 서버가 없습니다' : undefined}
                  onClick={() => save('build')}
                >
                  저장하고 빌드
                </button>
              </>
            )}
          </div>
        </Card>
      </div>
      {tpl && (
        <Dialog
          title={`${TEMPLATES[tpl][0]} 템플릿으로 바꿀까요?`}
          width={420}
          onClose={() => setTpl(undefined)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setTpl(undefined)}>
                취소
              </button>
              <button type="button" className="btn primary" onClick={() => (setDocker(TEMPLATES[tpl][1]), setTpl(undefined))}>
                바꾸기
              </button>
            </>
          }
        >
          <span>지금 편집기 내용({(docker ?? '').split('\n').length}줄)을 템플릿으로 바꿉니다. 컨텍스트 파일은 그대로입니다.</span>
        </Dialog>
      )}
      {missingDlg && lint && (
        <Dialog
          title="빌드할 수 없습니다"
          width={420}
          onClose={() => setMissingDlg(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => (setMissingDlg(false), setAfterSave('stay'), s.start(steps(false)))}>
                저장만
              </button>
              <button type="button" className="btn primary" onClick={() => (setMissingDlg(false), fileInput.current?.click())}>
                파일 추가하러 가기
              </button>
            </>
          }
        >
          {lint.missing.map((m) => (
            <span key={`${m.line}${m.src}`}>
              {m.line}번 줄 COPY {m.src} · 컨텍스트에 {m.src}가 없습니다.
            </span>
          ))}
          <span className="small muted">'저장만'은 초안으로 두고 새 버전으로 고정하지 않습니다.</span>
        </Dialog>
      )}
      {moving && (
        <MoveDialog
          file={moving}
          folders={[
            ...new Set(
              (files ?? []).flatMap((x) =>
                x.path
                  .split('/')
                  .slice(0, -1)
                  .map((_, i, a) => a.slice(0, i + 1).join('/')),
              ),
            ),
          ].sort()}
          copyLines={lint?.copyOf[moving.path] ?? []}
          taken={paths}
          onClose={() => setMoving(undefined)}
          onMove={(to) => (setFiles((fs) => (fs ?? []).map((y) => (y === moving ? { ...y, path: to } : y))), setMoving(undefined))}
        />
      )}
      {leave && (
        <Dialog
          title="저장하지 않고 나갈까요?"
          width={420}
          onClose={() => setLeave(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setLeave(false)}>
                계속 편집
              </button>
              {f.kind === 'draft' && (
                <button type="button" className="btn" disabled={problems.length > 0} title={problems[0]} onClick={() => (setLeave(false), save('leave', false))}>
                  초안 두고 나가기
                </button>
              )}
              <button type="button" className="btn danger" onClick={() => navigate('/images/builds')}>
                버리기
              </button>
            </>
          }
        >
          <span>
            {f.kind === 'draft'
              ? `Dockerfile과 고친 파일 ${(files ?? []).filter((x) => x.data).length}개를 아직 버전으로 저장하지 않았습니다. '초안 두고 나가기'는 초안에만 남깁니다. 빌드는 저장한 버전으로만 합니다.`
              : f.kind === 'upload' && zip
                ? `${zip.name}을 아직 올리지 않았습니다.`
                : '바꾼 설정이 저장되지 않았습니다.'}
          </span>
        </Dialog>
      )}
    </>
  );
}

/** 줄 번호가 붙은 편집기. marks의 줄은 번호 칸에 색을 입힌다 */
function LineEditor({
  value,
  onChange,
  readOnly,
  label,
  marks,
}: {
  value: string;
  onChange: (v: string) => void;
  readOnly?: boolean;
  label: string;
  marks?: { line: number; tone: 'ok' | 'wa' | 'er' }[];
}) {
  const gutter = useRef<HTMLDivElement>(null);
  const n = value.split('\n').length;
  const tone = (i: number) => {
    const m = marks?.filter((x) => x.line === i);
    return m?.some((x) => x.tone === 'er') ? 'var(--er)' : m?.some((x) => x.tone === 'wa') ? 'var(--wa)' : undefined;
  };
  return (
    <div className="row" style={{ alignItems: 'stretch', gap: 0, border: '1px solid var(--input)', borderRadius: 6, overflow: 'hidden', fontFamily: 'var(--mono, monospace)', fontSize: 13 }}>
      <div
        ref={gutter}
        aria-hidden
        style={{
          padding: '8px 6px',
          background: 'var(--surface-2)',
          color: 'var(--text-3, #8b949e)',
          textAlign: 'right',
          userSelect: 'none',
          overflow: 'hidden',
          lineHeight: '20px',
          minWidth: 34,
          maxHeight: 420,
        }}
      >
        {Array.from({ length: n }, (_, i) => (
          <div key={i} style={tone(i + 1) ? { color: '#fff', background: tone(i + 1), borderRadius: 3, padding: '0 3px' } : undefined}>
            {i + 1}
          </div>
        ))}
      </div>
      <textarea
        aria-label={label}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
        onScroll={(e) => gutter.current && (gutter.current.scrollTop = e.currentTarget.scrollTop)}
        style={{
          flex: 1,
          border: 0,
          padding: 8,
          lineHeight: '20px',
          fontFamily: 'inherit',
          fontSize: 'inherit',
          resize: 'vertical',
          minHeight: 300,
          maxHeight: 420,
          outline: 'none',
          whiteSpace: 'pre',
          overflow: 'auto',
        }}
        rows={Math.min(20, Math.max(12, n))}
      />
    </div>
  );
}

function FileTree({
  dockerPath,
  files,
  copyOf,
  folder,
  setFolder,
  menu,
  onOpen,
  sending,
}: {
  dockerPath: string;
  files: LFile[];
  copyOf: Record<string, number[]>;
  folder: string;
  setFolder: (f: string) => void;
  menu: (x: LFile) => MenuItem[];
  onOpen: (x: LFile) => void;
  sending?: string;
}) {
  const all = [dockerPath, ...files.map((x) => x.path)].sort();
  const lines = treeLines(all, 1e9);
  // treeLines와 같은 순서로 경로를 다시 만든다
  const flat: string[] = [];
  const walk = (prefix: string) => {
    const kids = [...new Set(all.filter((p) => p.startsWith(prefix)).map((p) => p.slice(prefix.length).split('/')[0]))].sort();
    for (const k of kids) {
      const p = prefix + k;
      flat.push(all.includes(p) ? p : p + '/');
      if (!all.includes(p)) walk(p + '/');
    }
  };
  walk('');
  return (
    <div className="code small" style={{ padding: 8 }}>
      <div className={folder === '' ? 'muted' : ''} style={{ cursor: 'pointer', fontWeight: folder === '' ? 700 : 400 }} onClick={() => setFolder('')}>
        (컨텍스트 루트){folder === '' ? ' ← 고름' : ''}
      </div>
      {lines.map((l, i) => {
        const p = flat[i] ?? '';
        const isDir = p.endsWith('/');
        const x = files.find((y) => y.path === p);
        const at = isDir ? Object.entries(copyOf).find(([q]) => q.startsWith(p))?.[1] : copyOf[p];
        return (
          <div key={i} className="row" style={{ gap: 8, alignItems: 'center', whiteSpace: 'pre' }}>
            <span
              style={{ cursor: isDir || x?.text ? 'pointer' : undefined, fontWeight: isDir && folder === p.slice(0, -1) ? 700 : 400 }}
              onClick={() => (isDir ? setFolder(p.slice(0, -1)) : x?.text && onOpen(x))}
            >
              {l}
            </span>
            {p === dockerPath && <Badge tone="tag">편집기</Badge>}
            {x && <span className="muted">{fmtBytes(x.bytes)}</span>}
            {sending === p ? <Badge tone="pr">올리는 중</Badge> : x?.data && <Badge tone="wa">{x.orig ? '고침' : '새 파일'}</Badge>}
            {x?.executable && <span className="muted">실행</span>}
            {x?.orig && x.orig !== x.path && <Badge tone="wa">옮김</Badge>}
            {at && at.length > 0 && <span className="muted">← {at[0]}번 줄 COPY</span>}
            {isDir && folder === p.slice(0, -1) && <span className="muted">← 고름</span>}
            <span className="grow" />
            {x && <Menu label={`${x.path} 메뉴`} items={menu(x)} />}
          </div>
        );
      })}
    </div>
  );
}

function MoveDialog({ file, folders, copyLines, taken, onClose, onMove }: { file: LFile; folders: string[]; copyLines: number[]; taken: string[]; onClose: () => void; onMove: (to: string) => void }) {
  const name = file.path.split('/').pop()!;
  const [dir, setDir] = useState(file.path.split('/').slice(0, -1).join('/'));
  const [newName, setNewName] = useState(name);
  const to = (dir ? `${dir}/` : '') + newName;
  const bad = !okPath(to) ? '경로가 올바르지 않습니다' : to !== file.path && taken.includes(to) ? '같은 경로에 파일이 있습니다' : undefined;
  return (
    <Dialog
      title={`${name} 옮기기`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={!!bad || to === file.path} onClick={() => onMove(to)}>
            옮기기
          </button>
        </>
      }
    >
      <Field label="폴더">
        <select value={dir} onChange={(e) => setDir(e.target.value)}>
          <option value="">(컨텍스트 루트)</option>
          {folders.map((f) => (
            <option key={f} value={f}>
              {f}/
            </option>
          ))}
        </select>
      </Field>
      <Field label="이름" error={bad}>
        <input className="mono" value={newName} onChange={(e) => setNewName(e.target.value.trim())} />
      </Field>
      {copyLines.length > 0 && <div className="note wa small">{copyLines[0]}번 줄 COPY의 경로와 맞지 않게 됩니다. Dockerfile도 고쳐야 합니다.</div>}
      <span className="small muted">저장할 때 서버에 옮기기로 보냅니다.</span>
    </Dialog>
  );
}

function RefPick({ v, set, secrets }: { v?: { secret: string; key: string }; set: (v: { secret: string; key: string }) => void; secrets: SecretView[] }) {
  const obj = secrets.find((s) => s.id === v?.secret);
  return (
    <>
      <select aria-label="보관함 객체" value={v?.secret ?? ''} onChange={(e) => set({ secret: e.target.value, key: '' })}>
        <option value="">보관함 객체</option>
        {secrets.map((s) => (
          <option key={s.id} value={s.id}>
            {s.path}
          </option>
        ))}
      </select>
      <select aria-label="키" value={v?.key ?? ''} disabled={!obj} onChange={(e) => set({ secret: v?.secret ?? '', key: e.target.value })}>
        <option value="">키</option>
        {(obj?.keys ?? []).map((k) => (
          <option key={k}>{k}</option>
        ))}
      </select>
    </>
  );
}

/** 태그 여러 개: 글자 그대로 · {version} · {commit}(Git만) */
function TagsField({ tags, git, set }: { tags: string[]; git: boolean; set: (t: string[]) => void }) {
  const [adding, setAdding] = useState<string>();
  const okTag = (t: string) => /^[A-Za-z0-9_{}][A-Za-z0-9_.{}-]{0,127}$/.test(t) && t.replace(/\{(version|commit)\}/g, 'x').match(/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/) !== null;
  return (
    <Field label="태그 (여러 개)" hint={`글자 그대로 · {version} 컨텍스트 버전 번호${git ? ' · {commit} 커밋(Git만)' : ''}을 섞어 씀`} group>
      <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        {tags.map((t) => (
          <span key={t} className="chip">
            <span className="mono">{t}</span>
            <button type="button" className="chip-x" aria-label={`${t} 빼기`} onClick={() => set(tags.filter((x) => x !== t))}>
              ✕
            </button>
          </span>
        ))}
        {adding === undefined ? (
          <button type="button" className="btn sm ghost" onClick={() => setAdding('')}>
            ＋ 태그
          </button>
        ) : (
          <>
            <input
              autoFocus
              className="mono"
              aria-label="새 태그"
              style={{ width: 150 }}
              placeholder={git ? 'main-{commit}' : 'v{version}'}
              value={adding}
              onChange={(e) => setAdding(e.target.value.trim())}
              onKeyDown={(e) => {
                if (e.key === 'Escape') setAdding(undefined);
                if (e.key === 'Enter' && okTag(adding) && !tags.includes(adding)) {
                  e.preventDefault();
                  set([...tags, adding]);
                  setAdding(undefined);
                }
              }}
            />
            <button type="button" className="btn sm" disabled={!okTag(adding) || tags.includes(adding)} onClick={() => (set([...tags, adding]), setAdding(undefined))}>
              넣기
            </button>
          </>
        )}
      </div>
    </Field>
  );
}

function ArgsField({ args, set, toSecret }: { args: Arg[]; set: (a: Arg[]) => void; toSecret: (a: Arg) => void }) {
  const upd = (i: number, a: Arg) => set(args.map((x, j) => (j === i ? a : x)));
  const [adding, setAdding] = useState<Arg>();
  const looks = args.filter((a) => SECRETISH.test(a.name));
  return (
    <Field label="빌드 인자" group>
      <div className="col" style={{ gap: 6 }}>
        {args.map((a, i) => (
          <div key={i} className="row" style={{ gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <input className="mono" aria-label="인자 이름" placeholder="APP_VERSION" style={{ width: 130 }} value={a.name} onChange={(e) => upd(i, { ...a, name: e.target.value.trim() })} />
            <input className="mono" aria-label="값" placeholder="값" style={{ flex: 1, minWidth: 100 }} value={a.value} onChange={(e) => upd(i, { ...a, value: e.target.value })} />
            <Menu
              label={`${a.name || '인자'} 메뉴`}
              items={[
                { label: '빌드 비밀값으로 옮기기…', hint: '이 인자는 지우고 비밀 마운트 안내', onSelect: () => toSecret(a) },
                { label: '값 복사', onSelect: () => void navigator.clipboard?.writeText(a.value) },
                { label: '', sep: true },
                { label: '지우기', danger: true, onSelect: () => set(args.filter((_, j) => j !== i)) },
              ]}
            />
          </div>
        ))}
        {adding ? (
          <div className="row" style={{ gap: 6, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <Field label="이름">
              <input autoFocus className="mono" style={{ width: 130 }} placeholder="APP_VERSION" value={adding.name} onChange={(e) => setAdding({ ...adding, name: e.target.value.trim() })} />
            </Field>
            <Field label="값">
              <input className="mono" placeholder="1.4.2" value={adding.value} onChange={(e) => setAdding({ ...adding, value: e.target.value })} />
            </Field>
            <button
              type="button"
              className="btn sm"
              disabled={!/^[A-Za-z_][A-Za-z0-9_]*$/.test(adding.name) || args.some((x) => x.name === adding.name)}
              onClick={() => (set([...args, adding]), setAdding(undefined))}
            >
              넣기
            </button>
            <button type="button" className="btn sm ghost" onClick={() => setAdding(undefined)}>
              취소
            </button>
          </div>
        ) : (
          <button type="button" className="btn sm" style={{ width: 'fit-content' }} onClick={() => setAdding({ name: '', value: '' })}>
            ＋ 인자
          </button>
        )}
        {looks.length > 0 && <div className="note wa small">{looks.map((a) => a.name).join(', ')}는 비밀값처럼 보입니다. 빌드 인자는 공개 값이라 빌드 기록에 그대로 남습니다. ⋯ › 빌드 비밀값으로 옮기기를 쓰세요.</div>}
      </div>
    </Field>
  );
}

function SecretsField({ items, set, secrets }: { items: DBuildSecret[]; set: (s: DBuildSecret[]) => void; secrets: SecretView[] }) {
  const upd = (i: number, s: DBuildSecret) => set(items.map((x, j) => (j === i ? s : x)));
  return (
    <Field label="빌드 비밀값" hint="빌드 인자는 공개 값으로 기록에 남습니다. 비밀은 여기서 고르고 Dockerfile에서 RUN --mount=type=secret으로 받습니다" group>
      <div className="col" style={{ gap: 6 }}>
        {items.map((s, i) => (
          <div key={i} className="row" style={{ gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <input className="mono" aria-label="비밀값 ID" placeholder="composer-token" style={{ width: 130 }} value={s.id} onChange={(e) => upd(i, { ...s, id: e.target.value.trim() })} />
            <RefPick v={s} secrets={secrets} set={(r) => upd(i, { ...s, ...r })} />
            <button type="button" className="btn sm" aria-label="지우기" onClick={() => set(items.filter((_, j) => j !== i))}>
              ×
            </button>
          </div>
        ))}
        <button type="button" className="btn sm" style={{ width: 'fit-content' }} onClick={() => set([...items, { id: '', realm: '', secret: '', key: '' }])}>
          ＋ 비밀값
        </button>
        <span className="small muted">
          Dockerfile에서 <code>RUN --mount=type=secret,id=ID</code>로 받습니다. 값은 보관함에만 있고, 새 값은 비밀값 보관함 화면에서 넣습니다.
        </span>
      </div>
    </Field>
  );
}

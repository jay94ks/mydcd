// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import YAML from 'yaml';
import { ApiError, enc } from '../api/client';
import { appSource, apps as fetchApps, dashboard, standaloneGet, standalonePlan, standaloneTask, tenantLimits } from '../api/endpoints';
import type { OpView, StandalonePlanView, StandaloneView } from '../api/types';
import { useAuth, useTenantRole } from '../auth/session';
import { clearDraft, loadDraft } from '../lib/drafts';
import { changedLines, useUnsaved } from '../components/Unsaved';
import { Badge, Card, OpId, Field, PageHeader, Segmented, type Tone } from '../components/ui';
import { ErrorBand } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { DiffView, YamlEditor } from '../components/Code';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { ContainerConsole } from '../components/ContainerConsole';
import { ImageInput, rememberImage } from '../components/ImageField';
import { useTenantChoices } from './AppForm';
import { usePoll } from '../lib/usePoll';
import { fmtBytes, fmtTime, middle } from '../lib/format';
import {
  GRACE_CHOICES,
  RESTART_LABEL,
  TTL_CHOICES,
  autoName,
  checkStandalone,
  emptyStandalone,
  importAppService,
  standaloneFromYaml,
  standaloneToYaml,
  type ImportParts,
  type ImportedFrom,
  type RestartPolicy,
  type SaPort,
  type SaRoute,
  type SaSecret,
  type SaVolume,
  type StandaloneForm,
} from '../lib/standalone';
import { NoTenant } from './Deploy';
import { ApprovalPrompt } from './VaultApproval';
import { appsLive } from '../lib/liveTopics';

const SECRETISH = /(PASSWORD|SECRET|TOKEN|KEY)/i;

function Chip({ children, onRemove, onClick }: { children: ReactNode; onRemove?: () => void; onClick?: () => void }) {
  return (
    <span className="chip">
      {onClick ? (
        <button type="button" className="linkish mono" onClick={onClick}>
          {children}
        </button>
      ) : (
        <span className="mono">{children}</span>
      )}
      {onRemove && (
        <button type="button" className="chip-x" aria-label="빼기" onClick={onRemove}>
          ✕
        </button>
      )}
    </span>
  );
}

function Hint({ children }: { children: ReactNode }) {
  return <span className="small muted">{children}</span>;
}

/** 작은 입력 다이얼로그 틀: 취소 / 확인 */
function FormDialog({ title, ok, disabled, onOk, onClose, children }: { title: string; ok: string; disabled?: boolean; onOk: () => void; onClose: () => void; children: ReactNode }) {
  return (
    <Dialog
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={disabled}
            onClick={() => {
              onOk();
              onClose();
            }}
          >
            {ok}
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 10 }}>
        {children}
      </div>
    </Dialog>
  );
}

function PortDialog({ onAdd, onClose }: { onAdd: (p: SaPort) => void; onClose: () => void }) {
  const [p, setP] = useState<SaPort>({ port: '', proto: 'tcp', expose: true, host: '', publish: '' });
  const range = /^\d{1,5}(-\d{1,5})?$/;
  const hostBad = p.expose && !!p.host && !/^[\d.]+$|:/.test(p.host);
  const bad = !/^\d{1,5}$/.test(p.port) || (p.expose && !!p.publish && !range.test(p.publish)) || hostBad;
  return (
    <FormDialog title="포트 추가" ok="추가" disabled={bad} onOk={() => onAdd(p.expose ? p : { ...p, host: '', publish: '' })} onClose={onClose}>
      <div className="row">
        <Field label="컨테이너 포트">
          <input className="mono" value={p.port} onChange={(e) => setP({ ...p, port: e.target.value.trim() })} placeholder="8080" />
        </Field>
        <Field label="프로토콜">
          <select value={p.proto} onChange={(e) => setP({ ...p, proto: e.target.value as 'tcp' })}>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
        </Field>
      </div>
      <label className="check">
        <input type="checkbox" checked={p.expose} onChange={(e) => setP({ ...p, expose: e.target.checked })} /> 서버 포트로 바로 공개
        <span className="small muted">끄면 망 안에서만 받습니다.</span>
      </label>
      {p.expose && (
        <>
          <div className="row">
            <Field label="받을 주소" hint="비우면 Docker 기본값(보통 모든 주소)" error={hostBad ? 'IPv4 또는 IPv6 주소' : undefined}>
              <input className="mono" value={p.host} onChange={(e) => setP({ ...p, host: e.target.value.trim().replace(/^\[|\]$/g, '') })} placeholder="127.0.0.1" />
            </Field>
            <Field label="서버 포트" hint="비우면 서버가 고름 · 범위 20000-20010도 됨" error={p.publish && !range.test(p.publish) ? '포트 번호 또는 범위' : undefined}>
              <input className="mono" value={p.publish} onChange={(e) => setP({ ...p, publish: e.target.value.trim() })} placeholder="18080" />
            </Field>
          </div>
          <div className="note info small">컨테이너가 도는 서버의 포트로 바로 받습니다. 외부 접속(도메인·인증서) 수신 주소는 자동으로 만들지 않습니다. 서버가 고른 포트는 다시 시작하면 바뀔 수 있으니, 주소가 늘 같아야 하면 서버 포트를 적으세요.</div>
        </>
      )}
    </FormDialog>
  );
}

function RouteDialog({ onAdd, onClose, temp }: { onAdd: (r: SaRoute) => void; onClose: () => void; temp: boolean }) {
  const [r, setR] = useState<SaRoute>({ host: '', path: '/', port: '', gateway: 'local', cert: 'auto' });
  return (
    <FormDialog title="외부 접속 경로 규칙" ok="추가" disabled={!r.host} onOk={() => onAdd(r)} onClose={onClose}>
      <Field label="호스트 이름">
        <input value={r.host} onChange={(e) => setR({ ...r, host: e.target.value.trim() })} placeholder="report.shop.example" />
      </Field>
      <div className="row">
        <Field label="경로 (앞부분)">
          <input className="mono" value={r.path} onChange={(e) => setR({ ...r, path: e.target.value.trim() })} />
        </Field>
        <Field group label="포트">
          <input className="mono" value={r.port} onChange={(e) => setR({ ...r, port: e.target.value.trim() })} placeholder="8080" />
        </Field>
      </div>
      <div className="row">
        <Field label="게이트웨이">
          <select value={r.gateway} onChange={(e) => setR({ ...r, gateway: e.target.value as SaRoute['gateway'] })}>
            <option value="local">로컬망 (기본)</option>
            <option value="external">외부망</option>
            <option value="both">둘 다</option>
          </select>
        </Field>
        <Field label="인증서">
          <select value={r.cert} onChange={(e) => setR({ ...r, cert: e.target.value as SaRoute['cert'] })}>
            <option value="auto">자동 발급</option>
            <option value="none">쓰지 않음 (HTTP)</option>
          </select>
        </Field>
      </div>
      <Hint>앱 폼의 같은 카드입니다. 같은 호스트·경로를 앱이 쓰고 있으면 실행 전 확인에서 충돌로 막습니다.{temp ? ' 임시는 수명이 다하면 경로도 사라집니다.' : ''}</Hint>
    </FormDialog>
  );
}

function VolumeDialog({ choices, onAdd, onClose }: { choices: ReturnType<typeof useTenantChoices>['volumes']; onAdd: (v: SaVolume) => void; onClose: () => void }) {
  const [v, setV] = useState<SaVolume>({ name: choices[0]?.name ?? '', target: '', readOnly: true });
  const cur = choices.find((x) => x.name === v.name);
  return (
    <FormDialog title="데이터 저장소 붙이기" ok="붙이기" disabled={!v.name || !v.target.startsWith('/')} onOk={() => onAdd(v)} onClose={onClose}>
      <Field label="저장소">
        <select value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })}>
          {choices.map((x) => (
            <option key={x.name} value={x.name}>
              {x.name} (작업 공간{x.node ? ` · ${x.node}` : ''})
            </option>
          ))}
        </select>
      </Field>
      <Field label="마운트 경로">
        <input className="mono" value={v.target} onChange={(e) => setV({ ...v, target: e.target.value.trim() })} placeholder="/data/reports" />
      </Field>
      <label className="check">
        <input type="radio" checked={v.readOnly} onChange={() => setV({ ...v, readOnly: true })} /> 읽기 전용
      </label>
      <label className="check">
        <input type="radio" checked={!v.readOnly} onChange={() => setV({ ...v, readOnly: false })} /> 읽기 · 쓰기 <span className="small muted">이 저장소에 다른 쓰는 쪽이 없을 때만 됩니다</span>
      </label>
      {cur && <Hint>지금 이 저장소를 쓰는 컨테이너 {cur.consumers}개{cur.app ? ` · ${cur.app}` : ''}</Hint>}
    </FormDialog>
  );
}

function SecretDialog({ choices, onAdd, onClose }: { choices: ReturnType<typeof useTenantChoices>['secrets']; onAdd: (s: SaSecret) => void; onClose: () => void }) {
  const [s, setS] = useState<SaSecret>({ name: choices[0]?.path ?? '', target: '', mode: '0400' });
  return (
    <FormDialog title="비밀값 넣기" ok="넣기" disabled={!s.name} onOk={() => onAdd(s)} onClose={onClose}>
      <Field group label="비밀값">
        <select value={s.name} onChange={(e) => setS({ ...s, name: e.target.value })}>
          {choices.map((x) => (
            <option key={x.path} value={x.path}>
              {x.path}
            </option>
          ))}
        </select>
      </Field>
      <Field label="공급 방식">
        <select value="file" onChange={() => undefined}>
          <option value="file">파일로 넣기 (/run/secrets/…)</option>
          <option value="env" disabled>
            환경 변수 값
          </option>
        </select>
      </Field>
      <div className="row">
        <Field label="파일 경로">
          <input className="mono" value={s.target} onChange={(e) => setS({ ...s, target: e.target.value.trim() })} placeholder={`/run/secrets/${s.name || '이름'}`} />
        </Field>
        <Field label="권한">
          <input className="mono" value={s.mode} onChange={(e) => setS({ ...s, mode: e.target.value.trim() })} style={{ width: 80 }} />
        </Field>
      </div>
      <Hint>값은 이 화면에 보이지 않고 작업 기록에도 이름만 남습니다.</Hint>
    </FormDialog>
  );
}

function ImportDialog({ tenant, onFill, onClose }: { tenant: string; onFill: (yaml: string, app: string, service: string, parts: ImportParts) => void; onClose: () => void }) {
  const list = usePoll((s) => fetchApps(tenant, s), [tenant], 0, appsLive(tenant));
  const [app, setApp] = useState('');
  const src = usePoll((s) => (app ? appSource(tenant, app, 0, s) : Promise.resolve(undefined)), [tenant, app]);
  const services = useMemo(() => {
    try {
      return Object.keys(((src.data ? YAML.parse(src.data.yaml) : {}) as { services?: object })?.services ?? {});
    } catch {
      return [];
    }
  }, [src.data]);
  const [svc, setSvc] = useState('');
  const [parts, setParts] = useState<ImportParts>({ imageCmd: true, netEnv: true, volumes: true, secrets: true, ingress: false });
  useEffect(() => {
    if (!app && list.data?.items[0]) setApp(list.data.items[0].app);
  }, [list.data, app]);
  useEffect(() => setSvc((s) => (services.includes(s) ? s : (services[0] ?? ''))), [services]);
  const box = (k: keyof ImportParts, label: string, hint?: string) => (
    <label className="check">
      <input type="checkbox" checked={parts[k]} onChange={(e) => setParts({ ...parts, [k]: e.target.checked })} /> {label}
      {hint && <span className="small muted">{hint}</span>}
    </label>
  );
  return (
    <FormDialog title="앱 서비스 설정 가져오기" ok="폼에 채우기" disabled={!src.data || !svc} onOk={() => src.data && onFill(src.data.yaml, app, svc, parts)} onClose={onClose}>
      <div className="row">
        <Field label="앱">
          <select value={app} onChange={(e) => setApp(e.target.value)}>
            {(list.data?.items ?? []).map((a) => (
              <option key={a.app}>{a.app}</option>
            ))}
          </select>
        </Field>
        <Field label="서비스">
          <select value={svc} onChange={(e) => setSvc(e.target.value)}>
            {services.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
      </div>
      {src.error !== undefined && <ErrorBand error={src.error} what="앱 원문을 읽지 못했습니다" />}
      {box('imageCmd', '이미지 · 명령')}
      {box('netEnv', '망 · 환경 변수 · 작업 디렉터리')}
      {box('volumes', '데이터 저장소', '가져오면 읽기 전용으로 바꿔 넣습니다')}
      {box('secrets', '비밀값', '고른 것만 넣습니다')}
      {box('ingress', '외부 접속 · 포트', '앱과 겹치면 충돌하므로 기본은 뺍니다')}
      <Hint>복사만 합니다. 만든 뒤에는 그 앱과 관계가 없습니다.</Hint>
    </FormDialog>
  );
}

type Run = { phase: 'plan' | 'up' | 'wait' | 'done' | 'failed'; plan?: StandalonePlanView; s?: StandaloneView };

export function StandaloneNewPage() {
  const { tenant, canDeploy } = useTenantRole();
  const me = useAuth().session?.user.username ?? '';
  const navigate = useNavigate();
  const loc = useLocation();
  const carried = loc.state as { yaml?: string; expected?: number; edit?: string; importedFrom?: ImportedFrom } | null;
  const editing = carried?.edit;
  const expected = carried?.expected ?? 0;
  const ch = useTenantChoices(tenant);
  const dash = usePoll((s) => (tenant ? dashboard(tenant, s) : Promise.resolve(undefined)), [tenant]);
  const limits = usePoll((s) => (tenant ? tenantLimits(tenant, s) : Promise.resolve([])), [tenant]);

  // 이 브라우저에 남겨 둔 초안(새로 실행일 때만). 고치기·가져오기로 들어오면 쓰지 않는다.
  const [draft] = useState(() => {
    if (carried?.yaml || !tenant) return undefined;
    // 공통 초안 꼴({value})과 예전 꼴({yaml}) 모두 읽는다
    const d = loadDraft<{ yaml?: string; importedFrom?: ImportedFrom; value?: { yaml: string; importedFrom?: ImportedFrom } }>(me, 'standalone', tenant);
    const v = d?.value ?? d;
    return v?.yaml && d ? { yaml: v.yaml, importedFrom: v.importedFrom, at: d.at } : undefined;
  });
  const initial = useMemo(() => {
    const src = carried?.yaml ?? draft?.yaml;
    if (src) {
      const r = standaloneFromYaml(src);
      if ('form' in r) return { ...r.form, importedFrom: carried?.importedFrom ?? draft?.importedFrom };
    }
    return emptyStandalone();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [mode, setMode] = useState<'form' | 'yaml'>(() => (draft && 'error' in standaloneFromYaml(draft.yaml) ? 'yaml' : 'form'));
  const [form, setForm] = useState<StandaloneForm>(initial);
  const [text, setText] = useState(() => carried?.yaml ?? draft?.yaml ?? standaloneToYaml(initial));
  const [draftNote, setDraftNote] = useState(!!draft);
  const [lostWarn, setLostWarn] = useState<string[]>();
  const [dlg, setDlg] = useState<'port' | 'route' | 'volume' | 'secret' | 'import' | 'review' | 'alias'>();
  const [aliasOf, setAliasOf] = useState<number>();
  const [autoNm] = useState(autoName);
  const set = (patch: Partial<StandaloneForm>) => setForm((f) => ({ ...f, ...patch }));

  // 이름을 비운 임시는 temp-xxxx
  const effective = useMemo(() => ({ ...form, name: form.name || (form.lifetime === 'temp' ? autoNm : '') }), [form, autoNm]);
  const yaml = mode === 'form' ? standaloneToYaml(effective, carried?.yaml) : text;
  const problems = mode === 'form' ? checkStandalone(effective) : [];
  const parsedYaml = useMemo(() => (mode === 'yaml' ? standaloneFromYaml(text) : undefined), [mode, text]);
  const yamlError = parsedYaml && 'error' in parsedYaml ? parsedYaml : undefined;

  // 나가기 확인: 처음 연 때와 정의가 달라졌고 아직 실행하지 않았으면 막는다.
  const baseline = useRef<string>();
  if (baseline.current === undefined) baseline.current = yaml;

  // 실행 전 확인: 고칠 때마다 계획(standalone-plan)을 새로 받는다(바꾸는 것 없음).
  const [plan, setPlan] = useState<StandalonePlanView>();
  const [planFor, setPlanFor] = useState<string>();
  const [planErr, setPlanErr] = useState<unknown>();
  // 계획에서 sfcd가 고정 서버 포트 겹침을 거절하면 포트 칸에 붙인다
  const portConflict = planErr instanceof ApiError && /host[-_]port[-_]conflict/i.test(`${planErr.code} ${planErr.body.message ?? ''}`);
  useEffect(() => {
    if (!tenant || problems.length || yamlError) return;
    const t = setTimeout(() => {
      standalonePlan(tenant, yaml)
        .then((p) => (setPlan(p), setPlanFor(yaml), setPlanErr(undefined)))
        .catch((e) => (setPlanErr(e), setPlan(undefined)));
    }, 500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenant, yaml, problems.length, !!yamlError]);
  const fresh = plan && planFor === yaml;
  const blocks = fresh ? plan.impact.filter((i) => i.level === 'block') : [];

  const m = useMutation();
  const [run, setRun] = useState<Run>();
  const [console_, setConsole] = useState<StandaloneView>();
  const dirty = yaml !== baseline.current && !run;
  const un = useUnsaved({ dirty, what: editing ? `${editing} 단독 컨테이너 고치기` : '단독 컨테이너 만들기', count: changedLines(baseline.current ?? '', yaml), unit: '줄', draft: editing || !tenant ? undefined : { kind: 'standalone', scope: tenant, value: { yaml, importedFrom: form.importedFrom } } });
  const name = mode === 'form' ? effective.name : ((parsedYaml && 'form' in parsedYaml && parsedYaml.form.name) || '');
  const shellNow = mode === 'form' ? form.mode === 'shell' && form.openTerminal : false;
  const waitTimer = useRef<number>();
  useEffect(() => () => window.clearTimeout(waitTimer.current), []);

  const up = async () => {
    setRun({ phase: 'up', plan });
    if (mode === 'form') rememberImage(form.image, editing ? `단독 컨테이너 ${name}` : undefined);
    const op = await m.run(`/t/${enc(tenant)}/standalone/up`, { yaml, expected, importedFrom: form.importedFrom });
    // up은 배포처럼 여러 단계 작업이다. 보호된 묶음이 있으면 running·approval-required로 멈춘다(아래 승인 칸).
    if (op && ['pending', 'running', 'unknown'].includes(op.state)) return;
    if (!op || op.state !== 'applied') return setRun({ phase: 'failed', plan });
    afterUp();
  };
  const afterUp = () => {
    if (!editing) clearDraft(me, 'standalone', tenant);
    setRun({ phase: 'wait', plan });
    const poll = async (n: number) => {
      const s = await standaloneGet(tenant, name).catch(() => undefined);
      if (s && (s.state === 'running' || s.state === 'exited' || s.state === 'removed')) {
        setRun({ phase: 'done', plan, s });
        if (s.state === 'running' && shellNow) setConsole(s);
        return;
      }
      if (n < 30) waitTimer.current = window.setTimeout(() => void poll(n + 1), 1000);
    };
    void poll(0);
  };
  // 승인·진행 뒤 작업이 적용되면 컨테이너가 뜨기를 기다린다
  const onUpOp = (o: OpView) => {
    m.setOp(o);
    if (o.action === 'standalone-up' && o.state === 'applied' && run?.phase === 'up') afterUp();
    else if (o.action === 'standalone-up' && (o.state === 'failed' || o.state === 'rejected') && run?.phase === 'up') setRun({ phase: 'failed', plan: run.plan });
  };
  const start = () => {
    if (!fresh || blocks.length) return;
    if (editing && plan.changes.length) setDlg('review');
    else void up();
  };

  const switchMode = (next: 'form' | 'yaml') => {
    if (next === mode) return;
    if (next === 'yaml') {
      setText(standaloneToYaml(effective, carried?.yaml));
      setMode('yaml');
      return;
    }
    const r = standaloneFromYaml(text);
    if ('error' in r) return; // 문법이 틀리면 폼으로 갈 수 없다
    if (r.lost.length && !lostWarn) return setLostWarn(r.lost);
    setForm(r.form);
    setLostWarn(undefined);
    setMode('form');
  };

  if (!tenant) return <NoTenant />;
  const nodes = dash.data?.nodes ?? [];
  const nodeLimit = limits.data?.find((l) => l.node === (effective.node || nodes[0]?.id));
  const lim = fresh ? plan.limits : undefined;
  const STEP: Record<'ok' | 'pr' | 'wait' | 'er', [Tone, string]> = { ok: ['ok', '✓'], pr: ['pr', '…'], wait: ['un', '○'], er: ['er', '✕'] };
  const step = (st: keyof typeof STEP, label: string, sub?: ReactNode) => (
    <li className="row" style={{ gap: 8 }}>
      <Badge tone={STEP[st][0]}>{STEP[st][1]}</Badge>
      <span>{label}</span>
      {sub && <span className="small muted">{sub}</span>}
    </li>
  );

  return (
    <>
      <div className="small muted">
        <Link to="/standalone">단독 컨테이너</Link> / {editing ? `${editing} 정의 고치기` : '새로 실행'}
      </div>
      <PageHeader
        title={editing ? `${editing} 정의 고치기` : '단독 컨테이너 새로 실행'}
        ids="UI-3F"
        actions={
          <>
            <Segmented
              label="작성 방식"
              value={mode}
              onChange={switchMode}
              options={[
                ['form', '폼'],
                ['yaml', 'YAML'],
              ]}
            />
            <button className="btn" onClick={() => setDlg('import')}>
              앱 서비스 설정 가져오기…
            </button>
          </>
        }
      />
      {!canDeploy && <div className="note wa small">이 작업 공간에서는 읽기 권한만 있어 미리보기까지만 됩니다(배포 권한 필요).</div>}
      {editing && <div className="note un small">정의를 바꾸면 컨테이너를 다시 만들기 때문에 쓰기 계층에 남긴 파일은 사라집니다(이름·서버는 그대로). 남겨야 할 데이터는 데이터 저장소에 두세요.</div>}
      {draftNote && draft && (
        <div className="note un small row between">
          <span>이 브라우저에 남겨 둔 초안({fmtTime(draft.at)})을 불러왔습니다.</span>
          <button
            className="btn sm"
            onClick={() => {
              clearDraft(me, 'standalone', tenant);
              const f = emptyStandalone();
              setForm(f);
              setText(standaloneToYaml(f));
              setMode('form');
              setDraftNote(false);
              baseline.current = undefined;
            }}
          >
            새로 쓰기
          </button>
        </div>
      )}
      {form.importedFrom && mode === 'form' && <div className="note un small">{form.importedFrom.app} / {form.importedFrom.service}의 설정을 복사해 채웠습니다. 앱과 연결되지 않습니다.</div>}
      {lostWarn && (
        <div className="note wa small row between">
          <span>폼에 없는 칸({lostWarn.join(', ')})은 폼으로 바꾸면 빠집니다. YAML로만 고칠 수 있습니다.</span>
          <span className="row">
            <button className="btn sm" onClick={() => setLostWarn(undefined)}>
              YAML에 남기
            </button>
            <button
              className="btn sm"
              onClick={() => {
                const r = standaloneFromYaml(text);
                if ('form' in r) setForm(r.form);
                setLostWarn(undefined);
                setMode('form');
              }}
            >
              빼고 폼으로
            </button>
          </span>
        </div>
      )}
      <div className="main-side">
        <div className="primary col" style={{ gap: 16 }}>
          {mode === 'yaml' ? (
            <>
              <YamlEditor value={text} onChange={setText} name="standalone.yaml" />
              {yamlError && (
                <div className="note er small">
                  {yamlError.line ? `${yamlError.line}번째 줄: ` : ''}
                  {yamlError.error} 문법이 맞아야 폼으로 돌아갈 수 있습니다.
                </div>
              )}
            </>
          ) : (
            <>
              <Card title="이름과 수명">
                <div className="g2">
                  <Field label="이름" hint={form.lifetime === 'temp' ? `비워 두면 ${autoNm}로 붙습니다. 작업 공간 안에서 유일, 망 안 DNS 이름으로도 쓰입니다` : '작업 공간 안에서 유일. 망 안 DNS 이름으로도 쓰입니다'}>
                    <input className="mono" value={form.name} readOnly={!!editing} onChange={(e) => set({ name: e.target.value.trim() })} placeholder={form.lifetime === 'temp' ? autoNm : 'report-cron'} />
                  </Field>
                  <Field group label="수명" hint="임시는 끝나면 지워지고, 고정은 지울 때까지 남습니다. 임시는 나중에 고정으로 바꿀 수 있습니다">
                    <Segmented
                      label="수명"
                      value={form.lifetime}
                      onChange={(lifetime) => !editing && set({ lifetime })}
                      options={[
                        ['fixed', '고정'],
                        ['temp', '임시'],
                      ]}
                    />
                  </Field>
                </div>
                <div className="g2">
                  <Field label="재시작 정책 (고정)">
                    <select value={form.restart} disabled={form.lifetime !== 'fixed'} onChange={(e) => set({ restart: e.target.value as RestartPolicy })}>
                      {(['on-failure', 'always', 'no'] as const).map((r) => (
                        <option key={r} value={r}>
                          {RESTART_LABEL[r]}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field group label="수명 · 유예 (임시)" hint={form.lifetime === 'fixed' ? '고정을 고르면 쓰지 않습니다' : '수명은 최대 24시간. 쉘은 연결이 끊긴 뒤 유예 안에 다시 붙지 않으면 지웁니다'}>
                    <span className="row" style={{ flexWrap: 'nowrap' }}>
                      <select aria-label="수명" value={form.ttl} disabled={form.lifetime !== 'temp'} onChange={(e) => set({ ttl: e.target.value })}>
                        {TTL_CHOICES.map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                      <select aria-label="끊긴 뒤 유예" value={form.grace} disabled={form.lifetime !== 'temp'} onChange={(e) => set({ grace: e.target.value })}>
                        {GRACE_CHOICES.map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </span>
                  </Field>
                </div>
              </Card>

              <Card title="실행">
                <Field group label="이미지" hint="이미지 고르기 다이얼로그에서 이미지 관리 목록에서 고르거나 직접 입력합니다. 신뢰 정책은 그대로 적용됩니다">
                  <ImageInput tenant={tenant} value={form.image} onChange={(image) => set({ image })} />
                </Field>
                <div className="g2">
                  <Field label="서버" hint={form.lifetime === 'fixed' ? '고정은 이 서버에 묶이고 다른 서버로 옮기지 않습니다' : undefined}>
                    <select value={form.node} onChange={(e) => set({ node: e.target.value })}>
                      <option value="">서버가 고름 (가장 여유 있는 서버)</option>
                      {nodes.map((n) => (
                        <option key={n.id} value={n.id}>
                          {n.id}
                          {n.cpuPercent !== undefined ? ` · CPU ${Math.round(n.cpuPercent)}%` : ''}
                          {n.memory ? ` · 메모리 ${Math.round((n.memory.used / n.memory.total) * 100)}%` : ''}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>
                <div className="g2">
                  <Field group label="방식" hint="엔트리포인트: 이미지 ENTRYPOINT/CMD 그대로. 쉘: 터미널로 붙어 명령 실행">
                    <Segmented
                      label="방식"
                      value={form.mode}
                      onChange={(m2) => set({ mode: m2, command: m2 === 'shell' && !form.command ? '/bin/sh' : m2 === 'entrypoint' && form.command === '/bin/sh' ? '' : form.command })}
                      options={[
                        ['entrypoint', '엔트리포인트'],
                        ['shell', '쉘'],
                      ]}
                    />
                  </Field>
                  {form.mode === 'shell' ? (
                    <Field label="명령" hint="쉘은 TTY와 stdin을 켭니다. 이미지에 /bin/sh가 없으면 실행 전 확인에서 경고합니다">
                      <input className="mono" value={form.command} onChange={(e) => set({ command: e.target.value })} placeholder="/bin/sh" />
                    </Field>
                  ) : (
                    <Field label="인자 (비우면 이미지 CMD)">
                      <input className="mono" value={form.command} onChange={(e) => set({ command: e.target.value })} placeholder="/app/report --every 1h" />
                    </Field>
                  )}
                </div>
                {form.mode === 'shell' ? (
                  <label className="check small">
                    <input type="checkbox" checked={form.openTerminal} onChange={(e) => set({ openTerminal: e.target.checked })} /> 실행하면 터미널 바로 열기
                  </label>
                ) : (
                  <label className="check small">
                    <input type="checkbox" checked={form.tty} onChange={(e) => set({ tty: e.target.checked })} /> TTY 붙이기 (터미널로 붙을 수 있게)
                  </label>
                )}
                <div className="g2">
                  <div className="col" style={{ gap: 6 }}>
                    <b className="small">환경 변수</b>
                    {form.env.map((r, i) => (
                      <div key={i} className="row" style={{ flexWrap: 'nowrap' }}>
                        <input className="mono" aria-label="키" placeholder="KEY" value={r.key} onChange={(e) => set({ env: form.env.map((x, j) => (j === i ? { ...x, key: e.target.value.trim() } : x)) })} style={{ width: 140 }} />
                        <input className="mono grow" aria-label="값" placeholder="value" type={SECRETISH.test(r.key) ? 'password' : 'text'} value={r.value} onChange={(e) => set({ env: form.env.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
                        <Menu
                          label={`${r.key || '변수'} 메뉴`}
                          items={[
                            { label: '값 바꾸기…', onSelect: () => (document.querySelectorAll<HTMLInputElement>('input[aria-label="값"]')[i]?.focus()) },
                            { label: '비밀 값 마킹', hint: 'AI로 보낼 때 가림', disabledReason: '꺼짐 · AI 기능(W2)과 함께 켜짐' },
                            { label: '키 이름 복사', onSelect: () => void navigator.clipboard?.writeText(r.key) },
                            { label: '제거하기', danger: true, onSelect: () => set({ env: form.env.filter((_, j) => j !== i) }) },
                          ]}
                        />
                      </div>
                    ))}
                    <button type="button" className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => set({ env: [...form.env, { key: '', value: '' }] })}>
                      ＋ 변수
                    </button>
                    <Hint>앱 편집 폼과 같은 행 편집입니다. 비밀번호 같은 값은 비밀값 보관함으로 옮기세요.</Hint>
                  </div>
                  <div className="g2" style={{ alignContent: 'start' }}>
                    <Field label="작업 디렉터리">
                      <input className="mono" value={form.workdir} onChange={(e) => set({ workdir: e.target.value.trim() })} placeholder="/app" />
                    </Field>
                    <Field label="사용자">
                      <input className="mono" value={form.user} onChange={(e) => set({ user: e.target.value.trim() })} placeholder="이미지 기본값" />
                    </Field>
                  </div>
                </div>
              </Card>

              <Card title="망 · 포트 · 외부 접속">
                <div className="g2">
                  <Field group label="망" hint="작업 공간이 쓸 수 있는 망을 이름으로 빌려 씁니다. 망을 누르면 별칭(기본 = 이름)을 바꿉니다">
                    <span className="row" style={{ gap: 6 }}>
                      {form.networks.map((n, i) => (
                        <Chip key={n.name} onClick={() => (setAliasOf(i), setDlg('alias'))} onRemove={() => set({ networks: form.networks.filter((_, j) => j !== i) })}>
                          {n.name}
                          {n.alias ? ` · ${n.alias}` : ''}
                        </Chip>
                      ))}
                      <Menu
                        label="망 더하기"
                        align="left"
                        button="＋ 망"
                        items={ch.networks.map((n) => ({
                          label: n.name,
                          hint: form.networks.some((x) => x.name === n.name) ? '이미 넣음' : n.cidr,
                          disabledReason: form.networks.some((x) => x.name === n.name) ? '이미 넣음' : undefined,
                          onSelect: () => set({ networks: [...form.networks, { name: n.name, alias: '' }] }),
                        }))}
                      />
                    </span>
                  </Field>
                  <Field group label="포트" error={portConflict ? '이 서버에서 이미 쓰는 포트입니다(HOST_PORT_CONFLICT). 다른 포트를 적거나 비워서 서버가 고르게 하세요.' : undefined}>
                    <span className="row" style={{ gap: 6 }}>
                      {form.ports.map((p, i) => (
                        <Chip key={i} onRemove={() => set({ ports: form.ports.filter((_, j) => j !== i) })}>
                          {p.expose ? `${p.host ? `${p.host.includes(':') ? `[${p.host}]` : p.host}:` : ''}${p.publish || '서버가 고름'}→` : ''}
                          {p.port}/{p.proto}
                        </Chip>
                      ))}
                      <button type="button" className="btn sm" onClick={() => setDlg('port')}>
                        ＋ 포트
                      </button>
                    </span>
                  </Field>
                </div>
                <Field group label="외부 접속 · 경로 규칙">
                  <span className="row" style={{ gap: 6 }}>
                    {form.routes.map((r, i) => (
                      <Chip key={i} onRemove={() => set({ routes: form.routes.filter((_, j) => j !== i) })}>
                        {r.host}
                        {r.path} → :{r.port || '?'} · {r.gateway === 'local' ? '로컬망' : r.gateway === 'external' ? '외부망' : '둘 다'}
                      </Chip>
                    ))}
                    {!form.routes.length && <span className="muted small">없음 ·</span>}
                    <button type="button" className="linkish small" onClick={() => setDlg('route')}>
                      ＋ 경로 규칙
                    </button>
                  </span>
                </Field>
                {form.lifetime === 'temp' && form.routes.length > 0 && <Hint>임시는 수명이 다하면 경로도 사라집니다.</Hint>}
              </Card>

              <Card title="데이터 저장소 · 비밀값">
                <div className="g2">
                  <Field group label="데이터 저장소" hint="쓰기는 그 저장소의 쓰는 쪽 규칙을 통과해야 합니다">
                    <span className="row" style={{ gap: 6 }}>
                      {form.volumes.map((v, i) => (
                        <Chip key={i} onRemove={() => set({ volumes: form.volumes.filter((_, j) => j !== i) })}>
                          {v.name} → {v.target} · {v.readOnly ? '읽기 전용' : '읽기·쓰기'}
                        </Chip>
                      ))}
                      <button type="button" className="btn sm" disabled={!ch.volumes.length} onClick={() => setDlg('volume')}>
                        ＋ 데이터 저장소
                      </button>
                    </span>
                  </Field>
                  <Field group label="비밀값" hint="앱과 같은 공급 방식">
                    <span className="row" style={{ gap: 6 }}>
                      {form.secrets.map((s, i) => (
                        <Chip key={i} onRemove={() => set({ secrets: form.secrets.filter((_, j) => j !== i) })}>
                          {s.name} → {s.target || `/run/secrets/${s.name}`}
                        </Chip>
                      ))}
                      <button type="button" className="btn sm" disabled={!ch.secrets.length} onClick={() => setDlg('secret')}>
                        ＋ 비밀값
                      </button>
                    </span>
                  </Field>
                </div>
              </Card>

              <Card title="상태 검사 · 로그 · 자원">
                <div className="g2">
                  <Field label="상태 검사">
                    <select value={form.health} onChange={(e) => set({ health: e.target.value as StandaloneForm['health'] })}>
                      <option value="none">없음</option>
                      <option value="cmd">명령으로 검사…</option>
                      <option value="http">HTTP로 검사…</option>
                      <option value="rule" disabled>
                        상태 검사 규칙 고르기…
                      </option>
                    </select>
                  </Field>
                  <Field label="로그 · 방식">
                    <select value={form.logDriver} onChange={(e) => set({ logDriver: e.target.value as StandaloneForm['logDriver'] })}>
                      <option value="">서버 기본 그대로</option>
                      <option value="local">
                        local · {form.logMaxSize || '10m'} × {form.logMaxFile || '3'}
                      </option>
                      <option value="json-file">json-file</option>
                    </select>
                  </Field>
                </div>
                {form.health !== 'none' && (
                  <div className="g2">
                    {form.health === 'cmd' ? (
                      <Field label="검사 명령">
                        <input className="mono" value={form.healthCmd} onChange={(e) => set({ healthCmd: e.target.value })} placeholder="/app/report --ping" />
                      </Field>
                    ) : (
                      <Field label="검사 주소" hint="컨테이너 안에서 엽니다">
                        <input className="mono" value={form.healthUrl} onChange={(e) => set({ healthUrl: e.target.value.trim() })} placeholder="http://127.0.0.1:8080/health" />
                      </Field>
                    )}
                    <Field label="간격">
                      <input className="mono" value={form.healthInterval} onChange={(e) => set({ healthInterval: e.target.value.trim() })} />
                    </Field>
                  </div>
                )}
                {form.logDriver && (
                  <div className="g2">
                    <Field label="max-size">
                      <input value={form.logMaxSize} onChange={(e) => set({ logMaxSize: e.target.value.trim() })} />
                    </Field>
                    <Field label="max-file">
                      <input value={form.logMaxFile} onChange={(e) => set({ logMaxFile: e.target.value.trim() })} />
                    </Field>
                  </div>
                )}
                <div className="g2">
                  <Field label="CPU 상한">
                    <input className="mono" value={form.cpus} onChange={(e) => set({ cpus: e.target.value.trim() })} placeholder="0.5" />
                  </Field>
                  <Field label="메모리 상한" hint="작업 공간 한도 안에서만">
                    <input value={form.memory} onChange={(e) => set({ memory: e.target.value })} placeholder="256 MiB" />
                  </Field>
                </div>
              </Card>
            </>
          )}
        </div>

        <div className="aside col" style={{ gap: 16 }}>
          <Card title="미리보기 (YAML)">
            <pre className="preview-yaml">
              <span className="d"># 단독 컨테이너 = app.yaml 서비스 하나와 같은 필드</span>
              {'\n' + yaml}
            </pre>
            <Hint>app.yaml 서비스 하나와 같은 필드입니다. depends_on·서비스 간 참조는 없습니다.</Hint>
          </Card>
          <Card title="실행 전 확인">
            {problems.length > 0 && (
              <ul className="note wa small" style={{ margin: 0, paddingLeft: 24 }}>
                {problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
            <div className="kv2">
              <span className="muted">작업 ID</span>
              <span>
                <OpId id={m.opId} />
              </span>
              <span className="muted">영향</span>
              <span>
                {!fresh ? (
                  <span className="muted">{problems.length || yamlError ? '칸을 채우면 계산합니다' : '계산 중…'}</span>
                ) : plan.impact.length === 0 ? (
                  '없음'
                ) : (
                  plan.impact.map((i, k) => (
                    <span key={k} style={{ display: 'block', color: i.level === 'block' ? 'var(--er)' : undefined }}>
                      {i.level === 'block' ? '✕ ' : ''}
                      {i.text}
                    </span>
                  ))
                )}
              </span>
              <span className="muted">자원 한도</span>
              <span>
                {lim ? `내 임시 ${lim.mine} / ${lim.mineMax} · 작업 공간 단독 ${lim.tenant} / ${lim.tenantMax}${lim.nodeMax ? ` · 이 서버 단독 ${lim.node ?? 0} / ${lim.nodeMax}` : ''}` : '—'}
                {nodeLimit ? ` · ${nodeLimit.node} 작업 공간 상한 CPU ${nodeLimit.cpus} · 메모리 ${fmtBytes(nodeLimit.memoryBytes)}` : ''}
              </span>
              {fresh && editing && (
                <>
                  <span className="muted">바뀌는 것</span>
                  <span>{plan.changes.length ? `${plan.changes.map((c) => c.field).join(', ')} (rev ${plan.revision} → ${plan.revision + 1}, 다시 만듦)` : '바뀐 칸이 없습니다'}</span>
                </>
              )}
            </div>
            {planErr !== undefined && <ErrorBand error={planErr} what="정의를 검사하지 못했습니다" />}
            <button className="btn primary" style={{ width: '100%' }} disabled={!canDeploy || !fresh || blocks.length > 0 || m.busy || (editing ? !plan?.changes.length : false) || (!!run && run.phase !== 'failed')} title={canDeploy ? undefined : '배포 권한 필요'} onClick={start}>
              변경 검토 후 실행 (standalone-plan)
            </button>
            {run && (
              <div className="col" style={{ gap: 6 }}>
                <b className="small">{name} 실행</b>
                <ul className="col" style={{ listStyle: 'none', margin: 0, padding: 0, gap: 4 }}>
                  {step('ok', '정의 검사', 'app.yaml 서비스 규칙')}
                  {step(run.plan?.impact.some((i) => i.kind === 'image' && i.level === 'block') ? 'er' : 'ok', '이미지 신뢰', run.plan?.impact.length === 0 || effective.image.includes('@') ? middle(effective.image.split('@')[1] ?? effective.image, 11, 4) : undefined)}
                  {step(run.phase === 'up' ? 'pr' : run.phase === 'failed' ? 'er' : 'ok', `만들기 ${run.s?.node ?? (effective.node || '서버가 고름')}`)}
                  {step(run.phase === 'done' ? (run.s?.state === 'running' ? 'ok' : 'er') : run.phase === 'wait' ? 'pr' : 'wait', form.health !== 'none' ? '상태 검사 통과 기다리기' : '뜨기를 기다리기')}
                </ul>
                {run.phase === 'done' && run.s?.state === 'running' && (
                  <div className="note ok small row between">
                    <span>
                      ✓ {name}을(를) {run.s.lifetime === 'fixed' ? '고정' : '임시'}으로 띄웠습니다.{form.health !== 'none' ? ' 상태 검사 통과.' : ''}
                    </span>
                    <span className="row">
                      {run.s.mode === 'shell' && (
                        <button className="btn sm" onClick={() => setConsole(run.s)}>
                          터미널 열기
                        </button>
                      )}
                      <button className="btn sm" onClick={() => navigate('/standalone')}>
                        목록으로
                      </button>
                    </span>
                  </div>
                )}
                {run.phase === 'done' && run.s && run.s.state !== 'running' && <div className="note wa small">컨테이너가 바로 끝났습니다(종료 코드 {run.s.exitCode ?? '?'}). 로그를 확인하세요.</div>}
              </div>
            )}
            {m.op && m.op.state !== 'applied' && (
              <>
                {casFailed(m.op) && <div className="note wa small">다른 사람이 먼저 정의를 바꿨습니다. 다시 읽은 뒤 검토하세요.</div>}
                <OpPanel op={m.op} onChange={onUpOp} />
                <ApprovalPrompt tenant={tenant} op={m.op} onOp={onUpOp} kind="standalone" />
              </>
            )}
            {blocks.length > 0 && (
              <div className="note er small">
                <b>실행 거부</b>
                {blocks.map((b, i) => (
                  <div key={i}>{b.text}</div>
                ))}
              </div>
            )}
            <MutationError error={m.error} />
          </Card>
        </div>
      </div>

      {dlg === 'port' && <PortDialog onAdd={(p) => set({ ports: [...form.ports, p] })} onClose={() => setDlg(undefined)} />}
      {dlg === 'route' && <RouteDialog temp={form.lifetime === 'temp'} onAdd={(r) => set({ routes: [...form.routes, r] })} onClose={() => setDlg(undefined)} />}
      {dlg === 'volume' && <VolumeDialog choices={ch.volumes} onAdd={(v) => set({ volumes: [...form.volumes, v] })} onClose={() => setDlg(undefined)} />}
      {dlg === 'secret' && <SecretDialog choices={ch.secrets} onAdd={(s) => set({ secrets: [...form.secrets, s] })} onClose={() => setDlg(undefined)} />}
      {dlg === 'alias' && aliasOf !== undefined && form.networks[aliasOf] && <AliasDialog net={form.networks[aliasOf].name} value={form.networks[aliasOf].alias} fallback={effective.name} onSave={(alias) => set({ networks: form.networks.map((n, j) => (j === aliasOf ? { ...n, alias } : n)) })} onClose={() => setDlg(undefined)} />}
      {dlg === 'import' && (
        <ImportDialog
          tenant={tenant}
          onClose={() => setDlg(undefined)}
          onFill={(src, app, svc, parts) => {
            const next = importAppService(form, src, app, svc, parts);
            setForm(next);
            if (mode === 'yaml') setText(standaloneToYaml({ ...next, name: next.name || (next.lifetime === 'temp' ? autoNm : '') }));
          }}
        />
      )}
      {dlg === 'review' && fresh && (
        <Dialog
          title={`${name} 변경 · rev ${plan.revision} → ${plan.revision + 1}`}
          width={720}
          onClose={() => setDlg(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setDlg(undefined)}>
                취소
              </button>
              <button className="btn primary" onClick={() => (setDlg(undefined), void up())}>
                적용 (standalone-up)
              </button>
            </>
          }
        >
          <DiffView lines={plan.diff} />
          <div className="note wa small" style={{ marginTop: 8 }}>
            컨테이너를 다시 만듭니다. 쓰기 계층의 파일은 사라집니다(데이터 저장소는 그대로).
          </div>
        </Dialog>
      )}
      {un.guard}
      {console_ && <ContainerConsole task={standaloneTask(console_)} canExec={canDeploy} initial="exec" onClose={() => setConsole(undefined)} />}
    </>
  );
}

function AliasDialog({ net, value, fallback, onSave, onClose }: { net: string; value: string; fallback: string; onSave: (a: string) => void; onClose: () => void }) {
  const [a, setA] = useState(value);
  return (
    <FormDialog title={`망 ${net}의 별칭`} ok="바꾸기" onOk={() => onSave(a)} onClose={onClose}>
      <Field label="별칭" hint={`비우면 이름(${fallback || '컨테이너 이름'})을 씁니다`}>
        <input className="mono" value={a} onChange={(e) => setA(e.target.value.trim())} placeholder={fallback} />
      </Field>
    </FormDialog>
  );
}


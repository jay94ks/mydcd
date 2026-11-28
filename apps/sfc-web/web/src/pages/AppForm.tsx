// SPDX-License-Identifier: Apache-2.0

import { useMemo } from 'react';
import YAML from 'yaml';
import { networks, vault, volumes } from '../api/endpoints';
import { Card, Field } from '../components/ui';
import { ImageInput } from '../components/ImageField';
import { portText } from '../lib/ports';
import { PortsField } from '../components/PortsField';
import { usePoll } from '../lib/usePoll';
import { networksLive, volumesLive } from '../lib/liveTopics';

export interface EnvRow {
  key: string;
  value: string;
}
export interface ServiceForm {
  name: string;
  image: string;
  node: string;
  replicas: number;
  command: string;
  ports: string; // "8080:80, 8443:443"
  env: EnvRow[];
  networks: { name: string; alias: string }[];
  volumes: { name: string; target: string; readOnly: boolean }[];
  secrets: { name: string; mode: 'file' | 'file+env'; envName: string }[];
  logDriver: '' | 'local' | 'json-file';
  logMaxSize: string;
  logMaxFile: string;
}
export interface AppFormState {
  name: string;
  services: ServiceForm[];
  /** x-sfc.ingress route 목록. node는 이 경로를 여는 서버 */
  routes: { node: string; host: string; path: string; service: string; port: string; gateway: 'local' | 'external' }[];
}

export const emptyService = (i: number): ServiceForm => ({
  name: i === 0 ? 'web' : `svc${i + 1}`,
  image: '',
  node: '',
  replicas: 1,
  command: '',
  ports: '',
  env: [],
  networks: [],
  volumes: [],
  secrets: [],
  logDriver: '',
  logMaxSize: '',
  logMaxFile: '',
});

export const emptyForm = (): AppFormState => ({ name: '', services: [emptyService(0)], routes: [] });

const SECRETISH = /(PASSWORD|SECRET|TOKEN|KEY)/i;

/** 서비스 폼 하나 → app.yaml 서비스 객체. 단독 컨테이너 정의도 같은 모양을 쓴다. */
export function serviceToObject(s: ServiceForm, refs?: { nets: Set<string>; vols: Set<string>; secs: Set<string> }): Record<string, unknown> {
  const svc: Record<string, unknown> = { image: s.image || undefined };
  if (s.command.trim()) svc.command = s.command.trim().split(/\s+/);
  if (s.replicas > 1) svc.deploy = { replicas: s.replicas };
  const ports = s.ports
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (ports.length) svc.ports = ports;
  const env = s.env.filter((e) => e.key);
  if (env.length) svc.environment = Object.fromEntries(env.map((e) => [e.key, e.value]));
  if (s.networks.length) {
    svc.networks = Object.fromEntries(s.networks.filter((n) => n.name).map((n) => [n.name, n.alias ? { aliases: [n.alias] } : {}]));
    s.networks.forEach((n) => n.name && refs?.nets.add(n.name));
  }
  if (s.volumes.length) {
    svc.volumes = s.volumes.filter((v) => v.name && v.target).map((v) => `${v.name}:${v.target}${v.readOnly ? ':ro' : ''}`);
    s.volumes.forEach((v) => v.name && refs?.vols.add(v.name));
  }
  if (s.secrets.length) {
    svc.secrets = s.secrets.filter((x) => x.name).map((x) => ({ source: x.name }));
    const fileEnv = s.secrets.filter((x) => x.mode === 'file+env' && x.envName);
    if (fileEnv.length) svc.environment = { ...((svc.environment as object) ?? {}), ...Object.fromEntries(fileEnv.map((x) => [x.envName, `/run/secrets/${x.name}`])) };
    s.secrets.forEach((x) => x.name && refs?.secs.add(x.name));
  }
  if (s.logDriver) {
    const options: Record<string, string> = {};
    if (s.logMaxSize) options['max-size'] = s.logMaxSize;
    if (s.logMaxFile) options['max-file'] = s.logMaxFile;
    svc.logging = { driver: s.logDriver, ...(Object.keys(options).length ? { options } : {}) };
  }
  if (s.node) svc['x-sfc'] = { node: s.node };
  return svc;
}

/** app.yaml 서비스 객체 → 폼(가져오기용, 폼에 없는 칸은 버린다). */
export function serviceFromObject(name: string, o: Record<string, unknown> | null | undefined): ServiceForm {
  // eslint 설정은 없지만 원문 모양이 자유로워 any로 읽고 칸마다 형을 확인한다.
  const v = (o ?? {}) as Record<string, any>;
  const f = emptyService(0);
  f.name = name;
  f.image = typeof v.image === 'string' ? v.image : '';
  f.node = typeof v['x-sfc']?.node === 'string' ? v['x-sfc'].node : '';
  f.replicas = Number(v.deploy?.replicas) || 1;
  f.command = Array.isArray(v.command) ? v.command.join(' ') : typeof v.command === 'string' ? v.command : '';
  f.ports = Array.isArray(v.ports) ? v.ports.map(portText).filter(Boolean).join(', ') : '';
  const env: Record<string, unknown> = Array.isArray(v.environment)
    ? Object.fromEntries((v.environment as string[]).map((l) => [l.split('=')[0], l.slice(l.indexOf('=') + 1)]))
    : (v.environment ?? {});
  const secretFiles = new Map<string, string>();
  for (const [k, val] of Object.entries(env)) {
    const m = /^\/run\/secrets\/(.+)$/.exec(String(val));
    if (m) secretFiles.set(m[1], k);
    else f.env.push({ key: k, value: String(val ?? '') });
  }
  const nets = v.networks;
  f.networks = Array.isArray(nets)
    ? nets.map((n: string) => ({ name: n, alias: '' }))
    : Object.entries((nets ?? {}) as Record<string, { aliases?: string[] } | null>).map(([n, x]) => ({ name: n, alias: x?.aliases?.[0] ?? '' }));
  f.volumes = (Array.isArray(v.volumes) ? v.volumes : []).flatMap((x: unknown) => {
    if (typeof x !== 'string') return [];
    const [name, target, ro] = x.split(':');
    return name && target ? [{ name, target, readOnly: ro === 'ro' }] : [];
  });
  f.secrets = (Array.isArray(v.secrets) ? v.secrets : []).flatMap((x: unknown) => {
    const name = typeof x === 'string' ? x : String((x as { source?: string })?.source ?? '');
    if (!name) return [];
    const envName = secretFiles.get(name);
    return [{ name, mode: envName ? ('file+env' as const) : ('file' as const), envName: envName ?? '' }];
  });
  const d = v.logging?.driver;
  if (d === 'local' || d === 'json-file') {
    f.logDriver = d;
    f.logMaxSize = String(v.logging?.options?.['max-size'] ?? '');
    f.logMaxFile = String(v.logging?.options?.['max-file'] ?? '');
  }
  return f;
}

/** 폼 → app.yaml. 별도 배포 로직 없이 이 원문으로 같은 경로를 탄다. */
/** 작업 공간은 요청 범위, 배포 구성 ID는 서버가 앱 이름으로 정한다(app.yaml 새 형식) */
export function formToYaml(f: AppFormState): string {
  const services: Record<string, unknown> = {};
  const refs = { nets: new Set<string>(), vols: new Set<string>(), secs: new Set<string>() };
  const { nets, vols, secs } = refs;
  for (const s of f.services) if (s.name) services[s.name] = serviceToObject(s, refs);
  const xm: Record<string, unknown> = {};
  const routes = f.routes.filter((r) => r.host && r.service);
  if (routes.length) xm.ingress = routes.map((r) => ({ ...(r.node ? { node: r.node } : {}), host: r.host, prefix: r.path || '/', service: r.service, ...(Number(r.port) ? { port: Number(r.port) } : {}), gateway: r.gateway }));
  const doc: Record<string, unknown> = { name: f.name, ...(Object.keys(xm).length ? { 'x-sfc': xm } : {}), services };
  if (nets.size) doc.networks = Object.fromEntries([...nets].map((n) => [n, { external: true }]));
  if (vols.size) doc.volumes = Object.fromEntries([...vols].map((n) => [n, { external: true }]));
  if (secs.size) doc.secrets = Object.fromEntries([...secs].map((n) => [n, { external: true }]));
  return YAML.stringify(doc, { lineWidth: 0 });
}

export function useTenantChoices(tenant: string) {
  const nets = usePoll((s) => networks(tenant, s), [tenant], 0, networksLive(tenant));
  const vols = usePoll((s) => volumes(tenant, s), [tenant], 0, volumesLive(tenant));
  const secs = usePoll((s) => vault(tenant, s), [tenant]);
  return { networks: nets.data?.items ?? [], volumes: vols.data?.items ?? [], secrets: (secs.data?.items ?? []).filter((x) => x.kind === 'object') };
}

function Rows<T>({ rows, onChange, blank, render, addLabel }: { rows: T[]; onChange: (r: T[]) => void; blank: T; render: (r: T, set: (v: T) => void) => React.ReactNode; addLabel: string }) {
  return (
    <div className="col" style={{ gap: 6 }}>
      {rows.map((r, i) => (
        <div key={i} className="row" style={{ flexWrap: 'nowrap' }}>
          {render(r, (v) => onChange(rows.map((x, j) => (j === i ? v : x))))}
          <button type="button" className="btn ghost sm" aria-label="행 지우기" onClick={() => onChange(rows.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <button type="button" className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => onChange([...rows, blank])}>
        ＋ {addLabel}
      </button>
    </div>
  );
}

export type TenantChoices = ReturnType<typeof useTenantChoices>;

/**
 * 서비스 하나의 칸(이미지·서버·명령·포트·환경 변수·망·저장소·비밀값·로그).
 * 앱 편집 폼과 단독 컨테이너 폼(UI-3F)이 같이 쓴다. standalone이면 서비스 이름·복제본 칸을 뺀다.
 */
export function ServiceFields({ tenant, value: s, onChange: set, nodes, choices: ch, standalone, extra }: { tenant: string; value: ServiceForm; onChange: (patch: Partial<ServiceForm>) => void; nodes: string[]; choices: TenantChoices; standalone?: boolean; extra?: React.ReactNode }) {
  return (
    <>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
        {!standalone && (
          <Field label="서비스 이름">
            <input value={s.name} onChange={(e) => set({ name: e.target.value.trim() })} />
          </Field>
        )}
        <Field group label="이미지" hint="digest 고정 권장 (repo@sha256:…)">
          <ImageInput tenant={tenant} value={s.image} onChange={(image) => set({ image })} />
        </Field>
        <Field label="서버">
          <select value={s.node} onChange={(e) => set({ node: e.target.value })}>
            <option value="">고르기</option>
            {nodes.map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </Field>
        {!standalone && (
          <Field label="복제본">
            <input type="number" min={1} max={16} value={s.replicas} onChange={(e) => set({ replicas: Math.max(1, Number(e.target.value) || 1) })} />
          </Field>
        )}
        {extra}
        <Field label="명령 (선택)">
          <input className="mono" value={s.command} onChange={(e) => set({ command: e.target.value })} placeholder="php worker.php" />
        </Field>
        <PortsField label="포트 (선택)" value={s.ports} onChange={(v) => set({ ports: v })} />
      </div>
      <div className="grid-2">
        <div className="col" style={{ gap: 6 }}>
          <b className="small">환경 변수</b>
          <Rows
            rows={s.env}
            blank={{ key: '', value: '' }}
            addLabel="변수"
            onChange={(env) => set({ env })}
            render={(r, setR) => (
              <>
                <input className="mono" aria-label="키" placeholder="KEY" value={r.key} onChange={(e) => setR({ ...r, key: e.target.value.trim() })} style={{ width: 160 }} />
                <input className="mono grow" aria-label="값" placeholder="value" type={SECRETISH.test(r.key) ? 'password' : 'text'} value={r.value} onChange={(e) => setR({ ...r, value: e.target.value })} />
                {SECRETISH.test(r.key) && <span className="badge wa" title="비밀번호처럼 보이는 값은 비밀값 보관함으로 옮기세요">비밀값?</span>}
              </>
            )}
          />
          <span className="small muted">
            <code>KEY=value</code> 여러 줄 붙여넣기:{' '}
            <button
              type="button"
              className="btn ghost sm"
              onClick={async () => {
                const t = await navigator.clipboard?.readText().catch(() => '');
                if (!t) return;
                const rows = t
                  .split('\n')
                  .map((l) => l.trim())
                  .filter((l) => l && !l.startsWith('#') && l.includes('='))
                  .map((l) => ({ key: l.slice(0, l.indexOf('=')).trim(), value: l.slice(l.indexOf('=') + 1) }));
                set({ env: [...s.env, ...rows] });
              }}
            >
              클립보드에서 넣기
            </button>
          </span>
        </div>
        <div className="col" style={{ gap: 6 }}>
          <b className="small">망 (공유 자원 이름 참조)</b>
          <Rows
            rows={s.networks}
            blank={{ name: '', alias: '' }}
            addLabel="망 연결"
            onChange={(networks) => set({ networks })}
            render={(r, setR) => (
              <>
                <select value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} aria-label="망">
                  <option value="">망 고르기</option>
                  {ch.networks.map((n) => (
                    <option key={n.name} value={n.name}>
                      {n.name} ({n.cidr})
                    </option>
                  ))}
                </select>
                <input aria-label="별칭" placeholder="별칭" value={r.alias} onChange={(e) => setR({ ...r, alias: e.target.value.trim() })} />
              </>
            )}
          />
          <b className="small">데이터 저장소</b>
          <Rows
            rows={s.volumes}
            blank={{ name: '', target: '', readOnly: false }}
            addLabel="저장소 연결"
            onChange={(volumes) => set({ volumes })}
            render={(r, setR) => (
              <>
                <select value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} aria-label="데이터 저장소">
                  <option value="">저장소 고르기</option>
                  {ch.volumes.map((v) => (
                    <option key={v.name} value={v.name}>
                      {v.name} ({v.kind === 'fixed' ? '고정' : '관리'} · {v.node})
                    </option>
                  ))}
                </select>
                <input className="mono" aria-label="마운트 경로" placeholder="/data" value={r.target} onChange={(e) => setR({ ...r, target: e.target.value.trim() })} />
                <label className="check small">
                  <input type="checkbox" checked={r.readOnly} onChange={(e) => setR({ ...r, readOnly: e.target.checked })} /> 읽기 전용
                </label>
              </>
            )}
          />
          <b className="small">비밀값</b>
          <Rows
            rows={s.secrets}
            blank={{ name: '', mode: 'file' as const, envName: '' }}
            addLabel="비밀값 연결"
            onChange={(secrets) => set({ secrets })}
            render={(r, setR) => (
              <>
                <select value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} aria-label="비밀값">
                  <option value="">비밀값 고르기</option>
                  {ch.secrets.map((x) => (
                    <option key={x.path} value={x.path}>
                      {x.path}
                      {x.group ? ` (${x.group})` : ''}
                    </option>
                  ))}
                </select>
                <select value={r.mode} onChange={(e) => setR({ ...r, mode: e.target.value as 'file' | 'file+env' })} aria-label="공급 방식">
                  <option value="file">파일로 넣기</option>
                  <option value="file+env">파일 + 경로 변수</option>
                  <option value="" disabled>
                    환경 변수 값
                  </option>
                </select>
                {r.mode === 'file+env' && <input className="mono" aria-label="경로 변수 이름" placeholder="DB_PASSWORD_FILE" value={r.envName} onChange={(e) => setR({ ...r, envName: e.target.value.trim() })} />}
              </>
            )}
          />
        </div>
      </div>
      <details>
        <summary className="small">로그 · 방식</summary>
        <div className="row" style={{ marginTop: 8 }}>
          <Field label="드라이버">
            <select value={s.logDriver} onChange={(e) => set({ logDriver: e.target.value as ServiceForm['logDriver'] })}>
              <option value="">서버 기본</option>
              <option value="local">local</option>
              <option value="json-file">json-file</option>
            </select>
          </Field>
          <Field label="max-size">
            <input value={s.logMaxSize} onChange={(e) => set({ logMaxSize: e.target.value })} placeholder="10m" />
          </Field>
          <Field label="max-file">
            <input value={s.logMaxFile} onChange={(e) => set({ logMaxFile: e.target.value })} placeholder="3" />
          </Field>
        </div>
        <span className="small muted">바꾸면 그 서비스 컨테이너를 다시 만듭니다.</span>
      </details>
    </>
  );
}

export function AppFormEditor({ tenant, value, onChange, nodes, lockName }: { tenant: string; value: AppFormState; onChange: (f: AppFormState) => void; nodes: string[]; lockName?: boolean }) {
  const ch = useTenantChoices(tenant);
  const set = (patch: Partial<AppFormState>) => onChange({ ...value, ...patch });
  const setSvc = (i: number, patch: Partial<ServiceForm>) => set({ services: value.services.map((s, j) => (j === i ? { ...s, ...patch } : s)) });
  const serviceNames = useMemo(() => value.services.map((s) => s.name).filter(Boolean), [value.services]);

  return (
    <div className="col" style={{ gap: 16 }}>
      <Card title="1. 앱">
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          <Field label="앱 이름" hint="소문자·숫자·-">
            <input value={value.name} readOnly={lockName} onChange={(e) => set({ name: e.target.value.trim() })} />
          </Field>
          <Field label="작업 공간">
            <input value={tenant} readOnly />
          </Field>
        </div>
      </Card>
      {value.services.map((s, i) => (
        <Card
          key={i}
          title={`2. 서비스 ${s.name || i + 1}`}
          actions={
            value.services.length > 1 && (
              <button type="button" className="btn sm danger" onClick={() => set({ services: value.services.filter((_, j) => j !== i) })}>
                서비스 빼기
              </button>
            )
          }
        >
          <ServiceFields tenant={tenant} value={s} onChange={(patch) => setSvc(i, patch)} nodes={nodes} choices={ch} />
        </Card>
      ))}
      <button type="button" className="btn" style={{ alignSelf: 'flex-start' }} onClick={() => set({ services: [...value.services, emptyService(value.services.length)] })}>
        ＋ 서비스 추가
      </button>
      <Card title="3. 외부 접속 · 경로 규칙">
        <Rows
          rows={value.routes}
          blank={{ node: nodes[0] ?? '', host: '', path: '/', service: serviceNames[0] ?? '', port: '', gateway: 'external' as const }}
          addLabel="경로 규칙"
          onChange={(routes) => set({ routes })}
          render={(r, setR) => (
            <>
              <input aria-label="호스트 이름" placeholder="shop.example" value={r.host} onChange={(e) => setR({ ...r, host: e.target.value.trim() })} />
              <input className="mono" aria-label="경로 앞부분" style={{ width: 100 }} value={r.path} onChange={(e) => setR({ ...r, path: e.target.value.trim() })} />
              <select aria-label="서비스" value={r.service} onChange={(e) => setR({ ...r, service: e.target.value })}>
                {serviceNames.map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
              <input aria-label="포트" placeholder="포트" style={{ width: 80 }} value={r.port} onChange={(e) => setR({ ...r, port: e.target.value.trim() })} />
              <select aria-label="게이트웨이" value={r.gateway} onChange={(e) => setR({ ...r, gateway: e.target.value as 'local' | 'external' })}>
                <option value="external">외부망</option>
                <option value="local">로컬망</option>
              </select>
              <select aria-label="여는 서버" value={r.node} onChange={(e) => setR({ ...r, node: e.target.value })}>
                {!r.node && <option value="">여는 서버</option>}
                {nodes.map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
            </>
          )}
        />
        <span className="small muted">x-sfc.ingress 경로 목록으로 만듭니다. 경로마다 그 경로를 받는 게이트웨이가 있는 서버를 고릅니다. 작업 공간이 외부망을 허용하지 않으면 거부됩니다.</span>
      </Card>
    </div>
  );
}

// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 외부 저장소 탭 (UI-83, 캔버스 RegistryExternal · RegistryExternalIx).
// 계약: docs/reference/web-api.md '외부 이미지 저장소 로그인'(sfcd 실제 계약, #232). 정의(source)에는 보관함 참조만 있고
// 자격 원문은 웹 어디에도 없다. 정의 검사·보관함 읽기·권한·기록 CAS는 sfcd 몫이다.
// 정의마다 실제로 읽는 서버(reader)를 연결해야 받기·로그인 시험이 된다. 정의를 바꾸면 읽던 서버가 멈추므로 다시 연결한다.
import { useEffect, useMemo, useRef, useState, type Ref } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ApiError } from '../api/client';
import {
  externalRegistries,
  externalRegistryPath,
  externalRegistryUsers,
  imageTrust,
  imageTrustPath,
  nodesOverview,
  registries,
  testExternalRegistry,
  vault,
  type ExternalRegistry,
  type LoginTest,
} from '../api/endpoints';
import type { DExternalRegistryUse, LoginTestCode } from '../api/dto';
import type { DiffLine, SecretView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, type Tone } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { DiffView } from '../components/Code';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { eulReul } from '../lib/josa';
import { fmtBytes } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { sendOnce, uncertain } from '../lib/opRetry';
import { ApprovalPrompt } from './VaultApproval';

const NEED = '이 작업 공간의 저장소 관리 권한이 필요합니다';

const CODE: Record<string, [string, Tone]> = {
  ok: ['로그인 확인', 'ok'],
  unauthorized: ['로그인 실패 · 401', 'er'],
  denied: ['받기 권한 없음', 'er'],
  'not-found': ['이미지 없음', 'wa'],
  unsupported: ['지원하지 않는 저장소', 'wa'],
  unavailable: ['연결 안 됨', 'er'],
  timeout: ['시간 초과', 'wa'],
  cancelled: ['취소됨', 'un'],
  'invalid-credential': ['로그인 정보를 읽지 못함', 'er'],
};
const FAIL_HELP: Record<string, string> = {
  unauthorized: '401 Unauthorized: 로그인 정보가 틀렸거나 로봇 계정이 만료되었습니다. 보관함의 비밀값을 새 값으로 바꾼 뒤 다시 시험하세요.',
  denied: '로그인은 됐지만 그 이미지를 받을 권한이 없습니다. 저장소에서 계정의 권한을 확인하세요.',
  'not-found': '저장소에 그 이미지나 태그가 없습니다. 이미지 이름을 확인하세요.',
  unsupported: '저장소가 이 받기 방식을 지원하지 않습니다. 저장소 종류와 주소를 확인하세요.',
  unavailable: '서버에서 저장소 주소에 닿지 못했습니다. 주소·포트와 서버의 바깥 연결을 확인하세요.',
  timeout: '저장소가 제때 답하지 않았습니다. 잠시 뒤 다시 시험하세요.',
  cancelled: '시험이 중간에 취소됐습니다. 다시 시험하세요.',
  'invalid-credential': '보관함에서 비밀값이나 키를 읽지 못했거나 값의 모양이 맞지 않습니다. 비밀값과 키 이름을 확인하세요.',
};
const codeLabel = (c: string) => CODE[c]?.[0] ?? c;
const agoMs = (ms: number | undefined) => {
  if (!ms) return '—';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  return s < 60 ? '방금' : s < 3600 ? `${Math.floor(s / 60)}분 전` : s < 86400 ? `${Math.floor(s / 3600)}시간 전` : `${Math.floor(s / 86400)}일 전`;
};
const AUTH: Record<ExternalRegistry['auth'], string> = { password: '사용자 + 비밀번호', token: '사용자 + 토큰', none: '없음 (공개)' };

/** 가장 최근의 결과: 이 화면의 마지막 시험과 서버들의 실제 받기 중 최근 것(오래된 보고는 뺀다) */
function lastResult(r: ExternalRegistry, t: LoginTest | undefined) {
  const pull = r.pulls.filter((p) => !p.stale && p.completedAt).sort((a, b) => b.completedAt - a.completedAt)[0];
  if (t && (!pull || t.at >= pull.completedAt)) return { code: t.code, at: t.at };
  return pull ? { code: pull.code, at: pull.completedAt } : undefined;
}
/** 그 정의의 상태 */
function status(r: ExternalRegistry, t: LoginTest | undefined): { label: string; tone: Tone; code?: LoginTestCode } {
  if (r.deleted) return { label: '지움 · 서버 멈추는 중', tone: 'un' };
  if (!r.enabled) return { label: '꺼짐', tone: 'un' };
  if (!r.reader) return { label: '읽을 서버 없음', tone: 'wa' };
  if (r.reader.draining) return { label: '연결 해제 중', tone: 'wa' };
  const last = lastResult(r, t);
  if (!last) return r.auth === 'none' ? { label: '익명 받기', tone: 'un' } : { label: '시험 전', tone: 'un' };
  const [label, tone] = CODE[last.code] ?? [last.code, 'wa' as Tone];
  if (last.code === 'ok') return r.auth === 'none' ? { label: '익명 받기', tone: 'un', code: 'ok' } : { label: `${label} · ${agoMs(last.at)}`, tone, code: 'ok' };
  return { label, tone, code: last.code };
}

/** 신뢰 출처 규칙은 '**' 아니면 정확한 경로 하나다(sfcd CheckImageTrust). prefix/** 는 그 저장소 전부로 넓힌다. */
const trustRules = (authority: string, repository: string) => [{ registry: authority, repository: repository === '**' || repository.endsWith('/**') ? '**' : repository }];

// ── 폼 ───────────────────────────────────────────────
interface Form {
  id: string;
  authority: string;
  repository: string;
  enabled: boolean;
  auth: ExternalRegistry['auth'];
  secretId: string;
  usernameKey: string;
  passwordKey: string;
  tls: 'public' | 'ca';
  caId: string;
  caKey: string;
  trust: boolean;
}
const blank = (): Form => ({ id: '', authority: '', repository: '**', enabled: true, auth: 'token', secretId: '', usernameKey: '', passwordKey: '', tls: 'public', caId: '', caKey: '', trust: true });
const fromRow = (r: ExternalRegistry): Form => ({
  id: r.id,
  authority: r.authority,
  repository: r.repository,
  enabled: r.enabled,
  auth: r.auth,
  secretId: r.credential?.id ?? '',
  usernameKey: r.credential?.usernameKey ?? '',
  passwordKey: r.credential?.passwordKey ?? '',
  tls: r.ca ? 'ca' : 'public',
  caId: r.ca?.id ?? '',
  caKey: r.ca?.key ?? '',
  trust: false,
});
const bodyOf = (tenant: string, f: Form) => ({
  authority: f.authority.trim(),
  repository: f.repository.trim() || '**',
  enabled: f.enabled,
  auth: f.auth,
  ...(f.auth !== 'none' ? { credential: { realm: tenant, id: f.secretId, usernameKey: f.usernameKey, passwordKey: f.passwordKey } } : {}),
  ...(f.tls === 'ca' ? { ca: { realm: tenant, id: f.caId, key: f.caKey } } : {}),
});
const AUTH_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d{1,5})?$/;
const REPO_RE = /^(\*\*|[a-z0-9._-]+(\/[a-z0-9._-]+)*(\/\*\*)?)$/;
function problems(f: Form, builtin: string[], taken: string[], isNew: boolean): Partial<Record<keyof Form, string>> {
  const e: Partial<Record<keyof Form, string>> = {};
  if (isNew && !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(f.id)) e.id = '소문자·숫자·- , 63자 이하';
  else if (isNew && taken.includes(f.id)) e.id = '이미 있는 ID입니다';
  if (!AUTH_RE.test(f.authority.trim())) e.authority = '소문자 host[:포트]';
  else if (builtin.includes(f.authority.trim())) e.authority = '내장 저장소 주소는 등록할 수 없습니다';
  if (!REPO_RE.test(f.repository.trim())) e.repository = '** , org/** 또는 정확한 경로 하나';
  if (f.auth !== 'none') {
    if (!f.secretId) e.secretId = '비밀값을 고르세요';
    if (!f.usernameKey) e.usernameKey = '키를 고르세요';
    if (!f.passwordKey) e.passwordKey = '키를 고르세요';
  }
  if (f.tls === 'ca' && (!f.caId || !f.caKey)) e.caId = 'CA 인증서가 든 비밀값과 키를 고르세요';
  return e;
}

function FormFields({
  f,
  set,
  secrets,
  errors,
  isNew,
  secretRef,
  tenant,
  onSecretMade,
}: {
  f: Form;
  set: (p: Partial<Form>) => void;
  secrets: SecretView[];
  errors: Partial<Record<keyof Form, string>>;
  isNew: boolean;
  secretRef?: Ref<HTMLSelectElement>;
  tenant: string;
  /** 새로 입력해 보관함에 저장한 뒤: 목록을 다시 읽는다 */
  onSecretMade: () => void;
}) {
  const [fresh, setFresh] = useState(false);
  const obj = secrets.find((s) => s.id === f.secretId);
  const ca = secrets.find((s) => s.id === f.caId);
  const rules = trustRules(f.authority.trim() || '주소', f.repository.trim() || '**');
  const fixed = isNew ? undefined : '바꿀 수 없음 · 다른 주소·경로는 새 ID로 등록';
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 12 }}>
        {isNew && (
          <Field label="ID" hint="주소에서 자동으로 채움 · 고칠 수 있음" error={f.id ? errors.id : undefined}>
            <input className="mono" value={f.id} onChange={(e) => set({ id: e.target.value })} placeholder="harbor" spellCheck={false} autoComplete="off" />
          </Field>
        )}
        <Field label={fixed ? "🔒 저장소 주소" : "저장소 주소"} hint={fixed} error={f.authority ? errors.authority : undefined}>
          <input
            className="mono"
            value={f.authority}
            disabled={!isNew}
            style={isNew ? undefined : { background: 'var(--bg)', color: 'var(--muted)' }}
            onChange={(e) => set({ authority: e.target.value.trim() })}
            onBlur={() =>
              isNew &&
              !f.id &&
              f.authority &&
              set({
                id: f.authority
                  .split(/[.:]/)[0]
                  .replace(/[^a-z0-9-]/g, '-')
                  .slice(0, 63),
              })
            }
            placeholder="harbor.corp.example:443"
            spellCheck={false}
            autoComplete="off"
          />
        </Field>
        <Field label={fixed ? "🔒 저장소 경로" : "저장소 경로"} hint={fixed ?? '** (전부), org/** (그 아래 전부) 또는 정확한 경로 하나'} error={errors.repository}>
          <input className="mono" value={f.repository} disabled={!isNew} style={isNew ? undefined : { background: 'var(--bg)', color: 'var(--muted)' }} onChange={(e) => set({ repository: e.target.value })} placeholder="platform/**" spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="로그인 방식">
          <select value={f.auth} onChange={(e) => set({ auth: e.target.value as Form['auth'] })}>
            <option value="token">{AUTH.token}</option>
            <option value="password">{AUTH.password}</option>
            <option value="none">{AUTH.none}</option>
          </select>
        </Field>
        <Field label="TLS">
          <select value={f.tls} onChange={(e) => set({ tls: e.target.value as Form['tls'] })}>
            <option value="public">공인 인증서 (기본)</option>
            <option value="ca">사내 CA 추가…</option>
          </select>
        </Field>
      </div>
      <label className="row small" style={{ gap: 8 }}>
        <input type="checkbox" checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
        켜기 <span className="muted">· 끄면 이 정의로 로그인해 받지 않고 서버를 연결할 수 없습니다</span>
      </label>
      {f.tls === 'ca' && <span className="small muted">CA 인증서는 비밀값 보관함에 넣어 두고 여기서는 고르기만 합니다.</span>}
      {f.tls === 'ca' && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 12 }}>
          <Field label="CA 인증서가 든 비밀값" error={errors.caId}>
            <select value={f.caId} onChange={(e) => set({ caId: e.target.value, caKey: '' })}>
              <option value="">고르세요</option>
              {secrets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.path}
                </option>
              ))}
            </select>
          </Field>
          <Field label="키 (PEM)">
            <select value={f.caKey} onChange={(e) => set({ caKey: e.target.value })} disabled={!ca}>
              <option value="">고르세요</option>
              {(ca?.keys ?? []).map((k) => (
                <option key={k}>{k}</option>
              ))}
            </select>
          </Field>
        </div>
      )}
      {f.auth !== 'none' && (
        <div className="inset col" style={{ gap: 10, background: 'var(--surface-2)' }}>
          <b className="small">로그인 정보 (비밀값 보관함)</b>
          <span className="segmented" role="radiogroup" aria-label="로그인 정보" style={{ alignSelf: 'flex-start' }}>
            <button type="button" role="radio" aria-checked={!fresh} className={fresh ? '' : 'on'} onClick={() => setFresh(false)}>
              보관함의 비밀값 고르기
            </button>
            <button type="button" role="radio" aria-checked={fresh} className={fresh ? 'on' : ''} onClick={() => setFresh(true)}>
              새로 입력해 보관함에 저장
            </button>
          </span>
          {fresh ? (
            <NewLoginSecret
              tenant={tenant}
              taken={secrets.map((x) => x.id)}
              suggest={f.id ? `${f.id}-login` : 'registry-login'}
              onSaved={(id) => {
                set({ secretId: id, usernameKey: 'username', passwordKey: 'password' });
                setFresh(false);
                onSecretMade();
              }}
            />
          ) : (
            <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 10 }}>
              <Field label="비밀값" error={errors.secretId}>
                <select ref={secretRef} value={f.secretId} onChange={(e) => set({ secretId: e.target.value, usernameKey: '', passwordKey: '' })}>
                  <option value="">고르세요</option>
                  {secrets.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.path}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="사용자 이름 키" error={f.secretId ? errors.usernameKey : undefined}>
                <select value={f.usernameKey} onChange={(e) => set({ usernameKey: e.target.value })} disabled={!obj}>
                  <option value="">고르세요</option>
                  {(obj?.keys ?? []).map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </select>
              </Field>
              <Field label={f.auth === 'token' ? '토큰 키' : '비밀번호 키'} error={f.secretId ? errors.passwordKey : undefined}>
                <select value={f.passwordKey} onChange={(e) => set({ passwordKey: e.target.value })} disabled={!obj}>
                  <option value="">고르세요</option>
                  {(obj?.keys ?? []).map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </select>
              </Field>
            </div>
          )}
          <span className="small muted">
            값은 웹에 보이지 않고 키 이름만 고릅니다. 이 작업 공간 보관함의 비밀값만 쓸 수 있습니다. 새로 입력한 값은 작업 공간 <Link to="/shared/vault">비밀값 보관함</Link>에 저장되고 웹에는 남지 않습니다.
          </span>
        </div>
      )}
      <label className="row small" style={{ gap: 8 }}>
        <input type="checkbox" checked={f.trust} onChange={(e) => set({ trust: e.target.checked })} />
        이미지 신뢰 출처(UI-82)에{' '}
        {rules.map((r, i) => (
          <code key={i}>
            {r.registry}/{r.repository}
          </code>
        ))}{' '}
        함께 추가
      </label>
      {rules[0].repository === '**' && f.repository.trim() !== '**' && f.repository.trim() !== '' && (
        <span className="small muted">신뢰 출처는 '**' 아니면 정확한 경로 하나만 받아서 {f.authority.trim() || '주소'}/** 로 넣습니다.</span>
      )}
    </div>
  );
}

// ── 탭 ───────────────────────────────────────────────
export function ExternalTab() {
  const { tenant, canDeploy } = useTenantRole();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const list = usePoll((s) => externalRegistries(tenant, s), [tenant]);
  const secretsQ = usePoll((s) => vault(tenant, s), [tenant], 0);
  const builtinQ = usePoll(() => registries(tenant), [tenant], 0);
  const secrets = useMemo(() => (secretsQ.data?.items ?? []).filter((s) => s.kind === 'object' && s.status === 'active'), [secretsQ.data]);
  const builtin = useMemo(() => (builtinQ.data?.items ?? []).map((r) => r.endpoint), [builtinQ.data]);
  const [sel, setSel] = useState<string>();
  const [tests, setTests] = useState<Record<string, LoginTest>>({});
  const [testing, setTesting] = useState<string>();
  const [del, setDel] = useState<ExternalRegistry>();
  const [bind, setBind] = useState<ExternalRegistry>();
  const [unbind, setUnbind] = useState<ExternalRegistry>();
  const usersRef = useRef<HTMLDivElement>(null);
  const secretRef = useRef<HTMLSelectElement>(null);
  const rows = list.data?.items ?? [];
  const cur = rows.find((r) => r.id === sel) ?? rows.find((r) => !r.deleted) ?? rows[0];
  const creating = params.get('new') === '1';
  const closeNew = () => setParams((p) => (p.delete('new'), p), { replace: true });

  const test = async (r: ExternalRegistry, image?: string) => {
    setTesting(r.id);
    try {
      const res = await testExternalRegistry(tenant, r.id, image || undefined);
      setTests((x) => ({ ...x, [r.id]: res }));
      if (res.code !== 'ok') toast(`${r.authority} 로그인 시험: ${codeLabel(res.code)}`);
      else toast(`${r.authority} 로그인 확인${image ? ` · ${image} 받기 확인` : ''}`);
    } catch (e) {
      toast(
        e instanceof ApiError && e.code === 'not-bound'
          ? '이 저장소를 읽을 서버가 연결돼 있지 않습니다. 서버를 먼저 연결하세요.'
          : e instanceof ApiError && e.status === 403
            ? '로그인 시험은 저장소 관리 권한이 필요합니다.'
            : '로그인 시험을 보내지 못했습니다.',
      );
    } finally {
      setTesting(undefined);
    }
  };
  const bindOff = (r: ExternalRegistry) =>
    !canDeploy ? NEED : r.deleted ? '지운 정의입니다' : !r.enabled ? '꺼진 정의는 연결할 수 없습니다' : r.reader ? `이미 ${r.reader.node}에 연결돼 있습니다` : undefined;
  const testOff = (r: ExternalRegistry) => (!canDeploy ? NEED : r.deleted ? '지운 정의입니다' : !r.reader ? '읽을 서버를 먼저 연결하세요' : r.reader.draining ? '연결을 해제하는 중입니다' : undefined);
  const menu = (r: ExternalRegistry): MenuItem[] => [
    { label: '설정 열기', onSelect: () => setSel(r.id) },
    {
      label: '로그인 정보 바꾸기',
      hint: r.reader ? '다시 연결 필요' : undefined,
      disabledReason: r.deleted ? '지운 정의입니다' : r.auth === 'none' ? '공개 저장소는 로그인 정보가 없습니다' : canDeploy ? undefined : NEED,
      onSelect: () => (setSel(r.id), setTimeout(() => secretRef.current?.focus(), 50)),
    },
    { label: '읽을 서버 연결…', disabledReason: bindOff(r), onSelect: () => setBind(r) },
    {
      label: '서버 연결 해제…',
      disabledReason: !canDeploy ? NEED : !r.reader ? '연결된 서버가 없습니다' : r.reader.draining ? '이미 해제하는 중입니다' : undefined,
      onSelect: () => setUnbind(r),
    },
    { label: '이 저장소의 이미지 보기', disabledReason: '서버 기능 대기 (외부 저장소 이미지 목록, REQ-18)' },
    { label: '쓰는 곳 보기', onSelect: () => (setSel(r.id), setTimeout(() => usersRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50)) },
    { sep: true, label: '' },
    { label: '등록 해제…', danger: true, disabledReason: r.deleted ? '이미 지웠습니다' : canDeploy ? undefined : NEED, onSelect: () => setDel(r) },
  ];

  return (
    <>
      <HelpBox terms="외부 저장소 (external registry) · 저장소 경로 (repository) · 읽는 서버 (reader) · 이미지 신뢰 출처 (image trust) · 로그인 시험 (test login)">
        <b>이 화면은</b> 클러스터 밖의 이미지 저장소(GHCR · Harbor · 사내 저장소 등)를 이 작업 공간({tenant})에 등록합니다. 로그인이 필요한 저장소는 로그인 정보를 비밀값 보관함에 두고, 연결한 서버
        하나가 그 저장소 주소에 한해서만 꺼내 씁니다. 웹 화면과 웹 앱 데이터에는 비밀번호·토큰이 남지 않습니다.
      </HelpBox>
      <Card>
        <Load q={list}>
          {() =>
            rows.length === 0 ? (
              <Empty kind="first" title="등록된 외부 저장소가 없습니다" action={canDeploy ? <Link to="?new=1">외부 저장소 등록</Link> : undefined}>
                공개 저장소는 등록 없이 신뢰 출처 탭에서 바로 추가해도 됩니다.
              </Empty>
            ) : (
              <div className="col" style={{ gap: 8 }}>
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>주소</th>
                        <th>저장소 경로</th>
                        <th style={{ width: 140 }}>로그인 방식</th>
                        <th>로그인 정보</th>
                        <th style={{ width: 120 }}>읽는 서버</th>
                        <th style={{ width: 170 }}>상태</th>
                        <th style={{ width: 110 }} />
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((r) => {
                        const st = status(r, tests[r.id]);
                        return (
                          <tr key={r.id} className={`clickable ${cur?.id === r.id ? 'selected' : ''}`} style={r.deleted ? { opacity: 0.6 } : undefined} onClick={() => setSel(r.id)}>
                            <td className="mono">{r.authority}</td>
                            <td className="mono">{r.repository}</td>
                            <td>{AUTH[r.auth]}</td>
                            <td>
                              {r.credential ? (
                                <span>
                                  비밀값 <b>{r.credential.id}</b> ({r.credential.usernameKey}, {r.credential.passwordKey})
                                </span>
                              ) : (
                                '—'
                              )}
                            </td>
                            <td className="mono">{r.reader ? r.reader.node : <span className="muted">없음</span>}</td>
                            <td>
                              <Badge tone={st.tone}>{st.label}</Badge>
                            </td>
                            <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                              <span className="row" style={{ justifyContent: 'flex-end', gap: 6, flexWrap: 'nowrap' }}>
                                {!r.deleted && !r.reader && r.enabled ? (
                                  <button className="btn sm" disabled={!!bindOff(r)} title={bindOff(r)} onClick={() => setBind(r)}>
                                    서버 연결
                                  </button>
                                ) : (
                                  <button className="btn sm" disabled={!!testOff(r) || testing === r.id} title={testOff(r)} onClick={() => void test(r)}>
                                    {testing === r.id ? '시험 중…' : '시험'}
                                  </button>
                                )}
                                <Menu label={`${r.authority} 메뉴`} items={menu(r)} />
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <span className="small muted">
                  상태는 마지막 로그인 시험과 서버들의 실제 이미지 받기 결과 중 최근 것입니다. 저장소마다 읽는 서버 하나를 연결해야 받기·시험이 되고, 로그인 시험은 그 읽는 서버가 대신 합니다. 설정을 바꾸면 읽던 서버가 멈추므로 다시
                  연결합니다. 등록된 외부 저장소는 이미지 신뢰 출처(UI-82)에도 같은 주소·경로로 들어가며, 신뢰 출처에서 빼면 받기가 막힙니다. 내장 저장소 주소는 여기 등록할 수 없습니다.
                </span>
              </div>
            )
          }
        </Load>
      </Card>
      {cur && (
        <>
          <div className="row" style={{ alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
            <EditCard
              key={`${cur.id}/${cur.revision}`}
              tenant={tenant}
              r={cur}
              secrets={secrets}
              builtin={builtin}
              canManage={canDeploy && !cur.deleted}
              status={status(cur, tests[cur.id])}
              secretRef={secretRef}
              onDone={list.refresh}
              onSecretMade={secretsQ.refresh}
            />
            <TestCard r={cur} t={tests[cur.id]} off={testOff(cur)} bindOff={bindOff(cur)} testing={testing === cur.id} onTest={(img) => void test(cur, img)} onBind={() => setBind(cur)} rows={rows} tests={tests} />
          </div>
          <div ref={usersRef}>
            <UsersCard tenant={tenant} r={cur} />
          </div>
        </>
      )}
      {creating && canDeploy && <RegisterDialog tenant={tenant} secrets={secrets} builtin={builtin} taken={rows.map((r) => r.id)} onClose={closeNew} onDone={list.refresh} onSecretMade={secretsQ.refresh} />}
      {del && <UnregisterDialog key={del.id} tenant={tenant} r={del} onClose={() => setDel(undefined)} onDone={() => (setSel(undefined), list.refresh())} />}
      {bind && <BindDialog key={bind.id} tenant={tenant} r={bind} onClose={() => setBind(undefined)} onDone={list.refresh} />}
      {unbind && <UnbindDialog key={unbind.id} tenant={tenant} r={unbind} onClose={() => setUnbind(undefined)} onDone={list.refresh} />}
    </>
  );
}

/** 머리글의 '외부 저장소 등록' */
export function ExternalRegisterButton() {
  const { canDeploy } = useTenantRole();
  return canDeploy ? (
    <Link className="btn sm primary" to="/images/external?new=1">
      외부 저장소 등록
    </Link>
  ) : (
    <button className="btn sm primary" disabled title={NEED}>
      외부 저장소 등록
    </button>
  );
}

function EditCard({
  tenant,
  r,
  secrets,
  builtin,
  canManage,
  status: st,
  secretRef,
  onDone,
  onSecretMade,
}: {
  tenant: string;
  r: ExternalRegistry;
  secrets: SecretView[];
  builtin: string[];
  canManage: boolean;
  status: { label: string; tone: Tone };
  secretRef: Ref<HTMLSelectElement>;
  onDone: () => void;
  onSecretMade: () => void;
}) {
  const [f, setF] = useState(() => fromRow(r));
  const [review, setReview] = useState(false);
  const o = fromRow(r);
  const errors = problems(f, builtin, [], false);
  const dirty = JSON.stringify(bodyOf(tenant, f)) !== JSON.stringify(bodyOf(tenant, o));
  return (
    <Card title={`${r.authority} 설정`} actions={<Badge tone={st.tone}>{st.label}</Badge>} className="grow">
      {r.deleted && <div className="note small">지운 정의입니다. 읽던 서버가 멈추면 목록에서 사라집니다.</div>}
      <fieldset disabled={!canManage} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
        <FormFields f={f} set={(p) => setF((x) => ({ ...x, ...p }))} secrets={secrets} errors={errors} isNew={false} secretRef={secretRef} tenant={tenant} onSecretMade={onSecretMade} />
      </fieldset>
      {dirty && r.reader && !r.reader.draining && <div className="note wa small">적용하면 이 저장소를 읽던 서버 {r.reader.node}가 멈춥니다. 적용한 뒤 서버를 다시 연결하세요.</div>}
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn primary" disabled={!canManage || (!dirty && !f.trust) || Object.keys(errors).length > 0} title={canManage ? undefined : NEED} onClick={() => setReview(true)}>
          변경 검토
        </button>
      </div>
      {review && <ReviewDialog tenant={tenant} id={r.id} before={r} f={f} onClose={() => setReview(false)} onDone={onDone} />}
    </Card>
  );
}

function TestCard({
  r,
  t,
  off,
  bindOff,
  testing,
  onTest,
  onBind,
  rows,
  tests,
}: {
  r: ExternalRegistry;
  t?: LoginTest;
  off?: string;
  bindOff?: string;
  testing: boolean;
  onTest: (image: string) => void;
  onBind: () => void;
  rows: ExternalRegistry[];
  tests: Record<string, LoginTest>;
}) {
  const [image, setImage] = useState(() => (r.repository !== '**' ? r.repository.replace(/\/\*\*$/, '/') : ''));
  const failing = rows.filter((x) => x.id !== r.id && status(x, tests[x.id]).code && status(x, tests[x.id]).code !== 'ok');
  return (
    <Card title="로그인 시험 결과" className="side">
      <KV items={[['읽는 서버', r.reader ? `${r.reader.node}${r.reader.draining ? ' · 해제하는 중' : ''}` : '연결 안 됨']]} />
      {!r.reader && !r.deleted && (
        <div className="note wa small col" style={{ gap: 6 }}>
          <span>이 저장소를 읽을 서버가 없어 받기와 로그인 시험을 할 수 없습니다.</span>
          <button className="btn sm" style={{ width: 'fit-content' }} disabled={!!bindOff} title={bindOff} onClick={onBind}>
            서버 연결…
          </button>
        </div>
      )}
      {t ? (
        <KV
          items={[
            ['시각', agoMs(t.at)],
            ['읽는 주체', `${r.reader?.node ?? '—'} · 세대 ${t.generation} · ${t.owner.length > 16 ? `${t.owner.slice(0, 12)}…` : t.owner}`],
            [
              '결과',
              <Badge key="r" tone={t.code === 'ok' ? 'ok' : (CODE[t.code]?.[1] ?? 'wa')}>
                {t.code === 'ok' ? '성공' : codeLabel(t.code)}
              </Badge>,
            ],
            ['확인 범위', t.image ? <code key="i">{t.image.normalized} manifest{t.pull ? ' · 레이어 HEAD' : ''}</code> : '로그인만'],
            ...(t.image ? ([['digest', <code key="d">{t.image.digest.slice(0, 19)}…</code>]] as [string, React.ReactNode][]) : []),
            ...(t.pull ? ([['받을 크기', `레이어 ${t.pull.blobs}개 · ${fmtBytes(t.pull.compressedBytes)} (${t.pull.platform})`]] as [string, React.ReactNode][]) : []),
            ['토큰', '저장 안 함'],
          ]}
        />
      ) : (
        <span className="small muted">이 화면에서 아직 시험하지 않았습니다.</span>
      )}
      <span className="small muted">
        시험은 읽는 서버가 보관함 값을 꺼내 저장소에 로그인해 보고 바로 지웁니다. 이미지를 적으면 manifest와 레이어까지 확인하며, 실제로 내려받지 않습니다.
      </span>
      <Field label="시험할 이미지 (선택)">
        <input className="mono" value={image} onChange={(e) => setImage(e.target.value.trim())} placeholder="shop-team/web:latest" spellCheck={false} autoComplete="off" />
      </Field>
      <button className="btn" style={{ width: 'fit-content' }} disabled={!!off || testing} title={off} onClick={() => onTest(image.endsWith('/') ? '' : image)}>
        {testing ? '시험 중…' : '로그인 시험'}
      </button>
      {r.pulls.length > 0 && (
        <div className="col" style={{ gap: 6, borderTop: '1px solid var(--line-2)', paddingTop: 10 }}>
          <b className="small">서버별 마지막 받기</b>
          <div className="table-wrap">
            <table className="tbl">
              <tbody>
                {r.pulls.map((p) => (
                  <tr key={p.node}>
                    <td className="mono">{p.node}</td>
                    <td>
                      <Badge tone={p.code === 'ok' ? 'ok' : (CODE[p.code]?.[1] ?? 'wa')}>{p.code === 'ok' ? '성공' : codeLabel(p.code)}</Badge> {p.stale && <Badge tone="un">오래된 값</Badge>}
                    </td>
                    <td className="small muted">
                      {p.stage} · {agoMs(p.completedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {[r, ...failing].map((x) => {
        const s = status(x, tests[x.id]);
        if (!s.code || s.code === 'ok' || !FAIL_HELP[s.code]) return null;
        return (
          <div key={x.id} className="col small muted" style={{ borderTop: '1px solid var(--line-2)', paddingTop: 10, gap: 4 }}>
            <b style={{ color: 'var(--text)' }}>{x.authority} 실패 안내</b>
            <span>
              {FAIL_HELP[s.code]}
              {x.credential && ` (비밀값 ${x.credential.id})`}
            </span>
          </div>
        );
      })}
    </Card>
  );
}

const KIND: Record<string, string> = { 'app-execution': '앱 실행', standalone: '단독 컨테이너', 'standalone-container': '단독 컨테이너' };
const useLabel = (u: DExternalRegistryUse) => (u.app ? `${u.app}${u.service ? ` · ${u.service}` : ''}` : u.instance ? `단독 ${u.instance}` : (KIND[u.kind] ?? u.kind));
function UsersCard({ tenant, r }: { tenant: string; r: ExternalRegistry }) {
  const [pages, setPages] = useState<{ items: DExternalRegistryUse[]; next?: string }>();
  const [err, setErr] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const load = async (after?: string) => {
    setBusy(true);
    setErr(undefined);
    try {
      const p = await externalRegistryUsers(tenant, r.id, after);
      setPages((x) => ({ items: [...(after ? (x?.items ?? []) : []), ...p.items], next: p.next }));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    setPages(undefined);
    void load();
  }, [tenant, r.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const u = pages?.items ?? [];
  return (
    <Card title="쓰는 곳">
      {err !== undefined && <MutationError error={err} />}
      {!pages ? (
        busy && <span className="small muted">불러오는 중…</span>
      ) : u.length === 0 ? (
        <span className="small muted">지금 이 정의로 로그인해 받는 이미지를 쓰는 앱·단독 컨테이너가 없습니다.</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>앱 · 서비스</th>
                <th style={{ width: 110 }}>서버</th>
                <th>이미지</th>
                <th style={{ width: 130 }}>종류</th>
              </tr>
            </thead>
            <tbody>
              {u.map((x, i) => (
                <tr key={i}>
                  <td>
                    {x.app ? <Link to={`/deploy/apps/${encodeURIComponent(tenant)}/${encodeURIComponent(x.app)}`}>{useLabel(x)}</Link> : useLabel(x)}
                    {x.deployment && <span className="muted"> ({x.deployment})</span>}
                  </td>
                  <td className="mono">{x.node ?? '—'}</td>
                  <td className="mono" title={x.image}>
                    {x.image}
                  </td>
                  <td className="small">
                    {KIND[x.kind] ?? x.kind}
                    {x.unknown && <Badge tone="wa">확인 못 함</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages?.next && (
        <button className="btn sm" style={{ width: 'fit-content' }} disabled={busy} onClick={() => void load(pages.next)}>
          {busy ? '불러오는 중…' : '더 보기'}
        </button>
      )}
      <span className="small muted">
        외부 저장소를 지우거나 로그인 정보를 빼면, 이미 받아 둔 이미지로 돌고 있는 컨테이너는 그대로지만 새로 받아야 하는 배포·이동은 막힙니다. 지우기 전에 이 목록을 보여 주고 확인을 받습니다.
      </span>
    </Card>
  );
}

// ── 등록 · 검토 · 해제 ───────────────────────────────────
function RegisterDialog({ tenant, secrets, builtin, taken, onClose, onDone, onSecretMade }: { tenant: string; secrets: SecretView[]; builtin: string[]; taken: string[]; onClose: () => void; onDone: () => void; onSecretMade: () => void }) {
  const [f, setF] = useState<Form>(blank);
  // 보낸 뒤에는 이 ID가 '이미 있는 ID'로 바뀌지 않게 연 순간의 목록을 쓴다
  const [frozen] = useState(taken);
  const [review, setReview] = useState(false);
  const errors = problems(f, builtin, frozen, true);
  if (review) return <ReviewDialog tenant={tenant} id={f.id} f={f} onClose={onClose} onDone={onDone} onBack={() => setReview(false)} />;
  return (
    <Dialog
      title="외부 저장소 등록"
      width={720}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={Object.keys(errors).length > 0} onClick={() => setReview(true)}>
            변경 검토
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <FormFields f={f} set={(p) => setF((x) => ({ ...x, ...p }))} secrets={secrets} errors={errors} isNew tenant={tenant} onSecretMade={onSecretMade} />
        <span className="small muted">등록한 뒤 읽을 서버를 연결해야 받기·로그인 시험이 됩니다. 주소와 저장소 경로는 등록한 뒤 바꿀 수 없습니다.</span>
      </div>
    </Dialog>
  );
}

const show = (f: Form) => ({
  '저장소 주소': f.authority.trim(),
  '저장소 경로': f.repository.trim() || '**',
  켜기: f.enabled ? '켬' : '끔',
  '로그인 방식': AUTH[f.auth],
  '로그인 정보': f.auth !== 'none' ? `비밀값 ${f.secretId} (${f.usernameKey}, ${f.passwordKey})` : '—',
  TLS: f.tls === 'ca' ? `사내 CA ${f.caId}/${f.caKey}` : '공인 인증서',
});
const PUT_ERR: Record<string, string> = {
  'scope-fixed': '등록한 주소·저장소 경로는 바꿀 수 없습니다. 다른 주소·경로는 새 ID로 등록하세요.',
};
function ReviewDialog({
  tenant,
  id,
  before,
  f,
  onClose,
  onDone,
  onBack,
}: {
  tenant: string;
  id: string;
  before?: ExternalRegistry;
  f: Form;
  onClose: () => void;
  onDone: () => void;
  onBack?: () => void;
}) {
  const toast = useToast();
  // 연 순간의 내용·revision을 고정한다
  const [snap] = useState(() => ({
    body: bodyOf(tenant, f),
    expected: before?.revision ?? 0,
    lines: diffLines(before ? show(fromRow(before)) : undefined, show(f)),
    trust: f.trust ? trustRules(f.authority.trim(), f.repository.trim() || '**') : [],
    reader: before?.reader && !before.reader.draining ? before.reader.node : undefined,
  }));
  const m = useMutation();
  const t = useMutation();
  const [trustErr, setTrustErr] = useState<unknown>();
  const changed = snap.lines.some((l) => l.op !== ' ');
  const send = async () => {
    const o = changed ? await sendOnce(m, externalRegistryPath(tenant, id), { ...snap.body, expected: snap.expected }, 'PUT') : undefined;
    if (o?.state === 'applied' || !changed) await applied();
  };
  const done = useRef(false);
  const applied = async () => {
    if (done.current) return;
    done.current = true;
    onDone();
    if (snap.trust.length) await addTrust();
    else toast(before ? `${before.authority} 설정을 바꿨습니다.${snap.reader && changed ? ' 서버를 다시 연결하세요.' : ''}` : `${snap.body.authority}을(를) 등록했습니다. 읽을 서버를 연결하세요.`);
  };
  const addTrust = async () => {
    try {
      const cur = await imageTrust(tenant);
      const have = new Set(cur.rules.map((r) => `${r.registry}/${r.repository}`));
      const add = snap.trust.filter((r) => !have.has(`${r.registry}/${r.repository}`));
      if (!add.length) return toast('신뢰 출처에 이미 있습니다.');
      const o = await sendOnce(t, imageTrustPath(tenant), { add, expected: cur.revision }, 'PATCH');
      if (o?.state === 'applied') toast(`신뢰 출처에 ${add.map((r) => `${r.registry}/${r.repository}`).join(', ')}을(를) 추가했습니다.`);
    } catch (e) {
      setTrustErr(e);
    }
  };
  const finished = (m.op?.state === 'applied' || !changed) && (!snap.trust.length || t.op?.state === 'applied' || t.error !== undefined || trustErr !== undefined);
  const putErr = m.error instanceof ApiError ? PUT_ERR[m.error.code] : undefined;
  return (
    <Dialog
      title={before ? `${before.authority} 변경 검토` : '외부 저장소 등록 검토'}
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            {onBack && !m.op && (
              <button className="btn" onClick={onBack}>
                뒤로
              </button>
            )}
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy || t.busy || !!putErr} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : before ? '적용' : '등록'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {changed && <DiffView lines={snap.lines} />}
        {changed && snap.reader && <div className="note wa small">적용하면 이 저장소를 읽던 서버 {snap.reader}가 멈춥니다. 적용한 뒤 서버를 다시 연결해야 받기가 됩니다.</div>}
        {snap.trust.length > 0 && (
          <span className="small">
            적용한 뒤 이미지 신뢰 출처에{' '}
            {snap.trust.map((r, i) => (
              <code key={i} style={{ marginRight: 4 }}>
                {r.registry}/{r.repository}
              </code>
            ))}
            규칙을 추가합니다(이미 있으면 건너뜀).
          </span>
        )}
        <span className="small muted">로그인 정보는 보관함 참조만 보냅니다. 값은 연결된 서버가 받기 직전에만 꺼내 씁니다.</span>
        {putErr ? <div className="note er small">{putErr}</div> : <MutationError error={m.error} />}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && void applied())} />}
        {t.op && <OpPanel op={t.op} onChange={t.setOp} />}
        {(t.error !== undefined || trustErr !== undefined) && (
          <>
            <div className="note wa small">저장소는 등록했지만 신뢰 출처를 추가하지 못했습니다. 신뢰 출처 탭에서 추가하세요.</div>
            <MutationError error={t.error ?? trustErr} />
          </>
        )}
      </div>
    </Dialog>
  );
}

function diffLines(a: Record<string, string> | undefined, b: Record<string, string>): DiffLine[] {
  return Object.keys(b).flatMap((k): DiffLine[] =>
    !a
      ? [{ op: '+' as const, text: `${k}: ${b[k] || '—'}` }]
      : a[k] === b[k]
        ? [{ op: ' ' as const, text: `${k}: ${b[k] || '—'}` }]
        : [
            { op: '-' as const, text: `${k}: ${a[k] || '—'}` },
            { op: '+' as const, text: `${k}: ${b[k] || '—'}` },
          ],
  );
}

function UnregisterDialog({ tenant, r, onClose, onDone }: { tenant: string; r: ExternalRegistry; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const users = usePoll((s) => externalRegistryUsers(tenant, r.id, undefined, s), [tenant, r.id], 0);
  const [snap] = useState(r);
  const [typed, setTyped] = useState('');
  const [dropTrust, setDropTrust] = useState(false);
  const m = useMutation();
  const t = useMutation();
  const rules = trustRules(snap.authority, snap.repository);
  const send = async () => {
    const o = await sendOnce(m, externalRegistryPath(tenant, snap.id), { expected: snap.revision }, 'DELETE');
    if (o?.state === 'applied') await applied();
  };
  const done = useRef(false);
  const applied = async () => {
    if (done.current) return;
    done.current = true;
    onDone();
    toast(`${snap.authority} 등록을 해제했습니다.`);
    if (!dropTrust) return;
    const cur = await imageTrust(tenant);
    const drop = new Set(rules.map((x) => `${x.registry}/${x.repository}`));
    const remove = cur.rules.filter((x) => drop.has(`${x.registry}/${x.repository}`)).map((x) => ({ registry: x.registry, repository: x.repository }));
    if (remove.length) await sendOnce(t, imageTrustPath(tenant), { remove, expected: cur.revision }, 'PATCH');
  };
  const u = users.data?.items ?? [];
  const finished = m.op?.state === 'applied' && (!dropTrust || !!t.op || t.error !== undefined);
  return (
    <Dialog
      danger
      title={`${snap.authority} 등록을 해제할까요?`}
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger" disabled={m.busy || (!uncertain(m) && typed !== snap.authority)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : '등록 해제'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <span>
          {u.length ? `쓰는 곳 ${u.length}${users.data?.next ? '개 이상' : '개'}(${[...new Set(u.map(useLabel))].join(', ')})가 다음 재시작·배포 때 이미지를 받지 못합니다.` : '이 등록으로 받는 이미지를 쓰는 곳이 없습니다.'} 신뢰 출처{' '}
          {rules.map((x) => `${x.registry}/${x.repository}`).join(', ')}도 함께 뺄지 고르세요.
        </span>
        <label className="row small" style={{ gap: 8 }}>
          <input type="checkbox" checked={dropTrust} onChange={(e) => setDropTrust(e.target.checked)} disabled={!!m.op} />
          신뢰 출처에서도 빼기
        </label>
        {!m.op && (
          <Field
            label={
              <>
                확인하려면 <b className="mono">{snap.authority}</b>
                {eulReul(snap.authority)} 입력하세요
              </>
            }
          >
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </Field>
        )}
        <MutationError error={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && void applied())} />}
        {t.op && <OpPanel op={t.op} onChange={t.setOp} />}
        <MutationError error={t.error} />
      </div>
    </Dialog>
  );
}


/**
 * 읽을 서버 연결(bind). 자격이 승인이 필요한 묶음이면 데몬이 원본을 보내지 않고 둔 채 approval-required로 기다린다.
 * 비밀번호는 승인 칸에만 있다가 보낼 때 꺼내고 비운다. 승인이 늦어 sfcd가 거절하면 새 opId로 다시 연결한다.
 */
function BindDialog({ tenant, r, onClose, onDone }: { tenant: string; r: ExternalRegistry; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const nodesQ = usePoll((s) => nodesOverview(s), [], 0);
  const nodes = (nodesQ.data?.nodes ?? []).map((n) => n.id);
  const [node, setNode] = useState('');
  useEffect(() => {
    if (!node && nodes[0]) setNode(nodes[0]);
  }, [nodes, node]);
  const m = useMutation();
  const done = useRef(false);
  const finish = () => {
    if (done.current) return;
    done.current = true;
    toast(`${r.authority}을(를) ${node}에 연결했습니다.`);
    onDone();
  };
  const go = async () => {
    const o = await sendOnce(m, `${externalRegistryPath(tenant, r.id)}/bind`, { node }, 'POST');
    if (o?.state === 'applied') finish();
  };
  const rejected = m.op?.state === 'failed' && m.op.errorCode === 'approval-rejected';
  const waiting = m.op?.state === 'running' && m.op.errorCode === 'approval-required';
  const again = async () => {
    m.reset();
    const o = await m.run(`${externalRegistryPath(tenant, r.id)}/bind`, { node }, 'POST');
    if (o?.state === 'applied') finish();
  };
  const notBindable = m.error instanceof ApiError && m.error.code === 'not-bindable';
  const applied = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${r.authority} 읽을 서버 연결`}
      width={560}
      onClose={onClose}
      footer={
        applied ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose} title={waiting ? '닫아도 비밀값 보관함의 승인 대기에 남습니다' : undefined}>
              {waiting ? '나중에' : '취소'}
            </button>
            {rejected ? (
              <button className="btn primary" disabled={m.busy} onClick={() => void again()}>
                {m.busy ? '보내는 중…' : '↻ 새로 연결'}
              </button>
            ) : (
              <button className="btn primary" disabled={m.busy || !node || waiting || notBindable || !!m.op} onClick={() => void go()}>
                {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : '연결'}
              </button>
            )}
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <span>
          고른 서버 하나가 이 정의로 {r.repository === '**' ? r.authority : `${r.authority}/${r.repository}`}에 로그인해 이미지를 받습니다. 로그인 정보는 그 서버만 보관함에서 꺼내 씁니다.
        </span>
        <Field label="서버" hint={nodesQ.error ? '서버 목록을 읽지 못해 이름을 직접 적습니다' : '그 서버의 배포 권한도 필요합니다'}>
          {nodesQ.error ? (
            <input className="mono" value={node} disabled={!!m.op} onChange={(e) => setNode(e.target.value.trim())} placeholder="node-a" spellCheck={false} autoComplete="off" />
          ) : (
            <select value={node} disabled={!!m.op} onChange={(e) => setNode(e.target.value)}>
              {nodes.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          )}
        </Field>
        {notBindable && <div className="note wa small">지금은 연결할 수 없습니다. 꺼져 있거나, 이미 읽는 서버가 있거나, 해제하는 중입니다. 목록을 새로 읽어 보세요.</div>}
        {!notBindable && <MutationError error={m.error} />}
        {m.op && waiting && <ApprovalPrompt tenant={tenant} op={m.op} kind="registry-bind" source={r.id} onOp={(o) => (m.setOp(o), o.state === 'applied' && finish())} />}
        {m.op && waiting && <span className="small muted">‘나중에’를 누르면 비밀값 보관함의 승인 대기로 남고, 거기서 승인해도 연결이 이어집니다.</span>}
        {m.op && !waiting && !rejected && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && finish())} />}
        {rejected && <div className="note er small">승인이 늦어 연결이 거절됐습니다. 앞서 한 승인의 유효 시간이 그 사이 지났습니다. ‘새로 연결’로 다시 시작하세요.</div>}
      </div>
    </Dialog>
  );
}

function UnbindDialog({ tenant, r, onClose, onDone }: { tenant: string; r: ExternalRegistry; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [snap] = useState(r);
  const m = useMutation();
  const go = async () => {
    const o = await sendOnce(m, `${externalRegistryPath(tenant, snap.id)}/unbind`, { expected: snap.revision }, 'POST');
    if (o?.state === 'applied') {
      toast(`${snap.authority}을(를) 읽던 서버 ${snap.reader?.node ?? ''}의 연결을 해제했습니다.`);
      onDone();
      onClose();
    }
  };
  const notBound = m.error instanceof ApiError && m.error.code === 'not-bound';
  return (
    <Dialog
      title={`${snap.authority} 서버 연결을 해제할까요?`}
      width={420}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={m.busy || notBound} onClick={() => void go()}>
            {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : '연결 해제'}
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 10 }}>
        <span>
          {snap.reader?.node}가 이 저장소 읽기를 멈춥니다. 이미 받아 둔 이미지로 도는 컨테이너는 그대로지만, 다시 연결하기 전까지 이 저장소에서 새로 받을 수 없습니다.
        </span>
        {notBound ? <div className="note wa small">이미 연결이 없거나 해제하는 중입니다.</div> : <MutationError error={m.error} />}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && (onDone(), onClose()))} />}
      </div>
    </Dialog>
  );
}

/**
 * 로그인 정보를 새로 입력해 작업 공간 보관함에 저장한다(vault-create → vault-write 두 단계).
 * 값은 이 칸에만 있다가 보낸 뒤 지운다. 웹은 저장하지 않는다.
 */
function NewLoginSecret({ tenant, taken, suggest, onSaved }: { tenant: string; taken: string[]; suggest: string; onSaved: (id: string) => void }) {
  const [id, setId] = useState(suggest);
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');
  const [made, setMade] = useState<string>();
  const mc = useMutation();
  const mv = useMutation();
  const toast = useToast();
  useEffect(() => () => setPass(''), []);
  const badId = !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(id) ? '소문자·숫자·‘-’' : !made && taken.includes(id) ? '이미 있는 비밀값입니다' : undefined;
  const busy = mc.busy || mv.busy;
  const save = async () => {
    const base = `/t/${encodeURIComponent(tenant)}/vault`;
    if (made !== id) {
      const o = await mc.run(base, { kind: 'secret', id, parent: tenant, keys: ['password', 'username'], profile: 'file' });
      if (o?.state !== 'applied') return;
      setMade(id);
    }
    const o = await mv.run(`${base}/value`, { path: id, keys: ['password', 'username'], values: { username: user, password: pass } });
    if (o?.state !== 'applied') return;
    setPass('');
    setUser('');
    toast(`보관함에 ${id}${eulReul(id)} 저장했습니다. 값은 웹에 남지 않습니다.`);
    onSaved(id);
  };
  return (
    <div className="col" style={{ gap: 10 }}>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 10 }}>
        <Field label="비밀값 이름" error={badId}>
          <input className="mono" value={id} disabled={!!made} onChange={(e) => setId(e.target.value.trim())} spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="사용자 이름">
          <input value={user} onChange={(e) => setUser(e.target.value)} spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="비밀번호 · 토큰">
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
        </Field>
      </div>
      <span className="small muted">작업 공간 보관함의 {id || '…'}에 username · password 두 키로 저장합니다. 보낸 뒤 이 칸을 비웁니다.</span>
      {mc.op?.state !== 'applied' && mc.op && <OpPanel op={mc.op} onChange={mc.setOp} />}
      {mv.op && mv.op.state !== 'applied' && <OpPanel op={mv.op} onChange={mv.setOp} />}
      <MutationError error={mc.error ?? mv.error} />
      <button type="button" className="btn" style={{ width: 'fit-content' }} disabled={busy || !!badId || !user || !pass} onClick={() => void save()}>
        {busy ? '저장 중…' : made ? '값 다시 보내기' : '보관함에 저장'}
      </button>
    </div>
  );
}

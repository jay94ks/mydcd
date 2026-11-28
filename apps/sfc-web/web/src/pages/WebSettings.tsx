// SPDX-License-Identifier: Apache-2.0

// 시스템 › 웹 앱 설정 (UI-C1, 캔버스 WebSettings · WebSettingsIx v109).
// 모두 웹 앱 자체 설정이라 sfcd 몫이 없다. 계약에 아직 없는 칸(개인 키 로그인, 동시 세션, 웹훅·MCP 보관, 웹 앱 정보 일부, 봉인 키 바꾸기)은
// 데몬 응답에 그 칸이 없으면 '웹 기능 준비 중'으로 꺼 두고, 저장할 때도 보내지 않는다(데몬은 모르는 칸을 거절한다).
import { useState, type ReactNode } from 'react';
import { putWebSettings, resetSeal, webSettings } from '../api/endpoints';
import type { DSealStatus, DSettingsReply, DWebSettings } from '../api/dto';
import { Badge, Card, Field, HelpBox, PageHeader, type Tone } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Refresh } from '../components/Refresh';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { WebDataCard, when } from './WebBackup';
import { ProviderLogCard } from './ProviderLog';
import { usePhone } from '../lib/viewport';
import { MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { fmtBytes } from '../lib/format';
import { useUnsaved } from '../components/Unsaved';
import { kindsLive } from '../lib/liveTopics';

const READY = '웹 기능 준비 중';
const SEAL: Record<string, [Tone, string]> = {
  ready: ['ok', '잠김 · 정상'],
  'no-key': ['wa', '봉인 키 없음'],
  'wrong-key': ['er', '키가 맞지 않음'],
  broken: ['er', '파일 손상'],
};
const KIND_NAME: Record<string, string> = {
  ai: 'AI 제공자 키 (Claude · OpenAI)',
  incident: '장애 대응 클러스터 키',
  mcp: 'MCP 서버 토큰',
  webhook: '웹훅 서명 비밀 · 헤더 토큰',
  dns: 'DNS 공급자 토큰 · ACME 계정 키',
  acme: 'ACME 계정 키',
  'deploy-check': '배포 확인 계정 키',
};

export function WebSettingsPage() {
  return usePhone() ? <MWebSettings /> : <DesktopWebSettings />;
}

/** 휴대폰 웹 앱 설정 (UI-M11 ④ 모양): 값은 글자로만, 봉인 값은 보이지 않음 */
function MWebSettings() {
  const q = usePoll((s) => webSettings(s), [], 0, kindsLive('settings'));
  useReadOnlyTop('웹 앱 설정', '시스템 관리자', '봉인 키·백업·로그인·보관 기간 바꾸기는 넓은 화면에서');
  const text = (k: Key, v: unknown) => {
    const f = LOGIN.find((x) => x.key === k);
    const o = f?.options.find(([x]) => x === v);
    if (o) return o[1];
    if (typeof v === 'number') return v === 0 && ZERO_DEFAULT[k] ? `기본 (${daysLabel(ZERO_DEFAULT[k]!)})` : daysLabel(v);
    return v === undefined ? READY : String(v);
  };
  return (
    <Load q={q} what="웹 앱 설정을 읽지 못했습니다">
      {(d) => {
        const [tone, label] = SEAL[d.seal.state] ?? ['er', d.seal.state];
        const files = d.seal.files ?? (d.seal.kinds ?? []).reduce((a, k) => a + k.count, 0);
        return (
          <>
            <div className={`mc${tone === 'er' ? ' xer' : ''}`}>
              <div className="hd">
                <b>봉인 키 · 봉인 파일</b>
                <Badge tone={tone}>{label}</Badge>
              </div>
              <div className="ln">봉인 파일 {files}개{d.seal.next ? ' · 키 바꾸는 중' : ''}</div>
              {d.seal.reason && <div className="ln">{d.seal.reason}</div>}
            </div>
            <MTiles
              items={[
                { label: '웹 데이터', value: fmtBytes(d.info.dbBytes), sub: `스키마 ${d.info.schema}` },
                { label: 'sfcd 연결', value: d.info.connected === false ? '끊김' : '연결됨', sub: d.info.sfcdVersion?.version ?? `웹 ${d.info.version}`, warn: d.info.connected === false },
              ]}
            />
            <div className="m-sec">
              <span>로그인 · 세션</span>
            </div>
            <div className="li">
              {LOGIN.map((f) => (
                <div key={f.key}>
                  <span className="el">{f.label}</span>
                  <span className="r">{text(f.key, d.settings[f.key])}</span>
                </div>
              ))}
            </div>
            <div className="m-sec">
              <span>기록 보관 기간</span>
            </div>
            <div className="li">
              {KEEP.map((f) => (
                <div key={f.label}>
                  <span className="el">{f.label}</span>
                  <span className="r">{f.fixed ?? (f.key ? text(f.key, d.settings[f.key]) : '—')}</span>
                </div>
              ))}
            </div>
          </>
        );
      }}
    </Load>
  );
}

function DesktopWebSettings() {
  const q = usePoll((s) => webSettings(s), [], 0, kindsLive('settings'));
  return (
    <>
      <PageHeader title="웹 앱 설정" ids="UI-C1" actions={<Refresh q={q} poll={false} />} after={<Badge tone="pr">시스템 관리자</Badge>} />
      <HelpBox terms="웹 데이터 (bbolt 파일) · 봉인 파일 (SFC_WEB_SEAL_KEY로 잠근 토큰·키 파일) · 봉인 키">
        <b>이 화면은</b> Seafield Cluster 웹 앱 자신의 설정입니다. 클러스터 설정이 아니라 웹 앱이 따로 가진 데이터(bbolt)와 봉인 파일, 로그인 방식, 기록 보관 기간을 다룹니다. 여기서 바꾼 것은 모두 설정 변경 기록에 남습니다.
      </HelpBox>
      <Load q={q}>
        {(d) => (
          <>
            {/* 같은 줄 카드 높이를 맞추려고 짧은 카드(로그인 · 웹 앱 정보)는 한 칸에 쌓는다 */}
            <div className="grid-2">
              <SealCard seal={d.seal} onChanged={q.refresh} />
              <WebDataCard info={d.info} onChanged={q.refresh} />
              <Settings key={JSON.stringify(d.settings)} d={d} onSaved={q.refresh} aside={<InfoCard info={d.info} />} />
            </div>
            <ProviderLogCard />
          </>
        )}
      </Load>
    </>
  );
}

// ── 봉인 키 · 봉인 파일 ──
function SealCard({ seal, onChanged }: { seal: DSealStatus; onChanged: () => void }) {
  const [dlg, setDlg] = useState<'' | 'rekey' | 'reset'>('');
  const [tone, label] = SEAL[seal.state] ?? ['er', seal.state];
  const kinds = seal.kinds ?? [];
  const files = seal.files ?? kinds.reduce((a, k) => a + k.count, 0);
  const canRekey = seal.fingerprint !== undefined;
  return (
    <Card
      title={
        <div className="row between" style={{ width: '100%' }}>
          <h2>봉인 키 · 봉인 파일</h2>
          <span className="row" style={{ gap: 6 }}>{seal.next && <Badge tone="pr">키 바꾸는 중</Badge>}<Badge tone={tone}>{label}</Badge></span>
        </div>
      }
    >
      <dl className="kv2 c120" style={{ fontSize: 13 }}>
        <dt>봉인 키</dt>
        <dd>
          {seal.keySource === undefined ? (
            <span className="muted">{READY} (키 출처·지문)</span>
          ) : (
            <>
              {seal.keySource === 'env' ? (
                <>
                  환경 변수 <span className="mono">SFC_WEB_SEAL_KEY</span>에서 받음
                </>
              ) : (
                '키 파일에서 받음'
              )}
              {seal.fingerprint && (
                <>
                  {' '}
                  · 지문 <span className="mono">{seal.fingerprint}</span>
                </>
              )}
            </>
          )}
        </dd>
        <dt>봉인 파일</dt>
        <dd className="mono">{seal.dir ? `${seal.dir} · 파일 ${files}개` : `파일 ${files}개`}</dd>
      </dl>
      {!seal.ready && (
        <div className={`note ${seal.state === 'no-key' ? 'wa' : 'er'} small`}>
          봉인 파일을 열 수 없습니다. SFC_WEB_SEAL_KEY가 없거나 다릅니다{seal.reason ? ` (${seal.reason})` : ''}. AI·MCP·웹훅·DNS 기능이 꺼진 채로 시작했습니다. 키를 되찾을 수 없으면 봉인 파일 초기화 후 값을 다시 넣으세요.
        </div>
      )}
      <div className="ltbl">
        <div className="srow th">
          <span>봉인 파일에 든 것</span>
          <span>개수</span>
          <span>마지막으로 바뀜</span>
        </div>
        {kinds.length === 0 && (
          <div className="srow">
            <span className="muted">아직 없음</span>
            <span />
            <span />
          </div>
        )}
        {kinds.map((k) => (
          <div key={k.kind} className="srow">
            <span>{KIND_NAME[k.kind] ?? k.kind}</span>
            <span>{k.count}</span>
            <span>{k.modified ? when(k.modified) : '—'}</span>
          </div>
        ))}
      </div>
      <span className="muted small">값은 이 화면에서도 보이지 않습니다. 봉인 키를 잃으면 이 값들은 되살릴 수 없고 다시 넣어야 합니다. 웹 데이터 백업에는 봉인 파일이 들어가지 않습니다.</span>
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        {!seal.ready && seal.state !== 'no-key' && (
          <button type="button" className="btn danger" onClick={() => setDlg('reset')}>
            봉인 파일 초기화…
          </button>
        )}
        <button type="button" className="btn" disabled={!canRekey} title={seal.fingerprint === undefined ? READY : undefined} onClick={() => setDlg('rekey')}>
          봉인 키 바꾸기…
        </button>
      </div>
      {dlg === 'rekey' && <RekeyDialog seal={seal} onClose={() => setDlg('')} />}
      {dlg === 'reset' && <ResetDialog seal={seal} onClose={() => setDlg('')} onDone={onChanged} />}
    </Card>
  );
}

function RekeyDialog({ seal, onClose }: { seal: DSealStatus; onClose: () => void }) {
  const next = seal.next;
  return (
    <Dialog
      title="봉인 키 바꾸기"
      onClose={onClose}
      footer={
        <button type="button" className="btn primary" onClick={onClose}>
          닫기
        </button>
      }
    >
      <ol className="steps3">
        <li className={next ? 'done' : 'on'}>새 키 넣고 다시 시작</li>
        <li className={next ? 'on' : ''}>시작할 때 다시 봉인</li>
        <li>옛 키 버리기</li>
      </ol>
      <p style={{ margin: 0 }}>
        봉인 키는 화면에서 바꾸지 않습니다. 웹 앱 컨테이너에 새 키를 <span className="mono">SFC_WEB_SEAL_KEY_NEXT</span>로 더 넣고 다시 시작하면, 웹 앱이 시작할 때 봉인 파일 {seal.files ?? 0}개를 새 키로 다시 잠급니다.
      </p>
      <dl className="kv2 c120" style={{ fontSize: 13 }}>
        <dt>지금 키 지문</dt>
        <dd className="mono">{seal.fingerprint ?? '—'}</dd>
        <dt>새 키 지문</dt>
        <dd>
          {next ? (
            <>
              <span className="mono">{next.fingerprint}</span> <Badge tone="pr">키 바꾸는 중</Badge>
            </>
          ) : (
            <span className="muted">없음 · SFC_WEB_SEAL_KEY_NEXT가 아직 없습니다</span>
          )}
        </dd>
      </dl>
      {next && (
        <div className="note info small">
          새 키로 다시 잠갔습니다. 이제 <span className="mono">SFC_WEB_SEAL_KEY</span>를 새 키 값으로 바꾸고 <span className="mono">SFC_WEB_SEAL_KEY_NEXT</span>를 지운 뒤 웹 앱을 다시 시작하세요.
        </div>
      )}
      <span className="muted small">지문은 키 해시의 앞뒤 몇 글자입니다. 키 값은 화면에 나오지 않습니다. 백업 파일도 봉인 키로 잠기므로, 옛 키로 만든 백업을 되살리려면 그 키가 필요합니다.</span>
    </Dialog>
  );
}

function ResetDialog({ seal, onClose, onDone }: { seal: DSealStatus; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const kinds = seal.kinds ?? [];
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await resetSeal();
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      danger
      title="봉인 파일을 초기화할까요?"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger solid" disabled={typed !== 'secrets' || busy} onClick={() => void go()}>
            {busy ? '지우는 중…' : '초기화'}
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>
        {kinds.length ? kinds.map((k) => `${(KIND_NAME[k.kind] ?? k.kind).split(' (')[0]} ${k.count}`).join(', ') + '을(를) 지웁니다.' : '봉인 파일을 모두 지웁니다.'} 그 설정은 남고 값만 비어 “다시 넣기 필요”로 표시됩니다.
      </p>
      <Field label={<>확인하려면 <span className="mono">secrets</span>을(를) 입력하세요</>}>
        <input value={typed} onChange={(e) => setTyped(e.target.value)} />
      </Field>
      {error !== undefined && <ErrorBand error={error} what="초기화하지 못했습니다" />}
    </Dialog>
  );
}

// ── 로그인 · 세션 / 기록 보관 기간 (설정 한 묶음) ──
type Key = keyof DWebSettings;
const opts = (vals: number[], label: (v: number) => string) => vals.map((v) => [v, label(v)] as [number, string]);
const daysLabel = (d: number) => (d % 365 === 0 ? `${d / 365}년` : `${d}일`);
// 0이면 데몬 기본값을 쓰는 칸 (#114)
const ZERO_DEFAULT: Partial<Record<Key, number>> = { webhookDeliveryRetentionDays: 30, mcpCallRetentionDays: 90, trashRetentionDays: 7 };
const DAYS = [7, 14, 30, 60, 90, 180, 365, 730, 1825, 3650];
const LOGIN: { key: Key; label: string; options: [number | boolean, string][] }[] = [
  { key: 'sessionIdleMinutes', label: '쓰지 않으면 끊김', options: opts([0, 15, 30, 60, 120, 240, 480, 1440], (v) => (v === 0 ? '끊지 않음' : v % 60 === 0 ? `${v / 60}시간` : `${v}분`)) },
  { key: 'sessionMaxHours', label: '최대 세션 길이', options: opts([0, 1, 4, 8, 12, 24, 72, 168, 720], (v) => (v === 0 ? 'sfcd 세션 만료를 따름' : v % 24 === 0 ? `${v / 24}일` : `${v}시간`)) },
  {
    key: 'allowKeyLogin',
    label: '개인 키 로그인 (브라우저 키)',
    options: [
      [true, '허용'],
      [false, '허용 안 함'],
    ],
  },
  { key: 'maxSessionsPerUser', label: '한 사용자 동시 세션', options: opts([0, 1, 2, 3, 5, 10, 20, 50], (v) => (v === 0 ? '제한 없음' : `${v}개`)) },
];
const KEEP: { key?: Key; label: string; min?: number; max?: number; fixed?: string }[] = [
  { key: 'notificationRetentionDays', label: '알림' },
  { key: 'webhookDeliveryRetentionDays', label: '웹훅 전송 기록' },
  { key: 'auditRetentionDays', label: '웹 설정 변경 기록', min: 30 },
  { key: 'mcpCallRetentionDays', label: 'MCP 도구 호출 기록' },
  { key: 'opRetentionDays', label: '작업 기록 · 끝난 로그인 기록' },
  { key: 'trashRetentionDays', label: '지운 것 (작업 기록 › 지운 것)', max: 30 },
  { label: '코디네이터 대화 · 장애 대응 기록', fixed: '사용자가 지울 때까지 (고정)' },
  { label: '보관된 앱 (내린 앱의 app.yaml)', fixed: '완전 삭제할 때까지 (고정)' },
];

function Settings({ d, onSaved, aside }: { d: DSettingsReply; onSaved: () => void; aside?: ReactNode }) {
  const toast = useToast();
  const cur = d.settings;
  const has = (k: Key) => cur[k] !== undefined;
  const [draft, setDraft] = useState<DWebSettings>({ ...cur });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [shrink, setShrink] = useState<{ label: string; from: number; to: number }[]>();
  const dirty = (Object.keys(cur) as Key[]).some((k) => draft[k] !== cur[k]);
  const loginDirty = LOGIN.some((f) => has(f.key) && draft[f.key] !== cur[f.key]);
  const changed = (Object.keys(cur) as Key[]).filter((k) => draft[k] !== cur[k]).length;
  const un = useUnsaved({ dirty: dirty && !busy, what: '웹 앱 설정', count: changed, noDraft: '설정 몇 칸이라 초안을 남기지 않습니다. 나가면 바꾼 값이 사라집니다.' });
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      // 데몬이 준 칸만 보낸다
      await putWebSettings(Object.fromEntries((Object.keys(cur) as Key[]).map((k) => [k, draft[k]])) as unknown as DWebSettings);
      toast('웹 앱 설정을 저장했습니다.');
      setShrink(undefined);
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const ask = () => {
    const eff = (k: Key, v: unknown) => ((v as number) === 0 && ZERO_DEFAULT[k] ? ZERO_DEFAULT[k]! : (v as number));
    const less = KEEP.filter((r) => r.key && has(r.key) && eff(r.key, draft[r.key]) < eff(r.key, cur[r.key])).map((r) => ({ label: r.label, from: eff(r.key!, cur[r.key!]), to: eff(r.key!, draft[r.key!]) }));
    if (less.length) setShrink(less);
    else void save();
  };
  const select = (k: Key, options: [number | boolean, string][], style?: React.CSSProperties) => {
    const v = draft[k];
    const all = v === undefined || options.some(([o]) => o === v) ? options : [...options, [v, typeof v === 'number' ? `${v}` : String(v)] as [number | boolean, string]];
    return (
      <select
        style={style}
        value={v === undefined ? '' : String(v)}
        disabled={!has(k) || busy}
        title={has(k) ? undefined : READY}
        onChange={(e) => {
          const raw = e.target.value;
          setDraft({ ...draft, [k]: raw === 'true' ? true : raw === 'false' ? false : Number(raw) });
        }}
      >
        {!has(k) && <option value="">{READY}</option>}
        {all.map(([o, l]) => (
          <option key={String(o)} value={String(o)}>
            {l}
          </option>
        ))}
      </select>
    );
  };
  const saveBtn = (
    <button type="button" className="btn primary" disabled={!dirty || busy} onClick={ask}>
      {busy ? '저장 중…' : '변경 저장'}
    </button>
  );
  return (
    <>
      {un.guard}
      <Card title="기록 보관 기간">
        <div className="ltbl">
          <div className="srow two th">
            <span>기록</span>
            <span>보관</span>
          </div>
          {KEEP.map((r) => (
            <div key={r.label} className="srow two">
              <span>{r.label}</span>
              {r.fixed ? <span className="muted">{r.fixed}</span> : select(r.key!, [...(ZERO_DEFAULT[r.key!] ? [[0, `기본값 (${daysLabel(ZERO_DEFAULT[r.key!]!)})`] as [number, string]] : []), ...opts((r.max ? [1, 3, 7, 14, 30] : DAYS).filter((x) => x >= (r.min ?? 1) && x <= (r.max ?? Infinity)), daysLabel)], { height: 30 })}
            </div>
          ))}
        </div>
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          {un.badge}
          {saveBtn}
        </div>
        {error !== undefined && <ErrorBand error={error} what="설정을 저장하지 못했습니다" />}
      </Card>
      <div className="card-stack">
        <Card title="로그인 · 세션">
          <div className="row2" style={{ gap: 12 }}>
            {LOGIN.map((f) => (
              <Field key={f.key} label={f.label} hint={has(f.key) ? undefined : READY}>
                {select(f.key, f.options)}
              </Field>
            ))}
          </div>
          <span className="muted small">비밀번호와 키 검사는 클러스터(sfcd)가 합니다. 웹 앱은 세션 시간만 정합니다. 쓰지 않으면 끊김은 자동 새로고침을 활동으로 세지 않습니다.</span>
          {loginDirty && <div className="row" style={{ justifyContent: 'flex-end' }}>{saveBtn}</div>}
        </Card>
        {aside}
      </div>
      {shrink && (
        <Dialog
          title={shrink.length === 1 ? `${shrink[0].label} 보관을 ${daysLabel(shrink[0].from)} → ${daysLabel(shrink[0].to)}로 줄일까요?` : '보관 기간을 줄일까요?'}
          onClose={() => setShrink(undefined)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setShrink(undefined)}>
                취소
              </button>
              <button type="button" className="btn primary" disabled={busy} onClick={() => void save()}>
                줄이기
              </button>
            </>
          }
        >
          {shrink.map((x) => (
            <p key={x.label} style={{ margin: 0 }}>
              {daysLabel(x.to)}이 지난 {x.label}{shrink.length > 1 ? `(${daysLabel(x.from)} → ${daysLabel(x.to)})` : ''}은 다음 정리 때(매시간) 지워집니다.
            </p>
          ))}
        </Dialog>
      )}
    </>
  );
}

// ── 웹 앱 정보 ──
function InfoCard({ info }: { info: DSettingsReply['info'] }) {
  const ready = (v: ReactNode | undefined) => (v === undefined || v === null || v === '' ? <span className="muted">{READY}</span> : v);
  return (
    <Card title="웹 앱 정보">
      <dl className="kv2" style={{ gridTemplateColumns: '140px minmax(0, 1fr)', fontSize: 13 }}>
        <dt>웹 앱 버전</dt>
        <dd className="mono">sfc-web {info.version}</dd>
        <dt>클러스터 연결</dt>
        <dd>
          <span className="mono">{info.socket}</span> {info.connected ? <Badge tone="ok">연결됨</Badge> : <Badge tone="er">끊김</Badge>}
          {info.sfcdVersion ? (
            <span title={[info.sfcdVersion.commit && `commit ${info.sfcdVersion.commit}`, info.sfcdVersion.buildTime && `빌드 ${new Date(info.sfcdVersion.buildTime).toLocaleString('ko-KR')}`].filter(Boolean).join(' · ') || undefined}>
              {' '}
              · sfcd <span className="mono">{info.sfcdVersion.version}</span> <span className="muted">(SFCP {info.sfcdVersion.protocol})</span>
            </span>
          ) : (
            <span className="muted"> · sfcd 판: 서버 기능 대기</span>
          )}
        </dd>
        <dt>웹 데이터</dt>
        <dd>
          schema {info.schema}
          {info.dbPath ? (
            <>
              {' '}
              · <span className="mono">{info.dbPath}</span>
            </>
          ) : null}
        </dd>
        <dt>컨테이너</dt>
        <dd>{ready(info.container && `${info.container.tenant} / ${info.container.app} / ${info.container.service}-${info.container.instance} · ${info.container.node}`)}</dd>
      </dl>
    </Card>
  );
}

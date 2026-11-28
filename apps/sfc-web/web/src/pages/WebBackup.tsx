// SPDX-License-Identifier: Apache-2.0

// 웹 앱 설정 › 웹 데이터 카드 (UI-C1, 캔버스 WebSettings · WebSettingsIx v108).
// 자동 백업 일정·실행은 웹 데몬 몫(계약 요청 중), 데이터 저장소 파일 쓰기·위임은 sfcd REQ-28이다.
// 백업 목록·지우기·위임은 로그인한 사용자 권한으로 낸다. 백업 파일에 비밀번호·키·봉인 값은 없다.
import { useEffect, useRef, useState } from 'react';
import { api, API_MODE, ApiError, noEndpoint } from '../api/client';
import { autoBackup, cancelRestore, userIdOf, fileGrantsPath, putAutoBackup, restoreFrom, runAutoBackup, tenantList, volumeFilePath, volumeFileUrl, volumeFiles, volumes } from '../api/endpoints';
import type { DVolumeFile } from '../api/dto';
import type { AutoBackupView as DAutoBackup } from '../api/endpoints';
import { useAuth } from '../auth/session';
import { Badge, Card, Field } from '../components/ui';
import { ErrorBand } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { fmtBytes } from '../lib/format';
import { iGa } from '../lib/josa';
import { usePoll } from '../lib/usePoll';
import { AutomationRow, AutomationWizard, useAutomation } from './Automation';
import { volumesLive } from '../lib/liveTopics';

const PREFIX = 'sfc-web-backups/';
const pad = (n: number) => String(n).padStart(2, '0');
/** 오늘 03:00 · 어제 03:00 · 11월 20일 */
export function when(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(new Date()) - day(d)) / 86400_000);
  if (diff === 0) return `오늘 ${hm}`;
  if (diff === 1) return `어제 ${hm}`;
  if (diff === -1) return `내일 ${hm}`;
  return `${d.getMonth() + 1}월 ${d.getDate()}일`;
}
const baseName = (p: string) => p.split('/').pop() ?? p;
const WAIT = '자동 백업 · 백업 목록 · 폴더 위임: 서버 기능 대기. 지금 백업 · 내려받기 · 되살리기(파일 올리기)는 지금 됩니다.';

type Info = { version: string; schema: number; dbBytes: number; restorePending: boolean };

export function WebDataCard({ info, onChanged }: { info: Info; onChanged: () => void }) {
  const toast = useToast();
  const ab = usePoll((s) => autoBackup(s), [], 0);
  const missing = !!ab.error && noEndpoint(ab.error);
  const a = ab.data;
  const [dlg, setDlg] = useState<'' | 'edit' | 'list' | 'restore' | 'automation'>('');
  const au = useAutomation();
  const [restoreFile, setRestoreFile] = useState<DVolumeFile>();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<unknown>();
  const run = async () => {
    setRunning(true);
    setError(undefined);
    try {
      await runAutoBackup();
      toast('백업을 시작했습니다. 끝나면 마지막 백업이 바뀝니다.');
      ab.refresh();
    } catch (e) {
      setError(e);
    } finally {
      setRunning(false);
    }
  };
  // 도는 동안만 2초마다 다시 읽는다
  useEffect(() => ab.setInterval(a?.running ? 2000 : 0), [a?.running]); // eslint-disable-line react-hooks/exhaustive-deps
  const cancel = async () => {
    setError(undefined);
    try {
      await cancelRestore();
      onChanged();
    } catch (e) {
      setError(e);
    }
  };
  const off = missing || !a;
  const offWhy = missing ? '서버 기능 대기' : ab.error ? '자동 백업 설정을 읽지 못했습니다' : undefined;
  const failed = a?.last && !a.last.ok;
  const sealOff = a?.sealReady === false;
  const SEAL_OFF = '봉인 키가 준비되지 않아 백업하거나 자동 백업에서 되살릴 수 없습니다';
  return (
    <Card
      title={
        <div className="row between" style={{ width: '100%' }}>
          <h2>웹 데이터 (bbolt)</h2>
          <span className="muted small">web.db · {fmtBytes(info.dbBytes)}</span>
        </div>
      }
    >
      <dl className="kv2 c120" style={{ fontSize: 13 }}>
        <dt>자동 백업</dt>
        <dd>
          {missing ? (
            <span className="muted">서버 기능 대기</span>
          ) : !a ? (
            <span className="muted">{ab.error ? '설정을 읽지 못했습니다' : '읽는 중…'}</span>
          ) : a.enabled && a.volume ? (
            <>
              매일 {a.at} · 작업 공간 {a.tenant}의 데이터 저장소 <span className="mono">{a.volume}</span> 폴더 <span className="mono">{a.prefix}</span> · {a.keep}개 보관
            </>
          ) : (
            <span className="muted">꺼짐{a.volume ? ` · 마지막 설정: ${a.tenant}/${a.volume}` : ' · 데이터 저장소를 아직 고르지 않았습니다'}</span>
          )}
        </dd>
        <dt>자동 작업 계정</dt>
        <dd>
          <AutomationRow q={au} />
        </dd>
        <dt>폴더 위임</dt>
        <dd>
          {!a ? (
            <span className="muted">—</span>
          ) : !a.account ? (
            <span className="muted">자동 작업 계정 · 서버 기능 대기</span>
          ) : (
            <>
              자동 작업 계정 <span className="mono">{a.account.username}</span> · 이 폴더만{' '}
              {a.granted === undefined ? <Badge tone="un">확인 못 함</Badge> : a.granted ? <Badge tone="ok">위임됨</Badge> : <Badge tone="wa">위임 없음</Badge>}
            </>
          )}
        </dd>
        <dt>마지막 백업</dt>
        <dd>
          {a?.last ? (
            <>
              {when(a.last.at)} {a.last.ok ? <Badge tone="ok">성공</Badge> : <Badge tone="er">실패</Badge>}
              {a.last.bytes ? ` · ${fmtBytes(a.last.bytes)}` : ''}
              {a.last.by ? ` · ${a.last.by}` : ''}
            </>
          ) : (
            <span className="muted">—</span>
          )}
        </dd>
        <dt>들어 있는 것</dt>
        <dd>보관된 앱 · 대화 · 장애 대응 기록 · 지침 · 웹훅 · MCP 서버 · DNS·인증서 설정 · 알림 · 사용자별 설정</dd>
        <dt>들어 있지 않은 것</dt>
        <dd>비밀번호 · 개인 키 · 세션 키 · 비밀값 보관함 값 · 클러스터 상태 사본</dd>
        <dt>보호</dt>
        <dd>{a?.sealed === false ? '봉인하지 않음' : '데이터 저장소의 백업은 웹 봉인 키로 암호화합니다. 저장소를 읽을 수 있는 사람도 내용은 볼 수 없습니다. 다른 설치로 옮기려면 SFC_WEB_SEAL_KEY를 같은 값으로 넣어야 합니다.'}</dd>
      </dl>
      {failed && (
        <div className="note er small row between wrap">
          <span>
            {when(a.last!.at)} 자동 백업 실패 · {a.last!.error ? failText(a.last!.error) : '이유를 받지 못했습니다'}
            {a.next ? ` 다음 시도는 ${when(a.next)}입니다.` : ''}
          </span>
          <button type="button" className="btn sm" disabled={running || sealOff} title={sealOff ? SEAL_OFF : undefined} onClick={() => void run()}>
            지금 다시 시도
          </button>
        </div>
      )}
      {info.restorePending && (
        <div className="note wa small row between wrap">
          <span>
            <b>되살리기 대기</b> · 웹 서버를 다시 시작하면 고른 백업으로 바뀝니다. 지금 데이터는 web.db.before-restore-… 파일로 남습니다.
          </span>
          <button type="button" className="btn sm" onClick={() => void cancel()}>
            되살리기 취소
          </button>
        </div>
      )}
      <div className="row wrap" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button type="button" className="btn" disabled={!!au.error && noEndpoint(au.error)} title={au.error && noEndpoint(au.error) ? '서버 기능 대기' : undefined} onClick={() => setDlg('automation')}>
          자동 작업 계정 켜기…
        </button>
        <button type="button" className="btn" disabled={off} title={offWhy} onClick={() => setDlg('edit')}>
          자동 백업 바꾸기…
        </button>
        <button type="button" className="btn" disabled={off || !a?.volume} title={offWhy ?? (!a?.volume ? '자동 백업을 먼저 정하세요' : undefined)} onClick={() => setDlg('list')}>
          백업 목록
        </button>
        <button type="button" className="btn" disabled={off || !a?.volume || running || !!a?.running || sealOff} title={offWhy ?? (!a?.volume ? '데이터 저장소를 먼저 고르세요' : sealOff ? SEAL_OFF : undefined)} onClick={() => void run()}>
          {running || a?.running ? '백업 중…' : '지금 백업'}
        </button>
        {API_MODE === 'mock' ? (
          <button type="button" className="btn" disabled title="목업에는 내려받을 파일이 없습니다">
            내려받기
          </button>
        ) : (
          <a className="btn" href="/api/v1/system/backup" download="web.db" onClick={() => toast('웹 데이터를 내려받습니다. 비밀번호·키·봉인 값은 들어 있지 않습니다.')}>
            내려받기
          </a>
        )}
        <button type="button" className="btn" disabled={info.restorePending} title={info.restorePending ? '되살리기 대기 중입니다' : undefined} onClick={() => (setRestoreFile(undefined), setDlg('restore'))}>
          백업에서 되살리기…
        </button>
      </div>
      {sealOff && <div className="note wa small">{SEAL_OFF}. 위의 봉인 키 · 봉인 파일 카드에서 SFC_WEB_SEAL_KEY를 확인하세요. 파일을 올려 되살리기는 됩니다.</div>}
      {missing && <span style={{ color: 'var(--faint)', fontSize: 12 }}>{WAIT}</span>}
      {error !== undefined && (sealError(error) ? <div className="note er small">{sealError(error)}</div> : <ErrorBand error={error} what="처리하지 못했습니다" />)}
      {dlg === 'automation' && <AutomationWizard cur={au.data} onClose={() => (setDlg(''), void au.refresh(), void ab.refresh())} />}
      {dlg === 'edit' && a && <AutoBackupDialog cur={a} onClose={() => setDlg('')} onSaved={ab.refresh} />}
      {dlg === 'list' && a && (
        <BackupListDialog
          cfg={a}
          onClose={() => setDlg('')}
          onRestore={(f) => (setRestoreFile(f), setDlg('restore'))}
        />
      )}
      {dlg === 'restore' && <RestoreDialog cfg={missing ? undefined : a} initial={restoreFile} schema={info.schema} onClose={() => setDlg('')} onDone={onChanged} />}
    </Card>
  );
}

/** 봉인 때문에 막힌 요청 (#112: run·restore-from 503 seal-unavailable, restore-from 422 seal-key) */
const sealError = (e: unknown) =>
  e instanceof ApiError && e.code === 'seal-unavailable'
    ? '봉인 키가 준비되지 않아 처리하지 못했습니다. SFC_WEB_SEAL_KEY를 확인하고 웹 앱을 다시 시작하세요.'
    : e instanceof ApiError && e.code === 'seal-key'
      ? '이 웹의 봉인 키로 풀리지 않는 백업입니다. 그 백업을 만든 설치의 SFC_WEB_SEAL_KEY를 같은 값으로 넣어야 되살릴 수 있습니다.'
      : undefined;

/** 데몬이 영어로 준 실패 이유 중 잘 아는 것만 우리말로 */
const failText = (e: string) =>
  /seal|decrypt|cipher/i.test(e)
    ? `봉인 키가 맞지 않아 백업을 읽거나 쓸 수 없습니다. (${e})`
    : e === 'automation-account-missing'
    ? '사람 없이 돌 자동 작업 계정이 아직 없어 예정 시각에 쓰지 못했습니다(아직 지원하지 않는 기능). 지금 백업을 눌러 주세요.'
    : /no space|quota|capacity/i.test(e)
    ? `데이터 저장소의 공간이 부족합니다. 보관 개수를 줄이거나 저장소 한도를 늘리세요. (${e})`
    : /grant|denied|forbidden/i.test(e)
      ? `자동 작업 계정이 이 폴더에 쓸 수 없습니다. 계정이 그 작업 공간의 구성원인지 확인하고 '자동 백업 바꾸기…'에서 다시 위임하세요. (${e})`
      : e;

// ── 자동 백업 바꾸기 · 끄기 ──
function AutoBackupDialog({ cur, onClose, onSaved }: { cur: DAutoBackup; onClose: () => void; onSaved: () => void }) {
  const { session } = useAuth();
  const toast = useToast();
  const [on, setOn] = useState(cur.enabled || !cur.volume);
  const [at, setAt] = useState(cur.at || '03:00');
  const [keep, setKeep] = useState(String(cur.keep || 14));
  const [tenant, setTenant] = useState(cur.tenant || session?.tenants[0]?.id || '');
  const [volume, setVolume] = useState(cur.volume ?? '');
  const [confirmOff, setConfirmOff] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  /** 저장했지만 위임할 수 없었다(관리자가 아님) */
  const [notManager, setNotManager] = useState(false);
  const m = useMutation();
  const tenants = usePoll((s) => tenantList(s), [], 0);
  const vols = usePoll((s) => (tenant ? volumes(tenant, s) : Promise.resolve(undefined)), [tenant], 0, volumesLive(tenant));
  const fixed = (vols.data?.items ?? []).filter((v) => v.kind === 'fixed' && !v.app);
  useEffect(() => {
    if (vols.data && !fixed.some((v) => v.name === volume)) setVolume(fixed[0]?.name ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vols.data]);
  const role = session?.tenants.find((t) => t.id === tenant)?.role;
  const manager = role === 'manager';
  const sameTarget = cur.tenant === tenant && cur.volume === volume;
  const needGrant = on && !!cur.account && !(sameTarget && cur.granted);
  const k = Number(keep);
  const problem = !/^([01]\d|2[0-3]):[0-5]\d$/.test(at) ? '시각을 HH:MM으로' : !Number.isInteger(k) || k < 1 || k > 365 ? '보관 개수는 1~365' : !tenant || !volume ? '작업 공간과 데이터 저장소를 고르세요' : undefined;

  const save = async (enabled: boolean, opts: { revoke?: boolean } = {}) => {
    setBusy(true);
    setError(undefined);
    try {
      // 관리자가 아니면 위임을 못 하므로 일정만 꺼진 채로 둔다
      const grantable = !needGrant || manager;
      await putAutoBackup({ enabled: enabled && grantable, at, keep: k, tenant, volume });

      onSaved();
      if (enabled && needGrant && !manager) {
        setNotManager(true);
        return;
      }
      if (enabled && needGrant && cur.account) {
        const op = await m.run(fileGrantsPath(tenant, volume), { prefix: PREFIX, user: cur.account.id || (await userIdOf(cur.account.username)) });
        onSaved();
        if (op?.state !== 'applied') return; // 작업 상태를 창에 보여 준다
      }
      if (!enabled && opts.revoke && cur.account && cur.tenant && cur.volume) {
        const op = await m.run(fileGrantsPath(cur.tenant, cur.volume), { prefix: PREFIX, user: cur.account.id || (await userIdOf(cur.account.username)) }, 'DELETE');
        onSaved();
        if (op?.state !== 'applied') return;
      }
      toast(enabled ? '자동 백업을 저장했습니다.' : '자동 백업을 껐습니다. 이미 만든 백업은 남습니다.');
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const submit = () => (!on && cur.enabled ? setConfirmOff(true) : void save(on));

  if (confirmOff)
    return (
      <Dialog
        title="자동 백업을 끌까요?"
        onClose={onClose}
        footer={
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={busy || m.busy} onClick={() => void save(false, { revoke })}>
              {busy ? '끄는 중…' : '끄기'}
            </button>
          </>
        }
      >
        <p style={{ margin: 0 }}>더 이상 매일 백업하지 않습니다. 이미 만든 백업은 데이터 저장소에 남습니다.</p>
        {cur.account && (
          <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
            <input type="checkbox" checked={revoke} onChange={(e) => setRevoke(e.target.checked)} disabled={cur.tenant ? session?.tenants.find((t) => t.id === cur.tenant)?.role !== 'manager' : true} />
            <span>
              자동 작업 계정의 폴더 위임도 거두기
              <span className="muted small" style={{ display: 'block' }}>
                {cur.tenant} 관리자 서명이 필요합니다
              </span>
            </span>
          </label>
        )}
        {error !== undefined && <ErrorBand error={error} what="끄지 못했습니다" />}
        <MutationError error={m.error} />
        {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
      </Dialog>
    );

  return (
    <Dialog
      title="자동 백업"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {notManager ? '닫기' : '취소'}
          </button>
          {!notManager && (
            <button type="button" className="btn primary" disabled={busy || m.busy || (on && !!problem)} title={on ? problem : undefined} onClick={submit}>
              {busy ? '저장하는 중…' : needGrant ? '위임하고 저장' : '저장'}
            </button>
          )}
        </>
      }
    >
      <label className="row" style={{ gap: 8 }}>
        <input type="checkbox" checked={on} onChange={(e) => setOn(e.target.checked)} />
        매일 자동 백업
      </label>
      <div className="row2">
        <Field label="시각" hint="웹 서버 시각">
          <input type="time" value={at} onChange={(e) => setAt(e.target.value)} disabled={!on} />
        </Field>
        <Field label="보관 개수" hint="넘으면 오래된 것부터 지움">
          <input type="number" min={1} max={365} value={keep} onChange={(e) => setKeep(e.target.value)} disabled={!on} />
        </Field>
      </div>
      <div className="row2">
        <Field label="작업 공간">
          <select value={tenant} onChange={(e) => setTenant(e.target.value)} disabled={!on}>
            {!(tenants.data ?? []).some((t) => t.id === tenant) && tenant && <option value={tenant}>{tenant}</option>}
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}
              </option>
            ))}
          </select>
        </Field>
        <Field label="데이터 저장소" hint="고정 데이터 저장소만" error={vols.data && !fixed.length ? '이 작업 공간에 앱에 딸리지 않은 고정 데이터 저장소가 없습니다' : undefined}>
          <select value={volume} onChange={(e) => setVolume(e.target.value)} disabled={!on || !fixed.length}>
            {fixed.map((v) => (
              <option key={v.name} value={v.name}>
                {v.name}
                {v.retain ? ' · 남김' : ''}
                {v.capacityBytes && v.usedBytes !== undefined ? ` · ${fmtBytes(Math.max(0, v.capacityBytes - v.usedBytes))} 여유` : v.capacityBytes ? ` · 용량 ${fmtBytes(v.capacityBytes)}` : ''}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="폴더" hint="바꿀 수 없음">
        <input className="mono" value={PREFIX} readOnly disabled />
      </Field>
      <div className="note info small">
        <b>자동 작업 계정에 이 폴더만 위임합니다.</b> 사람이 없는 시간에 돌도록 웹 앱의 자동 작업 계정{' '}
        {cur.account ? (
          <>
            <span className="mono">{cur.account.username}</span>
            {iGa(cur.account.username)}
          </>
        ) : (
          '자동 작업 계정(아직 지원하지 않음)이'
        )}{' '}
        이 데이터 저장소의 <span className="mono">{PREFIX}</span> 아래에서만 목록·쓰기·지우기를 합니다. 다른 폴더와 다른 저장소는 서버가 거절합니다. 위임은 그 작업 공간의 관리자만 할 수 있어 저장하면 서명을 한 번 더 받습니다. 자동 작업 계정은 그 작업 공간의 구성원(보기 이상)이어야 위임을 받을 수 있고, 구성원이 아니면 서버가 거절합니다. 백업 파일은 봉인 키로 암호화해 저장소를 읽는 사람도 내용을 볼 수 없고, 비밀번호·키·봉인 값은 들어 있지 않습니다.{!cur.account && ' 자동 작업 계정이 생기기 전에는 예정 시각에 쓰지 못하고 알림으로 알려 드립니다. 그때는 지금 백업을 눌러 주세요.'}
      </div>
      {notManager && (
        <div className="note wa small">
          작업 공간 {tenant}의 관리자가 아니라 위임할 수 없습니다. 일정은 저장했고 자동 백업은 꺼져 있습니다. {tenant} 관리자에게 이 화면에서 ‘위임하고 저장’을 눌러 달라고 하세요.
        </div>
      )}
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && (onSaved(), onClose()))} />}
      {m.op?.action === 'volume-file-grant' && (m.op.state === 'failed' || m.op.state === 'rejected') && /forbidden|denied/i.test(m.op.errorCode ?? '') && (
        <div className="note wa small">
          자동 작업 계정 <span className="mono">{cur.account?.username}</span>
          {iGa(cur.account?.username ?? '')} 작업 공간 {tenant}의 구성원이 아니어서 위임을 받지 못했습니다. 작업 공간 › 구성원에서 그 계정을 보기 이상으로 넣은 뒤 다시 저장하세요.
        </div>
      )}
    </Dialog>
  );
}

// ── 백업 목록 ──
function BackupListDialog({ cfg, onClose, onRestore }: { cfg: DAutoBackup; onClose: () => void; onRestore: (f: DVolumeFile) => void }) {
  const list = usePoll((s) => volumeFiles(cfg.tenant!, cfg.volume!, cfg.prefix || PREFIX, s), [cfg.tenant, cfg.volume], 0);
  const [del, setDel] = useState<DVolumeFile>();
  const [more, setMore] = useState(false);
  const files = [...(list.data ?? [])].sort((a, b) => (a.modifiedAt < b.modifiedAt ? 1 : -1));
  const shown = more ? files : files.slice(0, 10);
  const total = files.reduce((s, f) => s + f.bytes, 0);
  return (
    <>
      <Dialog
        width={720}
        title={
          <>
            자동 백업 · {cfg.volume}/{cfg.prefix || PREFIX}
          </>
        }
        onClose={onClose}
        footer={
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        }
      >
        {list.error ? (
          <ErrorBand error={list.error} what={list.error instanceof ApiError && list.error.status === 403 ? `작업 공간 ${cfg.tenant}의 데이터 저장소를 읽을 권한이 없습니다` : '백업 목록을 읽지 못했습니다'} />
        ) : !list.data ? (
          <span className="muted small">목록을 읽는 중…</span>
        ) : !files.length ? (
          <span className="muted small">아직 백업이 없습니다.</span>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>파일</th>
                  <th style={{ width: 100 }}>크기</th>
                  <th style={{ width: 120 }}>만든 때</th>
                  <th style={{ width: 48 }} />
                </tr>
              </thead>
              <tbody>
                {shown.map((f) => (
                  <tr key={f.path}>
                    <td className="mono" title={f.path}>
                      {baseName(f.path)}
                    </td>
                    <td>{fmtBytes(f.bytes)}</td>
                    <td className="muted">{when(f.modifiedAt)}</td>
                    <td>
                      <Menu
                        label={`${baseName(f.path)} 메뉴`}
                        items={[
                          { label: '내려받기', onSelect: () => window.open(volumeFileUrl(cfg.tenant!, cfg.volume!, f.path), '_blank', 'noopener') },
                          { label: '이것으로 되살리기…', onSelect: () => onRestore(f) },
                          { label: '지우기…', danger: true, onSelect: () => setDel(f) },
                        ]}
                      />
                    </td>
                  </tr>
                ))}
                {!more && files.length > shown.length && (
                  <tr>
                    <td colSpan={4}>
                      <button type="button" className="linkish small" onClick={() => setMore(true)}>
                        … {files.length - shown.length}개 더
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {list.data && (
          <span className="muted small">
            {files.length}개 · {fmtBytes(total)}. 데이터 저장소에서 바로 읽으며 웹 데이터에 따로 적어 두지 않습니다.
          </span>
        )}
      </Dialog>
      {del && <DeleteBackupDialog cfg={cfg} file={del} onClose={() => setDel(undefined)} onDone={list.refresh} />}
    </>
  );
}

function DeleteBackupDialog({ cfg, file, onClose, onDone }: { cfg: DAutoBackup; file: DVolumeFile; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const done = m.op?.state === 'applied';
  // 결과를 모를 때(응답 유실 502 volume-file-unknown, 연결 끊김, 진행 중)만 같은 opId로 이어 간다. 다른 거절은 새 opId로.
  const uncertain = (m.error !== undefined && !(m.error instanceof ApiError && m.error.code !== 'volume-file-unknown')) || (m.op && ['unknown', 'pending', 'running'].includes(m.op.state));
  const path = volumeFilePath(cfg.tenant!, cfg.volume!);
  const send = () => (uncertain ? m.again() : (m.error !== undefined && m.reset(), m.run(path, { path: file.path }, 'DELETE')));
  // 없는 파일은 404다. 이미 지워진 것이므로 목록만 새로 고친다.
  const gone = m.error instanceof ApiError && m.error.status === 404;
  useEffect(() => {
    if (done || gone) onDone();
  }, [done, gone, onDone]);
  const name = baseName(file.path);
  return (
    <Dialog
      danger
      title="이 백업을 지울까요?"
      onClose={onClose}
      footer={
        done || gone ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy || m.op?.state === 'failed' || m.op?.state === 'rejected'} onClick={() => void send()}>
              {m.busy ? '지우는 중…' : '지우기'}
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>
        <span className="mono">{name}</span> ({fmtBytes(file.bytes)})를 데이터 저장소에서 지웁니다. 되돌릴 수 없습니다.
      </p>
      {gone ? <div className="note info small">이 파일은 이미 없습니다. 목록을 새로 고쳤습니다.</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 백업에서 되살리기 ──
function RestoreDialog({ cfg, initial, schema, onClose, onDone }: { cfg?: DAutoBackup; initial?: DVolumeFile; schema: number; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const canList = !!cfg?.volume && cfg.sealReady !== false;
  const [src, setSrc] = useState<'auto' | 'file'>(initial || canList ? 'auto' : 'file');
  const list = usePoll((s) => (canList && src === 'auto' ? volumeFiles(cfg!.tenant!, cfg!.volume!, cfg!.prefix || PREFIX, s) : Promise.resolve(undefined)), [src, cfg?.tenant, cfg?.volume], 0);
  const files = [...(list.data ?? [])].sort((a, b) => (a.modifiedAt < b.modifiedAt ? 1 : -1));
  const [path, setPath] = useState(initial?.path ?? '');
  useEffect(() => {
    if (!path && files[0]) setPath(files[0].path);
  }, [files, path]);
  const picked = files.find((f) => f.path === path) ?? (initial?.path === path ? initial : undefined);
  const fileRef = useRef<HTMLInputElement>(null);
  const [upload, setUpload] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      if (src === 'auto') await restoreFrom({ tenant: cfg!.tenant!, volume: cfg!.volume!, path });
      else await api.upload('/system/restore', upload!);
      toast('되살리기를 예약했습니다. 웹 서버를 다시 시작하면 바뀝니다.');
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const ready = src === 'auto' ? !!picked : !!upload;
  return (
    <Dialog
      title="웹 데이터 되살리기"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger solid" disabled={!ready || busy} onClick={() => void go()}>
            {busy ? (src === 'file' ? '올리는 중…' : '보내는 중…') : '되살리기'}
          </button>
        </>
      }
    >
      <Field label="백업" hint="자동 백업 목록 또는 파일 올리기" group>
        <div className="row wrap" style={{ gap: 12, fontSize: 13 }}>
          <label className="row" style={{ gap: 6 }}>
            <input type="radio" name="src" checked={src === 'auto'} disabled={!canList} onChange={() => setSrc('auto')} />
            자동 백업{!cfg?.volume ? ' (아직 지원하지 않음)' : cfg.sealReady === false ? ' (봉인 키 준비 안 됨)' : ''}
          </label>
          <label className="row" style={{ gap: 6 }}>
            <input type="radio" name="src" checked={src === 'file'} onChange={() => setSrc('file')} />
            파일 올리기
          </label>
        </div>
        {src === 'auto' ? (
          list.error ? (
            <ErrorBand error={list.error} what="자동 백업 목록을 읽지 못했습니다" />
          ) : (
            <select aria-label="자동 백업" value={path} onChange={(e) => setPath(e.target.value)} disabled={!files.length && !initial}>
              {initial && !files.some((f) => f.path === initial.path) && (
                <option value={initial.path}>
                  자동 백업 · {when(initial.modifiedAt)} · {fmtBytes(initial.bytes)}
                </option>
              )}
              {files.map((f) => (
                <option key={f.path} value={f.path}>
                  자동 백업 · {when(f.modifiedAt)} · {fmtBytes(f.bytes)}
                </option>
              ))}
            </select>
          )
        ) : (
          <input ref={fileRef} type="file" aria-label="백업 파일" onChange={(e) => setUpload(e.target.files?.[0])} />
        )}
        <span className="muted small">{src === 'file' ? '최대 512 MiB · ' : ''}지금 웹 데이터 형식 schema {schema}. 형식이 맞지 않는 파일은 서버가 거절합니다.</span>
      </Field>
      <div className="note wa small">
        지금 웹 데이터를 이 백업으로 바꿉니다. 그 뒤에 생긴 대화·기록·설정은 사라집니다. 웹 앱이 다음에 시작할 때 이 백업으로 바뀝니다. 지금 데이터는 <span className="mono">web.db.before-restore-…</span> 파일로 남고, 다시 시작하기 전까지는 대기를 취소할 수 있습니다. 자동 백업은 웹 봉인 키로 암호화돼 있어, 다른 설치에서 만든 백업이면 SFC_WEB_SEAL_KEY를 그 설치와 같은 값으로 넣어야 합니다. 봉인 파일과 클러스터는 건드리지 않습니다.
      </div>
      {error !== undefined && (sealError(error) ? <div className="note er small">{sealError(error)}</div> : <ErrorBand error={error} what="되살리기를 예약하지 못했습니다" />)}
    </Dialog>
  );
}

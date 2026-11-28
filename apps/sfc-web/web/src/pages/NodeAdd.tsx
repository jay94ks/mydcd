// SPDX-License-Identifier: Apache-2.0

// 서버 › 서버 추가 마법사 (UI-13, 캔버스 NodeAdd · NodeAddIx). 시스템 관리자 전용.
// 계약: docs/reference/web-api.md "서버 추가 (UI-13)". 가입 명부·초대 서명·승인 판단은 sfcd가 맡고 웹은 아무것도 저장하지 않는다.
// 진행 단계는 GET /nodes 행의 join(invited → learner → ready → promoting → active)에서 읽는다. 창을 닫았다가 다시 열어도 이어진다.
import { useState, type ReactNode } from 'react';
import { API_MODE, ApiError, api, apiUrl } from '../api/client';
import { invitationPath, invitationSummary, nodesOverview } from '../api/endpoints';
import type { NodeView } from '../api/types';
import { Badge, Field } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { eulReul } from '../lib/josa';
import { usePoll } from '../lib/usePoll';
import { serversMeasured } from '../lib/liveTopics';

const JOIN: Record<string, [string, 'pr' | 'wa' | 'ok' | 'un']> = {
  invited: ['초대함 · 새 서버 가입 대기', 'pr'],
  learner: ['가입함 · 설치 확인 대기', 'pr'],
  ready: ['설치 확인됨 · 승격할 수 있음', 'ok'],
  promoting: ['투표 서버로 올리는 중', 'pr'],
  active: ['참여 중', 'ok'],
};
/** 마법사로 이어 할 수 있는 가입 단계 */
/** 가입이 아직 안 끝났다. ready는 설치 확인이 끝난 투표권 없는 서버의 자리(승격은 선택)라 가입 중이 아니다(membership: ready·active·demoting·moving은 가입 끝) */
export const joinInProgress = (n: NodeView) => n.join === 'invited' || n.join === 'learner' || n.join === 'promoting';

const ID_RE = /^[a-z][a-z0-9-]{0,62}$/;
const EP_RE = /^([a-z0-9.-]+|\[[0-9a-f:]+\]):\d{1,5}$/i;
const KEY_RE = /^[0-9a-f]{64}$/;
export function keyError(k: string): string | undefined {
  if (!k) return undefined;
  const bad = [...new Set(k.replace(/[0-9a-f]/g, ''))];
  if (k.length === 64 && !bad.length) return undefined;
  return `64자리 16진수가 아닙니다 (${k.length}자${bad.length ? `, 허용되지 않는 글자 ${bad.slice(0, 3).join(' ')}` : ''})`;
}

function Cmd({ text, who }: { text: string; who?: string }) {
  const toast = useToast();
  return (
    <div style={{ position: 'relative' }}>
      <pre className="mono" style={{ margin: 0, padding: '10px 12px', background: '#16191F', color: '#E8EAED', borderRadius: 6, whiteSpace: 'pre', overflowX: 'auto', lineHeight: '19px', fontSize: 12 }}>
        {text}
      </pre>
      <button
        type="button"
        className="btn sm"
        style={{ position: 'absolute', right: 6, top: 6, height: 26, fontSize: 11, background: '#22262D', color: '#E8EAED', borderColor: '#3A3F48' }}
        onClick={() => void navigator.clipboard?.writeText(text).then(() => toast(who ? `명령을 복사했습니다. 새 서버(${who})의 셸에 붙여 넣으세요.` : '명령을 복사했습니다.'))}
      >
        복사
      </button>
    </div>
  );
}

function Step({ n, done, title, where, children }: { n: number; done: boolean; title: string; where: string; children: ReactNode }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '28px minmax(0,1fr)', gap: 10 }}>
      <span style={{ width: 24, height: 24, borderRadius: 12, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, background: done ? 'var(--ok-strong)' : 'var(--accent)', color: '#fff' }}>{done ? '✓' : n}</span>
      <div className="col" style={{ gap: 6, minWidth: 0 }}>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <b style={{ fontSize: 14 }}>{title}</b>
          <span style={{ fontSize: 11, background: 'var(--un-bg)', borderRadius: 999, padding: '1px 8px', color: 'var(--text-2)' }}>{where}</span>
        </div>
        {children}
      </div>
    </div>
  );
}

export function AddServerWizard({ initial, onClose }: { initial?: string; onClose: () => void }) {
  const toast = useToast();
  const [node, setNode] = useState(initial);
  const nodes = usePoll((s) => nodesOverview(s), [], 5000, serversMeasured);
  const row = node ? nodes.data?.nodes.find((n) => n.id === node) : undefined;
  const join = row?.join;
  const sum = usePoll((s) => (node && (join === 'invited' || join === 'learner' || join === 'ready') ? invitationSummary(node, s) : Promise.resolve(undefined)), [node, join]);
  const [f, setF] = useState({ id: '', endpoint: '', key: '', joinId: '' });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((x) => ({ ...x, [k]: e.target.value.trim() }));
  const joinId = f.joinId || (f.id ? `join-${f.id}` : '');
  const m = useMutation();
  const [got, setGot] = useState(false);
  const [promote, setPromote] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const id = node ?? f.id;
  const ok = ID_RE.test(f.id) && EP_RE.test(f.endpoint) && KEY_RE.test(f.key) && ID_RE.test(joinId) && joinId !== 'genesis';
  const invite = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run('/nodes', { id: f.id, endpoint: f.endpoint, publicKey: f.key, joinId });
    if (o?.state === 'applied') done();
  };
  const done = () => {
    setNode(f.id);
    void nodes.refresh();
    toast(`${f.id} 가입을 승인했습니다. 3단계에서 초대 파일을 받으세요.`);
  };
  const s2 = !!row;
  const past = (j: string) => ['invited', 'learner', 'ready', 'promoting', 'active'].indexOf(join ?? '') >= ['invited', 'learner', 'ready', 'promoting', 'active'].indexOf(j);
  const canGet = join === 'invited' || join === 'learner' || join === 'ready';
  const file = `${id || '<이름>'}.invitation.json`;
  const download = async () => {
    if (!node) return;
    if (API_MODE === 'mock') {
      // 목업은 fetch를 가로채므로 본문을 받아 파일로 만든다(실제 데몬은 서명된 원문 그대로 받는다)
      const body = await api.get<unknown>(invitationPath(node));
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(body)], { type: 'application/json' }));
      a.download = `sfc-invitation-${node}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } else {
      const a = document.createElement('a');
      a.href = apiUrl(invitationPath(node));
      a.download = `sfc-invitation-${node}.json`;
      a.click();
    }
    setGot(true);
    toast(`${node} 초대 파일을 내려받았습니다. 웹은 보관하지 않으며, 다시 받으면 같은 내용입니다.`);
  };
  const copyInvite = async () => {
    if (!node) return;
    try {
      const r = API_MODE === 'mock' ? JSON.stringify(await api.get<unknown>(invitationPath(node))) : await (await fetch(apiUrl(invitationPath(node)), { credentials: 'same-origin' })).text();
      await navigator.clipboard?.writeText(r);
      setGot(true);
      toast('초대를 복사했습니다. 새 서버에 그대로 파일로 저장하세요.');
    } catch {
      toast('초대를 복사하지 못했습니다. 내려받기를 쓰세요.');
    }
  };
  const inProgress = !!row && join !== 'active';
  return (
    <Dialog
      title={
        <span className="col" style={{ gap: 2 }}>
          <b style={{ fontSize: 16 }}>서버 추가</b>
          <span className="muted" style={{ fontSize: 12, fontWeight: 400 }}>
            웹에서 할 일과 새 서버에서 실행할 CLI 명령을 순서대로 안내합니다
          </span>
        </span>
      }
      width={720}
      onClose={() => (inProgress ? setLeaving(true) : onClose())}
      footer={
        <>
          <span className="small muted" style={{ marginRight: 'auto' }}>
            가입 승인·초대 서명은 클러스터가 하고 웹은 아무것도 보관하지 않습니다.
          </span>
          {inProgress && (
            <button type="button" className="btn" onClick={() => setLeaving(true)}>
              나중에 이어 하기
            </button>
          )}
          <button type="button" className="btn primary" onClick={() => (inProgress ? setLeaving(true) : onClose())}>
            닫기
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 18 }}>
        <Step n={1} done={s2 || ok} title="새 서버에서 서버 신원 만들기" where={`새 서버${id ? ` (${id})` : ''}`}>
          <Cmd text="sfcli identity create /var/lib/sfc/identity" who={id || undefined} />
          <span className="muted small">출력된 64자리 공개키 HEX를 아래 칸에 붙여 넣으세요. 개인키는 새 서버에 그대로 둡니다.</span>
        </Step>
        <Step n={2} done={s2} title="가입 승인 (투표권 없음)" where="웹에서 · 시스템 관리자">
          {row ? (
            <div className="small">
              <b>{row.id}</b> · <code>{row.endpoint}</code> · 공개키 <code>{row.key ? `${row.key.slice(0, 8)}…${row.key.slice(-4)}` : '—'}</code> {join && JOIN[join] && <Badge tone={JOIN[join][1]}>{JOIN[join][0]}</Badge>}
            </div>
          ) : (
            <>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 10 }}>
                <Field label="서버 이름" error={f.id && !ID_RE.test(f.id) ? '소문자로 시작, 소문자·숫자·-' : nodes.data?.nodes.some((n) => n.id === f.id) ? '이미 쓰는 이름입니다' : undefined}>
                  <input value={f.id} onChange={set('id')} disabled={!!m.op} placeholder="node-d" spellCheck={false} autoComplete="off" />
                </Field>
                <Field label="접속 주소 (HOST:PORT)" error={f.endpoint && !EP_RE.test(f.endpoint) ? 'host:port' : undefined}>
                  <input className="mono" value={f.endpoint} onChange={set('endpoint')} disabled={!!m.op} placeholder="192.168.10.14:7443" spellCheck={false} autoComplete="off" />
                </Field>
                <div style={{ gridColumn: '1 / -1' }}>
                  <Field label="서버 공개키 (HEX)" error={keyError(f.key)}>
                    <input className="mono" value={f.key} onChange={set('key')} disabled={!!m.op} spellCheck={false} autoComplete="off" />
                  </Field>
                </div>
                <Field label="가입 ID" hint={f.joinId ? undefined : '비우면 join-<서버 이름>'} error={f.joinId && (!ID_RE.test(f.joinId) || f.joinId === 'genesis') ? '소문자로 시작, 소문자·숫자·- (genesis 불가)' : undefined}>
                  <input className="mono" value={f.joinId} onChange={set('joinId')} disabled={!!m.op} placeholder={f.id ? `join-${f.id}` : 'join-node-d'} spellCheck={false} autoComplete="off" />
                </Field>
              </div>
              <div className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
                <span className="muted small">CLI로 하려면:</span>
                <button type="button" className="btn primary" disabled={!ok || m.busy || !!m.op} onClick={() => void invite()}>
                  {m.busy ? '보내는 중…' : '가입 승인'}
                </button>
              </div>
              <Cmd text={`sfcli node add ${f.id || '<이름>'} \\\n  --endpoint ${f.endpoint || '<host:port>'} \\\n  --public-key ${f.key || '<공개키>'} \\\n  --join-id ${joinId || '<가입 ID>'}`} />
              {m.error !== undefined && (m.error instanceof ApiError && m.error.code === 'exists' ? <div className="note er small">이미 쓰는 이름·공개키·접속 주소·가입 ID입니다. 다른 값을 고르세요.</div> : <MutationError error={m.error} />)}
              {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && done())} />}
            </>
          )}
        </Step>
        <Step n={3} done={got || past('learner')} title="초대 파일 받기" where="웹에서">
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <button type="button" className="btn primary" disabled={!canGet} title={canGet ? undefined : row ? '초대 파일은 가입 대기·설치 확인 단계에서만 받을 수 있습니다' : '먼저 가입을 승인하세요'} onClick={() => void download()}>
              초대 파일 내려받기 ({file})
            </button>
            <button type="button" className="btn" disabled={!canGet} onClick={() => void copyInvite()}>
              초대 복사
            </button>
          </div>
          <span className="muted small">
            초대 파일은 그대로 새 서버의 <span className="mono">/etc/sfc/{file}</span>로 옮깁니다. 내용을 고치거나 설명을 덧붙이지 마세요.
          </span>
          <Cmd text={`sfcli node invitation ${id || '<이름>'} > ${file}`} />
        </Step>
        <Step n={4} done={past('learner')} title="새 서버에서 가입하고 실행" where={`새 서버${id ? ` (${id})` : ''}`}>
          <Cmd
            who={id || undefined}
            text={`sfcd --config /etc/sfc/node.yaml join \\\n  --cluster ${sum.data?.cluster ?? '<클러스터 ID>'} \\\n  --source-public-key ${sum.data?.source.key ?? '<서명 서버 공개키>'} \\\n  --invitation /etc/sfc/${file}\nsfcd --config /etc/sfc/node.yaml run`}
          />
          <span className="muted small">
            {sum.data ? (
              <>
                클러스터 ID와 서명 서버({sum.data.source.id}, {sum.data.source.endpoint}) 공개키는 이 클러스터 값으로 미리 채워 두었습니다. <b>다른 경로로 받은 서버 공개키와 한 번 대조하세요.</b>
              </>
            ) : (
              '가입을 승인하면 클러스터 ID와 서명 서버 공개키를 채웁니다.'
            )}{' '}
            성공하면 <span className="mono">status: Joined · voter: false</span>가 나옵니다.
          </span>
        </Step>
        <Step n={5} done={join === 'active' && !!row?.voter} title="설치 확인 후 투표 서버로 승격 (선택)" where="웹에서">
          <div className="row" style={{ justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
            {join ? <Badge tone={JOIN[join]?.[1] ?? 'un'}>{join === 'ready' ? '설치 확인됨' : join === 'active' ? (row?.voter ? '투표 서버' : '참여 중') : `${JOIN[join]?.[0] ?? join} · 자동으로 갱신`}</Badge> : <span className="muted small">가입을 승인하면 진행 상태가 보입니다.</span>}
            <button type="button" className="btn" disabled={join !== 'ready'} title={join === 'ready' ? undefined : '설치 확인(ready) 뒤에 올릴 수 있습니다'} onClick={() => setPromote(true)}>
              투표 서버로 승격
            </button>
          </div>
        </Step>
      </div>
      {promote && row && <PromoteDialog row={row} voters={nodes.data?.voters ?? 0} onClose={() => setPromote(false)} onDone={() => void nodes.refresh()} />}
      {leaving && (
        <Dialog
          title="나중에 이어 할까요?"
          width={420}
          onClose={() => setLeaving(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setLeaving(false)}>
                계속 하기
              </button>
              <button type="button" className="btn primary" onClick={onClose}>
                닫기
              </button>
            </>
          }
        >
          <span className="small muted">지금까지의 단계는 클러스터에 남아 있습니다. 서버 목록의 {id} 줄에서 '가입 이어 하기'로 이 창을 다시 열 수 있습니다.</span>
        </Dialog>
      )}
    </Dialog>
  );
}

function PromoteDialog({ row, voters, onClose, onDone }: { row: NodeView; voters: number; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [typed, setTyped] = useState('');
  const next = voters + 1;
  const tol = (n: number) => Math.floor((n - 1) / 2);
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`/nodes/${encodeURIComponent(row.id)}/promote`, row.joinRevision ? { expected: row.joinRevision } : {});
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${row.id}${eulReul(row.id)} 투표 서버로 올릴까요?`}
      danger
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy || typed !== row.id} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '승격'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {voters > 0 && (
          <div>
            투표 서버가 {voters} → {next}대가 됩니다. 과반은 {Math.floor(next / 2) + 1}대이고 견딜 수 있는 장애는 {tol(next)}대{tol(next) === tol(voters) ? ' 그대로' : ''}입니다.
            {next % 2 === 0 ? ' 홀수를 권합니다.' : ''}
          </div>
        )}
        <Field
          label={
            <>
              확인하려면 <b className="mono">{row.id}</b>
              {eulReul(row.id)} 입력하세요
            </>
          }
        >
          <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
        </Field>
        {m.error !== undefined && (m.error instanceof ApiError && m.error.code === 'not-ready' ? <div className="note wa small">아직 설치 확인(ready)이 아닙니다. 잠시 뒤 다시 하세요.</div> : <MutationError error={m.error} />)}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

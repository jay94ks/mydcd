// SPDX-License-Identifier: Apache-2.0

// 서버 상세 › 방화벽 설정 탭 (UI-1G, 캔버스 v263 NodeFirewall · NodeFirewallIx). 시스템 관리자만.
// 계약: docs/reference/web-api/05-section.md node-firewall 행, docs/reference/node-firewall.md (#740).
// Raft 없이 그 서버가 바로 적용한다. 변경은 읽은 revision과 바꿀 것(delta)만 보내고, 응답은 늘 200에 code로 실패를 알린다.
import { useEffect, useRef, useState } from 'react';
import { ApiError, newOpId } from '../api/client';
import type { DFirewall, DFirewallChange, DFirewallDelta, DFirewallResult, DFirewallRule } from '../api/dto';
import { nodeFirewall, nodeFirewallChange, nodeFirewallLog, users } from '../api/endpoints';
import { Dialog } from '../components/Dialog';
import { Refresh } from '../components/Refresh';
import { Load } from '../components/states';
import { useToast } from '../components/Toast';
import { Badge, Card, Field, HelpBox } from '../components/ui';
import { dayTime } from '../lib/format';
import { iGa } from '../lib/josa';
import { ACTION_TEXT, MAX_COMMENT, PROTO_TEXT, deltaText, needsPorts, prefixError, ruleErrors, ruleKey, ruleText } from '../lib/firewallRules';
import { usePoll } from '../lib/usePoll';

/** 잠금 규칙 이름 → [규칙, 왜] (캔버스 잠금 규칙 카드). '열림'은 서버가 준 포트로 채운다 */
const LOCKED: Record<string, [string, string, string?]> = {
  established: ['이미 맺은 연결 · 관련 연결', 'conntrack ESTABLISHED, RELATED', '모두'],
  loopback: ['루프백 (lo)', '서버 안 통신', '모두'],
  'icmpv6-neighbor': ['IPv6 이웃 탐색', '망 진단과 IPv6 동작', 'ICMPv6 이웃 탐색 · packet-too-big'],
  sfcp: ['SFCP', '다른 서버·원격 CLI 접속 (node.yaml node.listen)'],
  'keep-open': ['운영자 접속 보장', 'node.yaml firewall.keep_open · 원격에서 못 바꿈'],
  'sfc-devices': ['sfcd 장치', '가상 브릿지·TUN 패킷은 격리 규칙이 따로 판정', 'md* · TUN'],
  ingress: ['외부 접속 입구', '이 서버가 맡은 외부 접속 경로 · 설정이 바뀌면 같이 바뀜'],
};

/** 캔버스 잠금 규칙 카드의 줄 순서 */
const LOCKED_ORDER = ['established', 'loopback', 'icmpv6-neighbor', 'sfcp', 'keep-open', 'sfc-devices', 'ingress'];

/** 같은 이름의 잠금 규칙(keep_open 여러 개, 입구 80·443)은 한 줄로 묶는다 */
export function lockedRows(locked: DFirewall['locked']): { name: string; label: string; open: string; why: string }[] {
  const out: { name: string; label: string; open: string; why: string }[] = [];
  for (const l of locked) {
    const port = l.proto && l.port ? `${l.proto}/${l.port}` : undefined;
    const row = out.find((r) => r.name === l.name);
    if (row) {
      if (port) row.open = row.open ? `${row.open} · ${port}` : port;
      continue;
    }
    const [label, why, fixed] = LOCKED[l.name] ?? [l.name, l.reason];
    out.push({ name: l.name, label, why, open: fixed ?? port ?? '' });
  }
  const at = (n: string) => (LOCKED_ORDER.includes(n) ? LOCKED_ORDER.indexOf(n) : LOCKED_ORDER.length);
  return out.sort((a, b) => at(a.name) - at(b.name));
}

const CODE_TEXT: Record<string, string> = {
  'not-managed': '이 서버는 방화벽을 제어하지 않습니다.',
  invalid: '규칙이나 정책이 올바르지 않습니다.',
  duplicate: '이미 같은 규칙이 있습니다.',
  'too-many': '이 서버의 규칙이 256개라 더 넣을 수 없습니다.',
  missing: '없는 규칙입니다. 다른 사람이 먼저 지웠을 수 있습니다.',
  'operation-conflict': '같은 작업 ID로 다른 변경을 보냈습니다. 다시 적용하세요.',
};

type Outcome = { kind: 'done' } | { kind: 'band'; tone: 'warn' | 'err'; text: string } | { kind: 'failed' };

/** 변경 하나 보내기. 같은 변경을 다시 보낼 때(연결이 끊겨 결과를 모를 때)는 같은 opId를 쓴다 */
function useFirewallChange(node: string, onChanged: () => void) {
  const toast = useToast();
  const opId = useRef(newOpId());
  const [busy, setBusy] = useState(false);
  const send = async (revision: number, delta: DFirewallDelta): Promise<Outcome> => {
    setBusy(true);
    try {
      const r: DFirewallResult = await nodeFirewallChange(node, { opId: opId.current, revision, ...delta });
      opId.current = newOpId();
      if (!r.code) {
        toast(`✓ ${node} 방화벽에 적용했습니다 · revision ${r.firewall?.revision ?? r.change?.to ?? ''}`);
        onChanged();
        return { kind: 'done' };
      }
      onChanged();
      if (r.code === 'revision') {
        const now = r.firewall?.revision;
        let who = '다른 사람';
        try {
          const last = (await nodeFirewallLog(node)).log?.[0];
          if (last) who = (await loadUserNames()).get(last.user) ?? last.user;
        } catch {
          /* 누가 바꿨는지 못 읽어도 알린다 */
        }
        return { kind: 'band', tone: 'warn', text: `${who}${iGa(who)} 먼저 바꿔서 적용하지 않았습니다 (revision ${revision} → ${now ?? '?'}). 새 규칙을 다시 읽었습니다. 확인하고 다시 적용하세요.` };
      }
      if (r.code === 'apply-failed') {
        toast(`! 적용 실패: ${r.error ?? 'iptables 오류'}. 이전 규칙이 그대로 적용되어 있습니다`, 'er', 10_000);
        return { kind: 'failed' };
      }
      return { kind: 'band', tone: r.code === 'duplicate' ? 'warn' : 'err', text: `${CODE_TEXT[r.code] ?? '바꾸지 못했습니다.'}${r.error ? ` (${r.error})` : ''}` };
    } catch (e) {
      // 연결이 끊겨 결과를 모를 수 있다: opId를 그대로 두어 다시 보내도 한 번만 적용되게 한다
      if (e instanceof ApiError && e.code === 'unavailable') toast(`! ${node}에 연결되어 있지 않아 바꾸지 못했습니다`, 'er', 10_000);
      else toast(`! 바꾸지 못했습니다: ${e instanceof Error ? e.message : String(e)}`, 'er', 10_000);
      return { kind: 'failed' };
    } finally {
      setBusy(false);
    }
  };
  return { send, busy };
}

/** 기록의 user는 사용자 ID다. 사용자 목록을 한 번 읽어 이름으로 바꾼다(못 읽으면 ID 그대로) */
let userList: Promise<Map<string, string>> | undefined;
const loadUserNames = () =>
  (userList ??= users()
    .then((p) => new Map(p.items.map((u) => [u.id, u.username])))
    .catch(() => {
      userList = undefined;
      return new Map<string, string>();
    }));
function useUserNames() {
  const [m, setM] = useState<Map<string, string>>();
  useEffect(() => {
    let alive = true;
    void loadUserNames().then((x) => alive && setM(x));
    return () => {
      alive = false;
    };
  }, []);
  return (id: string) => m?.get(id) ?? id;
}

export function FirewallTab({ node }: { node: string }) {
  const q = usePoll((s) => nodeFirewall(node, s), [node], 0);
  const [logKey, setLogKey] = useState(0);
  const changed = () => {
    q.refresh();
    setLogKey((k) => k + 1);
  };
  return (
    <div className="col" style={{ gap: 16 }}>
      <HelpBox terms="방화벽 (iptables · ip6tables) · 잠금 규칙 (자동, 지울 수 없음) · 기본 정책 · 서버에 원래 있던 규칙 (운영자 규칙)">
        <b>이 화면은</b> 이 서버로 들어오는 연결 규칙입니다. 서버에 원래 있던 규칙은 그대로 두고, 그 앞에서 먼저 판정하는 규칙을 더합니다. 규칙은 이 서버에만 바로 적용되고, 누가 무엇을 바꿨는지만 클러스터에 기록됩니다. 서버의 node.yaml에서 방화벽 제어를 켠 서버만 바꿀 수 있습니다.
      </HelpBox>
      <Load q={q} what="방화벽 설정을 읽지 못했습니다">
        {(r) => (r.firewall?.managed ? <Managed node={node} fw={r.firewall} q={q} logKey={logKey} onChanged={changed} /> : <NotManaged />)}
      </Load>
    </div>
  );
}

function NotManaged() {
  return (
    <div className="col" style={{ gap: 10 }}>
      <div className="bn info">
        <b>이 서버는 방화벽을 제어하지 않습니다.</b> 서버의 node.yaml에 <span className="mono">firewall: {'{managed: true}'}</span>를 넣고 sfcd를 다시 시작하면 여기서 바꿀 수 있습니다. 운영자 접속 포트는 <span className="mono">keep_open</span>(기본 tcp/22)으로 항상 열립니다.
      </div>
      <span className="small muted">끄면 sfcd가 넣은 한 줄과 자기 규칙만 지웁니다. 서버에 원래 있던 규칙은 건드리지 않습니다.</span>
    </div>
  );
}

type RuleDlg = { kind: 'add' } | { kind: 'edit'; rule: DFirewallRule } | { kind: 'delete'; rule: DFirewallRule } | { kind: 'drop' };

function Managed({ node, fw, q, logKey, onChanged }: { node: string; fw: DFirewall; q: Parameters<typeof Refresh>[0]['q']; logKey: number; onChanged: () => void }) {
  const [dlg, setDlg] = useState<RuleDlg>();
  const [policy, setPolicy] = useState(fw.policy ?? 'return');
  const [band, setBand] = useState<Extract<Outcome, { kind: 'band' }>>();
  const ch = useFirewallChange(node, onChanged);
  const max = fw.maxRules ?? 256;
  const current = fw.policy ?? 'return';
  useEffect(() => setPolicy(current), [current]);
  const allows = fw.rules.some((r) => r.action === 'allow');
  const applyPolicy = async () => {
    setBand(undefined);
    const o = await ch.send(fw.revision, { policy });
    if (o.kind === 'band') setBand(o);
  };
  const locked = lockedRows(fw.locked);
  return (
    <>
      <div className="row between small muted" style={{ flexWrap: 'wrap', gap: 8 }}>
        <span>제어 켜짐 (node.yaml firewall.managed) · revision {fw.revision} · IPv4·IPv6에 같이 적용 · 시스템 관리자만 바꿀 수 있음</span>
        <span className="row" style={{ gap: 12 }}>
          <span>
            규칙 {fw.rules.length} / {max}
          </span>
          <Refresh q={q} poll={false} />
        </span>
      </div>
      {!fw.applied && (
        <div className="bn err">
          저장된 규칙을 이 서버에 적용하지 못했습니다{fw.applyError ? `: ${fw.applyError}` : ''}. 커널에는 이전 규칙이 남아 있습니다. 규칙을 고치거나 다시 적용하세요.
        </div>
      )}
      {band && <div className={`bn ${band.tone}`}>{band.text}</div>}
      <div className="grid-2">
        <Card title="기본 정책" actions={current === 'drop' ? <Badge tone="er">막기</Badge> : <Badge tone="ok">원래 규칙으로 넘김</Badge>}>
          <span className="small">아래 규칙 어디에도 맞지 않는 연결을 어떻게 할지 정합니다.</span>
          <div className="col" style={{ gap: 8 }} role="radiogroup" aria-label="기본 정책">
            <label className="row" style={{ alignItems: 'flex-start', gap: 8, cursor: 'pointer' }}>
              <input type="radio" name={`fw-policy-${node}`} checked={policy === 'return'} onChange={() => setPolicy('return')} style={{ marginTop: 3 }} />
              <span>
                서버에 원래 있던 규칙으로 넘김 <Badge tone="tag">기본값</Badge>
                <span className="small muted" style={{ display: 'block' }}>
                  제어를 켤 때의 값. 켜도 달라지는 것이 없습니다
                </span>
              </span>
            </label>
            <label className="row" style={{ alignItems: 'flex-start', gap: 8, cursor: 'pointer' }}>
              <input type="radio" name={`fw-policy-${node}`} checked={policy === 'drop'} onChange={() => setPolicy('drop')} style={{ marginTop: 3 }} />
              <span>
                막기
                <span className="small muted" style={{ display: 'block' }}>
                  여기 규칙이 전부 정합니다. 원래 있던 규칙은 남아 있지만 쓰이지 않습니다
                </span>
              </span>
            </label>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn" disabled={policy === current || ch.busy} onClick={() => (policy === 'drop' && !allows ? setDlg({ kind: 'drop' }) : void applyPolicy())}>
              정책 바꾸기…
            </button>
          </div>
        </Card>
        <Card title="잠금 규칙" actions={<span className="small muted">자동 · 지울 수 없음 · 가장 먼저 판정</span>}>
          <table className="tbl">
            <thead>
              <tr>
                <th>규칙</th>
                <th>열림</th>
                <th>왜</th>
              </tr>
            </thead>
            <tbody>
              {locked.map((l) => (
                <tr key={l.name}>
                  <td className="wrap">{l.label}</td>
                  <td className={`wrap${/\//.test(l.open) || l.name === 'sfc-devices' ? ' mono' : ''}`}>{l.open || '—'}</td>
                  <td className="wrap">{l.why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      <Card
        title="규칙"
        actions={
          <button className="btn primary" disabled={fw.rules.length >= max} title={fw.rules.length >= max ? `규칙은 ${max}개까지` : undefined} onClick={() => setDlg({ kind: 'add' })}>
            규칙 추가
          </button>
        }
      >
        {fw.rules.length >= max && <div className="bn err">이 서버의 규칙이 {max}개라 더 넣을 수 없습니다.</div>}
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>동작</th>
                <th>프로토콜</th>
                <th>포트</th>
                <th>출처</th>
                <th>메모</th>
                <th aria-label="작업" />
              </tr>
            </thead>
            <tbody>
              {sortRules(fw.rules).map((r) => (
                <tr key={r.id}>
                  <td>{r.action === 'deny' ? <Badge tone="er">막기</Badge> : <Badge tone="ok">허용</Badge>}</td>
                  <td>{PROTO_TEXT[r.proto]}</td>
                  <td className="mono">{r.ports ?? '—'}</td>
                  <td className="wrap">{r.from.length ? <span className="mono" style={{ whiteSpace: 'pre-line' }}>{r.from.join('\n')}</span> : <span className="muted">모든 곳</span>}</td>
                  <td className="wrap">{r.comment || '—'}</td>
                  <td>
                    <span className="row" style={{ gap: 6, justifyContent: 'flex-end', flexWrap: 'nowrap' }}>
                      <button className="btn sm" onClick={() => setDlg({ kind: 'edit', rule: r })}>
                        수정
                      </button>
                      <button className="btn sm danger" onClick={() => setDlg({ kind: 'delete', rule: r })}>
                        지우기
                      </button>
                    </span>
                  </td>
                </tr>
              ))}
              {!fw.rules.length && (
                <tr>
                  <td colSpan={6} className="muted">
                    아직 규칙이 없습니다. 잠금 규칙에 맞지 않는 연결은 기본 정책을 따릅니다.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <span className="small muted">막기 규칙을 허용 규칙보다 먼저 판정하므로 순서는 없습니다. 출처를 비우면 모든 곳입니다. IPv4와 IPv6 주소를 섞어 쓸 수 있습니다.</span>
      </Card>
      <div className="grid-2">
        <Card title="서버에 원래 있던 규칙" actions={<Badge tone="un">읽기 전용</Badge>}>
          <pre className="code dark" aria-label="서버에 원래 있던 INPUT 규칙">
            {operatorLines(fw)}
          </pre>
          {fw.operatorTruncated && <span className="small wa-text">줄이 많아 IPv4·IPv6 각각 200줄까지만 보입니다.</span>}
          <span className="small muted">서버에서 직접 넣은 INPUT 규칙입니다. 여기서 바꾸지 않습니다. 여기 규칙에 맞지 않는 연결은 이 규칙으로 판정합니다. 기본 정책을 ‘막기’로 바꾸면 쓰이지 않습니다.</span>
        </Card>
        <FirewallLog node={node} reload={logKey} />
      </div>
      {(dlg?.kind === 'add' || dlg?.kind === 'edit') && <RuleDialog node={node} fw={fw} rule={dlg.kind === 'edit' ? dlg.rule : undefined} onClose={() => setDlg(undefined)} onChanged={onChanged} />}
      {dlg?.kind === 'delete' && <DeleteDialog node={node} fw={fw} rule={dlg.rule} onClose={() => setDlg(undefined)} onChanged={onChanged} />}
      {dlg?.kind === 'drop' && <DropDialog node={node} fw={fw} onClose={() => setDlg(undefined)} onChanged={onChanged} />}
    </>
  );
}

/** 막기 먼저(판정 순서), 그다음 ID 순 */
const sortRules = (rules: DFirewallRule[]) => [...rules].sort((a, b) => (a.action === b.action ? Number((a.id ?? 'r0').slice(1)) - Number((b.id ?? 'r0').slice(1)) : a.action === 'deny' ? -1 : 1));

/** 운영자 규칙 상자: # IPv4 / # IPv6 머리와 sfcd가 넣은 한 줄 표시 */
function operatorLines(fw: DFirewall) {
  const block = (title: string, lines: string[]) => [
    <span key={`${title}-h`} className="muted">
      # {title}
      {'\n'}
    </span>,
    ...(lines.length ? lines : ['(규칙 없음)']).map((l, i) => (
      <span key={`${title}-${i}`}>
        {l}
        {/-j SFC-INPUT\b/.test(l) && <span className="muted">{'        # sfcd가 맨 위에 넣은 한 줄'}</span>}
        {'\n'}
      </span>
    )),
  ];
  return [...block('IPv4', fw.operator4), ...block('IPv6', fw.operator6)];
}

function FirewallLog({ node, reload }: { node: string; reload: number }) {
  const first = usePoll((s) => nodeFirewallLog(node, undefined, s), [node, reload], 0);
  const [older, setOlder] = useState<DFirewallChange[]>([]);
  const [more, setMore] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const names = useUserNames();
  useEffect(() => {
    setOlder([]);
    setMore(undefined);
  }, [first.data]);
  const rows = [...(first.data?.log ?? []), ...older];
  const hasMore = more ?? first.data?.more ?? false;
  const loadMore = async () => {
    const last = rows[rows.length - 1];
    if (!last) return;
    setBusy(true);
    try {
      const r = await nodeFirewallLog(node, last.to);
      const seen = new Set(rows.map((x) => x.operation));
      setOlder((o) => [...o, ...(r.log ?? []).filter((x) => !seen.has(x.operation))]);
      setMore(!!r.more);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="변경 기록" actions={<span className="small muted">50건씩 · 더 보기</span>}>
      <Load q={first} what="변경 기록을 읽지 못했습니다">
        {() => (
          <>
            <table className="tbl">
              <thead>
                <tr>
                  <th>시각</th>
                  <th>사용자</th>
                  <th>변경</th>
                  <th>revision</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.operation}>
                    <td style={{ whiteSpace: 'nowrap' }}>{dayTime(new Date(c.at * 1000).toISOString())}</td>
                    <td>{names(c.user)}</td>
                    <td className="wrap">{deltaText(c.delta, c.added)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {c.from} → {c.to}
                    </td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={4} className="muted">
                      아직 바꾼 기록이 없습니다.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {hasMore && (
              <div className="row" style={{ justifyContent: 'center' }}>
                <button className="btn sm" disabled={busy} onClick={() => void loadMore()}>
                  {busy ? '읽는 중…' : '더 보기'}
                </button>
              </div>
            )}
          </>
        )}
      </Load>
      <span className="small muted">기록은 클러스터에 남고, 규칙 자체는 이 서버에만 있습니다. 기록으로 규칙을 되살리지는 않습니다.</span>
    </Card>
  );
}

const blank = (): DFirewallRule => ({ action: 'allow', proto: 'tcp', ports: '', from: [], comment: '' });
/** 보낼 모양: 빈 칸은 뺀다 */
const tidy = (r: DFirewallRule): DFirewallRule => ({ ...(r.id ? { id: r.id } : {}), action: r.action, proto: r.proto, ...(needsPorts(r.proto) && r.ports ? { ports: r.ports.trim() } : {}), from: r.from, ...(r.comment?.trim() ? { comment: r.comment.trim() } : {}) });
const same = (a: DFirewallRule, b: DFirewallRule) => ruleKey(a) === ruleKey(b) && (a.comment ?? '') === (b.comment ?? '');

function RuleDialog({ node, fw, rule, onClose, onChanged }: { node: string; fw: DFirewall; rule?: DFirewallRule; onClose: () => void; onChanged: () => void }) {
  const [r, setR] = useState<DFirewallRule>(() => (rule ? { ...rule, ports: rule.ports ?? '', comment: rule.comment ?? '', from: [...rule.from] } : blank()));
  const [typed, setTyped] = useState('');
  const [band, setBand] = useState<Extract<Outcome, { kind: 'band' }>>();
  const ch = useFirewallChange(node, onChanged);
  const out = tidy(r);
  const errs = ruleErrors(out);
  const typedBad = typed.trim() ? prefixError(typed.trim()) : undefined;
  const dup = fw.rules.find((x) => x.id !== rule?.id && ruleKey(x) === ruleKey(out));
  const full = !rule && fw.rules.length >= (fw.maxRules ?? 256);
  const unchanged = !!rule && same(tidy({ ...rule, ports: rule.ports ?? '' }), out);
  const addFrom = () => {
    const v = typed.trim();
    if (!v || typedBad) return;
    if (!r.from.includes(v)) setR({ ...r, from: [...r.from, v] });
    setTyped('');
  };
  const apply = async () => {
    setBand(undefined);
    const o = await ch.send(fw.revision, rule ? { update: [out] } : { add: [out] });
    if (o.kind === 'done') onClose();
    else if (o.kind === 'band') setBand(o);
  };
  const portsOff = !needsPorts(r.proto);
  return (
    <Dialog
      title={rule ? `${rule.id} 수정` : `규칙 추가 · ${node}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={ch.busy || unchanged || !!dup || full || Object.keys(errs).length > 0 || !!typed.trim()} title={typed.trim() ? '적은 출처를 먼저 더하거나 지우세요' : undefined} onClick={() => void apply()}>
            {ch.busy ? '적용하는 중…' : '적용'}
          </button>
        </>
      }
    >
      {rule ? (
        <div className="row" style={{ gap: 10 }}>
          <Field label="동작">
            <select value={r.action} onChange={(e) => setR({ ...r, action: e.target.value as DFirewallRule['action'] })}>
              <option value="allow">{ACTION_TEXT.allow}</option>
              <option value="deny">{ACTION_TEXT.deny}</option>
            </select>
          </Field>
          <ProtoField r={r} setR={setR} />
        </div>
      ) : (
        <>
          <Field label="동작" group>
            <span className="col" style={{ gap: 6 }} role="radiogroup" aria-label="동작">
              <label className="row" style={{ gap: 8, cursor: 'pointer' }}>
                <input type="radio" name="fw-action" checked={r.action === 'allow'} onChange={() => setR({ ...r, action: 'allow' })} />
                허용
              </label>
              <label className="row" style={{ gap: 8, cursor: 'pointer', alignItems: 'flex-start' }}>
                <input type="radio" name="fw-action" checked={r.action === 'deny'} onChange={() => setR({ ...r, action: 'deny' })} style={{ marginTop: 3 }} />
                <span>
                  막기
                  <span className="small muted" style={{ display: 'block' }}>
                    허용보다 먼저 판정합니다
                  </span>
                </span>
              </label>
            </span>
          </Field>
        </>
      )}
      <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
        {!rule && <ProtoField r={r} setR={setR} />}
        <Field label="포트" hint="하나 또는 범위 (30000-30100). icmp·모두는 비움" error={!portsOff && r.ports ? errs.ports : undefined}>
          <input className="mono" value={portsOff ? '' : (r.ports ?? '')} disabled={portsOff} placeholder={portsOff ? '' : '443'} onChange={(e) => setR({ ...r, ports: e.target.value.trim() })} />
        </Field>
      </div>
      <Field label="출처" hint="CIDR 여러 개. 비우면 모든 곳. Enter로 더하기" error={typedBad ?? (r.from.length ? errs.from : undefined)} group>
        <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          {r.from.map((f) => (
            <span key={f} className="chip">
              <span className="mono">{f}</span>
              <button type="button" className="chip-x" aria-label={`${f} 빼기`} onClick={() => setR({ ...r, from: r.from.filter((x) => x !== f) })}>
                ×
              </button>
            </span>
          ))}
          <input
            className="mono grow"
            aria-label="출처 더하기"
            value={typed}
            placeholder="203.0.113.0/24"
            onChange={(e) => setTyped(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                addFrom();
              }
            }}
          />
          <button type="button" className="btn sm" disabled={!typed.trim() || !!typedBad} onClick={addFrom}>
            주소 더하기
          </button>
        </span>
      </Field>
      <Field label="메모" hint={`${MAX_COMMENT}자까지`} error={errs.comment}>
        <input value={r.comment ?? ''} maxLength={MAX_COMMENT + 10} onChange={(e) => setR({ ...r, comment: e.target.value })} />
      </Field>
      {dup && (
        <div className="bn warn">
          이미 같은 규칙이 있습니다: {dup.id} {ruleText(dup)}
        </div>
      )}
      {full && <div className="bn err">이 서버의 규칙이 {fw.maxRules ?? 256}개라 더 넣을 수 없습니다.</div>}
      {band && <div className={`bn ${band.tone}`}>{band.text}</div>}
      <span className="small muted">저장하면 이 서버에 바로 적용합니다. 서버가 연결되어 있지 않으면 실패하고, 나중에 적용되도록 쌓아 두지 않습니다.</span>
    </Dialog>
  );
}

function ProtoField({ r, setR }: { r: DFirewallRule; setR: (r: DFirewallRule) => void }) {
  return (
    <Field label="프로토콜" hint="tcp · udp · icmp · 모두">
      <select value={r.proto} onChange={(e) => setR({ ...r, proto: e.target.value as DFirewallRule['proto'] })}>
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
        <option value="icmp">icmp</option>
        <option value="any">모두</option>
      </select>
    </Field>
  );
}

function DeleteDialog({ node, fw, rule, onClose, onChanged }: { node: string; fw: DFirewall; rule: DFirewallRule; onClose: () => void; onChanged: () => void }) {
  const ch = useFirewallChange(node, onChanged);
  const [band, setBand] = useState<Extract<Outcome, { kind: 'band' }>>();
  return (
    <Dialog
      title={`${rule.id} 규칙을 지울까요?`}
      width={420}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn danger"
            disabled={ch.busy}
            onClick={() =>
              void ch.send(fw.revision, { delete: [rule.id ?? ''] }).then((o) => {
                if (o.kind === 'done') onClose();
                else if (o.kind === 'band') setBand(o);
              })
            }
          >
            {ch.busy ? '지우는 중…' : '지우기'}
          </button>
        </>
      }
    >
      <span>
        {ruleText(rule)}
        {rule.comment ? ` (${rule.comment})` : ''}
      </span>
      <span className="small muted">지우면 이 연결은 다음 규칙과 기본 정책을 따릅니다.</span>
      {band && <div className={`bn ${band.tone}`}>{band.text}</div>}
    </Dialog>
  );
}

/** 허용 규칙이 하나도 없을 때 '막기'로 바꾸기: 한 번 더 묻는다 */
function DropDialog({ node, fw, onClose, onChanged }: { node: string; fw: DFirewall; onClose: () => void; onChanged: () => void }) {
  const ch = useFirewallChange(node, onChanged);
  const [band, setBand] = useState<Extract<Outcome, { kind: 'band' }>>();
  const open = lockedRows(fw.locked)
    .filter((l) => ['sfcp', 'keep-open', 'ingress'].includes(l.name) && l.open)
    .map((l) => (l.name === 'sfcp' ? 'SFCP' : l.name === 'keep-open' ? `${l.open}(keep_open)` : `외부 접속 입구(${l.open})`));
  return (
    <Dialog
      title="기본 정책을 ‘막기’로 바꿀까요?"
      width={420}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn danger"
            disabled={ch.busy}
            onClick={() =>
              void ch.send(fw.revision, { policy: 'drop' }).then((o) => {
                if (o.kind === 'done') onClose();
                else if (o.kind === 'band') setBand(o);
              })
            }
          >
            {ch.busy ? '바꾸는 중…' : '막기로 바꾸기'}
          </button>
        </>
      }
    >
      <div className="bn warn">잠금 규칙 말고 허용 규칙이 없습니다. 바꾸면 {open.length ? open.join(', ') : '잠금 규칙'}만 열리고 나머지는 모두 막힙니다.</div>
      <span className="small muted">서버에 원래 있던 규칙은 남지만 쓰이지 않습니다.</span>
      {band && <div className={`bn ${band.tone}`}>{band.text}</div>}
    </Dialog>
  );
}

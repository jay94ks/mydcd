// SPDX-License-Identifier: Apache-2.0

import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { useState, type ReactNode } from 'react';
import type { Health, NodePhase, OpState } from '../api/types';
import { middle, pct } from '../lib/format';
import { API_MODE } from '../api/client';

export type Tone = 'ok' | 'pr' | 'wa' | 'er' | 'un' | 'tag';

export function Badge({ tone = 'tag', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone}`} title={title}>
      {children}
    </span>
  );
}

export const HEALTH: Record<Health, [Tone, string]> = {
  healthy: ['ok', '정상'],
  progressing: ['pr', '진행 중'],
  degraded: ['wa', '일부 오류'],
  unhealthy: ['er', '오류'],
  unknown: ['un', '확인 불가'],
};
export function HealthBadge({ health, reason }: { health: Health; reason?: string }) {
  const [tone, label] = HEALTH[health] ?? HEALTH.unknown;
  if (!reason) return <Badge tone={tone}>{label}</Badge>;
  return (
    <span className="health-reason">
      <Badge tone={tone}>{label}</Badge>
      <span className="small muted" title={reason}>
        {reason}
      </span>
    </span>
  );
}

const OPSTATE: Record<OpState, [Tone, string]> = {
  applied: ['ok', '완료'],
  failed: ['er', '적용 안 됨'],
  rejected: ['er', '거부'],
  unknown: ['un', '결과 불명'],
  pending: ['pr', '진행 중'],
  running: ['pr', '실행 중(터미널)'],
};
export function OpBadge({ state }: { state: OpState }) {
  const [tone, label] = OPSTATE[state] ?? OPSTATE.unknown;
  return <Badge tone={tone}>{label}</Badge>;
}

const PHASE: Record<NodePhase, [Tone, string]> = {
  ready: ['ok', '준비됨'],
  joining: ['un', '가입 대기'],
  isolated: ['wa', '격리됨'],
  removing: ['wa', '제거 중'],
  problem: ['er', '오류'],
  unknown: ['un', '확인 불가'],
  waiting: ['un', '대기 중'],
};
export const WAITING_TITLE = '이번 조회에서 2초 안에 답하지 않았습니다. 다른 값은 그 전에 저장된 것입니다.';
export function PhaseBadge({ phase, reason }: { phase: NodePhase; reason?: string }) {
  const [tone, label] = PHASE[phase] ?? PHASE.unknown;
  return (
    <Badge tone={tone} title={phase === 'waiting' ? WAITING_TITLE : reason}>
      {label}
    </Badge>
  );
}

export function Dot({ tone }: { tone: Tone }) {
  return <span className={`dot ${tone}`} aria-hidden="true" />;
}

/** 화면 번호(UI-nn)는 설계 표시라 목업에서만 보인다. 실제 화면에서는 번호 배지를 통째로 뺀다(화면 설계 표시 기준, 캔버스 v284). */
export function shownIds(ids: string | undefined, mock: boolean): string | undefined {
  return mock ? ids : undefined;
}

/** 화면 번호 배지. 실제 화면에서는 번호만 있으면 그리지 않는다. */
export function ScreenIds({ ids }: { ids?: string }) {
  const shown = shownIds(ids, API_MODE === 'mock');
  return shown ? <span className="ids">{shown}</span> : null;
}

export function PageHeader({ title, ids, actions, crumbs, after, sub }: { title: ReactNode; ids?: string; actions?: ReactNode; crumbs?: ReactNode; after?: ReactNode; sub?: ReactNode }) {
  // 휴대폰에서는 제목이 위쪽 막대로 가고 단추만 남긴다
  const phone = usePhone();
  useMobileTop(phone ? { title } : undefined, [phone, typeof title === 'string' ? title : ''], 'auto');
  if (phone) return after || actions ? <div className="row m-acts">{after}{actions}</div> : null;
  return (
    <>
      {crumbs && <div className="crumbs">{crumbs}</div>}
      <div className="row between">
        <div className="row" style={{ gap: 12 }}>
          <h1>{title}</h1>
          <ScreenIds ids={ids} />
          {after}
        </div>
        {actions && <div className="row">{actions}</div>}
      </div>
      {sub && <div className="page-sub">{sub}</div>}
    </>
  );
}

/** 화면 상단 안내 상자. 원래 기술 용어를 괄호로 함께 적는다. */
export function HelpBox({ children, terms }: { children: ReactNode; terms?: ReactNode }) {
  return (
    <aside className="help">
      <span>{children}</span>
      {terms && (
        <span className="terms">
          <b>용어</b> {terms}
        </span>
      )}
    </aside>
  );
}

export function Card({ title, actions, children, className = '', flush = false }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`card ${flush ? 'flush' : ''} ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Tile({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: 'ok' | 'er' | 'wa' }) {
  return (
    <div className="tile">
      <span className="label">{label}</span>
      <b style={tone ? { color: tone === 'ok' ? 'var(--ok)' : 'var(--er)' } : undefined}>{value}</b>
      {sub && <span className="small muted">{sub}</span>}
    </div>
  );
}

/** 다른 VM이 가져간 CPU 몫(cpu steal) 보조 표시. 없거나 반올림해 0이면 없음 */
export function cpuStealText(steal: number | undefined): string | undefined {
  return steal !== undefined && Math.round(steal) > 0 ? `다른 VM 사용 ${Math.round(steal)}%` : undefined;
}
export const CPU_STEAL_TIP = '공유 VPS에서 같은 호스트의 다른 VM이 가져간 CPU 몫입니다. 위 CPU 사용률에는 들어 있지 않습니다.';

export function UsageBar({ used, total, label, text, sub, subTitle }: { used?: number; total?: number; label: string; text: string; sub?: string; subTitle?: string }) {
  const p = pct(used, total);
  const cls = p >= 90 ? 'crit' : p >= 80 ? 'hi' : '';
  return (
    <div className="met">
      <span className="muted">{label}</span>
      <span className="bar" role="meter" aria-label={label} aria-valuenow={p} aria-valuemin={0} aria-valuemax={100}>
        <i className={cls} style={{ width: `${p}%` }} />
      </span>
      <span>
        {text}
        {sub && (
          <span className="small muted" title={subTitle}>
            {' · '}
            {sub}
          </span>
        )}
      </span>
    </div>
  );
}

/** 해시·digest·작업 ID: 가운데 줄임 + 복사 */
/** 좁은 곳의 작업 ID: 앞 8자리만 mono로, 올리면 전체(title), 누르면 복사. 전체 UUID는 작업 기록 상세에만 보인다 */
export function OpId({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="textbtn plain"
      style={{ fontFamily: 'var(--mono)', fontSize: 12 }}
      title={copied ? '복사했습니다' : `${id} · 눌러서 복사`}
      aria-label={`작업 ID ${id} 복사`}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard?.writeText(id).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {copied ? '복사됨' : id.slice(0, 8)}
    </button>
  );
}

export function Hash({ value, head = 8, tail = 6 }: { value: string; head?: number; tail?: number }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="row" style={{ gap: 4, flexWrap: 'nowrap', display: 'inline-flex' }}>
      <code title={value}>{middle(value, head, tail)}</code>
      <button
        type="button"
        className="btn ghost sm"
        aria-label="복사"
        title="복사"
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        {copied ? '✓' : '⧉'}
      </button>
    </span>
  );
}

export function KV({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div key={i} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** group: 안에 버튼·여러 칸이 있으면 label 대신 묶음(div role=group)으로 둔다(버튼 이름이 칸 이름으로 덮이지 않게). */
export function Field({ label, hint, error, children, group }: { label: ReactNode; hint?: ReactNode; error?: ReactNode; children: ReactNode; group?: boolean }) {
  const tail = error ? <span className="error">{error}</span> : hint ? <span className="hint">{hint}</span> : null;
  if (group)
    return (
      <div className="field" role="group" aria-label={typeof label === 'string' ? label : undefined}>
        <span>{label}</span>
        {children}
        {tail}
      </div>
    );
  return (
    <label className="field">
      {label}
      {children}
      {tail}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label, disabled }: { value: T; options: [T, string][]; onChange: (v: T) => void; label: string; disabled?: Partial<Record<T, string>> }) {
  return (
    <span className="segmented" role="radiogroup" aria-label={label}>
      {options.map(([v, l]) => (
        <button key={v} type="button" role="radio" aria-checked={v === value} className={v === value ? 'on' : ''} disabled={!!disabled?.[v] && v !== value} title={disabled?.[v]} onClick={() => onChange(v)}>
          {l}
        </button>
      ))}
    </span>
  );
}

/** 권한이 모자란 버튼은 숨기지 않고 흐리게 + 필요한 권한을 보인다. */
export function Guard({ allowed, need, children }: { allowed: boolean; need: string; children: (disabled: boolean, title?: string) => ReactNode }) {
  return <>{children(!allowed, allowed ? undefined : `${need} 권한이 필요합니다`)}</>;
}

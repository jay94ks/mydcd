// SPDX-License-Identifier: Apache-2.0

import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { useState, type ReactNode } from 'react';
import type { Health, NodePhase, OpState } from '../api/types';
import { middle, pct } from '../lib/format';

export type Tone = 'ok' | 'pr' | 'wa' | 'er' | 'un' | 'tag';

export function Badge({ tone = 'tag', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone}`} title={title}>
      {children}
    </span>
  );
}

const HEALTH: Record<Health, [Tone, string]> = {
  healthy: ['ok', '정상'],
  progressing: ['pr', '진행 중'],
  degraded: ['wa', '일부 문제'],
  unhealthy: ['er', '문제'],
  unknown: ['un', '확인 불가'],
};
export function HealthBadge({ health }: { health: Health }) {
  const [tone, label] = HEALTH[health] ?? HEALTH.unknown;
  return <Badge tone={tone}>{label}</Badge>;
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
  problem: ['er', '문제'],
  unknown: ['un', '확인 불가'],
};
export function PhaseBadge({ phase }: { phase: NodePhase }) {
  const [tone, label] = PHASE[phase] ?? PHASE.unknown;
  return <Badge tone={tone}>{label}</Badge>;
}

export function Dot({ tone }: { tone: Tone }) {
  return <span className={`dot ${tone}`} aria-hidden="true" />;
}

export function PageHeader({ title, ids, actions, crumbs, after }: { title: ReactNode; ids?: string; actions?: ReactNode; crumbs?: ReactNode; after?: ReactNode }) {
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
          {ids && <span className="ids">{ids}</span>}
          {after}
        </div>
        {actions && <div className="row">{actions}</div>}
      </div>
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

export function UsageBar({ used, total, label, text }: { used?: number; total?: number; label: string; text: string }) {
  const p = pct(used, total);
  const cls = p >= 90 ? 'crit' : p >= 80 ? 'hi' : '';
  return (
    <div className="met">
      <span className="muted">{label}</span>
      <span className="bar" role="meter" aria-label={label} aria-valuenow={p} aria-valuemin={0} aria-valuemax={100}>
        <i className={cls} style={{ width: `${p}%` }} />
      </span>
      <span>{text}</span>
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

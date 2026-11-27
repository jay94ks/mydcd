// SPDX-License-Identifier: Apache-2.0

import { useMemo, useRef } from 'react';
import YAML from 'yaml';
import type { DiffLine } from '../api/types';
import { compactDiff } from '../lib/diff';
import { Badge } from './ui';

export function CodeView({ text, lineNumbers = true }: { text: string; lineNumbers?: boolean }) {
  const lines = text.replace(/\n$/, '').split('\n');
  return (
    <pre className="code" tabIndex={0}>
      {lines.map((l, i) => (
        <span key={i}>
          {lineNumbers && <span className="ln">{i + 1}</span>}
          {l}
          {'\n'}
        </span>
      ))}
    </pre>
  );
}

export function DiffView({ lines, compact = true }: { lines: DiffLine[]; compact?: boolean }) {
  const shown = compact ? compactDiff(lines) : lines;
  if (!lines.some((l) => l.op !== ' ')) return <div className="note un small">바뀐 줄이 없습니다.</div>;
  return (
    <pre className="code diff" tabIndex={0} aria-label="변경 미리보기">
      {shown.map((l, i) => (
        <span key={i} className={l.op === '+' ? 'add' : l.op === '-' ? 'del' : l.op === '…' ? 'gap' : 'same'}>
          {l.op === '…' ? `  … ${l.text}` : `${l.op} ${l.text}`}
        </span>
      ))}
    </pre>
  );
}

export function yamlCheck(text: string): { ok: true } | { ok: false; line?: number; message: string } {
  if (!text.trim()) return { ok: false, message: '내용이 비어 있습니다.' };
  try {
    const doc = YAML.parseDocument(text);
    if (doc.errors.length) {
      const e = doc.errors[0];
      return { ok: false, line: e.linePos?.[0]?.line, message: e.message.split('\n')[0] };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}

/** app.yaml·partial cluster.yaml 편집. 문법만 즉시 확인하고, 계약 검사는 서버 plan이 한다. */
export function YamlEditor({ value, onChange, name = 'app.yaml', readOnly = false }: { value: string; onChange?: (v: string) => void; name?: string; readOnly?: boolean }) {
  const check = useMemo(() => yamlCheck(value), [value]);
  const file = useRef<HTMLInputElement>(null);
  return (
    <div className="editor">
      <div className="ed-head">
        <code>{name}</code>
        <span className="row">
          {check.ok ? <Badge tone="ok">문법 OK</Badge> : <Badge tone="er">문법 오류</Badge>}
          {!readOnly && (
            <>
              <button type="button" className="btn sm" onClick={() => file.current?.click()}>
                파일 열기
              </button>
              <input
                ref={file}
                type="file"
                accept=".yaml,.yml,text/yaml"
                hidden
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (f) onChange?.(await f.text());
                  e.target.value = '';
                }}
              />
            </>
          )}
        </span>
      </div>
      <textarea
        aria-label={name}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        wrap="off"
        onChange={(e) => onChange?.(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Tab' && !readOnly) {
            e.preventDefault();
            const t = e.currentTarget;
            const s = t.selectionStart;
            const v = t.value.slice(0, s) + '  ' + t.value.slice(t.selectionEnd);
            onChange?.(v);
            requestAnimationFrame(() => t.setSelectionRange(s + 2, s + 2));
          }
        }}
      />
      {!check.ok && (
        <div className="ed-foot note wa" style={{ borderRadius: 0 }}>
          {check.line ? `${check.line}번째 줄: ` : ''}
          {check.message}
        </div>
      )}
    </div>
  );
}

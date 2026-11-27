// SPDX-License-Identifier: Apache-2.0

// 서버 방화벽 규칙 검사와 글 (UI-1G, #740 internal/firewall/rules.go와 같은 규칙).
// 화면은 보내기 전에 같은 오류를 미리 보여 줄 뿐이고, 판정은 서버가 한다.
import type { DFirewallRule } from '../api/dto';

export const MAX_SOURCES = 32;
export const MAX_COMMENT = 120;

/** "443" 또는 "30000-30100". 맞으면 undefined */
export function portsError(s: string): string | undefined {
  const m = /^(\d+)(?:-(\d+))?$/.exec(s);
  if (!m) return '1-65535 사이 수 하나 또는 범위 (30000-30100)';
  const canon = (x: string) => String(Number(x)) === x;
  const a = Number(m[1]);
  const b = m[2] === undefined ? a : Number(m[2]);
  if (!canon(m[1]) || (m[2] !== undefined && !canon(m[2])) || a < 1 || a > 65535 || b > 65535) return '1-65535 사이 수 하나 또는 범위 (30000-30100)';
  if (b < a) return `범위는 작은 수부터: ${b}-${a}`;
  return undefined;
}

function v4(s: string): number[] | undefined {
  const p = s.split('.');
  if (p.length !== 4) return undefined;
  const out: number[] = [];
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || String(Number(x)) !== x || Number(x) > 255) return undefined;
    out.push(Number(x));
  }
  return out;
}

/** IPv6 주소를 16바이트로. 영역(%)·IPv4 꼬리는 받지 않는다 */
function v6(s: string): number[] | undefined {
  if (!/^[0-9a-fA-F:]+$/.test(s)) return undefined;
  const halves = s.split('::');
  if (halves.length > 2) return undefined;
  const part = (h: string) => (h === '' ? [] : h.split(':'));
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  if ([...head, ...tail].some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return undefined;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return undefined;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail].map((g) => parseInt(g, 16));
  return groups.flatMap((g) => [g >> 8, g & 255]);
}

/** 출처 prefix 하나 (호스트 비트 없이). 맞으면 undefined */
export function prefixError(s: string): string | undefined {
  const bad = '올바른 CIDR가 아닙니다';
  const m = /^([^/]+)\/(\d{1,3})$/.exec(s);
  if (!m || String(Number(m[2])) !== m[2]) return bad;
  const bytes = m[1].includes(':') ? v6(m[1]) : v4(m[1]);
  const bits = Number(m[2]);
  if (!bytes || bits > bytes.length * 8) return bad;
  for (let i = bits; i < bytes.length * 8; i++) if (bytes[i >> 3] & (0x80 >> (i & 7))) return `호스트 비트가 있습니다. 망 주소로 적으세요 (예: 203.0.113.0/24)`;
  return undefined;
}

export const needsPorts = (proto: DFirewallRule['proto']) => proto === 'tcp' || proto === 'udp';

/** 규칙 한 줄 전체 검사. 칸별 오류 */
export function ruleErrors(r: DFirewallRule): { ports?: string; from?: string; comment?: string } {
  const e: { ports?: string; from?: string; comment?: string } = {};
  const pe = needsPorts(r.proto) ? (r.ports ? portsError(r.ports) : `${r.proto}는 포트가 필요합니다`) : undefined;
  if (pe) e.ports = pe;
  else if (!needsPorts(r.proto) && r.ports) e.ports = `${r.proto === 'any' ? '모두' : r.proto}는 포트를 비웁니다`;
  if (r.from.length > MAX_SOURCES) e.from = `출처는 ${MAX_SOURCES}개까지`;
  else if (new Set(r.from).size !== r.from.length) e.from = '같은 출처가 두 번 있습니다';
  else
    for (const f of r.from) {
      const pe = prefixError(f);
      if (pe) {
        e.from = `${f}: ${pe}`;
        break;
      }
    }
  const c = r.comment ?? '';
  if ([...c].length > MAX_COMMENT) e.comment = `${MAX_COMMENT}자까지`;
  else if (/[\u0000-\u001f\u007f]/.test(c)) e.comment = '한 줄로 적으세요';
  return e;
}

/** 같은 규칙인지 가르는 열쇠(ID·메모 빼고, 출처 순서 무시) */
export const ruleKey = (r: DFirewallRule) => `${r.action} ${r.proto} ${r.ports ?? ''} ${[...r.from].sort().join(',')}`;

export const ACTION_TEXT: Record<DFirewallRule['action'], string> = { allow: '허용', deny: '막기' };
export const PROTO_TEXT: Record<DFirewallRule['proto'], string> = { tcp: 'tcp', udp: 'udp', icmp: 'icmp', any: '모두' };

/** "허용 tcp/443 ← 10.0.0.0/8, fd00::/8" · 출처가 없으면 "모든 곳" */
export function ruleText(r: DFirewallRule, withFrom = true): string {
  const what = `${ACTION_TEXT[r.action]} ${PROTO_TEXT[r.proto]}${r.ports ? `/${r.ports}` : ''}`;
  if (!withFrom) return what;
  return `${what} ${r.from.length ? `← ${r.from.join(', ')}` : '모든 곳'}`;
}

/** 변경 기록 한 줄: 무엇을 더하고 고치고 지웠는지 */
export function deltaText(d: { add?: DFirewallRule[]; update?: DFirewallRule[]; delete?: string[]; policy?: string }, added?: string[]): string {
  const out: string[] = [];
  (d.add ?? []).forEach((r, i) => out.push(`${added?.[i] ? `${added[i]} ` : ''}${ruleText(r)} 추가`));
  for (const r of d.update ?? []) out.push(`${r.id} 수정 → ${ruleText(r)}`);
  for (const id of d.delete ?? []) out.push(`${id} 지움`);
  if (d.policy) out.push(`기본 정책 ${d.policy === 'drop' ? '막기' : '원래 규칙으로 넘김'}`);
  return out.join(' · ') || '—';
}

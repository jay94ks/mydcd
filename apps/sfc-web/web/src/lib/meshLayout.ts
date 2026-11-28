// SPDX-License-Identifier: Apache-2.0

// 서버 › 서버 간 연결 그래프 배치. 서버는 원 위에, 역할 글자는 원 바깥쪽(중심 반대편)에 둔다.
// 링크의 지연 글자는 선 가운데부터 다른 글자·서버와 겹치지 않는 자리를 찾는다
// (마주 보는 대각선 두 개가 가운데에서 겹치던 문제). 연결을 연 쪽(dialer)이 있으면 받은 쪽 끝에 화살표를 둔다.

export interface Pt {
  x: number;
  y: number;
}
interface Box {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}
export interface MeshLayoutNode {
  id: string;
  x: number;
  y: number;
  /** 역할 글자 자리 */
  label: Pt & { anchor: 'start' | 'middle' | 'end' };
}
export interface MeshLayoutLink {
  a: string;
  b: string;
  /** 지연 글자 자리(가운데 정렬). 글자가 없으면 없다 */
  label?: Pt;
  /** 화살표 끝(받은 쪽 원 가장자리)과 양 날개 */
  arrow?: [Pt, Pt, Pt];
}

export const NODE_R = 30;
const FONT = 11;

/** 11px 글자 폭 어림: 한글·전각은 11, 그 밖은 6.5 */
export function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ᄀ-ᇿ　-鿿가-힯＀-￯★]/.test(ch) ? FONT : 6.5;
  return w;
}

const box = (cx: number, cy: number, w: number, h: number): Box => ({ x0: cx - w / 2, y0: cy - h / 2, x1: cx + w / 2, y1: cy + h / 2 });
const hit = (a: Box, b: Box) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

function labelBox(l: MeshLayoutNode['label'], text: string): Box {
  const w = textWidth(text);
  const x0 = l.anchor === 'start' ? l.x : l.anchor === 'end' ? l.x - w : l.x - w / 2;
  return { x0, y0: l.y - FONT, x1: x0 + w, y1: l.y + 3 };
}

export function meshLayout(
  ids: string[],
  roleText: (id: string) => string,
  links: { a: string; b: string; text?: string; dialer?: string }[],
  W: number,
  H: number,
): { nodes: MeshLayoutNode[]; links: MeshLayoutLink[] } {
  const cx = W / 2;
  const cy = H / 2;
  const r = Math.min(W, H) / 2 - 56;
  const nodes: MeshLayoutNode[] = ids.map((id, i) => {
    const t = (2 * Math.PI * i) / ids.length - Math.PI / 2;
    const ux = ids.length > 1 ? Math.cos(t) : 0;
    const uy = ids.length > 1 ? Math.sin(t) : 1;
    const x = cx + (ids.length > 1 ? r * ux : 0);
    const y = cy + (ids.length > 1 ? r * uy : 0);
    // 원 바깥쪽에 역할 글자. 위·아래는 가운데 정렬, 옆은 원 옆에 붙인다
    const anchor = ux > 0.5 ? 'start' : ux < -0.5 ? 'end' : 'middle';
    const d = NODE_R + 8;
    const label = anchor === 'middle' ? { x, y: uy < 0 ? y - d : y + d + FONT - 2, anchor } : { x: x + ux * d, y: y + uy * d + 4, anchor };
    return { id, x, y, label: label as MeshLayoutNode['label'] };
  });
  const pos = new Map(nodes.map((n) => [n.id, n]));
  const taken: Box[] = nodes.flatMap((n) => [box(n.x, n.y, NODE_R * 2 + 4, NODE_R * 2 + 4), ...(roleText(n.id) ? [labelBox(n.label, roleText(n.id))] : [])]);
  const out: MeshLayoutLink[] = [];
  for (const l of links) {
    const a = pos.get(l.a);
    const b = pos.get(l.b);
    if (!a || !b) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len;
    const uy = dy / len;
    const row: MeshLayoutLink = { a: l.a, b: l.b };
    if (l.dialer === l.a || l.dialer === l.b) {
      // 연 쪽 → 받은 쪽. 받은 쪽 원 가장자리에 화살촉
      const s = l.dialer === l.a ? 1 : -1;
      const to = l.dialer === l.a ? b : a;
      const tip = { x: to.x - s * ux * (NODE_R + 2), y: to.y - s * uy * (NODE_R + 2) };
      const back = { x: tip.x - s * ux * 10, y: tip.y - s * uy * 10 };
      row.arrow = [tip, { x: back.x - uy * 5, y: back.y + ux * 5 }, { x: back.x + uy * 5, y: back.y - ux * 5 }];
    }
    if (l.text) {
      const w = textWidth(l.text) + 6;
      let pick: Box | undefined;
      let at: Pt | undefined;
      // 가운데부터 바깥으로, 선 양옆으로 비켜 본다
      outer: for (const t of [0.5, 0.4, 0.6, 0.32, 0.68]) {
        for (const side of [-1, 1]) {
          // 선에 수직으로 비킨다. 수평선은 위·아래, 수직선은 옆으로 글자 반 폭만큼
          const off = 6 + Math.abs(ux) * 4 + Math.abs(uy) * (w / 2);
          const px = a.x + dx * t + -uy * side * off;
          const py = a.y + dy * t + ux * side * off;
          const bx = box(px, py - FONT / 2 + 2, w, FONT + 4);
          if (!taken.some((x) => hit(x, bx))) {
            pick = bx;
            at = { x: px, y: py + 2 };
            break outer;
          }
        }
      }
      if (!pick || !at) {
        at = { x: a.x + dx / 2 - uy * 10, y: a.y + dy / 2 + ux * 10 + 2 };
        pick = box(at.x, at.y - FONT / 2, w, FONT + 4);
      }
      taken.push(pick);
      row.label = at;
    }
    out.push(row);
  }
  return { nodes, links: out };
}

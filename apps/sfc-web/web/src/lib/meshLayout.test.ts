// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { meshLayout, textWidth } from './meshLayout';

const role: Record<string, string> = { jay2: '★ 리더', jay3: '투표', jay4: '투표', vps1: '투표권 없음' };
const links = [
  { a: 'jay2', b: 'vps1', text: '11.579 ms', dialer: 'jay2' },
  { a: 'jay2', b: 'jay3', text: '0.649 ms' },
  { a: 'jay2', b: 'jay4', text: '12.059 ms' },
  { a: 'vps1', b: 'jay3', text: '10.889 ms', dialer: 'jay3' },
  { a: 'vps1', b: 'jay4', text: '9.713 ms' },
  { a: 'jay3', b: 'jay4', text: '1.254 ms' },
];
const box = (x: number, y: number, t: string) => ({ x0: x - textWidth(t) / 2, x1: x + textWidth(t) / 2, y0: y - 11, y1: y + 3 });
const hit = (a: ReturnType<typeof box>, b: ReturnType<typeof box>) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

describe('meshLayout', () => {
  // 스크린샷: jay2 위, jay3 오른쪽, jay4 아래, vps1 왼쪽. 대각선 두 개가 가운데에서 겹쳤다
  const lay = meshLayout(['jay2', 'jay3', 'jay4', 'vps1'], (id) => role[id], links, 520, 320);
  it('keeps link labels apart from each other and from role labels', () => {
    const boxes = lay.links.map((l, i) => box(l.label!.x, l.label!.y, links[i].text));
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) expect(hit(boxes[i], boxes[j]), `${i}/${j}`).toBe(false);
    for (const n of lay.nodes) {
      const w = textWidth(role[n.id]);
      const x0 = n.label.anchor === 'start' ? n.label.x : n.label.anchor === 'end' ? n.label.x - w : n.label.x - w / 2;
      const rb = { x0, x1: x0 + w, y0: n.label.y - 11, y1: n.label.y + 3 };
      for (const b of boxes) expect(hit(rb, b), n.id).toBe(false);
    }
  });
  it('puts role labels outside the ring', () => {
    const top = lay.nodes.find((n) => n.id === 'jay2')!;
    const left = lay.nodes.find((n) => n.id === 'vps1')!;
    expect(top.label.y).toBeLessThan(top.y);
    expect(left.label.anchor).toBe('end');
  });
  it('points the arrow at the side that was dialed', () => {
    const l = lay.links[0];
    const vps1 = lay.nodes.find((n) => n.id === 'vps1')!;
    const jay2 = lay.nodes.find((n) => n.id === 'jay2')!;
    const tip = l.arrow![0];
    expect(Math.hypot(tip.x - vps1.x, tip.y - vps1.y)).toBeLessThan(Math.hypot(tip.x - jay2.x, tip.y - jay2.y));
    expect(lay.links[3].arrow).toBeDefined();
    expect(lay.links[1].arrow).toBeUndefined();
  });
});

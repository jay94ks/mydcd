// SPDX-License-Identifier: Apache-2.0

/** IPv4 CIDR 도우미(망 만들기 칸 검사·추천). 최종 판단은 mydcd가 한다. */
export interface Cidr {
  base: number;
  bits: number;
}
const ip4 = (s: string): number | undefined => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return undefined;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return undefined;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
};
export const ipText = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
const mask = (bits: number) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);

/** "10.40.0.0/24" → {base, bits}. 호스트 비트가 켜져 있으면 undefined(데몬과 같은 규칙) */
export function parseCidr(s: string): Cidr | undefined {
  const [a, b, extra] = s.trim().split('/');
  if (extra !== undefined || b === undefined || !/^\d{1,2}$/.test(b)) return undefined;
  const bits = Number(b);
  const base = ip4(a);
  if (base === undefined || bits > 32) return undefined;
  if ((base & mask(bits)) >>> 0 !== base) return undefined;
  return { base, bits };
}
export const cidrText = (c: Cidr) => `${ipText(c.base)}/${c.bits}`;
export const overlaps = (a: Cidr, b: Cidr) => {
  const m = mask(Math.min(a.bits, b.bits));
  return (a.base & m) >>> 0 === (b.base & m) >>> 0;
};
export const firstHost = (c: Cidr) => ipText(c.base + 1);
/** gateway가 c 안의 호스트 주소인지(망 주소 자체는 안 됨) */
export function hostIn(c: Cidr, addr: string): boolean {
  const n = ip4(addr);
  return n !== undefined && (n & mask(c.bits)) >>> 0 === c.base && n !== c.base;
}

/** 시스템 망(mydc-system)이 쓰는 대역. 사용자 망의 CIDR·터널 주소는 이 안에 둘 수 없다 */
export const SYSTEM_CIDR: Cidr = { base: ((10 << 24) | (254 << 16)) >>> 0, bits: 16 };
export const SYSTEM_TEXT = '10.254.0.0/16은 시스템 망(mydc-system)이 쓰는 대역이라 쓸 수 없습니다';
export const inSystem = (c: Cidr) => overlaps(c, SYSTEM_CIDR);

/** 망 칸에 대한 문제. 없으면 undefined */
export function cidrProblem(text: string, taken: { name: string; node?: string; cidr: string }[]): string | undefined {
  const c = parseCidr(text);
  if (!c) return '10.40.2.0/24 같은 IPv4 망 주소를 적어 주세요(호스트 비트는 0).';
  if (c.bits > 29) return '/29보다 좁은 망은 만들 수 없습니다.';
  if (inSystem(c)) return SYSTEM_TEXT;
  for (const t of taken) {
    const o = parseCidr(t.cidr);
    if (o && overlaps(c, o)) return `${t.name}${t.node ? `(${t.node})` : ''}의 ${t.cidr}와 겹칩니다`;
  }
  return undefined;
}

/** 이미 쓰는 망과 겹치지 않는 /24 추천(10.40.x.0/24부터) */
export function suggestCidr(taken: string[]): string {
  const used = taken.map(parseCidr).filter((x): x is Cidr => !!x);
  for (let x = 0; x < 256; x++) {
    const c = { base: ((10 << 24) | (40 << 16) | (x << 8)) >>> 0, bits: 24 };
    if (!inSystem(c) && !used.some((u) => overlaps(c, u))) return cidrText(c);
  }
  return '10.41.0.0/24';
}

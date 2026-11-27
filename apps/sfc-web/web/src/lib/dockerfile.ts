// SPDX-License-Identifier: Apache-2.0

// Dockerfile을 화면과 목업에서 가볍게 읽는다(FROM 이미지, COPY·ADD 원본). 빌더의 진짜 해석은 서버가 한다.
export interface DockerfileParse {
  /** 앞 단계 이름이 아닌 FROM 이미지와 그 줄 번호(1부터) */
  from: { image: string; line: number }[];
  /** --from= 없는 COPY·ADD의 원본 경로 */
  copies: { line: number; srcs: string[] }[];
  /** # syntax= 줄 번호 */
  syntax: number[];
}
export function parseDockerfile(text: string): DockerfileParse {
  const from: DockerfileParse['from'] = [];
  const copies: DockerfileParse['copies'] = [];
  const syntax: number[] = [];
  const stages = new Set<string>();
  text.split('\n').forEach((raw, i) => {
    const l = raw.trim();
    if (/^#\s*syntax\s*=/i.test(l)) syntax.push(i + 1);
    const m = l.match(/^(FROM|COPY|ADD)\s+(.*)$/i);
    if (!m) return;
    const words = m[2].split(/\s+/);
    if (m[1].toUpperCase() === 'FROM') {
      const img = words.find((w) => !w.startsWith('--'));
      if (img && !stages.has(img.toLowerCase())) from.push({ image: img, line: i + 1 });
      const as = words.findIndex((w) => w.toLowerCase() === 'as');
      if (as >= 0 && words[as + 1]) stages.add(words[as + 1].toLowerCase());
      return;
    }
    if (words.some((w) => w.startsWith('--from='))) return;
    const args = words.filter((w) => !w.startsWith('--'));
    copies.push({ line: i + 1, srcs: args.slice(0, -1).map((s) => s.replace(/^\.\//, '').replace(/\/$/, '')) });
  });
  return { from, copies, syntax };
}

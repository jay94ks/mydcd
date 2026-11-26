// SPDX-License-Identifier: Apache-2.0

// 인증서 자동화 경로 검사 (canvas v176 YamlDeployIx): app.yaml의 외부 접속 경로가 /.well-known/acme-challenge/이거나
// 그 아래이면 경고만 한다. 외부 접속이 이 경로를 언제나 웹 앱의 HTTP 확인 응답기로 보내므로 그 경로 규칙은 무시된다.
// 배포는 막지 않는다. 줄 번호를 보이려고 YAML을 해석하지 않고 줄 단위로 찾는다.

export interface AcmePathHit {
  /** 1부터. 블록 모양이면 그 항목의 첫 줄(- host: …), 한 줄 모양이면 path가 있는 줄 */
  from: number;
  to: number;
  path: string;
}

const PATH_RE = /(?:^|[\s{,])path:\s*['"]?(\/\.well-known\/acme-challenge(?:\/[^'"\s,}]*)?)['"]?\s*(?:[,}#]|$)/;
const indent = (s: string) => s.length - s.trimStart().length;

export function acmePathHits(yaml: string): AcmePathHit[] {
  const lines = yaml.split('\n');
  const out: AcmePathHit[] = [];
  lines.forEach((line, i) => {
    if (line.trimStart().startsWith('#')) return;
    const m = PATH_RE.exec(line);
    if (!m) return;
    let from = i;
    if (!/^\s*-\s/.test(line) && !line.includes('{')) {
      // 블록 모양: 같은 항목의 '- ' 줄까지 거슬러 올라간다
      const ind = indent(line);
      for (let j = i - 1; j >= 0 && j >= i - 20; j--) {
        const l = lines[j];
        if (!l.trim()) continue;
        if (indent(l) > ind) continue;
        if (/^\s*-\s/.test(l) && indent(l) < ind) from = j;
        break;
      }
    }
    out.push({ from: from + 1, to: i + 1, path: m[1] });
  });
  return out;
}

export const hitRows = (h: AcmePathHit) => (h.from === h.to ? `${h.to}행` : `${h.from}–${h.to}행`);

// SPDX-License-Identifier: Apache-2.0

// 서비스 ports 한 줄을 짧은 글 모양으로 바꾼다(docs/architecture/app-and-cluster-spec.md '서비스의 호스트 포트 직접 공개').
// 짧은 모양 "127.0.0.1:18080:8080/tcp"는 그대로, 긴 모양 {target, published, host_ip, protocol}은 같은 뜻의 짧은 글로.
export function portText(p: unknown): string {
  if (p === null || p === undefined) return '';
  if (typeof p !== 'object') return String(p);
  const o = p as Record<string, unknown>;
  const s = (v: unknown) => (v === undefined || v === null || v === '' ? '' : String(v));
  const target = s(o.target);
  if (!target) return '';
  const published = s(o.published);
  const host = s(o.host_ip);
  const proto = s(o.protocol);
  // host_ip가 IPv6면 대괄호로 감싼다
  const hostPart = host ? `${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:` : '';
  return `${published ? `${hostPart}${published}:` : hostPart ? `${hostPart}:` : ''}${target}${proto ? `/${proto}` : ''}`;
}

/** 짧은 글 한 줄을 나눈다. 받을 주소·서버 포트가 없으면 ''. 못 읽으면 undefined */
export interface PortParts {
  host: string;
  published: string;
  target: string;
  proto: string;
}
export function parsePort(text: string): PortParts | undefined {
  const t = text.trim();
  if (!t) return undefined;
  const slash = t.lastIndexOf('/');
  const main = slash >= 0 ? t.slice(0, slash) : t;
  const proto = slash >= 0 ? t.slice(slash + 1).toLowerCase() : 'tcp';
  let host = '';
  let rest = main;
  if (rest.startsWith('[')) {
    const end = rest.indexOf(']');
    if (end < 0 || rest[end + 1] !== ':') return undefined;
    host = rest.slice(1, end);
    rest = rest.slice(end + 2);
  }
  const parts = rest.split(':');
  if (host ? parts.length !== 2 : parts.length > 3) return undefined;
  const target = parts[parts.length - 1];
  const published = parts.length >= 2 ? parts[parts.length - 2] : '';
  if (!host && parts.length === 3) host = parts[0];
  const range = /^\d{1,5}(-\d{1,5})?$/;
  if (!range.test(target) || (published && !range.test(published)) || (proto !== 'tcp' && proto !== 'udp')) return undefined;
  return { host, published, target, proto };
}
/** 미리 보기 '서버에 공개' 칸 글 */
export function publishText(p: PortParts): string {
  const host = p.host ? (p.host.includes(':') ? `[${p.host}]` : p.host) : '';
  return p.published ? `${host ? `${host}:` : ''}${p.published}` : `${host ? `${host} · ` : ''}서버가 고름`;
}

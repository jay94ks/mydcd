// SPDX-License-Identifier: Apache-2.0

// 본인 계정에 공개키 로그인 수단을 더할 때(add-credential) 새 키로 서명하는 증명.
// 바이트는 sfcd access.CredentialAdditionBytes와 같다(docs/reference/client-authentication.md):
//   "sfc-self-credential-addition-1\0" + cluster ID 32 + revision uint64 LE
//   + User·Credential.ID·Method·Label 각각 [uint64 LE 길이 + UTF-8] + 새 공개키 32 + Challenge 32
// Challenge는 브라우저가 만든 32바이트이고, 재사용은 계정 revision CAS가 막는다.
import { sign, type UnlockedKey } from './keystore';

const utf8 = new TextEncoder();
const fromHex = (h: string): Uint8Array => {
  if (!/^([0-9a-f]{2})*$/i.test(h)) throw new Error('hex가 아닙니다');
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
const u64 = (n: number) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};

export interface CredentialAddition {
  user: string;
  id: string;
  method: string;
  label?: string;
  /** 새 공개키 hex 64 */
  publicKey: string;
  challenge: Uint8Array;
}

export function credentialAdditionBytes(clusterId: string, revision: number, c: CredentialAddition): Uint8Array {
  const cluster = fromHex(clusterId);
  const pub = fromHex(c.publicKey);
  if (cluster.length !== 32 || pub.length !== 32 || c.challenge.length !== 32) throw new Error('클러스터 ID·공개키·challenge는 32바이트입니다');
  const parts: Uint8Array[] = [utf8.encode('sfc-self-credential-addition-1\0'), cluster, u64(revision)];
  for (const v of [c.user, c.id, c.method, c.label ?? '']) {
    const b = utf8.encode(v);
    parts.push(u64(b.length), b);
  }
  parts.push(pub, c.challenge);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

/** add-credential 페이로드(본인 추가, 새 키로 서명한 증명 포함). Challenge는 숫자 배열([32]byte), Proof는 base64 */
export async function selfAdditionPayload(key: UnlockedKey, clusterId: string, revision: number, c: Omit<CredentialAddition, 'challenge'>, challenge = crypto.getRandomValues(new Uint8Array(32))) {
  const full = { ...c, challenge };
  const proof = fromHex(await sign(key, credentialAdditionBytes(clusterId, revision, full)));
  return {
    User: c.user,
    Credential: { ID: c.id, Method: c.method, PublicKey: [...fromHex(c.publicKey)] },
    ...(c.label ? { Label: c.label } : {}),
    Challenge: [...challenge],
    Proof: b64(proof),
  };
}

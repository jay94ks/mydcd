// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { credentialAdditionBytes, selfAdditionPayload } from './credentialProof';
import { hex } from './keystore';

// sfcd access.CredentialAdditionBytes로 만든 값(seed 0x01×32, cluster 00..1f, revision 42, challenge 200+i%50)
const MSG =
  '7366632d73656c662d63726564656e7469616c2d6164646974696f6e2d3100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2a000000000000000600000000000000757365722d370b0000000000000062726f777365722d6162630b00000000000000707269766174652d6b65790900000000000000eb85b8ed8ab8ebb6818a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cc8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7';
const SIG = 'hNHLQ/wC+utDJj2SudIYN8K7NmhHiOOxxJNJBCV8YYXFrnnC+ueBHCuQaVKWagL/X5XhvJH/whDS+zP8RqW+Aw==';
const PUB = '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c';
const cluster = hex(Uint8Array.from({ length: 32 }, (_, i) => i));
const challenge = Uint8Array.from({ length: 32 }, (_, i) => 200 + (i % 50));
const add = { user: 'user-7', id: 'browser-abc', method: 'private-key', label: '노트북', publicKey: PUB };

describe('본인 키 추가 증명', () => {
  it('바이트가 sfcd와 같다', () => {
    expect(hex(credentialAdditionBytes(cluster, 42, { ...add, challenge }))).toBe(MSG);
  });
  it('새 키 서명과 페이로드 꼴이 sfcd와 같다', async () => {
    const seed = new Uint8Array(32).fill(1);
    const p = await selfAdditionPayload({ kind: 'js', seed }, cluster, 42, add, challenge);
    expect(p.Proof).toBe(SIG);
    expect(p.Challenge).toEqual([...challenge]);
    expect(p.Credential).toEqual({ ID: 'browser-abc', Method: 'private-key', PublicKey: [138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92] });
    expect(p.Label).toBe('노트북');
  });
  it('32바이트가 아니면 거절', () => {
    expect(() => credentialAdditionBytes('00', 1, { ...add, challenge })).toThrow();
  });
});

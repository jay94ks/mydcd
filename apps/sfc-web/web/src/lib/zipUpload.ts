// SPDX-License-Identifier: Apache-2.0

// 빌드 컨텍스트 zip 조각 올리기. 4 MiB 조각을 빠진 것만 보내고, 끊기면 같은 파일로 이어 올린다(서버 업로드는 약 24시간 열려 있다).
// 이어 올리기 정보(업로드 ID·파일 이름·크기·digest)는 이 브라우저 localStorage에 둔다. 비밀값은 없다.
import { api, ApiError, newOpId } from '../api/client';
import type { DOp } from '../api/dto';
import { putZipChunk, zipUpload, zipUploadsPath, type ZipUploadView } from '../api/endpoints';
import { sha256Hex } from './cryptoCompat';

export const ZIP_CHUNK_MAX = 500 * 1024 * 1024;
export type ZipSaved = { upload: string; name: string; bytes: number; modified: number; digest: string; sent: number; finishOpId?: string };
export type ZipProgress = { phase: 'hash' | 'send' | 'finish'; sent: number; total: number };

const key = (t: string, id: string) => `sfc.zipUpload.${t}/${id}`;
export function loadZipSaved(t: string, id: string): ZipSaved | undefined {
  try {
    const v = localStorage.getItem(key(t, id));
    return v ? (JSON.parse(v) as ZipSaved) : undefined;
  } catch {
    return undefined;
  }
}
const store = (t: string, id: string, v: ZipSaved | undefined) => {
  try {
    if (v) localStorage.setItem(key(t, id), JSON.stringify(v));
    else localStorage.removeItem(key(t, id));
  } catch {
    // 저장 못 하면 이어 올리기만 안 된다
  }
};
export const sameFile = (s: ZipSaved, f: File) => s.name === f.name && s.bytes === f.size && s.modified === f.lastModified;

export class ZipPaused extends Error {
  constructor() {
    super('paused');
    this.name = 'ZipPaused';
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sentOf = (u: ZipUploadView) => Math.max(0, u.length - (u.missingChunks ?? []).reduce((a, n) => a + (n === u.chunks - 1 ? u.length - n * u.chunkBytes : u.chunkBytes), 0));

/** 조각 올리기 한 번. begin op가 적용되지 않으면 그 op를, 끝나면 finish op를 돌려준다 */
export async function chunkedZip(o: { tenant: string; ctx: string; file: File; opId: string; stop: () => boolean; onProgress: (p: ZipProgress) => void }): Promise<{ op: DOp }> {
  const { tenant, ctx, file } = o;
  let saved = loadZipSaved(tenant, ctx);
  if (saved && !sameFile(saved, file)) saved = undefined;
  if (!saved) {
    o.onProgress({ phase: 'hash', sent: 0, total: file.size });
    const digest = await sha256Hex(await file.arrayBuffer());
    let r = await api.post<{ op: DOp }>(zipUploadsPath(tenant, ctx), { opId: o.opId, length: file.size, digest });
    // 결과를 아직 모르면 잠깐 묻고, 그래도 모르면 그 op를 보여 준다(다시 하면 같은 opId로 같은 업로드)
    for (let i = 0; i < 10 && ['pending', 'running', 'unknown'].includes(r.op.state); i++) {
      await sleep(1000);
      r = await api.post<{ op: DOp }>(`/ops/${encodeURIComponent(o.opId)}/result`);
    }
    // 시작이 적용되기 전에는 다음 단계로 넘어가면 안 되므로 결과 모름은 오류로 올린다(다시 하면 같은 opId)
    if (['pending', 'running', 'unknown'].includes(r.op.state)) throw new Error('업로드 시작 결과를 아직 모릅니다. 다시 시도하면 같은 작업으로 이어 갑니다.');
    if (r.op.state !== 'applied') return r;
    saved = { upload: `web-${o.opId}`, name: file.name, bytes: file.size, modified: file.lastModified, digest, sent: 0 };
    store(tenant, ctx, saved);
  }
  let u: ZipUploadView;
  try {
    u = await zipUpload(tenant, ctx, saved.upload);
    if (u.expiresAt && Date.parse(u.expiresAt) <= Date.now()) throw new ApiError(404, { code: 'not-found', message: 'expired' });
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      store(tenant, ctx, undefined);
      throw new Error('이어 올릴 업로드가 서버에 없습니다(끝났거나 취소됨). 다시 저장하면 처음부터 올립니다.');
    }
    throw e;
  }
  const report = (v: ZipUploadView) => {
    const sent = sentOf(v);
    saved = { ...saved!, sent };
    store(tenant, ctx, saved);
    o.onProgress({ phase: 'send', sent, total: v.length });
  };
  report(u);
  for (let round = 0; round < 100 && (u.missingChunks ?? []).length; round++) {
    const missing = [...(u.missingChunks ?? [])];
    let next = 0;
    const worker = async () => {
      while (next < missing.length) {
        if (o.stop()) return;
        const n = missing[next++];
        const blob = file.slice(n * u.chunkBytes, Math.min(file.size, (n + 1) * u.chunkBytes));
        for (let k = 0; ; k++) {
          try {
            const v = await putZipChunk(tenant, ctx, saved!.upload, n, blob);
            u = v;
            report(v);
            break;
          } catch (e) {
            // 409 conflict: 올리는 사이 업로드 revision이 움직였으면 같은 조각을 다시 보내면 된다(#229, 확인된 부분은 건너뜀).
            // 몇 번 다시 보내도 같으면 컨텍스트·정책이 바뀌었거나 업로드가 만료된 것(#215): 이 업로드는 더 못 쓴다
            if (e instanceof ApiError && e.status === 409 && e.code === 'conflict') {
              if (k < 2) {
                await sleep(300 * (k + 1));
                continue;
              }
              store(tenant, ctx, undefined);
              throw new Error('그 사이 컨텍스트나 빌드 설정이 바뀌었거나 업로드가 만료됐습니다. 다시 저장하면 처음부터 올립니다.');
            }
            // 그 밖의 4xx(길이·digest·없는 업로드)는 다시 보내도 같다. 503 storage-unavailable 등 5xx는 잠깐 뒤 다시
            if (k >= 2 || (e instanceof ApiError && e.status >= 400 && e.status < 500)) throw e;
            await sleep(800 * (k + 1));
          }
        }
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    if (o.stop()) throw new ZipPaused();
    u = await zipUpload(tenant, ctx, saved.upload);
    report(u);
  }
  o.onProgress({ phase: 'finish', sent: u.length, total: u.length });
  const fid = saved.finishOpId ?? newOpId();
  store(tenant, ctx, { ...saved, finishOpId: fid });
  let res: { op: DOp };
  try {
    res = await api.post<{ op: DOp }>(`${zipUploadsPath(tenant, ctx)}/${encodeURIComponent(saved.upload)}/finish`, { opId: fid });
  } catch (e) {
    // 422 part-refused: 다 받았지만 컨텍스트 zip이 아니다(경로·Dockerfile 없음·풀면 너무 큼). 같은 파일로는 다시 해도 같다
    if (e instanceof ApiError && e.status === 422 && e.code === 'part-refused') {
      store(tenant, ctx, undefined);
      throw new Error('올린 zip을 빌드 컨텍스트로 쓸 수 없습니다(바깥을 가리키는 경로, Dockerfile 없음, 또는 풀면 빌드 입력 한도보다 큼). zip을 고쳐 다시 올리세요.');
    }
    throw e;
  }
  if (res.op.state === 'applied') store(tenant, ctx, undefined);
  else if (res.op.state === 'failed' || res.op.state === 'rejected') store(tenant, ctx, { ...saved, finishOpId: undefined });
  return res;
}

/** 멈춘 업로드 버리기 */
export async function abortZip(tenant: string, ctx: string) {
  const s = loadZipSaved(tenant, ctx);
  store(tenant, ctx, undefined);
  if (!s) return;
  try {
    await api.del(`${zipUploadsPath(tenant, ctx)}/${encodeURIComponent(s.upload)}`, { opId: newOpId() });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
}

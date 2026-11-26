// SPDX-License-Identifier: Apache-2.0

/**
 * 브라우저에서 zip을 풀어 파일 목록으로 바꾼다. 서버로는 풀린 파일만 간다.
 * 저장(0)·deflate(8)만 받고, zip64·암호·링크·장치 항목은 거절하거나 뺀다.
 */
export interface UnzipEntry {
  path: string;
  data: Uint8Array;
}
export interface UnzipResult {
  files: UnzipEntry[];
  /** 뺀 항목과 이유 */
  skipped: string[];
}

const MAX_ENTRIES = 2000;

async function inflate(raw: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate-raw');
  const out = new Blob([raw as BlobPart]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(out).arrayBuffer());
}

export async function unzip(buf: ArrayBuffer, maxFile: number): Promise<UnzipResult> {
  const v = new DataView(buf);
  const u8 = new Uint8Array(buf);
  // 끝 레코드(EOCD)는 뒤에서 22~65557바이트 안에 있다
  let eocd = -1;
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) {
    if (v.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('zip 파일이 아닙니다');
  const count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  if (count === 0xffff || p === 0xffffffff) throw new Error('zip64는 받지 않습니다. 더 작게 묶어 주세요');
  if (count > MAX_ENTRIES) throw new Error(`항목이 ${count}개입니다. 한 번에 ${MAX_ENTRIES}개까지 풉니다`);
  const dec = new TextDecoder();
  const files: UnzipEntry[] = [];
  const skipped: string[] = [];
  for (let n = 0; n < count; n++) {
    if (v.getUint32(p, true) !== 0x02014b50) throw new Error('zip 목차가 깨졌습니다');
    const flags = v.getUint16(p + 8, true);
    const method = v.getUint16(p + 10, true);
    const csize = v.getUint32(p + 20, true);
    const usize = v.getUint32(p + 24, true);
    const nlen = v.getUint16(p + 28, true);
    const xlen = v.getUint16(p + 30, true);
    const clen = v.getUint16(p + 32, true);
    const attr = v.getUint32(p + 38, true);
    const off = v.getUint32(p + 42, true);
    const name = dec.decode(u8.subarray(p + 46, p + 46 + nlen)).replace(/\\/g, '/');
    p += 46 + nlen + xlen + clen;
    if (name.endsWith('/')) continue;
    if (name.startsWith('__MACOSX/') || name.endsWith('/.DS_Store') || name === '.DS_Store') continue;
    const type = (attr >>> 16) & 0xf000;
    if (type && type !== 0x8000) {
      skipped.push(`${name}: 링크·장치 항목이라 뺍니다`);
      continue;
    }
    if (flags & 1) {
      skipped.push(`${name}: 암호가 걸린 항목이라 뺍니다`);
      continue;
    }
    if (usize > maxFile) {
      skipped.push(`${name}: 파일 하나가 너무 큽니다`);
      continue;
    }
    if (v.getUint32(off, true) !== 0x04034b50) throw new Error(`${name}: zip 항목이 깨졌습니다`);
    const start = off + 30 + v.getUint16(off + 26, true) + v.getUint16(off + 28, true);
    const raw = u8.subarray(start, start + csize);
    let data: Uint8Array;
    if (method === 0) data = raw.slice();
    else if (method === 8) data = await inflate(raw);
    else {
      skipped.push(`${name}: 풀 수 없는 압축 방식(${method})입니다`);
      continue;
    }
    files.push({ path: name, data });
  }
  return { files, skipped };
}

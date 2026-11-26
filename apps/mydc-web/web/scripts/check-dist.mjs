// SPDX-License-Identifier: Apache-2.0

// 운영 빌드(dist)에 목업 계층이 들어가면 실패한다. 목업 계정·저장 키·목업 전용 문구를 찾는다.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = new URL('../dist/assets/', import.meta.url).pathname;
const marks = ['mydc.mock.session', 'mydc.mock.registered-keys', 'u-alice', '목업 셸입니다'];
const hits = [];
for (const f of readdirSync(dir)) {
  if (!f.endsWith('.js')) continue;
  const text = readFileSync(join(dir, f), 'utf8');
  for (const m of marks) if (text.includes(m)) hits.push(`${f}: ${m}`);
}
if (hits.length) {
  console.error('운영 빌드에 목업이 들어 있습니다:\n  ' + hits.join('\n  '));
  process.exit(1);
}
console.log('dist: 목업 없음');

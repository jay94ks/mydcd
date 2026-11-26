// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { sseParser, toStreamEvent, execPath } from './streams';
import { splitArgs } from '../components/TerminalPane';

describe('컨테이너 스트림', () => {
  it('SSE: 조각난 본문을 이어 붙이고 주석(ping)은 버린다', () => {
    const p = sseParser();
    expect(p('event: target\ndata: {"a"')).toEqual([]);
    expect(p(':1}\n\n: ping\n\nevent: end\r\ndata: {"type":"end"}\r\n\r\n')).toEqual([
      { event: 'target', data: '{"a":1}' },
      { event: 'end', data: '{"type":"end"}' },
    ]);
  });

  it('레코드: base64를 풀고 text가 없으면 UTF-8로 읽는다', () => {
    const e = toStreamEvent('stdout', { type: 'stdout', sequence: 3, data: btoa('hi\n') });
    expect(e).toMatchObject({ type: 'stdout', sequence: 3, text: 'hi\n' });
    expect(toStreamEvent('error', { type: 'error', code: 'target-changed' })).toEqual({ type: 'error', code: 'target-changed' });
    expect(toStreamEvent('ping', {})).toBeUndefined();
  });

  it('터미널 주소: cmd를 여러 번, TTY면 rows/cols', () => {
    const u = execPath({ tenant: 'shop', app: 'php-shop' }, { opId: 'o', service: 'web', instance: '1', cmd: ['sh', '-c', 'ls -l'], tty: true, stdin: true, rows: 30, cols: 100 });
    expect(u).toBe('/t/shop/apps/php-shop/exec?opId=o&service=web&instance=1&cmd=sh&cmd=-c&cmd=ls+-l&tty=1&rows=30&cols=100&stdin=1');
  });

  it('단독 컨테이너 터미널 주소: service·instance 없이 /standalone/{name}', () => {
    const u = execPath({ tenant: 'shop', app: '', standalone: 'dbg-1' }, { opId: 'o', service: 'dbg-1', instance: '1', cmd: ['/bin/sh'], tty: false, stdin: true });
    expect(u).toBe('/t/shop/standalone/dbg-1/exec?opId=o&cmd=%2Fbin%2Fsh&stdin=1');
  });

  it('명령 나누기: 따옴표 칸은 한 인자', () => {
    expect(splitArgs(`sh -c "ls -l /" 'a b'`)).toEqual(['sh', '-c', 'ls -l /', 'a b']);
  });
});

// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { checkSpec, composeValue, countAfter, groupRecords, ipv6, recordDelta, relName, showValue, specOk, valueParts, type DnsRecord, type RecordType } from './dnsRecords';

const Z = 'shop.internal.';
const RS: DnsRecord[] = [
  { name: 'www.shop.internal.', type: 'CNAME', value: 'web.php-shop.shop.internal.', served: true },
  { name: 'legacy.shop.internal.', type: 'A', value: '192.0.2.7', served: true },
  { name: 'legacy.shop.internal.', type: 'A', value: '192.0.2.8', served: false },
  { name: 'shop.internal.', type: 'TXT', value: '"v=spf1 -all"', ttl: 300, served: true },
  { name: 'shop.internal.', type: 'MX', value: '10 mail.shop.internal.', served: true },
];
const ctx = (over = {}) => ({ zone: Z, net: 'shop-net', others: groupRecords(RS, Z), appNames: ['web.php-shop'], ...over });
const spec = (name: string, type: RecordType, rows: string[][], ttl = '') => ({ name, type, rows, ttl });

describe('직접 더한 이름', () => {
  it('zone 아래 상대 이름과 묶음', () => {
    expect(relName('www.shop.internal.', Z)).toBe('www');
    expect(relName('shop.internal.', Z)).toBe('');
    expect(relName('example.org', Z)).toBe('example.org');
    expect(groupRecords(RS, Z)).toEqual([
      { name: '', type: 'MX', values: ['10 mail.shop.internal.'], served: true },
      { name: '', type: 'TXT', values: ['"v=spf1 -all"'], ttl: 300, served: true },
      { name: 'legacy', type: 'A', values: ['192.0.2.7', '192.0.2.8'], served: false },
      { name: 'www', type: 'CNAME', values: ['web.php-shop.shop.internal.'], served: true },
    ]);
  });

  it('종류별 값은 sfcd 정규형으로 만든다', () => {
    expect(composeValue('A', ['192.0.2.7'])).toEqual({ value: '192.0.2.7' });
    expect(composeValue('A', ['224.0.0.1']).error).toBeTruthy();
    expect(composeValue('AAAA', ['2001:0DB8:0:0:0:0:0:7'])).toEqual({ value: '2001:db8::7' });
    expect(composeValue('AAAA', ['::']).error).toBeTruthy();
    expect(composeValue('AAAA', ['ff02::1']).error).toBeTruthy();
    expect(composeValue('AAAA', ['::ffff:192.0.2.1']).error).toBeTruthy();
    expect(composeValue('CNAME', ['Example.org'])).toEqual({ value: 'example.org.' });
    expect(composeValue('CNAME', ['web']).error).toBeTruthy();
    expect(composeValue('MX', ['10', 'mail.example.org.'])).toEqual({ value: '10 mail.example.org.' });
    expect(composeValue('MX', ['70000', 'mail.example.org']).error).toBeTruthy();
    expect(composeValue('SRV', ['10', '5', '5432', 'db.shop.internal'])).toEqual({ value: '10 5 5432 db.shop.internal.' });
    expect(composeValue('CAA', ['ISSUE', 'letsencrypt.org', ''])).toEqual({ value: '0 issue "letsencrypt.org"' });
    expect(composeValue('CAA', ['issue', 'x', '1']).error).toBeTruthy();
    expect(composeValue('TXT', ['v=spf1 -all'])).toEqual({ value: '"v=spf1 -all"' });
    expect(composeValue('TXT', ['"a" "b\\"c"'])).toEqual({ value: '"a" "b\\"c"' });
    expect(composeValue('TXT', ['안'])).toEqual({ value: '"\\236\\149\\136"' });
    expect(composeValue('TXT', ['"a']).error).toBeTruthy();
  });

  it('TXT는 255바이트 조각으로 나누고 읽을 때는 붙여 보인다', () => {
    const long = 'x'.repeat(300);
    const v = composeValue('TXT', [long]).value!;
    expect(v).toBe(`"${'x'.repeat(255)}" "${'x'.repeat(45)}"`);
    expect(valueParts('TXT', v)).toEqual([`"${long}"`]);
    expect(composeValue('TXT', valueParts('TXT', v)).value).toBe(v);
    expect(composeValue('TXT', ['x'.repeat(1100)]).error).toBeTruthy();
    expect(valueParts('TXT', '"\\236\\149\\136"')).toEqual(['"안"']);
  });

  it('읽은 값 → 칸 → 다시 만든 값이 같다(고치기에서 안 바뀐 값은 변경분에 안 들어감)', () => {
    const cases: [RecordType, string][] = [
      ['A', '192.0.2.7'],
      ['AAAA', '2001:db8::7'],
      ['CNAME', 'web.php-shop.shop.internal.'],
      ['MX', '10 mail.example.org.'],
      ['SRV', '10 5 5432 db.shop.internal.'],
      ['CAA', '128 issuewild "ca.example.net"'],
      ['TXT', '"a" "b"'],
    ];
    for (const [t, v] of cases) expect(composeValue(t, valueParts(t, v)).value).toBe(v);
    expect(showValue('CAA', '0 issue "letsencrypt.org"')).toBe('0 issue "letsencrypt.org"');
    expect(showValue('MX', '10 mail.example.org.')).toBe('10 mail.example.org');
  });

  it('IPv6 정규형(RFC 5952)', () => {
    expect(ipv6('2001:db8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1');
    expect(ipv6('fd00:10:240:0:0:0:0:21')).toBe('fd00:10:240::21');
    expect(ipv6('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1');
    expect(ipv6('64:ff9b::192.0.2.1')).toBe('64:ff9b::c000:201');
    expect(ipv6('1::2::3')).toBeUndefined();
  });

  it('검사: 영역 밖·ns·CNAME 공존·이미 있는 종류·앱 서비스 이름', () => {
    expect(specOk(checkSpec(spec('api', 'A', [['192.0.2.1']]), ctx()))).toBe(true);
    expect(checkSpec(spec('cache.other.test.', 'A', [['192.0.2.1']]), ctx()).name).toBe('shop-net의 도메인 영역(shop.internal) 안의 이름만 더할 수 있습니다');
    expect(checkSpec(spec('api.shop.internal.', 'A', [['192.0.2.1']]), ctx()).rel).toBe('api');
    expect(checkSpec(spec('ns', 'A', [['192.0.2.1']]), ctx()).name).toMatch(/^ns\.shop\.internal는/);
    expect(checkSpec(spec('', 'CNAME', [['example.org']]), ctx()).type).toBe('도메인 영역 자체(shop.internal)에는 CNAME을 둘 수 없습니다');
    expect(checkSpec(spec('@', 'CAA', [['issue', 'letsencrypt.org', '0']]), ctx()).type).toBeUndefined();
    expect(checkSpec(spec('www', 'A', [['192.0.2.1']]), ctx()).type).toMatch(/이미 CNAME이 있어 A를/);
    expect(checkSpec(spec('legacy', 'A', [['192.0.2.9']]), ctx()).type).toMatch(/이미 A가 있습니다/);
    expect(checkSpec(spec('web.php-shop', 'A', [['192.0.2.1']]), ctx()).name).toMatch(/앱 서비스가 이미 쓰는 이름/);
    expect(checkSpec(spec('x', 'A', Array(9).fill(['192.0.2.1'])), ctx()).value).toContain('한 이름·종류에 값은 8개까지입니다.');
    expect(checkSpec(spec('x', 'A', [['192.0.2.1']], '0'), ctx()).ttlError).toBeTruthy();
    expect(checkSpec(spec('x', 'A', [['192.0.2.1']], '60'), ctx()).ttl).toBe(60);
  });

  it('CNAME과 다른 종류는 같이 못 둔다(캔버스 문구)', () => {
    const c = checkSpec(spec('', 'CNAME', [['example.org']]), ctx({ zone: 'shop.sfc.test', others: groupRecords([{ name: 'cache.shop.sfc.test.', type: 'TXT', value: '"x"' }, { name: 'cache.shop.sfc.test.', type: 'MX', value: '10 m.example.org.' }], 'shop.sfc.test') }));
    expect(c.type).toBe('도메인 영역 자체(shop.sfc.test)에는 CNAME을 둘 수 없습니다');
    const d = checkSpec(spec('cache', 'CNAME', [['example.org']]), ctx({ zone: 'shop.sfc.test', others: groupRecords([{ name: 'cache.shop.sfc.test.', type: 'TXT', value: '"x"' }, { name: 'cache.shop.sfc.test.', type: 'MX', value: '10 m.example.org.' }], 'shop.sfc.test') }));
    expect(d.type).toBe('cache.shop.sfc.test에 이미 MX · TXT가 있어 CNAME을 둘 수 없습니다');
  });

  it('변경분: 고치기는 바뀐 값만, TTL이 바뀌면 모두 빼고 다시 더한다, 영역 자체는 @', () => {
    const g = groupRecords(RS, Z);
    const [mx, txt, legacy, www] = g;
    expect(recordDelta(legacy, { name: 'legacy', type: 'A', values: ['192.0.2.8', '192.0.2.9'] })).toEqual({
      remove: [{ name: 'legacy', type: 'A', value: '192.0.2.7' }],
      add: [{ name: 'legacy', type: 'A', value: '192.0.2.9' }],
    });
    expect(recordDelta(legacy, { name: 'legacy', type: 'A', values: ['192.0.2.7', '192.0.2.8'], ttl: 30 })).toEqual({
      remove: [
        { name: 'legacy', type: 'A', value: '192.0.2.7' },
        { name: 'legacy', type: 'A', value: '192.0.2.8' },
      ],
      add: [
        { name: 'legacy', type: 'A', value: '192.0.2.7', ttl: 30 },
        { name: 'legacy', type: 'A', value: '192.0.2.8', ttl: 30 },
      ],
    });
    expect(recordDelta(txt, { name: '', type: 'TXT', values: ['"v=spf1 -all"'], ttl: 300 })).toEqual({ remove: [], add: [] });
    expect(recordDelta(mx)).toEqual({ remove: [{ name: '@', type: 'MX', value: '10 mail.shop.internal.' }], add: [] });
    expect(recordDelta(www)).toEqual({ remove: [{ name: 'www', type: 'CNAME', value: 'web.php-shop.shop.internal.' }], add: [] });
    expect(countAfter(RS, recordDelta(undefined, { name: 'x', type: 'A', values: ['192.0.2.1', '192.0.2.2'] }))).toBe(7);
  });
});

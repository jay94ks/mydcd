// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { countingText, flavorTrafficText, trafficVerdict, type VpsServerStatus } from './vps';

const base: VpsServerStatus = { name: 'v', updatedAt: 0, capKRW: 0, soFarKRW: 0, projectedKRW: 0, baseSoFarKRW: 0, baseMonthKRW: 0, trafficSoFarKRW: 0, trafficMonthKRW: 0, usedGB: 0, projectedGB: 0, recentMB: 0, judgeable: true };
const nov27 = new Date(2026, 10, 27);

describe('VPS 트래픽 (#698)', () => {
  it('일간 판정: 월말 제공량은 남은 날만큼 쌓이고 월 최대에서 멈춘다', () => {
    const x = { ...base, includedGB: 20, includedPeriod: 'DAY' as const, includedMonthGB: 540, includedMaxGB: 600, usedGB: 590, projectedGB: 720 };
    expect(trafficVerdict(x, 10, nov27)).toEqual({ tone: 'er', text: '이미 50 GB 넘음 · 월말 약 720 GB → 초과 120 GB (₩1,200)' });
    const y = { ...x, includedMonthGB: 500, usedGB: 412, projectedGB: 470 };
    expect(trafficVerdict(y, 10, nov27).text).toBe('남은 88 GB · 월말 약 470 GB / 560 GB · 초과 없음 예상');
  });
  it('제공량을 모르면 초과를 계산하지 않는다', () => {
    expect(trafficVerdict({ ...base, usedGB: 88 }).text).toBe('제공량 모름 · 초과 요금은 계산하지 않음');
  });
  it('세는 방식과 타입 표 문구', () => {
    expect(countingText('tx')).toBe('TX만');
    expect(countingText(undefined)).toBe('세는 방식 모름');
    expect(flavorTrafficText({ gb: 20, period: 'DAY', maxGB: 600, estimated: true }, 'tx')).toBe('하루 20 GB · 월 최대 600 GB · TX만 · 추정');
    expect(flavorTrafficText({ gb: 2000, period: 'MONTH' })).toBe('월 2 TB');
  });
});

describe('초과 요금 구간 (#698 overageTiers)', () => {
  it('구간 이름과 넘은 양의 구간', async () => {
    const { IWINV_TIERS, tierRange, tierIndex } = await import('./vps');
    expect(IWINV_TIERS.map((_, i) => tierRange(IWINV_TIERS, i))).toEqual(['1,000 GB까지', '1,000–2,000 GB', '2,000–3,000 GB', '3,000–4,000 GB', '4,000 GB 넘음']);
    expect(tierIndex(IWINV_TIERS, 254)).toBe(0);
    expect(tierIndex(IWINV_TIERS, 1500)).toBe(1);
    expect(tierIndex(IWINV_TIERS, 9000)).toBe(4);
  });
});

describe('트래픽 조기 감시 설정 (#701)', () => {
  it('창 1–60, 평균은 창의 2배 이상·1440 이하, 0은 기본', async () => {
    const { guardError } = await import('./vps');
    expect(guardError(0, 0)).toBeUndefined();
    expect(guardError(10, 0)).toBeUndefined();
    expect(guardError(10, 15)).toBe('누적 평균 기간은 측정 창의 2배(20분) 이상이어야 합니다');
    expect(guardError(40, 0)).toBe('누적 평균 기간은 측정 창의 2배(80분) 이상이어야 합니다');
    expect(guardError(61, 200)).toBe('측정 창은 1–60분입니다');
    expect(guardError(5, 1500)).toBe('누적 평균 기간은 1440분 이하입니다');
  });
});

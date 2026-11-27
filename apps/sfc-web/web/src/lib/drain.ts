// SPDX-License-Identifier: Apache-2.0

// 서버 비우기(drain-node) 상태. sfcd 값(Running·Succeeded·Partial 등, 대소문자 무관)을 사람 말로 옮긴다.
const DRAIN_KO: Record<string, string> = { planned: '준비', pending: '준비', running: '옮기는 중', done: '끝남', completed: '끝남', succeeded: '끝남', partial: '일부만 옮김', failed: '실패', blocked: '막힘' };
/** 모르는 값은 그대로 */
export const drainStateText = (s: string) => DRAIN_KO[s.toLowerCase()] ?? s;
/** 끝난 상태가 아니면 진행 중으로 본다 */
export const drainRunning = (s: string) => !['done', 'completed', 'succeeded', 'partial', 'failed'].includes(s.toLowerCase());

// SPDX-License-Identifier: Apache-2.0

// 저장 경로 추가 (UI-14, 캔버스 v272–v274 NodeDetailIx '경로 추가', NodeDisksIx '여기에 저장 경로 만들기').
// 디스크를 고르고 그 마운트 위치 아래 하위 경로를 정한다. sfcd가 prepare-storage(#799)로 디렉터리를 준비하고
// (미사용 디스크면 포맷·마운트까지) 돌려준 rootPath로 기존 POST /nodes/{node}/storage(합의)를 보낸다.
// 손으로 마운트한 곳(fstab)·시스템 디스크는 sfcd가 하위 경로를 만들지 않으므로 '경로 직접 적기'로 전체 경로를 적는다.
import { useState } from 'react';
import type { DBlockDisk, DBlockPart, DDiskOp, DNodeDevices } from '../api/dto';
import type { StorageRoot } from '../api/types';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { Field } from '../components/ui';
import { fmtBytes } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { tenantList } from '../api/endpoints';
import { canFormat, diskNameError, managedRecord, MOUNT_BASE, mountPathError } from './NodeDisks';
import { elapsed, FailBand, Steps, useDiskRunner, useTicker, type StepState } from './DiskActions';

const GiB = 1024 ** 3;
const DIRECT = '__direct__';

/** 고를 수 있는 자리: sfcd가 마운트한 추가 디스크 파티션, 포맷할 미사용 디스크, (흐리게) 손으로 마운트한 곳·시스템 디스크 */
export type RootTarget =
  | { kind: 'mount'; disk: DBlockDisk; part: DBlockPart; mount: string; managed: boolean }
  | { kind: 'unused'; disk: DBlockDisk; reformat: boolean; ok: boolean }
  | { kind: 'system'; disk: DBlockDisk };

const mountsOf = (p: DBlockPart) => (p.swap ? [] : [...(p.mounts ?? []), ...(p.holders ?? []).filter((h) => !h.swap).flatMap((h) => h.mounts ?? [])].filter((m) => !m.startsWith('/boot')));

export function rootTargets(dev: DNodeDevices | undefined): RootTarget[] {
  const out: RootTarget[] = [];
  for (const d of dev?.disks ?? []) {
    if (d.class === 'system' || d.locked) out.push({ kind: 'system', disk: d });
    else if (d.class === 'unused') out.push({ kind: 'unused', disk: d, reformat: (d.parts ?? []).some((p) => p.fsType), ok: canFormat(d) });
    else for (const p of d.parts ?? []) for (const m of mountsOf(p)) out.push({ kind: 'mount', disk: d, part: p, mount: m, managed: !!dev && managedRecord(dev, p)?.path === m });
  }
  return out;
}
const keyOf = (t: RootTarget) => (t.kind === 'mount' ? `m:${t.part.name}:${t.mount}` : `${t.kind}:${t.disk.name}`);

/** sfcd 하위 경로 규칙: 영문·숫자·.·-·_ 이름을 /로 8단까지. 빈 값은 마운트 위치 그대로 */
export function subPathError(s: string): string | undefined {
  if (!s) return undefined;
  const parts = s.split('/');
  if (parts.length > 8 || parts.some((x) => !/^[A-Za-z0-9._-]+$/.test(x) || x === '.' || x === '..')) return '영문·숫자·.·-·_ 이름을 /로 이어 8단까지 씁니다(.. 안 됨, 비우면 마운트 위치 그대로)';
  return undefined;
}
const join = (base: string, sub: string) => (sub ? `${base.replace(/\/$/, '')}/${sub}` : base);
const free = (p: DBlockPart) => (p.space ? fmtBytes(p.space.available) : undefined);

function targetLabel(t: RootTarget): string {
  if (t.kind === 'system') return `${t.disk.name} · 시스템 디스크 — 디스크 탭에서`;
  if (t.kind === 'unused') return `${t.disk.name} · ${t.reformat ? 'ext4 있음 · 다시 포맷' : '빈 디스크'} · ${fmtBytes(t.disk.size)}${t.ok ? '' : ' — 포맷할 수 없음'}`;
  const f = free(t.part);
  return `${t.part.name}${t.disk.kind === 'bundle' ? ' · 디스크 묶음' : t.part.label ? ` · ${t.part.label}` : ''} · ${t.mount}${f ? ` · 여유 ${f}` : ''}${t.managed ? '' : ' (직접 마운트) — 경로 직접 적기로'}`;
}

/**
 * 저장 경로 추가. initial: 디스크 탭의 '여기에 저장 경로 만들기'가 고른 마운트(없으면 직접 적기 경로).
 * dev가 없으면(읽지 못함) 경로 직접 적기만.
 */
export function AddRootDialog({ node, dev, taken, initialMount, onClose, onDone, onReload }: { node: string; dev?: DNodeDevices; taken: StorageRoot[]; initialMount?: string; onClose: () => void; onDone: () => void; onReload: () => void }) {
  const targets = rootTargets(dev);
  const fromDisk = initialMount !== undefined;
  const start = fromDisk ? targets.find((t) => t.kind === 'mount' && t.managed && t.mount === initialMount) : undefined;
  const [sel, setSel] = useState<string>(start ? keyOf(start) : fromDisk || !dev ? DIRECT : '');
  // 보낸 뒤에는 고른 자리를 고정한다(포맷 뒤 다시 읽으면 미사용 디스크가 추가 디스크로 옮겨 간다)
  const [fixed, setFixed] = useState<RootTarget>();
  const t = fixed ?? targets.find((x) => keyOf(x) === sel);
  const direct = sel === DIRECT;
  const ts = usePoll((s) => tenantList(s), []);
  const [rid, setRid] = useState('');
  const [sub, setSub] = useState('');
  const [subTouched, setSubTouched] = useState(false);
  const [path, setPath] = useState(fromDisk && !start ? initialMount : '');
  const [dname, setDname] = useState('');
  const [dnameTouched, setDnameTouched] = useState(false);
  const [mpath, setMpath] = useState('');
  const [mpathTouched, setMpathTouched] = useState(false);
  const [typed, setTyped] = useState('');
  const [all, setAll] = useState(true);
  const [tenants, setTenants] = useState<string[]>([]);
  const [cap, setCap] = useState('');
  const m = useMutation();
  const r = useDiskRunner(node, t && t.kind !== 'system' ? t.disk.name : '');
  const [prep, setPrep] = useState<DDiskOp>();
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState<number>();
  useTicker(busy);

  const started = !!prep || busy || !!m.op;
  const subPath = subTouched ? sub : rid;
  const label = dnameTouched ? dname : rid.slice(0, 16);
  const mountPath = mpathTouched ? mpath : label ? `${MOUNT_BASE}/${label}` : '';
  const unused = t?.kind === 'unused' ? t : undefined;
  const base = t?.kind === 'mount' ? t.mount : unused ? mountPath : '';
  const finalPath = direct ? path.replace(/\/$/, '') : base ? join(base, subPath) : '';

  const idErr = !started && rid ? (!/^[a-z][a-z0-9-]{0,62}$/.test(rid) ? '영문 소문자로 시작하고 영문 소문자·숫자·-만 씁니다(63자까지)' : taken.some((x) => x.name === rid) ? '이 서버에 같은 ID가 있습니다' : undefined) : undefined;
  const subErr = !direct && !started ? subPathError(subPath) : undefined;
  const pathErr =
    direct && !started && path
      ? !path.startsWith('/') || path === '/' || /(^|\/)\.\.?(\/|$)/.test(path) || path.includes('//')
        ? '/로 시작하는 정리된 절대 경로여야 합니다(/ 자체, .., // 안 됨)'
        : taken.some((x) => x.path === finalPath)
          ? '이미 등록한 경로입니다'
          : undefined
      : undefined;
  const takenErr = !direct && !started && finalPath && taken.some((x) => x.path === finalPath) ? '이미 등록한 경로입니다. 하위 경로를 바꿔 주세요' : undefined;
  const dnameErr = unused && !started && (dnameTouched || rid) ? diskNameError(label) : undefined;
  const mpathErr = unused && !started && mountPath ? mountPathError(mountPath, dev) : undefined;
  const capBytes = cap.trim() ? Math.round(Number(cap) * GiB) : 0;
  const capErr = cap.trim() && !(Number(cap) > 0 && capBytes <= 2 ** 60) ? '0보다 큰 GiB 값(비우면 한도 없음)' : undefined;
  const okTarget = direct ? !!path && !pathErr : t?.kind === 'mount' ? t.managed : !!unused?.ok;
  const ready = !!rid && !idErr && !subErr && !takenErr && !dnameErr && !mpathErr && !capErr && okTarget && (!unused || (!!label && !!mountPath && typed === unused.disk.name)) && !busy;
  const root = (p: string) => ({ id: rid, path: p, tenants: all ? [] : [...tenants].sort(), ...(all ? { allTenants: true } : {}), ...(capBytes ? { capacityBytes: capBytes } : {}) });

  const register = async (p: string) => {
    const op = await sendOp(m, `/nodes/${encodeURIComponent(node)}/storage`, root(p));
    if (op?.state === 'applied') onDone();
  };
  const go = async () => {
    if (direct) return void register(finalPath);
    if (!t || t.kind === 'system') return;
    setFixed(t);
    setBusy(true);
    setAt(Date.now());
    try {
      let o = prep;
      if (o?.state !== 'done') {
        // 포맷 뒤에 실패했으면 format:false와 그때 받은 uuid로 다시 보낸다(label은 포맷할 때만, sfcd가 거절한다)
        const formatted = unused && prep?.uuid;
        const body =
          t.kind === 'mount'
            ? { part: t.part.name, uuid: t.part.uuid, subPath }
            : formatted
              ? { part: prep.part ?? t.disk.name, uuid: prep.uuid, format: false, mountPath, subPath }
              : { part: t.disk.name, serial: t.disk.serial || undefined, wwn: t.disk.wwn || undefined, size: t.disk.size, tableId: t.disk.tableID || undefined, format: true, mountPath, label, subPath };
        o = await r.run('prepare-storage', body, (x) => setPrep((p) => ({ ...x, uuid: x.uuid ?? p?.uuid })));
        if (o?.state !== 'done' || !o.rootPath) return;
        onReload();
      }
      if (m.op?.state !== 'applied') await register(o.rootPath ?? finalPath);
    } finally {
      setBusy(false);
    }
  };

  const rootState: StepState = !m.op ? (m.error !== undefined ? 'fail' : 'wait') : m.op.state === 'applied' ? 'done' : m.op.state === 'failed' || m.op.state === 'rejected' ? 'fail' : 'run';
  const fmtStep = (o?: DDiskOp): StepState => (!o ? (r.fail && unused ? 'fail' : 'wait') : o.state === 'done' || !['partition', 'format'].includes(o.step) ? 'done' : o.state === 'failed' ? 'fail' : 'run');
  const mntStep = (o?: DDiskOp): StepState => (!o || (o.state === 'running' && ['partition', 'format'].includes(o.step)) ? 'wait' : o.state === 'done' ? 'done' : o.state === 'failed' ? 'fail' : 'run');
  const done = rootState === 'done';
  const notManaged = r.fail?.op?.code === 'not-managed';
  const hostDisk = t && t.kind !== 'system' ? t.disk.name : (dev?.disks ?? []).find((d) => (d.parts ?? []).some((p) => mountsOf(p).some((x) => x === initialMount || (x === '/' && initialMount?.startsWith('/srv/')))))?.name;
  const title = fromDisk ? `${hostDisk ?? initialMount} 위에 저장 경로 만들기` : `저장 경로 추가 (${node})`;

  const choose = (k: string) => {
    setSel(k);
    setTyped('');
  };
  return (
    <Dialog
      title={title}
      onClose={onClose}
      width={560}
      danger={!!unused}
      footer={
        done ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {started ? '닫기' : '취소'}
            </button>
            <button type="button" className={unused ? 'btn danger solid' : 'btn primary'} disabled={!ready} onClick={() => void go()}>
              {busy ? '진행 중…' : started ? '이어서 하기' : unused ? '포맷하고 추가' : fromDisk ? '만들기' : '추가'}
            </button>
          </>
        )
      }
    >
      <Field label={fromDisk ? '저장 경로 ID' : 'ID'} error={idErr}>
        <input className="mono" value={rid} onChange={(e) => setRid(e.target.value.trim())} placeholder="data3" disabled={started} autoComplete="off" />
      </Field>
      {!fromDisk && (
        <Field label="디스크" hint={dev ? '추가 디스크와 미사용 디스크만 고를 수 있습니다. 시스템 디스크는 디스크 탭의 ‘여기에 저장 경로 만들기’에서' : '디스크 목록을 읽지 못해 경로를 직접 적습니다'}>
{started ? (
            <span className="mono">{t ? targetLabel(t).replace(/ — .*$/, '') : '경로 직접 적기'}</span>
          ) : (
                    <select value={sel} onChange={(e) => choose(e.target.value)} disabled={!dev}>
            {dev && (
              <option value="" disabled>
                디스크를 고르세요
              </option>
            )}
            {(['mount', 'unused', 'system'] as const).map((k) => {
              const rows = targets.filter((x) => x.kind === k);
              if (!rows.length) return null;
              return (
                <optgroup key={k} label={k === 'mount' ? '추가 디스크' : k === 'unused' ? '미사용 디스크 · 포맷하고 마운트' : '시스템 디스크'}>
                  {rows.map((x) => (
                    <option key={keyOf(x)} value={keyOf(x)} disabled={x.kind === 'system' || (x.kind === 'mount' && !x.managed) || (x.kind === 'unused' && !x.ok)}>
                      {targetLabel(x)}
                    </option>
                  ))}
                </optgroup>
              );
            })}
            <option value={DIRECT}>경로 직접 적기… (운영자가 직접 마운트한 곳)</option>
          </select>
          )}
        </Field>
      )}
      {direct && (
        <Field label="경로" error={pathErr} hint="이미 있는 빈 디렉터리 · ext4만 · 서버가 파일 시스템·겹침을 확인합니다. Seafield Cluster가 마운트하지 않은 디스크(fstab 등)는 sfcd가 하위 경로를 만들지 않으므로 전체 경로를 적습니다">
          <input className="mono" value={path} onChange={(e) => setPath(e.target.value.trim())} placeholder="/mnt/media/sfc" disabled={started} />
        </Field>
      )}
      {unused && (
        <>
          <Field label="디스크 이름" error={dnameErr} hint="파일시스템 label · 마운트 위치 이름">
            <input className="mono" value={label} onChange={(e) => (setDname(e.target.value.trim()), setDnameTouched(true))} placeholder="archive" disabled={started} autoComplete="off" />
          </Field>
          <Field label="마운트 위치" error={mpathErr} hint="바꿀 수 있음">
            <input className="mono" value={mountPath} onChange={(e) => (setMpath(e.target.value.trim()), setMpathTouched(true))} placeholder={`${MOUNT_BASE}/archive`} disabled={started} />
          </Field>
        </>
      )}
      {!direct && base && (
        <Field label="하위 경로" error={subErr ?? takenErr} hint={finalPath ? `최종 경로 ${finalPath} · 없으면 sfcd가 만듭니다(0700)` : undefined}>
          <span className="row" style={{ gap: 0, alignItems: 'stretch' }}>
            <span className="mono muted" style={{ alignSelf: 'center', paddingRight: 2 }}>
              {base.replace(/\/$/, '')}/
            </span>
            <input className="mono" style={{ flex: 1 }} value={subPath} onChange={(e) => (setSub(e.target.value.trim()), setSubTouched(true))} placeholder="data3" disabled={started} />
          </span>
        </Field>
      )}
      <Field label="허용 작업 공간" group hint={all ? '켜면 지금·나중 작업 공간 모두 허용' : undefined}>
        <label className="check">
          <input type="checkbox" checked={all} disabled={started} onChange={(e) => setAll(e.target.checked)} /> 모든 작업 공간
        </label>
        {!all && (
          <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {(ts.data ?? []).map((x) => (
              <label key={x.id} className={`choice ${tenants.includes(x.id) ? 'on' : ''}`}>
                <input type="checkbox" checked={tenants.includes(x.id)} disabled={started} onChange={(e) => setTenants(e.target.checked ? [...tenants, x.id] : tenants.filter((y) => y !== x.id))} /> {x.id}
              </label>
            ))}
          </span>
        )}
      </Field>
      <Field label="용량 한도 (GiB, 비우면 제한 없음)" error={capErr} hint="이 경로의 데이터 저장소 용량 합계 상한">
        <input inputMode="decimal" value={cap} onChange={(e) => setCap(e.target.value.replace(/[^\d.]/g, ''))} disabled={started} placeholder="제한 없음" style={{ width: 160 }} />
      </Field>
      {unused && !started && (
        <>
          <div className="bn err small">
            {unused.disk.name}를 ext4로 포맷하고 마운트한 뒤 저장 경로를 등록합니다. 디스크의 모든 데이터가 지워집니다.
          </div>
          <Field label={`확인: 디스크 이름 ${unused.disk.name} 입력`}>
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value.trim())} placeholder={unused.disk.name} autoComplete="off" spellCheck={false} />
          </Field>
        </>
      )}
      {!unused && !started && (fromDisk ? <div className="note small">저장 경로는 클러스터 자원이라 등록은 합의로 남습니다.{t?.kind === 'mount' && free(t.part) ? ` 디스크 여유 ${free(t.part)}.` : ''}</div> : <div className="note small">추가하면 서버가 경로(파일 시스템·남은 공간·다른 경로와 겹침)를 확인합니다. 확인이 끝날 때까지 목록에 ‘서버 확인 대기’로 보입니다.</div>)}
      {started && !direct && (
        <>
          <span className="small">
            <b>{unused ? '포맷하고 추가' : '저장 경로 준비'}</b> {t && t.kind !== 'system' ? t.disk.name : ''} → 저장 경로 {rid}
          </span>
          <Steps
            rows={[
              ...(unused ? [{ label: '포맷 (ext4)', state: fmtStep(prep), detail: prep?.state === 'running' && ['partition', 'format'].includes(prep.step) ? elapsed(at) : undefined }] : []),
              { label: unused ? '마운트' : '하위 경로 만들기', state: mntStep(prep), detail: prep?.rootPath || mountPath ? <span className="mono">{unused ? (prep?.mountPath ?? mountPath) : (prep?.rootPath ?? finalPath)}</span> : undefined },
              { label: '저장 경로 등록', state: rootState, detail: rootState === 'done' ? '서버 확인 대기' : undefined },
            ]}
          />
          {unused && <span className="small muted">포맷이나 마운트가 실패하면 저장 경로는 등록하지 않습니다.</span>}
        </>
      )}
      {direct ? null : notManaged ? (
        <div className="bn err small">
          직접 마운트한 디스크라 sfcd가 하위 경로를 만들지 않습니다. 경로 직접 적기로 전체 경로를 적어 주세요.{' '}
          <button type="button" className="btn sm" onClick={() => (setPath(finalPath), setPrep(undefined), setFixed(undefined), choose(DIRECT))}>
            경로 직접 적기
          </button>
        </div>
      ) : (
        <FailBand fail={r.fail} onReload={onReload} />
      )}
      <MutationError error={m.error} />
      {m.op && rootState !== 'done' && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

// SPDX-License-Identifier: Apache-2.0

// 목업 시나리오(계약 DTO 모양). 실제 sfcd 응답이 아니며 화면 개발용 예시 값이다.
import type * as D from '../dto';
import type { ImageView } from '../types';

const GiB = 1024 ** 3;
export const nowSec = () => Math.floor(Date.now() / 1000);
const t0 = nowSec();
export const agoSec = (s: number) => t0 - s;
export const agoIso = (s: number) => new Date((t0 - s) * 1000).toISOString();

export interface MockUser extends D.DUserRecord {
  password: string;
}
export const users: MockUser[] = [
  { id: 'u-alice', username: 'alice', password: 'alice', enabled: true, systemAdmin: true, revision: 12, credentials: [{ id: 'pw', method: 'password', enabled: true }] },
  { id: 'u-bob', username: 'bob', password: 'bob', enabled: true, systemAdmin: false, revision: 4, credentials: [{ id: 'pw', method: 'password', enabled: true }] },
  { id: 'u-carol', username: 'carol', password: 'carol', enabled: false, systemAdmin: false, revision: 2, credentials: [{ id: 'tok', method: 'token', enabled: true }] },
  { id: 'u-web-auto', username: 'sfc-web-auto', password: '', enabled: true, systemAdmin: false, revision: 1, credentials: [{ id: 'key', method: 'private-key', enabled: true }] },
];

/** tenant → user id → role */
export const memberships: Record<string, Record<string, 'manager' | 'viewer'>> = {
  shop: { 'u-alice': 'manager', 'u-bob': 'viewer', 'u-web-auto': 'viewer' },
  internal: { 'u-alice': 'manager', 'u-carol': 'manager' },
  lab: { 'u-alice': 'viewer' },
  'legacy-lab': {},
};
export const tenantRev: Record<string, number> = { shop: 7, internal: 3, lab: 2, 'legacy-lab': 9 };
export const retiring: Record<string, D.DTenantRetirement> = {
  'legacy-lab': { tenant: 'legacy-lab', retiring: true, index: 4012, rootRevision: 401, targetCount: 3, ownerCount: 3, closedOwners: 2, remainingCount: 1, remaining: ['volume/lab-data@node-a'], operation: 'retire-lab', phase: 'retiring' },
};

export const members: D.DMember[] = [
  { id: 'node-a', systemAddress: '10.254.240.11', key: '3f9a1c0e5b7d22a8e41f09c3b6d5a7e8f1c2b3a4d5e6f708192a3b4c5d6e7f80', endpoint: '10.0.0.11:7443', revision: 31, joinRevision: 4, phase: 'active', voter: true, admitsWork: true, scheduling: { enabled: false, revision: 2 }, join: 'active', identity: { operation: 'rotate-node-a-0911', phase: 'Installed' } },
  { id: 'node-b', systemAddress: '10.254.240.12', key: 'a01d77e0c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6', endpoint: '10.0.0.12:7443', revision: 30, joinRevision: 5, phase: 'active', voter: true, admitsWork: true, scheduling: { enabled: false, revision: 1 }, join: 'active' },
  { id: 'node-c', systemAddress: '10.254.240.13', key: 'c21b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c', endpoint: '10.0.0.13:7443', revision: 29, joinRevision: 29, phase: 'pending', voter: false, pendingOperation: 'invite-node-c', join: 'invited' },
];

export const summaries: D.DNodeSummary[] = [
  { node: 'node-a', build: { enabled: true }, status: 'ready', state: 'ready', ready: true, stale: false, role: 'leader', cpuPercent: 42, memUsed: 19.5 * GiB, memTotal: 32 * GiB, diskUsed: 830 * GiB, diskTotal: 1000 * GiB, containers: 11, observedAt: agoSec(4),
    clusterApps: [{ name: 'web', image: 'sfc/web', version: '0.9.0', ports: [{ name: 'web', port: 8080, protocol: 'tcp' }, { name: 'acme', port: 8081, protocol: 'tcp' }, { name: 'direct', port: 8082, protocol: 'tcp' }], digest: 'sha256:3b7e0c4d9a1f2e3d4c5b6a7980f1e2d3c4b5a6978877665544332211009988d1', state: 'running', address: '10.254.0.11', restarts: 0, control: 'node-config', actions: [] }] },
  { node: 'node-b', build: { enabled: false, reason: 'ENGINE_BUILD_OFF' }, status: 'ready', state: 'ready', ready: true, stale: false, role: 'voter', cpuPercent: 18, cpuStealPercent: 7.4, memUsed: 23 * GiB, memTotal: 32 * GiB, diskUsed: 400 * GiB, diskTotal: 1000 * GiB, containers: 12, observedAt: agoSec(5),
    clusterApps: [{ name: 'web', image: 'sfc/web', version: '0.9.0', ports: [], state: 'refused', reason: 'already-running', runningOn: 'node-a', address: '10.254.0.11', restarts: 0, control: 'node-config', actions: [] }] },
  // 데몬 #373: 서버 단계(pending)가 그대로 오고 관측 숫자는 없다
  { node: 'node-c', build: { enabled: false, reason: 'UNKNOWN' }, status: 'pending', state: 'pending', ready: false, stale: true, role: 'non-voter', containers: 0, observedAt: agoSec(40),
    clusterApps: [{ name: 'web', image: 'sfc/web', ports: [], state: 'image-mismatch', reason: 'release-unverified', restarts: 0, control: 'node-config', actions: [] }] },
];

function task(tenant: string, app: string, service: string, instance: string, node: string, observed: D.DTask['observed'], health: D.DTask['health'], generation: number, restarts: number, staleSec = 6, exitCode?: number): D.DTask {
  return {
    tenant,
    app,
    service,
    instance,
    node,
    image: service === 'db' ? 'docker.io/library/mysql@sha256:9c2e41d07a5f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9' : 'docker.io/library/php@sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8',
    generation,
    desired: 'running',
    observed,
    health,
    restarts,
    exitCode,
    startedAt: agoSec(3 * 3600),
    observedAt: agoSec(staleSec),
    lastCheck: health === 'healthy' ? 'http-ok · 통과' : undefined,
  };
}
export const tasks: D.DTask[] = [
  task('shop', 'php-shop', 'web', '1', 'node-a', 'running', 'healthy', 7, 2),
  task('shop', 'php-shop', 'web', '2', 'node-b', 'running', 'healthy', 7, 2, 190),
  task('shop', 'php-shop', 'worker', '1', 'node-a', 'running', 'none', 3, 0),
  task('shop', 'mysql', 'db', '1', 'node-a', 'running', 'healthy', 2, 0),
  task('shop', 'worker-batch', 'worker', '1', 'node-b', 'exited', 'unhealthy', 5, 4, 6, 1),
  task('shop', 'worker-batch', 'worker', '2', 'node-b', 'restarting', 'starting', 5, 5),
  task('internal', 'grafana', 'grafana', '1', 'node-a', 'running', 'healthy', 1, 0),
  task('internal', 'grafana', 'prometheus', '1', 'node-b', 'running', 'healthy', 1, 0),
  task('lab', 'notebook', 'jupyter', '1', 'node-b', 'running', 'none', 2, 1),
];

export const storageRoots: D.DStorageRoot[] = [
  // #684: 초기화 때 서버가 스스로 등록하는 기본 저장 경로(모든 작업 공간, 한도 없음)
  { node: 'node-a', id: 'default', path: '/var/lib/sfc/volumes', tenants: [], allTenants: true, capacityBytes: 0, generation: 1, revision: 1, draining: false },
  { node: 'node-b', id: 'default', path: '/var/lib/sfc/volumes', tenants: [], allTenants: true, capacityBytes: 0, generation: 1, revision: 1, draining: false },
  { node: 'node-a', id: 'data1', path: '/srv/sfc/data1', tenants: ['shop', 'internal'], generation: 1, revision: 4, draining: false },
  { node: 'node-b', id: 'data1', path: '/srv/sfc/data1', tenants: ['shop', 'internal', 'lab'], generation: 1, revision: 3, draining: false },
  { node: 'node-b', id: 'backup', path: '/srv/sfc/backup', tenants: ['shop'], capacityBytes: 200 * 1024 ** 3, generation: 1, revision: 2, draining: false },
  { node: 'node-c', id: 'build-c', path: '/srv/sfc/build-c', tenants: ['shop'], generation: 1, revision: 1, draining: false },
  // 느린 저장소, node-a의 기본 보관 위치(#920)
  { node: 'node-a', id: 'slow1', path: '/mnt/pool1/archive', tenants: ['shop'], generation: 1, revision: 1, draining: false, archiveDefault: true },
];

const disk = (node: string, mount: string, device: string, fsType: string, purpose: string, total: number, used: number, storageRootID?: string): D.DNodeDisk => ({
  node,
  mount,
  device,
  fsType,
  purpose,
  storageRootID,
  total,
  used,
  free: total - used,
  observedAt: agoSec(30),
});
export const disks: D.DNodeDisk[] = [
  disk('node-a', '/', 'nvme0n1p2', 'ext4', 'system', 40 * GiB, 22 * GiB),
  disk('node-a', '/var/lib/docker', 'nvme0n1p3', 'ext4', 'container-runtime', 200 * GiB, 120 * GiB),
  disk('node-a', '/srv/sfc/data1', 'sdb1', 'xfs', 'storage-root', 1024 * GiB, 412 * GiB, 'data1'),
  disk('node-b', '/', 'nvme0n1p2', 'ext4', 'system', 40 * GiB, 31 * GiB),
  disk('node-b', '/var/lib/docker', 'nvme0n1p3', 'ext4', 'container-runtime', 200 * GiB, 184 * GiB),
  disk('node-b', '/srv/sfc/data1', 'sdb1', 'xfs', 'storage-root', 1024 * GiB, 300 * GiB, 'data1'),
  disk('node-b', '/srv/sfc/backup', 'sdc1', 'xfs', 'storage-root', 2048 * GiB, 1930 * GiB, 'backup'),
  disk('node-c', '/srv/sfc/build-c', 'sdb1', 'xfs', 'storage-root', 312 * GiB, 271 * GiB, 'build-c'),
  // 데몬 #365: 한 디스크에 용도·저장 경로가 여럿이거나, 크기를 모르는 오래된 관측
  { ...disk('node-c', '/srv/sfc/shared', '', 'xfs', 'storage-root', 0, 0), purposes: ['storage-root', 'container-runtime'], storageRoots: ['logs-c', 'cache-c'], total: undefined, used: undefined, free: undefined, stale: true },
];

/** 서버 장치 목록 (#689). node-a만: 시스템 nvme0n1, 추가 sdb(운영자 마운트·저장 경로 + LVM)·sdc(sfcd 마운트), 미사용 sdh(ext4 있음)·sdz(빈 디스크), 찾지 못한 sdd 기록 */
export const devices: Record<string, D.DNodeDevices> = {
  'node-a': {
    node: 'node-a',
    observedAt: Math.floor(Date.now() / 1000) - 20,
    disks: [
      { name: 'nvme0n1', class: 'system', locked: true, size: 256 * GiB, model: 'Samsung SSD 980 PRO', serial: 'S5GXNX0T', rotational: false, table: 'gpt', purposes: ['system', 'container-runtime'],
        parts: [
          { name: 'nvme0n1p1', number: 1, size: 0.5 * GiB, fsType: 'vfat', mounts: ['/boot/efi'], purposes: ['system'] },
          { name: 'nvme0n1p2', number: 2, size: 40 * GiB, fsType: 'ext4', mounts: ['/'], space: { total: 40 * GiB, used: 22 * GiB, available: 16 * GiB }, purposes: ['system'] },
          { name: 'nvme0n1p3', number: 3, size: 200 * GiB, fsType: 'ext4', mounts: ['/var/lib/docker'], space: { total: 200 * GiB, used: 120 * GiB, available: 70 * GiB }, purposes: ['container-runtime'] },
          { name: 'nvme0n1p4', number: 4, size: 8 * GiB, fsType: 'swap', swap: true, purposes: ['swap'] },
        ] },
      { name: 'sdb', class: 'additional', size: 2048 * GiB, model: 'WDC WD20EFRX', serial: 'WD-WCC4M0', rotational: true, table: 'gpt', purposes: ['storage-root'],
        parts: [
          { name: 'sdb1', number: 1, size: 1024 * GiB, fsType: 'xfs', uuid: '2d7f0c3e-6a1b-4e95-8f20-c4b7d1a9e360', mounts: ['/srv/sfc/data1'], space: { total: 1024 * GiB, used: 412 * GiB, available: 612 * GiB }, purposes: ['storage-root'], storageRoots: ['data1'] },
          { name: 'sdb2', number: 2, size: 1024 * GiB, fsType: 'LVM2_member', holders: [{ name: 'dm-0', kind: 'lvm', mapper: 'vg0-media', fsType: 'ext4', mounts: ['/mnt/media'], space: { total: 1000 * GiB, used: 120 * GiB, available: 830 * GiB } }] },
        ] },
      // sfcd가 마운트한 디스크(#689 3단계): 위에 저장 경로가 없어 마운트를 풀 수 있다
      { name: 'sdc', class: 'additional', size: 932 * GiB, model: 'Samsung SSD 870 EVO', serial: 'S6PNNM0T', wwn: '0x5002538f4231a1b2', rotational: false, table: 'gpt', tableID: '7d1c9e2a-0b4f-4e8a-9c61-2f5a8b3d1e07',
        parts: [{ name: 'sdc1', number: 1, size: 931 * GiB, fsType: 'ext4', uuid: 'c3a14f0e-58d2-4b7a-9e10-6a2f8c4d71b5', label: 'fast1', mounts: ['/var/lib/sfc-disks/fast1'], space: { total: 916 * GiB, used: 2 * GiB, available: 868 * GiB } }] },
      { name: 'sdh', class: 'unused', size: 14904 * GiB, model: 'TOSHIBA MG08', serial: '51R0A0XKF', rotational: true, table: 'gpt', tableID: '3f6e1b90-44a2-4c1d-8e57-b0d29a6c5f13',
        parts: [{ name: 'sdh1', number: 1, size: 14904 * GiB, fsType: 'ext4', uuid: '9b2e7a41-0c6d-4f38-a5e2-1d84c07bd410', label: 'old-backup' }] },
      { name: 'sdz', class: 'unused', size: 4096 * GiB, model: 'ST4000VN008', serial: 'ZDH8K2LQ', rotational: true, parts: [] },
      { name: 'sdk', class: 'unused', size: 4096 * GiB, model: 'ST4000VN008', serial: 'ZDH8K7RM', rotational: true, parts: [] },
      { name: 'sdg', class: 'unused', size: 931.5 * GiB, model: 'Samsung SSD 870 EVO', serial: 'S6PNNM1K', rotational: false, parts: [] },
      // 디스크 묶음 pool1 (#811): LVM 미러, sdj를 찾지 못해 한쪽 고장
      { name: 'pool1', class: 'additional', kind: 'bundle', bundle: 'pool1', size: 3726 * GiB, parts: [{ name: 'pool1', number: 0, size: 3726 * GiB, fsType: 'ext4', uuid: 'b00d1a2e-7c41-4f0a-9d3e-5a6b7c8d9e01', label: 'pool1', mounts: ['/var/lib/sfc-disks/pool1'], space: { total: 3650 * GiB, used: 1130 * GiB, available: 2330 * GiB } }] },
      { name: 'sdi', class: 'bundle-member', bundle: 'pool1', size: 3726 * GiB, model: 'WDC WD40EFRX', serial: 'WD-WCC7K1A2', rotational: true, parts: [] },
    ],
    bundles: [
      { name: 'pool1', backend: 'lvm', mode: 'mirror', size: 3726 * GiB, device: '/dev/dm-9', state: 'degraded', syncPercent: 0, members: [{ disk: 'sdi', serial: 'WD-WCC7K1A2', size: 3726 * GiB, state: 'ok' }, { disk: 'sdj', serial: 'WD-WCC7K9F3', size: 3726 * GiB, state: 'missing' }] },
    ],
    recorded: [
      { uuid: 'c3a14f0e-58d2-4b7a-9e10-6a2f8c4d71b5', path: '/var/lib/sfc-disks/fast1', disk: 'sdc', part: 'sdc1' },
      { uuid: 'b00d1a2e-7c41-4f0a-9d3e-5a6b7c8d9e01', path: '/var/lib/sfc-disks/pool1', disk: 'pool1', part: 'pool1' },
      { uuid: '6f1c3d57-92ab-4e06-b8f4-7c15e9d0a02e', path: '/var/lib/sfc-disks/media', disk: 'sdd', part: 'sdd1', reason: 'disk-not-found' },
    ],
  },
};

export const raft: D.DRaftStatus = {
  leader: 'node-a',
  observedBy: 'node-a',
  term: 14,
  commitIndex: 48211,
  appliedIndex: 48211,
  configurationIndex: 47002,
  voters: 2,
  quorum: 2,
  respondingVoters: 2,
  stale: false,
  servers: [
    { node: 'node-a', suffrage: 'voter', role: 'leader', matchIndex: 48211, appliedIndex: 48211, lag: 0, snapshotIndex: 45000, logEntries: 3211, logBytes: 12_400_000, lastContactAt: agoSec(0), stale: false },
    { node: 'node-b', suffrage: 'voter', role: 'follower', matchIndex: 48209, appliedIndex: 48208, lag: 2, snapshotIndex: 45000, logEntries: 3209, logBytes: 12_380_000, lastContactAt: agoSec(1), stale: false },
    // 데몬 #367: 아직 숫자를 알리지 않은 가입 대기 서버
    { node: 'node-c', suffrage: 'non-voter', role: 'pending', stale: true },
  ],
  lastSnapshotIndex: 45000,
  lastSnapshotAt: agoSec(7200),
  elections: [
    { term: 14, leader: 'node-a', at: agoSec(86400 * 2), reason: '이전 리더 연결 끊김' },
    { term: 13, leader: 'node-b', at: agoSec(86400 * 5), reason: '시작' },
  ],
};

export const mesh: D.DMeshLink[] = [
  { nodeA: 'node-a', nodeB: 'node-b', state: 'up', rttMillis: 0.8, lossPercent: 0, observedAt: agoSec(4), dialer: 'node-b' },
  { nodeA: 'node-a', nodeB: 'node-c', state: 'pending', rttMillis: 0, lossPercent: 0, observedAt: agoSec(4) },
  { nodeA: 'node-b', nodeB: 'node-c', state: 'pending', observedAt: agoSec(4), stale: true },
];

export const PHP_SHOP_V13 = `name: php-shop
services:
  web:
    image: docker.io/library/php@sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8
    deploy:
      replicas: 2
    networks:
      shop-net:
        aliases: [web]
    volumes:
      - uploads:/var/www/uploads
    secrets:
      - source: db-password
    x-sfc:
      node: node-a
networks:
  shop-net:
    external: true
volumes:
  uploads:
    external: true
secrets:
  db-password:
    external: true
`;
export const PHP_SHOP_V14 = PHP_SHOP_V13.replace('name: php-shop\n', `name: php-shop
x-sfc:
  ingress:
    - node: node-b
      host: shop.example.com
      prefix: /
      service: web
      port: 8080
      gateway: external
`).replace(
  'networks:\n  shop-net:\n    external: true',
  `  worker:
    image: docker.io/library/php@sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8
    command: ["php", "worker.php"]
    networks:
      shop-net: {}
    x-sfc:
      node: node-a
networks:
  shop-net:
    external: true`,
);
export function simpleApp(name: string, _tenant: string, service: string, replicas: number, node = 'node-b'): string {
  return `name: ${name}
services:
  ${service}:
    image: docker.io/library/${service}:latest
    deploy:
      replicas: ${replicas}
    x-sfc:
      node: ${node}
`;
}
const MYSQL_V3 = `name: mysql
services:
  db:
    image: docker.io/library/mysql@sha256:9c2e41d07a5f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9
    networks:
      shop-db:
        aliases: [db]
    volumes:
      - mysql-data:/var/lib/mysql
    secrets:
      - source: db-password
    x-sfc:
      node: node-a
networks:
  shop-db:
    external: true
volumes:
  mysql-data:
    external: true
secrets:
  db-password:
    external: true
`;

export interface MockSource {
  version: number;
  yaml: string;
  submitter: string;
  operation: string;
  status: string;
  acceptedAt: number;
}
export const sources: Record<string, MockSource[]> = {
  'shop/php-shop': [
    { version: 12, yaml: PHP_SHOP_V13.replace('php@sha256:a1f3', 'php@sha256:0000'), submitter: 'cd', operation: 'cd-4e1a9c2', status: 'failed', acceptedAt: agoSec(86400 * 4) },
    { version: 13, yaml: PHP_SHOP_V13, submitter: 'alice', operation: 'up-60b1', status: 'succeeded', acceptedAt: agoSec(86400 * 3) },
    { version: 14, yaml: PHP_SHOP_V14, submitter: 'alice', operation: 'up-7f3a', status: 'succeeded', acceptedAt: agoSec(720) },
  ],
  'shop/mysql': [{ version: 3, yaml: MYSQL_V3, submitter: 'alice', operation: 'up-91c2', status: 'running', acceptedAt: agoSec(240) }],
  'shop/worker-batch': [{ version: 5, yaml: simpleApp('worker-batch', 'shop', 'worker', 2), submitter: 'cd', operation: 'cd-77aa', status: 'succeeded', acceptedAt: agoSec(86400) }],
  'internal/grafana': [{ version: 2, yaml: simpleApp('grafana', 'internal', 'grafana', 1, 'node-a').replace('name: grafana\n', 'name: grafana\nx-sfc:\n  ingress:\n    - node: node-a\n      host: grafana.internal\n      prefix: /\n      service: grafana\n      port: 3000\n      gateway: local\n').replace('    deploy:', '    expose: ["3000"]\n    deploy:'), submitter: 'carol', operation: 'up-ff01', status: 'succeeded', acceptedAt: agoSec(86400 * 6) }],
  'lab/notebook': [{ version: 1, yaml: simpleApp('notebook', 'lab', 'jupyter', 1), submitter: 'alice', operation: 'up-0001', status: 'succeeded', acceptedAt: agoSec(86400 * 9) }],
  // 장애 기록·외부 접속 목업이 가리키는 앱(shop-api·billing·metrics)도 실제로 있게 둔다
  'shop/shop-api': [{ version: 16, yaml: simpleApp('shop-api', 'shop', 'api', 2, 'node-b'), submitter: 'cd', operation: 'cd-5b20', status: 'succeeded', acceptedAt: agoSec(150 * 60) }],
  'shop/billing': [{ version: 9, yaml: simpleApp('billing', 'shop', 'billing-api', 1), submitter: 'bob', operation: 'up-b909', status: 'succeeded', acceptedAt: agoSec(27 * 3600) }],
  'internal/metrics': [{ version: 4, yaml: simpleApp('metrics', 'internal', 'prometheus', 1, 'node-a'), submitter: 'carol', operation: 'up-m004', status: 'succeeded', acceptedAt: agoSec(86400 * 5) }],
};

const opsum = (id: string, status: string, completedAgo: number, submitter = 'alice', failed = false): D.DOperationSummary => ({ id, status, completedAt: status === 'running' ? 0 : agoSec(completedAgo), submitter, failed, epoch: 1 });
export const apps: D.DAppView[] = [
  { tenant: 'shop', app: 'php-shop', deployment: 'main', revision: 14, operation: opsum('up-7f3a', 'succeeded', 720), claims: 3, health: 'healthy', observedAt: agoSec(6) },
  { tenant: 'shop', app: 'mysql', deployment: 'main', revision: 3, operation: opsum('up-91c2', 'running', 0), claims: 1, health: 'healthy', observedAt: agoSec(6) },
  {
    tenant: 'shop',
    app: 'worker-batch',
    deployment: 'main',
    revision: 5,
    operation: opsum('cd-77aa', 'succeeded', 86400, 'cd'),
    claims: 0,
    health: 'degraded',
    healthReason: { code: 'TASK_EXITED', key: 'task/worker/1', kind: 'task', name: 'worker', node: 'node-b', exit: 1 },
    observedAt: agoSec(6),
    cd: { revision: 3, repository: 'https://git.shop.internal/ops/worker-batch.git', branch: 'main', mode: 'manual', paused: false, running: '4e1a9c2', candidate: 'b77d210', candidateDigest: 'b77d210'.padEnd(64, '0') },
  },
  { tenant: 'internal', app: 'grafana', deployment: 'main', revision: 2, operation: opsum('up-ff01', 'succeeded', 86400 * 6, 'carol'), claims: 1, health: 'healthy', observedAt: agoSec(7) },
  { tenant: 'lab', app: 'notebook', deployment: 'main', revision: 1, operation: opsum('up-0001', 'succeeded', 86400 * 9), claims: 0, health: 'healthy', observedAt: agoSec(8) },
  { tenant: 'shop', app: 'shop-api', deployment: 'main', revision: 16, operation: opsum('cd-5b20', 'succeeded', 150 * 60, 'cd'), claims: 2, health: 'degraded', healthReason: { code: 'REPLICAS_PARTIAL', kind: 'task', name: 'api', node: 'node-b' }, observedAt: agoSec(6) },
  { tenant: 'shop', app: 'billing', deployment: 'main', revision: 9, operation: opsum('up-b909', 'succeeded', 27 * 3600, 'bob'), claims: 1, health: 'degraded', healthReason: { code: 'TASK_FAILED', kind: 'task', name: 'billing-api', node: 'node-a', failure: 'IMAGE_NOT_FOUND' }, observedAt: agoSec(6) },
  { tenant: 'internal', app: 'metrics', deployment: 'main', revision: 4, operation: opsum('up-m004', 'succeeded', 86400 * 5, 'carol'), claims: 1, health: 'healthy', observedAt: agoSec(7) },
];

export const archived: D.DArchived[] = [
  { key: 'shop~analytics~1795000000', tenant: 'shop', app: 'analytics', digest: '5e0b7c1d9a2f4e6b8c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b', version: 6, volumes: ['analytics-data'], downBy: 'alice', downAt: agoIso(86400 * 3), downOp: 'down-a1', yaml: simpleApp('analytics', 'shop', 'metabase', 1) },
  { key: 'shop~old-blog~1794000000', tenant: 'shop', app: 'old-blog', digest: 'aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66', version: 21, volumes: [], downBy: 'bob', downAt: agoIso(86400 * 11), downOp: 'down-b2', yaml: simpleApp('old-blog', 'shop', 'wordpress', 1) },
  // 데이터 보관(#920): 원래 자리 · 보관됨 + 묶는 중 · 정상 종료 아님 · 저장소 없음
  { key: 'shop~legacy-cron~1795100000', tenant: 'shop', app: 'legacy-cron', digest: '', version: 8, volumes: ['cron-cache', 'cron-logs', 'cron-state'], downBy: 'alice', downAt: agoIso(86400 * 9), downOp: 'down-c3', yaml: simpleApp('legacy-cron', 'shop', 'cron', 1) },
  { key: 'shop~media-old~1794500000', tenant: 'shop', app: 'media-old', digest: '', version: 21, volumes: ['media-uploads', 'media-thumbs'], downBy: 'alice', downAt: agoIso(86400 * 16), downOp: 'down-m4', yaml: simpleApp('media-old', 'shop', 'media', 1, 'node-a') },
  { key: 'shop~batch-etl~1794200000', tenant: 'shop', app: 'batch-etl', digest: '', version: 5, volumes: ['etl-db'], downBy: 'bob', downAt: agoIso(86400 * 19), downOp: 'down-e5', yaml: simpleApp('batch-etl', 'shop', 'etl', 1) },
  { key: 'shop~old-report~1793600000', tenant: 'shop', app: 'old-report', digest: '', version: 3, volumes: [], downBy: 'bob', downAt: agoIso(86400 * 26), downOp: 'down-r6', yaml: simpleApp('old-report', 'shop', 'report', 1) },
];

export const uploads: (D.DUpload & { tenant: string })[] = [{ tenant: 'shop', id: 'upl-55e1', app: 'analytics', deployment: 'main', revision: 4, length: 5 * (1 << 20) - 100, digest: '00'.repeat(32), missing: [3, 4] }];

export const resources: D.DResourceEntry[] = [
  { key: 'net/shop/shop-net', tenant: 'shop', network: { name: 'shop-net', kind: 'tun', cidr: '10.40.0.0/24, 10.40.4.0/24', nodes: ['node-a', 'node-b'], revision: 18, dns: { zone: 'shop.sfc.test.', enabled: true, revision: 3, upstreams: ['1.1.1.1'], ttl: 300, negativeTtl: 5, reverse: false, resolver: '10.40.0.1' } } },
  { key: 'net/shop/shop-db', tenant: 'shop', network: { name: 'shop-db', kind: 'tun', cidr: '10.40.1.0/26', nodes: ['node-a'], revision: 4, toggles: ['local', 'bridge-inbound'] } },
  { key: 'net/internal/mon-net', tenant: 'internal', network: { name: 'mon-net', kind: 'tun', cidr: '10.41.0.0/24', nodes: ['node-a', 'node-b'], revision: 6, toggles: ['bridge-inbound'] } },
  { key: 'net/internal/logs-net', tenant: 'internal', network: { name: 'logs-net', kind: 'tun', cidr: '10.41.8.0/24', nodes: ['node-b'], revision: 2, toggles: ['local', 'bridge-inbound'] } },
  { key: 'net/lab/cache-net', tenant: 'lab', network: { name: 'cache-net', kind: 'tun', cidr: '10.42.0.0/24', nodes: ['node-b'], revision: 2, toggles: ['local', 'bridge-inbound'] } },
  { key: 'limit/shop/node-a', tenant: 'shop', limit: { node: 'node-a', cpus: 2, memoryBytes: 8 * GiB, maxContainers: 20, revision: 3 } },
  { key: 'limit/shop/node-b', tenant: 'shop', limit: { node: 'node-b', cpus: 2, memoryBytes: 8 * GiB, maxContainers: 20, revision: 3 } },
  { key: 'limit/internal/node-a', tenant: 'internal', limit: { node: 'node-a', cpus: 4, memoryBytes: 8 * GiB, maxContainers: 10, revision: 1 } },
  { key: 'limit/lab/node-b', tenant: 'lab', limit: { node: 'node-b', cpus: 2, memoryBytes: 4 * GiB, maxContainers: 5, revision: 1 } },
  { key: 'route/shop/shop.example', tenant: 'shop', route: { host: 'shop.example', path: '/', app: 'php-shop', service: 'web', port: 8080, revision: 2 } },
];
export const tenantNodes: Record<string, string[]> = { shop: ['node-a', 'node-b'], internal: ['node-a', 'node-b'], lab: ['node-b'], 'legacy-lab': [] };

// 작업 공간 간 연결(tenancy.Route). 제안한 쪽의 승인은 제안과 함께 붙는다
export type MockRoute = Omit<D.DRoute, 'side' | 'state' | 'source' | 'destination'> & { source: Required<Pick<D.DRouteEnd, 'tenant' | 'network' | 'node' | 'name'>> & Pick<D.DRouteEnd, 'cidr'>; destination: Required<Pick<D.DRouteEnd, 'tenant' | 'network' | 'node' | 'name'>> & Pick<D.DRouteEnd, 'cidr'> };
const rEnd = (tenant: string, name: string, node: string, cidr?: string) => ({ tenant, network: `${name}-${node}`, node, name, ...(cidr ? { cidr } : {}) });
/** 망·저장소를 쓰는 곳(network-users / volume-users). 키는 tenant/이름 */
const svc = (app: string, service: string, node: string, n = 1): D.DResourceUser => ({ kind: 'service', app, service, node, attached: true, selection: Array.from({ length: n }, (_, i) => ({ app, service, instance: String(i + 1) })) });
export const networkUsers: Record<string, D.DResourceUser[]> = {
  'shop/shop-net': [svc('php-shop', 'web', 'node-a', 2), svc('php-shop', 'web', 'node-b'), svc('php-shop', 'db', 'node-b'), { kind: 'standalone', standalone: 'debug-shell', node: 'node-a', attached: true }],
  'shop/shop-db': [svc('php-shop', 'db', 'node-a')],
  'internal/mon-net': [svc('monitoring', 'prometheus', 'node-b')],
};
export const volumeUsers: Record<string, D.DResourceUser[]> = {
  'shop/uploads': [{ ...svc('php-shop', 'web', 'node-a', 2), readOnly: false }],
  'shop/mysql-data': [{ ...svc('php-shop', 'db', 'node-a'), readOnly: false }, { kind: 'standalone', standalone: 'mysql-dump', node: 'node-a', readOnly: true, attached: false }, { kind: 'volume-operation', consumer: 'backup-mysql-data-0412', node: 'node-a', readOnly: true, attached: true }],
  'internal/prom-data': [{ ...svc('monitoring', 'prometheus', 'node-b'), readOnly: false }],
};
export const routes: MockRoute[] = [
  { key: 'route/shop/r-metrics', id: 'r-metrics', sourceTenant: 'shop', source: rEnd('shop', 'shop-net', 'node-a', '10.40.0.0/24'), destination: rEnd('internal', 'mon-net', 'node-a', '10.41.0.0/24'), protocol: 'tcp', ports: [{ first: 9090, last: 9090 }], phase: 'active', approvals: [{ tenant: 'shop', user: 'alice' }, { tenant: 'internal', user: 'carol' }], revision: 4 },
  { key: 'route/shop/r-ingest', id: 'r-ingest', sourceTenant: 'shop', source: rEnd('shop', 'shop-net', 'node-a', '10.40.0.0/24'), destination: rEnd('analytics', 'ingest', 'node-c', '10.42.0.0/24'), protocol: 'tcp', ports: [{ first: 443, last: 443 }], phase: 'pending', approvals: [{ tenant: 'shop', user: 'alice' }], revision: 2 },
  { key: 'route/internal/r-scrape', id: 'r-scrape', sourceTenant: 'internal', source: rEnd('internal', 'mon-net', 'node-b', '10.41.0.0/24'), destination: rEnd('shop', 'shop-net', 'node-b', '10.40.4.0/24'), protocol: 'tcp', ports: [{ first: 9100, last: 9100 }], phase: 'pending', approvals: [{ tenant: 'internal', user: 'carol' }], revision: 1 },
  // 철회 뒤 양쪽 서버 닫힘 보고를 기다리는 연결(가짜 어댑터처럼 revoking에 머문다)
  { key: 'route/shop/old-cache', id: 'old-cache', sourceTenant: 'shop', source: rEnd('shop', 'shop-net', 'node-b', '10.40.4.0/24'), destination: rEnd('lab', 'cache-net', 'node-b', '10.43.0.0/24'), protocol: 'udp', ports: [{ first: 6379, last: 6379 }], phase: 'revoking', approvals: [{ tenant: 'shop', user: 'alice' }, { tenant: 'lab', user: 'carol' }], revision: 6 },
];
// 데이터 저장소 백업·복원 행(데몬 volume-backups / volume-restores 모양)
export const volumeBackups: D.DVolumeBackup[] = [
  { key: 'shop/uploads/b-0921', tenant: 'shop', volume: 'uploads', id: 'b-0921', node: 'node-a', phase: 'Ready', revision: 7, bytes: 12 * GiB, createdAt: Math.floor(Date.now() / 1000) - 3600 * 9 },
  { key: 'shop/uploads/b-0920', tenant: 'shop', volume: 'uploads', id: 'b-0920', node: 'node-a', phase: 'Ready', revision: 6, bytes: 11 * GiB, createdAt: Math.floor(Date.now() / 1000) - 3600 * 33 },
  { key: 'shop/uploads/b-0919', tenant: 'shop', volume: 'uploads', id: 'b-0919', node: 'node-a', phase: 'Failed', revision: 5, bytes: 0, createdAt: Math.floor(Date.now() / 1000) - 3600 * 57, failure: 'staging limit exceeded' },
];
export const volumeRestores: D.DVolumeRestore[] = [];
/** 내린 앱 저장소 보관(#920). sfcd처럼 저장소마다 끝난 기록은 하나만 */
export const volumeArchives: (D.DVolumeArchive & { tenant: string; volume: string })[] = [
  { tenant: 'shop', volume: 'media-uploads', id: 'a-1113', node: 'node-a', store: 'slow1', phase: 'Archived', compression: 'zstd', maxBytes: 64 * GiB, tarBytes: 18.4 * GiB, dataBytes: 6.1 * GiB, revision: 4 },
  { tenant: 'shop', volume: 'media-thumbs', id: 'a-1128', node: 'node-a', store: 'slow1', phase: 'Packing', compression: 'zstd', maxBytes: 64 * GiB, revision: 1 },
  { tenant: 'shop', volume: 'etl-db', id: 'a-1120', node: 'node-b', store: 'default', phase: 'Failed', compression: 'zstd', maxBytes: 64 * GiB, failure: 'unclean-exit', revision: 2 },
];
/** 보관에 쓰는 두 키(클러스터 키 · 관리자 키). 하나라도 없으면 archiveReady false */
export const archiveKeys = { cluster: true, admin: true };
export const volumes: D.DVolume[] = [
  { key: 'vol/shop/uploads', tenant: 'shop', name: 'uploads', kind: 'shared', node: 'node-a', storage: 'data1', app: 'php-shop', revision: 5, consumers: 1, capacityBytes: 50 * GiB, usedBytes: 12 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true, writer: 'php-shop/web', retained: [{ moveID: 'mv-0915', node: 'node-b', state: 'retained' }] },
  { key: 'vol/shop/mysql-data', tenant: 'shop', name: 'mysql-data', kind: 'fixed', node: 'node-a', storage: 'data1', revision: 3, consumers: 1, usedBytes: 48 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true, writer: 'php-shop/db' },
  { key: 'vol/shop/analytics-data', tenant: 'shop', name: 'analytics-data', kind: 'shared', node: 'node-b', storage: 'data1', app: 'analytics', revision: 2, consumers: 0, retain: true },
  // 내린 앱 저장소(데이터 보관 #920)
  { key: 'vol/shop/cron-cache', tenant: 'shop', name: 'cron-cache', kind: 'shared', node: 'node-b', storage: 'data1', app: 'legacy-cron', revision: 3, consumers: 0, capacityBytes: 10 * GiB, usedBytes: 4.2 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/cron-logs', tenant: 'shop', name: 'cron-logs', kind: 'shared', node: 'node-b', storage: 'data1', app: 'legacy-cron', revision: 2, consumers: 0, capacityBytes: 2 * GiB, usedBytes: 0.8 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/cron-state', tenant: 'shop', name: 'cron-state', kind: 'shared', node: 'node-a', storage: 'data1', app: 'legacy-cron', revision: 2, consumers: 0, capacityBytes: GiB, usedBytes: 12 * 1024 ** 2, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/media-uploads', tenant: 'shop', name: 'media-uploads', kind: 'shared', node: 'node-a', storage: 'data1', app: 'media-old', revision: 6, consumers: 0, capacityBytes: 30 * GiB, usedBytes: 0, usageObservedAt: Date.now() - 4 * 60_000, retain: true, phase: 'Archived', archiveID: 'a-1113', archivePhase: 'Archived' },
  { key: 'vol/shop/media-thumbs', tenant: 'shop', name: 'media-thumbs', kind: 'shared', node: 'node-a', storage: 'data1', app: 'media-old', revision: 4, consumers: 0, capacityBytes: 10 * GiB, usedBytes: 7.9 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true, phase: 'Archived', archiveID: 'a-1128', archivePhase: 'Packing' },
  { key: 'vol/shop/etl-db', tenant: 'shop', name: 'etl-db', kind: 'shared', node: 'node-b', storage: 'data1', app: 'batch-etl', revision: 3, consumers: 0, capacityBytes: 20 * GiB, usedBytes: 6.5 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/registry-data', tenant: 'shop', name: 'registry-data', kind: 'fixed', node: 'node-a', storage: 'data1', revision: 2, consumers: 1, capacityBytes: 200 * GiB, usedBytes: 41 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/registry-stg-data', tenant: 'shop', name: 'registry-stg-data', kind: 'fixed', node: 'node-b', storage: 'data1', revision: 1, consumers: 0, capacityBytes: 12 * GiB, usedBytes: 2 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/sfc-web-backup', tenant: 'shop', name: 'sfc-web-backup', kind: 'fixed', node: 'node-a', storage: 'data1', revision: 1, consumers: 0, capacityBytes: 3 * GiB, usedBytes: 900 * 1024 * 1024, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/shop/registry-ci-data', tenant: 'shop', name: 'registry-ci-data', kind: 'fixed', node: 'node-b', storage: 'data1', revision: 1, consumers: 0, capacityBytes: 100 * GiB, usedBytes: 0, usageObservedAt: Date.now() - 4 * 60_000, retain: true },
  { key: 'vol/internal/prom-data', tenant: 'internal', name: 'prom-data', kind: 'shared', node: 'node-b', storage: 'data1', revision: 1, consumers: 1, usedBytes: 20 * GiB, usageObservedAt: Date.now() - 4 * 60_000, retain: true, writer: 'monitoring/prometheus' },
];

const noAcl = (): D.DVaultACL => ({ users: [], services: [], denyUsers: [], denyServices: [] });
const vrow = (tenant: string, path: string, kind: 'object' | 'group', revision: number, x: Partial<D.DVault> = {}): D.DVault & { tenant: string } => {
  const segs = path.split('/');
  return { tenant, realm: tenant, path, kind, profile: kind === 'group' ? '' : 'file', keys: [], revision, id: segs[segs.length - 1], parent: segs.length > 1 ? segs[segs.length - 2] : tenant, status: 'active', acl: noAcl(), ...x };
};
export const vault: (D.DVault & { tenant: string })[] = [
  vrow('shop', 'common', 'group', 2),
  vrow('shop', 'common/tenant-defaults', 'object', 5, { keys: ['SMTP_HOST', 'SMTP_PASSWORD'], group: 'common' }),
  vrow('shop', 'db-cred', 'group', 2, { protected: true, maxApprovalAge: 7 * 86400 }),
  vrow('shop', 'db-cred/db-password', 'object', 4, { keys: ['password'], group: 'db-cred', acl: { users: ['alice'], services: ['php-shop/web', 'php-shop/db'], denyUsers: [], denyServices: [] } }),
  vrow('shop', 'db-cred/db-root-password', 'object', 2, { keys: ['password'], group: 'db-cred' }),
  vrow('shop', 'web-runtime-overrides', 'object', 3, { keys: ['FEATURE_FLAGS'] }),
  vrow('shop', 'stripe-key', 'object', 1, { keys: ['key'] }),
  vrow('shop', 'ghcr-shop', 'object', 2, { keys: ['username', 'token'] }),
  vrow('shop', 'registry-login', 'group', 1, { protected: true, maxApprovalAge: 7 * 86400 }),
  vrow('shop', 'registry-login/harbor-robot', 'object', 1, { keys: ['username', 'password'], group: 'registry-login' }),
  vrow('shop', 'corp-root-ca', 'object', 1, { keys: ['ca.pem'] }),
  vrow('internal', 'grafana-admin', 'object', 2, { keys: ['user', 'password'] }),
  // 클러스터 보관함(realm "", 시스템 관리자, 데몬 #74). 최상위 묶음 'cluster'(parent ""). 목업은 처음에 초기화 전이고 초기화하면 아래가 보인다
  { ...vrow('cluster', 'cluster', 'group', 1), realm: '', path: '', parent: '' },
  { ...vrow('cluster', 'shared-smtp', 'group', 3), realm: '', parent: 'cluster' },
  { ...vrow('cluster', 'shared-smtp/relay-password', 'object', 4, { keys: ['password'], group: 'shared-smtp' }), realm: '' },
  { ...vrow('cluster', 'backup-s3', 'object', 2, { keys: ['ACCESS_KEY', 'SECRET_KEY'] }), realm: '', parent: 'cluster' },
];

/** 보관함 쓰는 곳(데몬 #298: sfcd vault-usages 행). secrets는 비밀값 ID. 클러스터 것은 tenant 'cluster' */
export const vaultUsages: (D.DVaultUsage & { tenant: string })[] = [
  { tenant: 'shop', app: 'php-shop', deployment: 'php-shop-7', service: 'web', node: 'node-a', id: 'use-1', generation: 3, secrets: ['db-password'], live: true },
  { tenant: 'shop', app: 'php-shop', deployment: 'php-shop-7', service: 'db', node: 'node-a', id: 'use-2', generation: 4, secrets: ['db-root-password', 'db-password'], live: true },
  { tenant: 'shop', app: 'php-shop', deployment: 'php-shop-7', service: 'web', node: 'node-a', id: 'use-3', generation: 5, secrets: ['tenant-defaults'], live: true },
  { tenant: 'shop', app: 'legacy-shop', deployment: 'legacy-shop-2', service: 'web', node: 'node-b', id: 'use-4', generation: 6, secrets: ['web-runtime-overrides'], live: false },
  { tenant: 'cluster', app: 'nightly-backup', deployment: 'nightly-backup-3', service: 'runner', node: 'node-b', id: 'use-5', generation: 7, secrets: ['backup-s3'], live: true },
];

/** 상태 검사 스크립트(이름별 버전). 원본 글·쓰는 곳은 버전에 둔다(REQ-40·41 흉내) */
export type MockLcVersion = Omit<D.DLifecycleVersion, 'modules'> & { modules: { path: string; version: string }[]; source: string; uses: D.DLifecycleUse[] };
export type MockLifecycle = { tenant: string; name: string; recordRevision: number; versions: MockLcVersion[] };
const goCheck = (body: string) =>
  `package checker\n\nimport (\n\t"context"\n\n\tlifecycle "github.com/jay94ks/seafield/lifecycle/v1"\n)\n\nfunc Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) {\n${body}\treturn lifecycle.Result{Schema: 1, Status: lifecycle.Pass, Reason: "ok"}, nil\n}\n`;
const http = (path: string) => goCheck(`\tr, err := probe.Healthz(ctx, lifecycle.HTTPProbe{Service: "web", Path: "${path}", Port: 8080})\n\tif err != nil {\n\t\treturn lifecycle.Result{Schema: 1, Status: lifecycle.Unknown, Reason: "probe-error"}, err\n\t}\n\tif r.StatusCode != 200 {\n\t\treturn lifecycle.Result{Schema: 1, Status: lifecycle.Fail, Reason: "not-ready"}, nil\n\t}\n`);
const tcp = (svc: string, port: number) => goCheck(`\tr, err := probe.Connect(ctx, lifecycle.TCPProbe{Service: "${svc}", Port: ${port}})\n\tif err != nil || !r.Connected {\n\t\treturn lifecycle.Result{Schema: 1, Status: lifecycle.Fail, Reason: "closed"}, nil\n\t}\n`);
const lcv = (revision: number, active: boolean, source: string, uses: D.DLifecycleUse[] = [], modules: { path: string; version: string }[] = []): MockLcVersion => ({ revision, active, deleted: false, digest: Array.from(source).reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7).toString(16).padStart(8, '0').repeat(8), length: source.length, modules, source, uses });
export const lifecycles: MockLifecycle[] = [
  { tenant: 'shop', name: 'http-ready', recordRevision: 3, versions: [lcv(1, false, http('/')), lcv(3, true, http('/readyz'), [{ revision: 3, kind: 'app-binding', app: 'php-shop', service: 'web', node: 'node-a' }, { revision: 3, kind: 'app-binding', app: 'analytics', service: 'api', node: 'node-b' }])] },
  { tenant: 'shop', name: 'mysql-ping', recordRevision: 1, versions: [lcv(1, true, tcp('db', 3306), [{ revision: 1, kind: 'app-binding', app: 'php-shop', service: 'db', node: 'node-a' }], [{ path: 'golang.org/x/text', version: 'v0.21.0' }])] },
  { tenant: 'shop', name: 'legacy-tcp', recordRevision: 3, versions: [lcv(1, false, tcp('web', 80)), lcv(2, false, tcp('web', 8080))] },
];
const policy = (tenant: string, revision: number, modules: { path: string; version: string; digest: string; length: number }[]): D.DLifecyclePolicy => ({
  tenant,
  revision,
  enabled: true,
  build: { nodes: [], targets: [], image: '', toolchain: '', maxJobs: 0, nanoCPU: 0, memoryBytes: 0, workspaceBytes: 0, artifactBytes: 0, timeoutMS: 0 },
  execution: { maxConcurrent: 4, timeoutMS: 5000, nanoCPU: 500_000_000, memoryBytes: 64 << 20, maxPIDs: 32, outputBytes: 65536, probeBytes: 65536, capabilities: ['connect', 'healthz'] },
  resolver: { allowPackages: [], denyPackages: [], modules, sourceCacheBytes: 16 << 20 },
  compiledCacheBytes: 0,
});
export const defaultLifecyclePolicy = (tenant: string) => policy(tenant, 0, []);
/** 상태 검사 정책. 없는 작업 공간은 기본값(configured:false) */
export const lifecyclePolicies: Record<string, D.DLifecyclePolicy> = {
  shop: policy('shop', 2, [{ path: 'golang.org/x/text', version: 'v0.21.0', digest: 'c02cd1c3d98a41e4c2b246c9bf9492e2f7a149ee4746a4706e629a7a999c2124', length: 1 << 20 }, { path: 'github.com/tidwall/gjson', version: 'v1.18.0', digest: '9d1c5e0c3a7b2f4e8d6a1b0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f', length: 180_000 }]),
};

export const registryLimits = (gib: number): D.DRegistryLimits => ({
  metadata: { manifestBytes: 4 << 20, records: 4096, totalBytes: 64 << 20 },
  blobs: { blobBytes: Math.min(4 * GiB, gib * GiB), totalBytes: gib * GiB, records: 16384 },
  budget: { cpu: 1e9, memory: 256 << 20 },
  maxRequests: 64,
  maxHeaderBytes: 16 << 10,
  requestTimeoutMS: 60000,
  tokenSeconds: 300,
});
export const registries: D.DRegistry[] = [
  { tenant: 'shop', id: 'builtin', name: 'builtin', endpoint: 'registry.shop.internal', revision: 4, generation: 1, active: true, repositories: 2, node: 'node-a', address: '0.0.0.0:443', certificateID: '9c41d2e85f30a7b16c94e0d3f8a2b57e1c06d49a3b8e72f5c1d0a6e94b3f7e07', volume: 'registry-data', enabled: true, observedAt: Date.now() - 5000, status: 'serving', limits: registryLimits(200) },
  { tenant: 'shop', id: 'shop-staging', name: 'shop-staging', endpoint: 'registry-stg.sfc:5000', revision: 2, generation: 1, active: false, repositories: 0, node: 'node-b', address: '0.0.0.0:5000', volume: 'registry-stg-data', enabled: false, status: 'stopped', limits: registryLimits(12) },
];

export const images: (ImageView & { tenant: string })[] = [
  { tenant: 'shop', registry: 'builtin', repo: 'shop/web', tag: 'v14', digest: 'sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8', sizeBytes: 182_000_000, pushedAt: agoIso(800), usedBy: ['php-shop'] },
  { tenant: 'shop', registry: 'builtin', repo: 'shop/web', tag: 'v13', digest: 'sha256:0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8a1f3b9e07c44d2e8f1a', sizeBytes: 181_000_000, pushedAt: agoIso(86400 * 3), usedBy: [] },
  { tenant: 'shop', registry: 'builtin', repo: 'shop/worker', tag: 'v5', digest: 'sha256:77e0a01dc3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6', sizeBytes: 96_000_000, pushedAt: agoIso(86400), usedBy: ['worker-batch'] },
  { tenant: 'shop', registry: 'dockerhub', repo: 'library/mysql', tag: '8.4', digest: 'sha256:9c2e41d07a5f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9', sizeBytes: 590_000_000, pushedAt: agoIso(86400 * 20), usedBy: ['mysql'] },
  { tenant: 'shop', registry: 'builtin', repo: 'shop/migrate', tag: '0.4', digest: 'sha256:3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a', sizeBytes: 64_000_000, pushedAt: agoIso(86400 * 7), usedBy: [] },
  { tenant: 'shop', registry: 'ghcr', repo: 'shop-team/report', tag: '2.2-rc1', digest: 'sha256:9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d', sizeBytes: 71_000_000, pushedAt: agoIso(86400), usedBy: [], trusted: false },
];

export interface MockOp extends D.DOp {
  user: string;
  digest: string;
}
export const ops: MockOp[] = [
  { id: '7d1c2e3f-0000-4000-8000-00000000a001', requestId: 'r-1', action: 'set-membership', target: 'bob', tenant: 'shop', state: 'unknown', errorCode: 'unknown', resultFound: false, submittedAt: agoIso(540), updatedAt: agoIso(540), user: 'u-alice', digest: 'seed' },
  { id: '7d1c2e3f-0000-4000-8000-00000000a002', requestId: 'r-2', action: 'begin-app', target: 'php-shop', tenant: 'shop', state: 'applied', resultFound: true, resultCode: 0, index: 48102, revision: 14, submittedAt: agoIso(780), updatedAt: agoIso(720), user: 'u-alice', digest: 'seed' },
  { id: '7d1c2e3f-0000-4000-8000-00000000a003', requestId: 'r-3', action: 'create-tenant', target: 'shop', tenant: 'shop', state: 'failed', resultFound: true, resultCode: 1, submittedAt: agoIso(2400), updatedAt: agoIso(2400), user: 'u-alice', digest: 'seed' },
];

export const notifications: D.DNotification[] = [
  { id: 'n1', kind: 'op-unknown', severity: 'warning', tenant: 'shop', title: '결과 불명', body: '작업 7d1c2e3f · set-membership', link: '/system/ops', action: true, createdAt: agoIso(540) },
  { id: 'n2', kind: 'op-failed', severity: 'error', tenant: 'shop', title: '작업 실패', body: 'create-tenant shop · 결과 코드 1', link: '/system/ops', action: false, createdAt: agoIso(2400) },
  { id: 'n3', kind: 'deploy-done', severity: 'info', tenant: 'shop', title: '배포 완료', body: 'php-shop 버전 14', link: '/deploy/apps/shop/php-shop', action: false, createdAt: agoIso(720), readAt: agoIso(700) },
];
export const notifyKinds = ['op-failed', 'op-unknown', 'deploy-done'];
export const notifyPrefs: D.DNotifyPrefs = { mutedKinds: [], mutedTenants: [], browser: false };

export const webDefaults: D.DWebSettings = { sessionMaxHours: 0, sessionIdleMinutes: 0, opRetentionDays: 90, auditRetentionDays: 365, notificationRetentionDays: 90, allowKeyLogin: true, maxSessionsPerUser: 5, webhookDeliveryRetentionDays: 30, mcpCallRetentionDays: 90, trashRetentionDays: 0 };
export const webState = {
  settings: { ...webDefaults, sessionIdleMinutes: 60, sessionMaxHours: 12 } as D.DWebSettings,
  restorePending: false,
  seal: {
    state: 'ready',
    ready: true,
    keySource: 'env',
    fingerprint: '3f9a…c21e',
    dir: '/var/lib/sfc-web/secrets/',
    files: 15,
    next: { fingerprint: 'b07e…914a' },
    kinds: [
      { kind: 'ai', count: 2, modified: agoIso(86400 * 20) },
      { kind: 'incident', count: 1, modified: agoIso(86400 * 4) },
      { kind: 'mcp', count: 3, modified: agoIso(3600 * 2) },
      { kind: 'webhook', count: 5, modified: agoIso(86400) },
      { kind: 'dns', count: 3, modified: agoIso(86400 * 13) },
      { kind: 'deploy-check', count: 1, modified: agoIso(86400 * 2) },
    ],
  } as D.DSealStatus,
};
export const audit: D.DAudit[] = [
  { id: 'a2', at: agoIso(3600), user: 'u-alice', username: 'alice', area: 'web-settings', action: 'update', target: 'sessionIdleMinutes', before: { sessionIdleMinutes: 0 }, after: { sessionIdleMinutes: 60 } },
  { id: 'a1', at: agoIso(86400), user: 'u-alice', username: 'alice', tenant: 'shop', area: 'archived', action: 'purge', target: 'old-blog' },
];

/** 단독 컨테이너. 캔버스 UI-3E 목록과 같은 줄. bob의 임시 하나는 관리자만 본다. */
export type MockStandalone = D.DStandalone & { tenant: string };
const sa = (x: Omit<MockStandalone, 'tenant' | 'restarts' | 'connections' | 'observedAt'> & Partial<MockStandalone>): MockStandalone => ({ tenant: 'shop', restarts: 0, connections: 0, observedAt: agoSec(6), ...x });
export const standalone: MockStandalone[] = [
  sa({
    name: 'temp-7c2a',
    lifetime: 'temp',
    mode: 'shell',
    image: 'registry.shop.internal/shop/web:v14',
    digest: 'sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8',
    node: 'node-a',
    state: 'running',
    expiresAt: agoSec(-48 * 60),
    graceSeconds: 600,
    connections: 1,
    owner: 'u-alice',
    ownerName: 'alice',
    revision: 1,
    createdAt: agoSec(12 * 60),
    yaml: `name: temp-7c2a\nlifetime: temp\nttl: 1h\ngrace: 10m\nmode: shell\nimage: registry.shop.internal/shop/web:v14\ncommand: [/bin/sh]\ntty: true\nstdin_open: true\nnetworks: [shop-net]\nvolumes: [uploads:/srv/uploads:ro]\ndeploy: {resources: {limits: {cpus: "0.5", memory: 256M}}}\nx-sfc: {node: node-a}\n`,
  }),
  sa({
    name: 'report-cron',
    importedFrom: { app: 'php-shop', service: 'worker', items: ['imageCmd', 'netEnv', 'volumes'], by: 'u-bob', at: agoSec(3 * 86400) },
    lifetime: 'fixed',
    mode: 'entrypoint',
    image: 'registry.shop.internal/shop/worker:v5',
    digest: 'sha256:77e0a01dc3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6',
    node: 'node-b',
    state: 'running',
    restartPolicy: 'on-failure',
    owner: 'u-bob',
    ownerName: 'bob',
    revision: 3,
    createdAt: agoSec(9 * 86400),
    yaml: `name: report-cron\nlifetime: fixed\nrestart: on-failure\nmode: entrypoint\nimage: registry.shop.internal/shop/worker:v5\ncommand: [/app/report, --every, 1h]\nenvironment:\n  DB_HOST: db\nnetworks: [shop-net]\nhealthcheck: {test: [CMD, /app/report, --ping], interval: 30s}\nlogging: {driver: local, options: {max-size: 10m, max-file: "3"}}\nx-sfc: {node: node-b}\n`,
  }),
  sa({
    name: 'adminer',
    lifetime: 'fixed',
    mode: 'entrypoint',
    image: 'docker.io/library/adminer:4.8',
    node: 'node-a',
    state: 'running',
    restartPolicy: 'always',
    owner: 'u-alice',
    ownerName: 'alice',
    revision: 2,
    createdAt: agoSec(20 * 86400),
    yaml: `name: adminer\nlifetime: fixed\nrestart: always\nmode: entrypoint\nimage: docker.io/library/adminer:4.8\nnetworks: [shop-net]\nports: [8080/tcp]\nx-sfc:\n  node: node-a\n  ingress:\n    - {node: node-a, host: adminer.shop.example, prefix: /, port: 8080, gateway: local}\n`,
  }),
  sa({
    name: 'temp-3e55',
    lifetime: 'temp',
    mode: 'shell',
    image: 'docker.io/library/busybox:1.36',
    node: 'node-a',
    state: 'running',
    expiresAt: agoSec(-40 * 60),
    graceSeconds: 600,
    disconnectedAt: agoSec(4 * 60),
    owner: 'u-alice',
    ownerName: 'alice',
    revision: 1,
    createdAt: agoSec(20 * 60),
    yaml: `name: temp-3e55\nlifetime: temp\nttl: 1h\ngrace: 10m\nmode: shell\nimage: docker.io/library/busybox:1.36\ncommand: [/bin/sh]\ntty: true\nstdin_open: true\nnetworks: [shop-net]\n`,
  }),
  sa({
    name: 'temp-91d0',
    lifetime: 'temp',
    mode: 'entrypoint',
    image: 'registry.shop.internal/shop/migrate:0.4',
    node: 'node-b',
    state: 'running',
    expiresAt: agoSec(-57 * 60),
    graceSeconds: 600,
    owner: 'u-bob',
    ownerName: 'bob',
    revision: 1,
    createdAt: agoSec(3 * 60),
    yaml: `name: temp-91d0\nlifetime: temp\nttl: 1h\ngrace: 10m\nmode: entrypoint\nimage: registry.shop.internal/shop/migrate:0.4\ncommand: [./migrate, up]\nnetworks: [shop-net]\nx-sfc: {node: node-b}\n`,
  }),
  sa({
    name: 'temp-0a19',
    lifetime: 'temp',
    mode: 'entrypoint',
    image: 'registry.shop.internal/shop/web:v13',
    node: 'node-b',
    state: 'removed',
    exitCode: 1,
    endedAt: agoSec(25 * 60),
    owner: 'u-alice',
    ownerName: 'alice',
    revision: 1,
    createdAt: agoSec(50 * 60),
    yaml: `name: temp-0a19\nlifetime: temp\nttl: 1h\ngrace: 10m\nmode: entrypoint\nimage: registry.shop.internal/shop/web:v13\ncommand: [php, artisan, cache:warm]\nx-sfc: {node: node-b}\n`,
  }),
];

// ── 묶음 승인 (UI-72) ──
/** 자동 배포 후보가 쓰는 보호 묶음(후보 digest → 묶음). 등록한 사람은 alice */
export const cdCandidateGroups: Record<string, { registrant: string; groups: { realm: string; group: string; services: string[]; approved: boolean }[] }> = {
  ['shop/worker-batch/' + 'b77d210'.padEnd(64, '0')]: { registrant: 'u-alice', groups: [{ realm: 'shop', group: 'db-cred', services: ['batch'], approved: false }] },
};
export const grantedApprovals: (D.DGrantedApproval & { tenant: string })[] = [
  { tenant: 'shop', id: 'approval-1f0c', realm: 'shop', group: 'db-cred', user: 'u-alice', app: 'php-shop', deployment: 'main', services: ['db'], nodes: ['node-a'], approvedAt: nowSec() - 86400 * 2, expiresAt: nowSec() + 86400 * 5, issuer: 'node-a', revoking: false, consumers: 1 },
];
export const approvalCollection: Record<string, number> = { shop: 4 };

/** 신뢰 출처(UI-82). 쓰는 이미지는 라우터가 앱·단독 컨테이너에서 센다 */
export const imageTrust: Record<string, { revision: number; rules: { registry: string; repository: string }[] }> = {
  shop: {
    revision: 7,
    rules: [
      { registry: 'docker.io', repository: '**' },
      { registry: 'registry.shop.internal', repository: '**' },
      { registry: 'quay.io', repository: 'prometheus/node-exporter' },
      { registry: 'ghcr.io', repository: '**' },
      { registry: 'harbor.corp.example:443', repository: '**' },
    ],
  },
  internal: { revision: 3, rules: [{ registry: 'docker.io', repository: '**' }] },
};

/** 내장 저장소 이미지. usedBy = 쓰는 앱(실행 중·CD 후보), archived = 웹 보관된 앱 */
/** 저장소 이미지 목업(#242). 한 줄 = 한 digest, tags는 그 digest를 가리키는 태그. pushedAt은 Unix 초(외부 저장소는 모름 = 0) */
export type MockRegistryImage = { tenant: string; registry: string; external?: boolean; repository: string; digest: string; tags: string[] | null; bytes: number; pushedAt: number | string; inUse: number; usedBy: string[]; archived?: string[] };
const hex = (seed: string) => {
  let out = '';
  for (let k = 0; out.length < 64; k++) {
    let h = (2166136261 ^ Math.imul(k + 1, 2654435761)) >>> 0;
    for (const c of `${k}:${seed}`) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
    h = Math.imul(h ^ (h >>> 13), 0x5bd1e995) >>> 0;
    out += ((h ^ (h >>> 15)) >>> 0).toString(16).padStart(8, '0');
  }
  return 'sha256:' + out.slice(0, 64);
};
const ri = (repository: string, tags: string[], mb: number, agoS: number, usedBy: string[] = [], archived?: string[]): MockRegistryImage => ({
  tenant: 'shop',
  registry: 'builtin',
  repository,
  digest: hex(repository + '@' + tags.join(',') + agoS),
  tags,
  bytes: mb * 1_000_000,
  pushedAt: agoSec(agoS),
  inUse: 0,
  usedBy,
  archived,
});
export const registryImages: MockRegistryImage[] = [
  ri('shop/web', ['v2.14.0', 'stable'], 212, 7200, ['php-shop/web', 'php-shop/worker']),
  ri('shop/web', ['v2.13.2'], 211, 86400 * 3),
  ri('shop/web', ['pr-418'], 211, 86400 * 5),
  ri('shop/web', ['pr-411'], 210, 86400 * 9),
  ri('shop/web', ['v2.12.0'], 209, 86400 * 40),
  ri('shop/web', ['v2.11.4'], 208, 86400 * 52, [], ['old-blog']),
  ri('shop/worker', ['v5'], 96, 86400, ['worker-batch']),
  ri('shop/worker', ['v4'], 95, 86400 * 35),
  ri('shop/worker', [], 94, 86400 * 60),
  ri('shop/report', [], 64, 86400 * 6, ['php-shop/report']),
  ri('shop/report', ['v1.9'], 63, 86400 * 45),
  ri('shop/migrate', ['0.4'], 64, 86400 * 7),
  ri('shop/migrate', ['release-0.3'], 62, 86400 * 70),
];
// 외부 저장소 ghcr(읽는 서버 있음)의 이미지. 외부 목록은 올린 시각을 모른다
registryImages.push(
  { ...ri('shop-team/web', ['1.4', 'latest'], 88, 0, ['php-shop/edge']), registry: 'ghcr', external: true, pushedAt: 0 },
  { ...ri('shop-team/web', ['1.3'], 87, 0), registry: 'ghcr', external: true, pushedAt: 0 },
  { ...ri('shop-team/tools', ['2025.11'], 41, 0), registry: 'ghcr', external: true, pushedAt: 0 },
);
/** 저장소 정리 상태(#242 maintenance 요약). unref = GC로 돌아올 바이트(목업 값), lastGCAt은 Unix 밀리초 */
export const registryMaint: Record<string, { unref: number; lastGCAt?: number; lastGCOperation?: string; reclaimed: number }> = {
  'shop/builtin': { unref: 180 << 20, lastGCAt: Date.now() - 86400_000 * 6, lastGCOperation: 'web-6b1d0e8c-2f4a-4c1e-9a77-1d2e3f405162', reclaimed: 2_400_000_000 },
};

/** 외부 저장소(UI-83, #232 mock). test = 로그인 시험 결과 코드, users = 이 정의를 쓰는 곳 */
export type MockExternalRegistry = D.DExternalRegistry & { tenant: string; test: D.LoginTestCode; users: D.DExternalRegistryUse[] };
const pull = (node: string, code: string, ago: number, stale = false) => ({ node, stage: code === 'ok' ? 'done' : 'manifest', code, completedAt: agoSec(ago), reportedAt: agoSec(ago - 2), stale });
export const externalRegistries: MockExternalRegistry[] = [
  {
    tenant: 'shop',
    id: 'ghcr',
    authority: 'ghcr.io',
    repository: 'shop-team/**',
    enabled: true,
    auth: 'token',
    credential: { realm: 'shop', id: 'ghcr-shop', usernameKey: 'username', passwordKey: 'token' },
    revision: 3,
    deleted: false,
    reader: { node: 'node-a', owner: 'web-1', generation: 4, draining: false },
    pulls: [pull('node-a', 'ok', 180), pull('node-b', 'ok', 3600, true)],
    test: 'ok',
    users: [
      { app: 'php-shop', deployment: 'main', service: 'web', node: 'node-a', instance: 'web-1', kind: 'app-execution', match: 'shop-team/**', image: 'ghcr.io/shop-team/web@sha256:a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8' },
      { app: 'php-shop', deployment: 'main', service: 'worker', node: 'node-a', instance: 'worker-1', kind: 'app-execution', match: 'shop-team/**', image: 'ghcr.io/shop-team/worker@sha256:7d0ab8e0a01dc3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8' },
    ],
  },
  {
    tenant: 'shop',
    id: 'harbor',
    authority: 'harbor.corp.example:443',
    repository: 'platform/**',
    enabled: true,
    auth: 'password',
    credential: { realm: 'shop', id: 'harbor-robot', usernameKey: 'username', passwordKey: 'password' },
    ca: { realm: 'shop', id: 'corp-root-ca', key: 'ca.pem' },
    revision: 2,
    deleted: false,
    pulls: [pull('node-b', 'unauthorized', 7200)],
    test: 'unauthorized',
    users: [{ app: 'platform-api', deployment: 'main', service: 'api', kind: 'app-execution', match: 'platform/**', image: 'harbor.corp.example:443/platform/api:1.8.3' }],
  },
  { tenant: 'shop', id: 'quay', authority: 'quay.io', repository: '**', enabled: false, auth: 'none', revision: 1, deleted: false, pulls: [], test: 'ok', users: [] },
];

/** 가상 브릿지 (UI-5D, #704). state는 읽는 작업 공간마다 router가 붙인다 */
export type MockBridge = Omit<D.DBridge, 'state' | 'ports' | 'approvals'> & { ports: { first: number; last: number }[]; approvals: { tenant: string; user: string }[] };
const br = (owner: string, name: string, a: string, b: [string, string], x: Partial<MockBridge>): MockBridge => ({ kind: 'bridge', owner, name, a: { tenant: owner, network: a }, b: { tenant: b[0], network: b[1] }, direction: 'both', protocol: 'all', ports: [], phase: 'open', approvals: [], generation: 1, revision: 1, ...x });
export const bridges: MockBridge[] = [
  br('shop', 'net-db', 'shop-net', ['shop', 'shop-db'], {}),
  br('shop', 'metrics', 'shop-net', ['internal', 'mon-net'], { direction: 'a-to-b', protocol: 'tcp', ports: [{ first: 9090, last: 9100 }], approvals: [{ tenant: 'shop', user: 'alice' }, { tenant: 'internal', user: 'carol' }], revision: 3 }),
  br('internal', 'ingest-db', 'mon-net', ['shop', 'shop-db'], { phase: 'pending', approvals: [{ tenant: 'internal', user: 'carol' }], revision: 1 }),
  br('shop', 'cache-sync', 'shop-db', ['lab', 'cache-net'], { phase: 'pending', protocol: 'tcp', ports: [{ first: 6379, last: 6379 }], approvals: [{ tenant: 'shop', user: 'alice' }] }),
  br('shop', 'old-metrics', 'shop-net', ['lab', 'cache-net'], { direction: 'a-to-b', phase: 'closing', protocol: 'tcp', ports: [{ first: 9100, last: 9100 }], approvals: [{ tenant: 'shop', user: 'alice' }, { tenant: 'lab', user: 'dave' }], revision: 4 }),
];

# 클러스터 백업

`sfcli cluster backup create`는 클러스터 상태(FSM snapshot)와 클러스터 마스터 키를 클러스터 밖으로 꺼내, 관리자가 가진 백업 키로 암호화한 파일 하나에 담는다. 모든 voter를 잃었을 때 되살리는 데 쓴다. 노드 로컬 기록, 노드 신원 키, 볼륨 데이터, registry blob, sfc-web 데이터는 넣지 않는다.

## 순서

1. CLI가 이번 백업에만 쓸 1회용 X25519 키를 만든다.
2. CLI가 서명한 user operation `cluster-backup`을 보낸다. payload는 `ClusterBackupChange{Operation, Recipient}`다. `Recipient`는 1회용 키의 공개 반쪽이고, `Expected`는 0이다.
   - 시스템 관리자만 보낼 수 있다(`ManageCluster`). 계정이나 credential의 operation 제한에 `cluster-backup`이 있어야 한다.
   - 기록은 `control/cluster-backups`에 쌓인다. 최근 64개만 남고, 오래된 것부터 빠진다. 기록에는 누가, 언제, 어느 1회용 키로 요청했는지만 있다.
3. CLI가 SFCP purpose **ClusterBackup=20** 스트림을 연다. 요청 body는 `ClusterBackupRequest{Schema:1, Operation, ExpiresAt, Nonce}`이고, 세션과 연결 서명이 함께 간다.
4. 받은 서버는 quorum barrier(리더는 ReadIndex, follower는 리더의 status로 받은 floor까지 기다림)를 거친다. 그 view에서 다음을 확인한다.
   - 같은 사용자의 기록이 있다.
   - 기록 뒤 15분(`ClusterBackupWindow`)이 지나지 않았다.
   - 세션이 지금도 백업 권한을 가진다.
5. 서버가 voter이면 직접 만든다. voter가 아니면(non-voter, 공개 gateway 등) 요청을 relay(kind 3)로 리더에게 넘기고, 받은 frame을 그대로 돌려준다. relay하는 서버를 지나는 것은 봉인된 마스터 키와 공개 snapshot 바이트뿐이다.
6. voter는 barrier floor 이상인 자기 FSM을 MDS1 snapshot으로 내보낸다. Raft snapshot과 같은 바이트이고, 로그를 줄이지는 않는다. 그다음 마스터 키를 기록의 `Recipient`로 봉인하고, manifest에 자기 신원 키로 서명해 보낸다.
7. CLI가 마스터 키를 풀고 파일 전체를 백업 키로 암호화해 쓴다. 다 받은 뒤 파일 전체를 다시 확인(`verify`와 같다)하고, 그때서야 `--out` 이름으로 바꾼다.

## 스트림 (purpose 20)

| kind | 방향 | 필드 |
|---|---|---|
| 1 | CLI → 서버 | tag1 Envelope JSON, tag2 SHA-256(tag1) |
| 3 | member relay → voter | kind1과 같다. `Envelope.Relay`에 relay 서명이 있다 |
| 2 | 서버 → CLI | tag1 `ClusterBackupReply` JSON, tag2 요청 header digest |
| 4 | 서버 → CLI | tag1 offset(u64 LE), tag2 snapshot 바이트(최대 24KiB), tag3 요청 header digest |

`ClusterBackupReply{Schema, Operation, Code, Manifest?, Signature?, Master?}`의 흐름은 다음과 같다.

- 처음 kind2는 `Code:"ready"`다. 서명된 `Manifest`, `Signature`, `Master:{Ephemeral, Box}`를 담는다.
- 그 뒤 kind4 chunk가 offset 순서로 `Manifest.SnapshotSize` 바이트만큼 온다.
- 마지막 kind2는 `Code:"ok"`다.
- 거부는 `ready` 없이 kind2 하나로 끝난다. 코드는 `denied`(기록 없음, 기한 지남, 권한 없음), `unavailable`(마스터 키나 snapshot을 못 만듦, 리더 모름), `target-changed`(relay 받은 쪽이 voter가 아님)다.
- voter는 chunk를 보내기 전마다 기록, 권한, 자기 voter 자격을 다시 확인한다.

CLI는 다음을 확인한다.

- manifest의 cluster와 operation이 요청과 같다.
- 서명이 manifest의 `VoterKey`로 맞는다.
- chunk offset이 이어진다.
- 받은 바이트 수와 SHA-256이 manifest와 같다.

## 마스터 키 봉인

- X25519(1회용 수신 키, voter가 매번 새로 만든 ephemeral 키)로 공유 비밀을 만든다.
- 그 비밀에서 HKDF-SHA256으로 AES-256-GCM 키를 유도한다. info는 `"sfc-cluster-backup-seal-1\0" || cluster || recipient || ephemeral || operation`이다.
- nonce는 0이다. ephemeral 키가 매번 새것이라 안전하다. AAD도 info와 같다.

다른 수신 키, operation, cluster로는 열리지 않는다.

## Manifest

```
Manifest {
  Schema: 1, Cluster: [32], Version, Operation, User, CreatedAt,
  RaftIndex, Term, Index,            // snapshot 위치(Raft 위치·term·명령 순번)
  SnapshotSize, SnapshotDigest,      // MDS1 전체의 크기와 SHA-256
  StateDigest,                       // MDS1 header의 상태 digest
  Members: [{ID, Key, Voter}], Voter, VoterKey,
  MasterCheck,                       // SHA-256("sfc-cluster-backup-master-1\0" || cluster || master)
  Admin, TrustRoot,                  // bootstrap 관리자 키, 저장 기록을 묶는 trust root
  Genesis: {ID, Key, Endpoint, Voter} // 처음 서버. `sfcd restore`가 이 정책으로 새 서버를 세운다
}
```

- 서명 대상은 `"sfc-cluster-backup-manifest-1\0" || JSON`이다. JSON은 엄격하게 푼다. 모르는 필드는 거부하고, 다시 인코딩한 바이트가 같아야 한다.
- `Voter`는 `Members`에 voter로 있어야 하고, 그 `Key`가 `VoterKey`와 같아야 한다.

## 백업 파일 (`.sfcbak`)

정수는 LE다. 앞의 42바이트는 평문 header이고, 이어서 chunk가 온다.

```
"MDBK" | schema:u32=1 | kdf:u8 | salt[16] | argon memoryKiB:u32 | iterations:u32 | threads:u8 | nonce[8]
chunk* = len:u32 | AES-256-GCM(chunk plaintext)
```

### 키 유도

- `kdf=1`은 키 파일이다. 32바이트 그대로, 또는 hex 64자(끝 개행 하나 허용)다. Argon2 칸은 0이다.
- `kdf=2`는 비밀번호다. Argon2id(64MiB, 3회, 4 thread)로 32바이트를 만든다.
- 어느 쪽이든 그 32바이트와 salt로 HKDF-SHA256(info `sfc-cluster-backup-1`) 키를 만든다.

### chunk

- 평문 chunk는 64KiB다. 마지막 chunk만 더 짧을 수 있고, 비어 있을 수도 있다.
- nonce는 `nonce[8] || counter:u32`다.
- AAD는 `header || counter:u32 || last:u8`다. 마지막 chunk에만 last=1이다. 그래서 잘리거나 chunk가 빠지거나 뒤에 덧붙인 파일은 열리지 않는다.

### 평문

```
"MDBP" | manifestLength:u32 | manifest JSON | signature[64] | master[32] | MDS1 snapshot(SnapshotSize)
```

## 확인 (`verify`)

`sfcli cluster backup verify`는 서버 없이 다음을 확인한다.

1. 파일을 인증된 끝까지 푼다.
2. manifest 서명을 확인한다.
3. 마스터 키가 `MasterCheck`와 맞는지 본다.
4. MDS1 header의 cluster binding과 configuration checksum을 확인한다.
5. 상태를 엄격하게 decode한다. Raft 복원과 같은 검사다.
6. snapshot 전체 SHA-256과 Raft 위치를 manifest와 대조한다.

백업 키가 틀린 경우와 파일이 손상된 경우는 같은 오류로 보인다.

## 시험

- `internal/clusterbackup`: chunk 경계 round trip, 틀린 키, 손상, 잘림, 덧붙임, 비밀번호 키, 서명 범위, 봉인 수신자.
- `internal/cluster/control TestClusterBackupRecordsAndWork`: 기록, 중복·CAS·빈 키 거부, 15분 창, 64개 유지, snapshot 복원.
- `internal/app TestClusterBackupFromEveryMember`: voter 2대와 non-voter 1대에서 백업을 받는다. 기록 없는 요청은 거부되고, 다른 수신 키로는 열리지 않는다. 같은 마스터 키를 받고, snapshot 안에 자기 기록이 있다.
- `cmd/sfcli TestClusterBackupCreateAndVerifyWithoutTerminal`: `SFC_NONINTERACTIVE=1`과 키 파일, 비밀번호 파일로 만들고 확인한다. 파일은 mode 0600이고, 반쪽 파일이 남지 않으며, 같은 `--out`은 거부된다.

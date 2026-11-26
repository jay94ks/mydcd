## 관리 변경

기존 `mydc manage apply <change.json> --request-id <id>` 또는 같은 User `submit`을 사용한다. 클라이언트는 `whoami`의 `ImageBuildRootRevision`으로 outer RootRevision을 고정한다. 아래 Expected는 각 record의 별도 revision이다. 삭제나 consume로 원 ID를 초기화하지 않으며 원 operation의 result/resume 규칙을 따른다.

| action | payload | Expected·효과 |
|---|---|---|
| `set-image-build-policy` | `{Spec: Policy}` | 최초0/기존 policy revision. 고정 builder digest·현재 trust·내장 결과 registry·허용 root와 저장 예산 확인 |
| `delete-image-build-policy` | `{Tenant,ID:""}` | 현재 policy revision. live context나 열린 upload가 있으면 거부 |
| `put-build-context` | `{Spec: ContextSpec}` | 최초0/현재 context revision. policy의 node/root/platform 부분집합. 기존 root/종류 retarget 금지 |
| `delete-build-context` | `{Tenant,ID}` | 현재 context revision. 열린 upload/보존 버전이 있으면 거부 |
| `begin-build-zip-upload` | `{Tenant,Context,Upload,Length,Digest,ExpiresAt,ChunkBytes?}` | 최초0. 같은 ID/tombstone 재사용 금지. 길이≤500,000,000 bytes·고정 scope·예산 예약·tenant당 열린 upload≤16 |
| `put-build-zip-part` | `{Tenant,Upload,Receipt}` | legacy stage-only part의 명시 UserOperation. 해당 upload revision과 원 owner PartReceipt만 수락. 새 CLI의 Record part는 아래 owner report로 확정하며 **raw Data를 받는 Raft action이 아님** |
| `upload-build-zip` | `{Tenant,ID,Upload,Fact}` | 해당 upload revision. 전 part·owner SealReceipt·creator/context/정책 CAS를 확인하고 버전 생성과 upload close를 같은 변경으로 수행 |
| `abort-build-zip-upload` | `{Tenant,Upload}` | 해당 upload revision. creator만 가능. 원 bytes의 물리 회수 완료를 뜻하지 않음 |

정책/컨텍스트의 네 정의/삭제 action은 tenant 관리 명령으로 쓸 수 있다. upload 작업·owner fact 수락은 별도 명시 운영 경로이며 app.yaml/CD에 합치지 않는다. part/abort/consume의 upload CAS(서버가 action에서 정한다)는 관련 없는 root 변경을 허용하지만 원 upload CAS와 현재 context/policy/root를 완화하지 않는다. begin은 outer root CAS를 유지한다.

`Policy`는 `Schema=1, Tenant, Nodes:[{Node,Root}], Concurrency, Seconds, CPUMillis, MemoryBytes, WorkspaceBytes, CacheBytes, Registry, Platforms, BuilderImage, Cleanup:{HighWaterPercent,UnusedDays}`다. `Root`는 등록된 `nodestorage.Reference` 전체이고 `BuilderImage`는 canonical SHA-256 digest여야 한다. CPU·메모리·동시성·시간 제한의 실제 집행은 builder 연결의 수락 조건이다. `WorkspaceBytes`는 컨텍스트 확장/빌드 입력 수락 예산, `CacheBytes`는 캐시 정리 목표다. MVP는 파일시스템 쓰기 강제 상한이나 tenant별 디스크 고갈의 엄격한 격리를 제공하지 않으며 ext4 project quota 준비를 요구하지 않는다. 기존 보존 컨텍스트/upload의 논리적 저장 예약 검사는 유지하며 파일시스템 쓰기 강제 상한과 구분한다. 등록 root의 기존 ext4·identity·tenant 격리와 원 자료 정리·실패 정산은 유지한다.

`ContextSpec`은 `Tenant,ID,Kind,Root,Dockerfile,Arguments?,Secrets?,Repository,Tags,Platforms,Git?`다. `Kind`는 `upload|git|draft`이며 Git일 때만 `Git:{Repository,Ref,Path,CredentialProfile,Automatic}`를 둔다. `Secrets` 항목은 `{ID,Realm,Secret,Key}`라는 참조다. `Repository`는 선택된 내장 registry 아래의 상대 repository이고 tag는 literal·`{version}`·`{commit}` 조합이다. Git source 확인은 아래 별도 명령을 사용한다. Automatic=false이면 정의 등록만으로 version 보관·이미지 build를 실행하지 않는다. Automatic=true이면 원 수락 정의를 근거로 아래 자동 빌드 경로가 동작하며, 정의의 Applied를 실제 build/push 완료로 판단하지 않는다.

PartReceipt는 `{Schema:1,Scope:[32],Index,Length,Digest:[32],Signature:base64}`다. Scope는 creator·cluster/tenant/context/upload·원 root generation/context/policy revision·ZIP 길이/지문·Dockerfile·expanded 예산·기한과 optional `ChunkBytes`의 지문이다. `ChunkBytes` 생략/0은 기존24,576 bytes이고,32768은32KiB다. 그 밖의 값은 거부한다. 한 Scope의 조각 크기는 고정이며 마지막만 잔여 길이다. native byte offset은 `Index * Scope.PartSize()`이고 part 개수·길이도 같은 값으로 계산한다.0은 JSON에서 생략하여 기존 Scope Hash·영수증/서명 바이트를 유지한다. SealReceipt는 `{Schema:1,Scope,ZIP,Tree,Entries,ExpandedBytes,Signature}`로 전체 ZIP/트리 검사의 owner 확인이다. 원문의 바이트는 이 문서의 관리 요청/결과에 포함하지 않는다.


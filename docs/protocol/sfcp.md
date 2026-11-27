# SFCP 재설계

User purpose8 `image-builds Part:"cache-prunes"`와 기존 member Management의
`image-build-cache-prune-work`는 [수락·대기 명세](../reference/image-build-jobs/14-section.md)를
따른다. 원 cache/사용자 승인·source scope와 Raft 수락 순서를 유지하며 별도 전송 번호나
비인증 SDK listener를 추가하지 않는다. native 실행/종료 연결과 queued 수락은 구분한다.


member `image-build-job-work`의 optional Blocked는 자원 대기와 취소·기한/권한 회수를
구분한다. [worker 수명·원 결과](../reference/image-build-jobs/04-owner.md)를 따르며
native unknown·종료 사실과 원 operation ID를 보존한다. 로그 EOF나 통신 timeout만으로
관리 자원/Secret 사용 참조를 반환하지 않는다.

member Management `image-build-base-work`/`image-build-base-owner`는 accepted job의 FROM
digest 해결이다. 원 builder key/job/Spec와 current quorum·신뢰·원 source reader scope를
확인하고 공개 metadata만 반환한다. [요청/응답·고정 입력](../reference/image-build-jobs/04-owner.md)을
따르며 Secret 값이나 library 비인증 RPC로 우회하지 않는다. begin 후에는 원 digest를 재조회한다.

User purpose8 `image-builds`의 `Part:"caches"`와 member `image-build-caches-owner`는
[노드·컨텍스트 cache 목록](../reference/image-build-jobs/12-section.md)을 사용한다.
현재 tenant/node 범위·공유 namespace 목록과 원 owner의 관측 요약을 구분하며 원 Spec/
Session/host path를 사용자 페이지에 넣지 않는다. Unix와 네트워크의 사용자 형식은 같다.

User purpose8 `image-build-cache`와 member Management `image-build-cache-owner`는
[빌드 캐시 관측 형식](../reference/image-build-jobs/10-section.md)을 사용한다.
현재 사용자/tenant/node 권한과 원 job/epoch를 검사하며 항목은 원 owner DB에서 읽는다.
Unix/QUIC의 사용자 요청은 같고 조회로 native daemon이나 새 job을 만들지 않는다.
optional `Page.Cleanup`은 같은 owner의 [빌드 종료 자동 정리](../reference/image-build-jobs/11-section.md)
receipt이며 원 전송 의도/완전 응답/Unknown을 구분한다.

User purpose8 `image-build-logs`와 member Management `image-build-logs-owner`는
원 job의 가린 node-local 로그를 페이지로 읽는다. 선택 필드 `ImageBuildLog.Tail:true`는
마지막 MaxBytes 바이트를 바로 선택한다. After와 혼합하지 않으며, 이후 Tail 없이
응답 Next를 After로 보내면 새 출력을 이어 읽는다. Unix/QUIC는 같은 현재 사용자 권한과
원 cluster/tenant/Spec/epoch·byte offset cursor를 사용한다. [메시지·누락/한도 표시](../reference/image-build-jobs/08-section.md)를
따르며 로그 bytes를 Raft로 복제하거나 로그 EOF를 native 종료 증거로 쓰지 않는다.

User purpose8의 save-build-git과 member image-build-git-owner는 원 commit/tree·ID/기한의 사용자 proof를 전달한다. Unix/QUIC가 같은 [메시지/재개 경계](../reference/image-build-contexts/14-git-archive.md#git-보관의-사용자-메시지와-cli)를 쓰며 별도 Git/파일 server를 열지 않는다. 저장된 owner 증거만으로 공유 버전을 게시하지 않으며 현재 creator의 signed User/Raft 변경을 사용한다.

`build-draft`의 freeze plan은 원 snapshot/ID/기한에 고정하고 node의 실제 archive 증거를 반환한다. 원 creator의 `publish-build-draft` signed User/Raft 변경만 immutable version을 게시한다. 같은 [archive/메시지 경계](../reference/image-build-contexts/12-draft-freeze.md)를 사용하며 bytes/가짜 part slot을 Raft에 넣지 않는다.

같은 User `build-draft Kind:result`는 원 Scope/Edit와 result-purpose proof로 [원 편집 결과](../reference/image-build-contexts/06-draft.md#과거-편집의-원-결과-조회)를 metadata에서 조회한다. 현재 권한·원 설정/데이터 계보를 확인하되 과거 편집을 실행하거나 새 root pin을 만들지 않는다. `OK|PENDING|DISCARDED|NOT_INITIALIZED`를 구분하며 조회 proof는 편집/publish 승인으로 사용할 수 없다. Unix/QUIC와 member owner relay는 같은 메시지를 사용한다.


User의 과거 보관 결과 조회는 기존 `build-draft Kind:freeze-result`와
`save-build-git Result:true`를 사용한다. 각각 freeze-result Transfer/Git Proof.Result를
서명에 고정하고 현재 creator/권한을 검사한다. 원 plan 만료는 새 조회 proof만으로
저장/게시 승인이 되지 않는다. 저장된 native seal의 원 증거와 optional Reclaimed,
미완료/폐기/기록 부재는 [같은 메시지 명세](../reference/image-build-contexts/15-freeze-git.md)를 따른다.
새 transport/purpose나 비인증 RPC를 만들지 않는다.

User 목적8의 `build-draft`는 [draft 메시지](../reference/image-build-contexts/06-draft.md)를 사용한다. 원 사용자 서명의 scope/편집 지문은 `image-build-draft-owner` relay에서도 유지한다. file-part/status/seal은 같은 원 편집과 조각 지문을 사용하고 전체 파일 검증 전 draft revision을 올리지 않는다. 원 CAS가 지나간 pending 파일은 owner가 미사용 본문을 회수할 때 원 intent의 폐기 상태를 보존하며, 그 뒤 원 조각/상태/seal은 충돌을 반환한다. 완료 edit의 원 결과는 계속 보존하며 새 wire field나 작업 ID를 만들지 않는다. 새 transport/purpose 번호를 만들지 않으며 mutable 입력 편집과 Raft의 immutable version 게시·빌드 수락을 구분한다. Git version의 optional Commit·관리 publish-build-git도 기존 User/Raft 변경을 사용하며 [보관/게시 경계](../reference/image-build-contexts/14-git-archive.md)를 따른다.


이미지 빌드 Secret은 기존 Management `image-build-secret-inputs`와 SecretFetch의 optional `AppInputFetch.ImageBuild:{Tenant,Job,Snapshot}`를 사용한다. [선택자·응답·terminal 증거](../reference/image-build-jobs/02-secret.md)의 원 job/owner·ReadSet/MinimumIndex와 현재 provider 권한을 검사하며 Task/Move/ExternalRegistry 선택자와 배타적이다. 승인 Purpose=`image-build`는 `resolve/build`에 서명하고 원 terminal UseGone은 같은 purpose와 lease를 보존한다. 새 wire 번호나 비인증 Vault/빌더 경로는 없다.

member Management `image-build-registry-permit {Tenant,Job,Snapshot,Action,Image,At}`는 [빌드 job의 내장 registry 자격](../reference/image-build-jobs/04-owner.md)을 확인한다. 현재 quorum·원 job/owner와 정확한 Repository/Run을 반환하며 사용자 Session·앱 Task 권한을 합성하지 않는다. running/unknown pull은 begin Inputs와 optional Sources의 원 digest/registry generation/owner에 고정한다. begin Sources는 외부 reader/read-set 또는 내장 registry definition의 공개 참조만 서명하며 job 실제 종결 전 원 source 반환을 막는다. 새로운 wire 번호나 별도 RPC를 만들지 않는다.

member `image-build-base-token-owner`는 `{Read,Challenge:{Host,Realm,Service,Scopes},Additional?:[ImageBuildBaseRead,...]}`를 원 source owner로 전달하고 `{Token,IssuedAt,ExpiresIn}`을 보호 응답한다. 원 Builder membership·current quorum·running/unknown의 begin/source binding과 실제 registry challenge를 확인한다. 복수 pull scope는 총8개 이내의 같은 job/owner·external reader selection/generation/ReadSet으로 한정하고 교환 전후 모든 원 Read를 검사한다. managed 자격은 단일 repository 경계를 유지한다. token은 Raft/관측/log에 저장하지 않고 password/refresh token/CA를 반환하지 않는다. [정확한 Bearer 교환 명세](../reference/image-build-jobs/04-owner.md)를 따르며 일반 User 메시지나 별도 TCP RPC가 아니다.

이미지 빌드 job은 User purpose8의 `image-build-job-plan`/`image-builds Part:jobs`와 기존 member Management `image-build-job-work`/`image-build-job-report`로 연결한다. [메시지/서명/상태 전이](../reference/image-build-jobs.md)의 원 Spec·version·accepted grant를 보존한다. 신규 wire 번호/별도 BuildKit 비인증 TCP 경로를 열지 않는다.

job complete의 원 `Closure.At`은 실제 정산 증거를 고정한 시각이며 현재 보고 envelope의
`At` 이하여야 한다. quorum 단절 후에는 같은 signed closure를 현재 CAS/epoch·새 report
서명으로 보고한다. 종료 시각을 다시 쓰거나 과거 시각으로 현재 보고의 freshness 검사를 우회하지 않는다.

User purpose8의 `build-context-content`와 member Management `image-build-content-owner`는 보존 컨텍스트의 파일 트리/Dockerfile/regular file 조회다. Unix·QUIC는 같은 원 Session·현재 tenant 권한·immutable version/tree/epoch cursor를 사용한다. [요청·응답 포맷과 한도](../reference/image-build-contexts/04-dockerfile.md)를 따른다. 새 목적 번호나 별도 HTTP/file 경로를 만들지 않는다.

자동 빌드의 member Management `image-build-automatic-git-report`는 원 accepted put-build-context 승인·owner SavedGit·시작 시각/의도 지문으로 archive/version/queued job·Secret usage를 같은 FSM 변경에 확정한다. [메시지·권위/수락 경계](../reference/image-build-contexts/17-git.md)를 따르며 source 관측만으로 빌드를 수락하지 않는다. 기존 worker와 실제 Run.Spec 지문을 사용한다.

자동 Git 관측은 같은 source 검사 코어를 사용하고 member Management `image-build-git-observation-report`의 원 수락 정의/owner 서명·관측 CAS를 기존 ModuleReport/Raft에 저장한다. User `image-builds Part:contexts`의 optional GitObservation으로 공개 결과만 읽는다. [메시지/권한](../reference/image-build-contexts/16-git.md)을 따르며 원 사용자 승인 없는 노드 관리 변경이나 자동 build 제출로 해석하지 않는다.

User 목적8의 `check-build-context`와 member Management의 `image-build-source-owner`는 등록된 Git source 확인이다. 원 Session·선택 context/policy revision/epoch·node/root를 보존하고 owner는 fetch 전후 current 권한을 검사한다. [메시지/응답·예산](../reference/image-build-contexts/03-user.md)을 따르며 원 Git/자격 bytes는 원 operation/Raft나 응답에 넣지 않는다.

빌드 자료 만료/회수의 member `image-build-artifact-work`·`image-build-owner-report`는 기존 Management 안의 current owner/quorum 경계다. User의 `delete-build-version`은 원 signed operation이고 owner의 `expired/reclaimed`는 원 scope/고정 fact의 보고다. [수명·메시지 형식](../reference/image-build-contexts/01-section.md)을 따르며 socket EOF/timeout을 native 미실행 또는 closure로 바꾸지 않는다.

이미지 컨텍스트의 User `build-zip-transfer`는 `[Tenant,ImageBuildTransfer:{Upload,Kind,Expected,Index?,Data?,Proof?,Record?}]`를 같은 목적8에 전송한다. signed begin과 UploadScope의 optional `ChunkBytes`는 생략/0이면24KiB,32768이면32KiB이며 한 Scope에서 고정된다. Data의 길이·index offset과 Scope Hash/part proof/receipt가 같은 크기에 결합된다. 신규 CLI만 현재 Session JSON≤8KiB일 때32768을 선택하고 큰 Session은 legacy0을 선택한다. 원 begin/journal이 있으면 재선택하지 않으며 User/Management frame 상한128KiB와 schema1은 유지한다. member `image-build-owner`는 원 Session·사용자 part proof와 정확한 Data를 보존한다. part의 현재 quorum 조회는 `image-build-part-permit {Session,Tenant,Upload,Expected,Index,Proof,At}`를 사용하며 Data/Kind/별도 Record 필드는 없다. canonical decode는 raw Data 혼입을 거부하고 Record·원 Session 전체(Approval 포함)의 결합은 변경 없는 Proof로 검사한다. 이 metadata-only read는 원 owner/scope/root/CAS·현재 권한·epoch와 같은 Work를 반환하며 native 쓰기·seal·publish를 수행하지 않는다. 기존 fullData `image-build-io-permit`는 동일 permit 코어와 Data 길이/SHA 검사를 유지하고 seal도 이 기존 method를 사용한다. 실제 User/owner 전송과 Spool/native receipt·owner report/Raft 확정 경계는 그대로이며 새 Session 크기 제한은 추가하지 않는다. optional `Record:true`는 사용자 part proof의 같은 필드와 원 Session 전체(Approval 포함) 지문(`Proof.Session`)에도 서명되며 owner의 기존 `image-build-owner-report`가 정확한 영수증/slot을 확정한다. 이때 성공 응답의 `Recorded:true`와 `UploadRevision`은 native 기록과 공유 확정 뒤에만 반환한다. 생략된 `Record`는 기존 stage-only 동작과 per-part UserOperation을 유지한다. [전송·결과 형식](../reference/image-build-contexts/05-zip.md)을 따른다. 별도 wire 번호나 비인증 data 경로는 없다.

이미지 빌드 metadata는 기존 User 목적8에 `image-builds {Tenant,ImageBuild:{Part,ID,Upload},After?}`와 `Reply.ImageBuild`를 추가한다. [메시지·페이지·signed action 명세](../reference/image-build-contexts.md)를 따른다. `whoami`의 optional `ImageBuildRootRevision`은 `control/image-builds` 원 operation의 outer CAS다. part/abort/consume만 기존 ModuleUpload의 해당 upload CAS를 쓰며 정책·context revision/current root 검사는 유지한다. 추가 transport·외부 RPC나 wire 번호 변경을 만들지 않는다.

User의 node-summary/node-disks/node-tenant-usage/mesh-links/raft-status는 [노드 관측 API](../reference/node-observations.md)의 선택자·공개 DTO·페이지·현재 권한을 사용한다. raft-status만 연결한 node의 로컬 마지막 적용 정책으로 인증하고 quorum 없이 stale 진단을 반환하며 관리 변경을 허용하지 않는다. Observation kind1/2의 최대60KiB signed node-observation은 host/disk/tenant usage/link/consensus/task 중 하나를 현재 멤버끼리 전달·로컬 저장한 ACK다. 기존 purpose와 schema1을 유지하며 관리 Raft 확정/실행 grant로 취급하지 않는다.

User kind1의 `tasks`는 typed `Params:{Node,Tenant,App,Standalone?,After?}`와 현재 Session으로 수락된 Task·서명된 관측을 조회한다. Unix·네트워크에서 같은 payload와 현재 Read/tenant/node 권한을 사용한다. 응답 `Data:{Tasks,Next,RootRevision}`의 [행 형식·cursor·신선도](../reference/task-observability.md)는 동일하며 새 제어 권한이나 별도 전송 경로를 만들지 않는다.

User kind1의 `app-source`·`app-revisions`는 Tenant·AppSource 선택자와 현재 Read session으로 원문/버전을 읽는다. 원문은 고정된 버전·Section(`source`/`local-services`/`overlays`)·digest의24KiB 유한 part이고 버전 목록은 root/scope/필터 고정 페이지다. Unix·네트워크가 같은 [원문·metadata 형식](../reference/app-source.md)을 사용하며 조회로 배포나 비밀값 입력을 실행하지 않는다. wire/DB schema는1을 유지한다.

SFCP는 Seafield Cluster 노드 간 관리·복제·상태 보고·터널 데이터와 사용자 관리 API에 사용하는 바이너리 프로토콜이다. 원격 node 통신은 QUIC/TLS, 로컬 관리 접속은 [Unix TLS/record](../reference/unix-sockets.md)를 사용한다. 두 어댑터는 같은 frame/TLV와 현재 인증·권한·업무 상태 전이 코어를 공유한다. 자체 schema는1이며 기존 C++ 바이트 형식과 혼용하지 않는다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 메시지 목적 | [sfcp/01-section.md](sfcp/01-section.md) |
| 공통 규칙 | [sfcp/02-section.md](sfcp/02-section.md) |
| schema=1 바이트 계약 | [sfcp/03-schema-1.md](sfcp/03-schema-1.md) |
| 실제 관리/전송 계약 | [sfcp/04-section.md](sfcp/04-section.md) |
| Volume transfer 경계 | [sfcp/05-volume-transfer.md](sfcp/05-volume-transfer.md) |
| Secret 보호 입력과 승인 | [sfcp/06-secret.md](sfcp/06-secret.md) |
| user 인증·tenant 권한 경계 | [sfcp/07-user-tenant.md](sfcp/07-user-tenant.md) |
| 관리 DNS의 원 owner 보고 | [sfcp/08-dns-owner.md](sfcp/08-dns-owner.md) |
| 동적 node admission/회수 | [sfcp/09-node-admission.md](sfcp/09-node-admission.md) |
| User 목적의 실제 개인키 로그인·조회 | [sfcp/10-user.md](sfcp/10-user.md) |
| User 목적의 서명 관리 operation | [sfcp/11-user-operation.md](sfcp/11-user-operation.md) |
| Managed 가입 directory 경계 | [sfcp/12-managed-directory.md](sfcp/12-managed-directory.md) |
| User 자원 정책·조회 | [sfcp/13-user.md](sfcp/13-user.md) |
| SecretFetch의 원격 앱 입력 | [sfcp/14-secretfetch.md](sfcp/14-secretfetch.md) |
| Volume 사용량 조회 | [sfcp/15-volume.md](sfcp/15-volume.md) |
| 이관 대상 실행과 전송 정산 | [sfcp/16-section.md](sfcp/16-section.md) |
| 이관 대상의 비공개 입력 준비 | [sfcp/17-section.md](sfcp/17-section.md) |
| Shared Volume backup operation | [sfcp/18-shared-volume-backup-operation.md](sfcp/18-shared-volume-backup-operation.md) |
| Unix 관리 스트림 Contract1 | [sfcp/19-unix-contract1.md](sfcp/19-unix-contract1.md) |
| 최초 등록용 공개 확인 Contract1 | [sfcp/20-contract1.md](sfcp/20-contract1.md) |
| Lifecycle artifact의 member 소비 | [sfcp/21-lifecycle-artifact-member.md](sfcp/21-lifecycle-artifact-member.md) |
| tenant 내장 registry의 관리 경계 | [sfcp/22-tenant-registry.md](sfcp/22-tenant-registry.md) |
| 서버 전송 실패 진단 | [sfcp/23-section.md](sfcp/23-section.md) |
| 노드 shell — purpose19 | [sfcp/24-shell-purpose19.md](sfcp/24-shell-purpose19.md) |
| 컨테이너 운영 조회 메시지 | [sfcp/25-section.md](sfcp/25-section.md) |
| CD 이력·원 값·서비스 변경점 | [sfcp/26-cd.md](sfcp/26-cd.md) |
| tenant 허용 저장 경로 조회 | [sfcp/27-tenant.md](sfcp/27-tenant.md) |
| Ingress 관측·Raft 차단과 CertificateMaterial | [sfcp/28-ingress-raft-certificatematerial.md](sfcp/28-ingress-raft-certificatematerial.md) |
| 서비스 POST·Git probe | [sfcp/29-post-git-probe.md](sfcp/29-post-git-probe.md) |
| 단독 컨테이너와 Volume 파일 | [sfcp/30-volume.md](sfcp/30-volume.md) |
| Lifecycle 편집기 source 메시지 | [sfcp/31-lifecycle-source.md](sfcp/31-lifecycle-source.md) |
| 내장 Secret 값 복제 VaultValue | [sfcp/32-vault-value.md](sfcp/32-vault-value.md) |

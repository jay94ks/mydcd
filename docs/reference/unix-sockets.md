# Unix 소켓 끝점과 관리 프로토콜

이미지 ZIP part의 내부 member `image-build-part-permit`는
`{Session,Tenant,Upload,Expected,Index,Proof,At}`의 canonical metadata-only current quorum 조회다.
Data 혼입은 거부하며 원 사용자 proof/Session Approval·scope/root/CAS·현재 권한을
기존 fullData permit와 같은 코어로 검사한다. 큰 Session에 새 16KiB 제한을 두지 않는다.
User `build-zip-transfer`/member `image-build-owner`는 실제 Data 길이/SHA와 Spool receipt를
계속 검사하며 이 조회로 native 쓰기·seal·publish가 발생하지 않는다. seal과 기존 fullData
`image-build-io-permit`도 유지한다. 기존 frame/관리 입력 상한·목적/스키마1을 사용하며
[SFCP 계약](../protocol/sfcp.md)의 동일한 내부 경계를 따른다.

User `image-builds Part:"cache-prunes"`와 member `image-build-cache-prune-work`는
[수동 정리 수락·대기 형식](image-build-jobs/14-section.md)을 사용한다.
수락/Allowed는 실행 완료가 아니다. Unix도 같은 현재 사용자 권한·quorum을 사용한다.


이미지 빌드 SDK의 `buildkit.sock`은 등록 root 아래 원 job의 private output 디렉터리에
유한 rootless daemon이 만드는 내부 끝점이다. `/run/sfcdp.sock` 관리 API와 다르며
사용자/원격 노드 접속용 TCP listener가 아니다. 고정 BuildKit v0.35.1 SDK의 gRPC
Info/Solve/Session/Status와 파일·Secret/auth session을 원 FD의 Unix 연결로 사용한다.
[실행·원 결과·종료 경계](image-build-jobs/07-section.md)를 따른다.

member `image-build-job-work {Tenant,ID,At}`의 응답은
`{Schema:1,Run,Allowed,RootRevision,Epoch,Index,Blocked?}`다. [대기/회수와 worker 정산](image-build-jobs/04-owner.md)을
따르며 slot/budget 대기를 사용자 취소로 바꾸지 않는다. 같은 원 job의 종료 사실을 보고하는
메시지는 기존 `image-build-job-report`이고 노드 키가 새 사용자 관리 명령을 만드는 경로가 아니다.
begin의 optional `Sources:[{Image,Owner,External?,ReadSet?,Managed?}]`는
[정확한 형식과 수명](image-build-jobs/04-owner.md)에 따라 원 reader/run을 고정한다.
원 job complete 전 source closed/승인 반환을 거부하며 자격·token 본문은 포함하지 않는다.

member `image-build-base-work`는 `{Tenant,Job,Snapshot,Source:{Reference,Platform,Stage,Kind,Line},At}`로
현재 수락 job의 base 해결 scope를 받고, `image-build-base-owner`는 그 `{Cluster,Builder,Query,Target,Index,Epoch}`를
원 source owner로 전달한다. 결과는 `{Schema:1,Cluster,Builder,Tenant,Job,Snapshot,Source,Result}`이며
Result는 공개 manifest/digest metadata다. [원 입력·소유자·인증/포맷](image-build-jobs/04-owner.md)을
따르며 source의 실제 자격과 승인 참조를 다른 노드로 복사하는 메시지가 아니다.

member `image-build-base-tls-owner`는 원 `ImageBuildBaseRead`,
`image-build-registry-tls-owner`는 원 `ImageBuildRegistryPermit`을 입력받는다. 응답은
`{Authority,Certificates:[base64 DER,...],Fingerprint:[32]}`다. [TLS 자료/상한/수명](image-build-jobs/06-tls.md)을
따르며 일반 사용자/Vault 읽기가 아니다. 설치된 원 Builder만 native owner를 호출하고
그 owner가 current quorum·begin/source 또는 registry run/serving leaf 지문을 재확인한다.
key/password·다른 Vault 값은 반환하지 않으며 host OS·Docker trust를 바꾸지 않는다.

member `image-build-base-token-owner` 요청은
`{Read:{Cluster,Builder,Query,Target,Index,Epoch},Challenge:{Host,Realm,Service,Scopes},Additional?:[ImageBuildBaseRead,...]}`이며
보호된 응답은 `{Token,IssuedAt,ExpiresIn}`이다. [Bearer 교환의 정확한 제한](image-build-jobs/04-owner.md)을
따른다. 일반 사용자 Unix API나 Secret 조회가 아니며 원 Builder→source owner의 SFCP로만
전달한다. 현재 quorum·running/unknown의 원 source binding·실제 registry challenge를 확인하고
동일 reader의 Additional(최대7개)도 같은 job/owner·credential generation/ReadSet·pull scope로 확인하며 token/password를 관측·Raft·로그에 기록하지 않는다.

User `image-builds {Tenant,ImageBuild:{Part:"caches",ID?:context,Node?:node},After?}`는
현재 조회 가능한 cache 범위를 중복 없이 나열하고 원 node의 마지막 SDK 요약을 붙인다.
`Reply.ImageBuild.Caches/InventoryRoot`와 최대4행·노드별 UNAVAILABLE/미관측·삭제된 job의
캐시 보존 및 member `image-build-caches-owner`의 [전체 형식](image-build-jobs/12-section.md)을 따른다.

User `image-build-cache {Tenant,ImageBuildCache:{Job} 또는 {Job:"",Cache:[32],Node},After?}`는 원 job의
context/root/builder 캐시의 마지막 실제 SDK 관측을 읽는다. 응답의 `ImageBuildCache`는
공유 job/epoch와 node-local `Page`·outer `Next`를 담고, 미관측/성공/최근 관측 실패·시각을
구분한다. 내부 member `image-build-cache-owner`는 원 owner에서 현재 사용자 권한을
재검사한다. [전체 필드·페이지·오류](image-build-jobs/10-section.md)를 따른다.
조회만으로 daemon 기동·build 재실행·cache 삭제를 하지 않는다. `Page.Cleanup?`은 원
job의 빌드 종료 자동 정리 의도/SDK 결과이며 [단계·불명 의미](image-build-jobs/11-section.md)를 따른다.

User `image-build-logs {Tenant,ImageBuildLog:{Job,MaxBytes:1..24576,Tail?:true},After?}`의
`Reply.ImageBuildLog`는 `{Tenant,Job,Root:[32],Epoch,Phase,Next,Page:{Schema:1,Job:[32],Offset,Next,Total,Data,Available,Truncated,Gap,Unclosed}}`다.
공통 Schema/Nonce/Session proof를 사용하고 Data는 가린 bytes의 base64 JSON이다.
Tail은 같은 snapshot의 마지막 MaxBytes 바이트를 선택하며 After와 혼합하지 않는다.
이후 Tail 없이 Next를 After로 보내면 새로 추가된 bytes를 이어 읽는다.
member `image-build-logs-owner`는 현재 사용자 권한을 원 owner에서 다시 검사하는 내부
Management relay다. [로그 포맷·cursor·한도·종료 의미](image-build-jobs/08-section.md)를
따르며 native 로그 EOF를 작업 완료로 취급하거나 로그 본문을 Raft에 저장하지 않는다.

User `save-build-git {Tenant,ImageBuildGit:{Plan,Proof}}`와 `Reply.ImageBuildGit:{Schema,Plan,Code,Saved?}`는 [Git 보관 메시지](image-build-contexts/14-git-archive.md#git-보관의-사용자-메시지와-cli)를 따른다. 현재 사용자/등록 scope와 원 session-key proof는 member image-build-git-owner relay에서도 확인한다. native 보관과 creator의 publish-build-git/Raft 게시를 구분하며 기존 purpose8/schema1을 사용한다.

User `build-draft Kind:freeze`의 Freeze plan/Proof·`Reply.ImageBuildDraft.Frozen`과 관리 `publish-build-draft`의 payload/Expected·원 creator 승인은 [freeze/게시 메시지](image-build-contexts/12-draft-freeze.md)를 따른다. 같은 User 목적8/member owner relay이며 node 증거만으로 version을 게시하지 않는다.

같은 User `build-draft Kind:result`는 `{Context,Scope,Edit,Proof}`와 `Proof.Transfer:{Kind:"result"}`를 사용한다. Data/Freeze/cursor를 보내지 않는다. 원 metadata 결과의 `OK`는 `{Revision,Digest,Edit:{Edit,Draft,Revision}}`, 나머지 `PENDING|DISCARDED|NOT_INITIALIZED`는 결과 필드가 없는 동일 DraftResponse다. 현재 권한/원 지문을 확인하는 조회이며 과거 편집을 실행하지 않는다. 설정 변경/삭제·원 pin 반환 뒤의 [메시지/CLI 계약](image-build-contexts/06-draft.md#과거-편집의-원-결과-조회)을 따른다.


User 목적8의 `build-draft Kind:freeze-result`는 원 `Scope/Freeze`와
`Proof.Transfer:{Kind:"freeze-result"}`를 사용한다. `save-build-git`는 원 `Plan`과
`Result:true`, 서명된 `Proof.Result:true`를 함께 사용한다. 기존 owner member relay와
같은 frame/EOF 계약이며 현재 creator/권한·원 plan 지문을 검사한다. 완료 응답의 기존
Frozen/Saved와 optional Reclaimed, `PENDING|DISCARDED|NOT_INITIALIZED`의 정확한
[형식/수명](image-build-contexts/15-freeze-git.md)을 따른다. 현재 본문 가용성을
추정하거나 원 plan 갱신·fetch·파일/pin·seal 저장·게시를 실행하지 않는다.

User `build-draft {Tenant,ImageBuildDraft:{Context,Kind:"plan"|"tree"|"file"|"edit"|"file-part"|"file-status"|"file-seal",...}}`와 `Reply.ImageBuildDraft`의 scope/사용자 proof·원 편집 결과·8개 tree 항목·24KiB inline 파일/원 조각·File progress 포맷은 [draft 메시지](image-build-contexts/06-draft.md)를 따른다. owner relay는 같은 member Management `image-build-draft-owner`다. 노드 로컬 입력 편집은 version 게시/배포 변경이 아니다. CAS가 지나간 pending 파일의 owner 회수 뒤에는 원 조각/상태/seal 요청을 충돌로 거부하며, 완료한 원 edit 결과와 메시지 형식은 유지한다. [본문 정리](image-build-contexts/13-draft.md)를 따른다.


빌드 Secret은 [job 승인·메시지 명세](image-build-jobs/02-secret.md)의 optional Plan.Uses와 signed terminal report.Secrets를 사용한다. `image-build-secret-inputs`는 member Management의 `{Selection:{Tenant,Job,Snapshot},At}` metadata 조회이며 실제 값은 기존 SecretFetch에서 선택적인 `AppInputFetch.ImageBuild`로 원 job/ReadSet에 고정한다. 관리 Unix socket에서 Secret 원문을 조회하거나 새 끝점을 만들지 않는다.

빌드 내부의 registry 허가는 기존 인증 member Management `image-build-registry-permit`와 OCI HTTP `/token`의 BuildSubject를 사용한다. [형식·수명·issuer 분리](image-build-jobs/04-owner.md)를 따르며 사용자 관리 Unix socket을 Docker API나 비인증 BuildKit socket으로 바꾸지 않는다.

이미지 빌드 job의 User `image-build-job-plan`·`image-builds`의 `Part:"jobs"`와 signed `begin-image-build/cancel-image-build/delete-image-build-job`은 같은 purpose8·원 인증/CAS 코어를 사용한다. [Spec/Change/Jobs/owner report 포맷](image-build-jobs.md)을 따르며 Secret 값·ZIP bytes·빌드 로그를 Raft에 넣지 않는다.

User `build-context-content {Tenant,ImageBuildContent:{Version:[32],Part:"tree"|"dockerfile"|"file",Path?,Offset?},After?}`와 `Reply.ImageBuildContent`는 [보존 버전 조회](image-build-contexts/04-dockerfile.md)를 사용한다. 현재 Read/ManageRegistry·owner/root/epoch·보존 version을 검사하며 원 bytes를 Raft에 넣지 않는다. `image-build-content-owner`는 같은 member Management의 native owner 조회이고 별도 socket을 열지 않는다.

Sfc의 로컬 관리 끝점은 **`unix:///run/sfcdp.sock`**이다. `sfcd`가 생성하며 `sfcli`와 로컬 관리 클라이언트가 접속한다. 프로토콜은 **AF_UNIX stream → TLS → SFCP 인증 → Unix record → SFCP frame/TLV → 업무 payload** 순서다.

이 문서는 현재 schema/Contract **1**의 구현을 설명한다. [명령 대상표](../architecture/command-targets.md)는 명령의 대상·권한을, [SFCP](../protocol/sfcp.md)는 공통 메시지/서명을 규정한다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 끝점 목록 | [unix-sockets/01-section.md](unix-sockets/01-section.md) |
| 설정과 접속 | [unix-sockets/02-section.md](unix-sockets/02-section.md) |
| 파일 권한과 소유권 | [unix-sockets/03-section.md](unix-sockets/03-section.md) |
| 연결 수립과 최초 신뢰 | [unix-sockets/04-section.md](unix-sockets/04-section.md) |
| SFCP 인증 handshake | [unix-sockets/05-sfcp-handshake.md](unix-sockets/05-sfcp-handshake.md) |
| Unix record Contract1 | [unix-sockets/06-unix-record-contract1.md](unix-sockets/06-unix-record-contract1.md) |
| 공통 SFCP frame | [unix-sockets/07-sfcp-frame.md](unix-sockets/07-sfcp-frame.md) |
| 허용 메시지와 payload | [unix-sockets/08-payload.md](unix-sockets/08-payload.md) |
| 메시지 인코딩 규칙 | [unix-sockets/09-section.md](unix-sockets/09-section.md) |
| User 메시지 목록 | [unix-sockets/10-user.md](unix-sockets/10-user.md) |
| 중첩 객체 포맷 | [unix-sockets/11-section.md](unix-sockets/11-section.md) |
| SecretInput 메시지 목록과 포맷 | [unix-sockets/12-secretinput.md](unix-sockets/12-secretinput.md) |
| Reply와 오류 포맷 | [unix-sockets/13-reply.md](unix-sockets/13-reply.md) |
| 메시지 교환 순서 | [unix-sockets/14-section.md](unix-sockets/14-section.md) |
| 사용자 인증·관리 권한·원 결과 | [unix-sockets/15-section.md](unix-sockets/15-section.md) |
| 예산과 종료 | [unix-sockets/16-section.md](unix-sockets/16-section.md) |
| 서버 실패 진단 로그 | [unix-sockets/17-section.md](unix-sockets/17-section.md) |
| 구현 위치 | [unix-sockets/18-section.md](unix-sockets/18-section.md) |
| 컨테이너 운영 조회 | [unix-sockets/19-section.md](unix-sockets/19-section.md) |
| 노드 shell purpose19 | [unix-sockets/20-shell-purpose19.md](unix-sockets/20-shell-purpose19.md) |
| 컨테이너 양방향 스트림 purpose15 | [unix-sockets/21-purpose15.md](unix-sockets/21-purpose15.md) |
| 최초 credential의 보호 메시지 | [unix-sockets/22-credential.md](unix-sockets/22-credential.md) |
| 이미지 내용 전송 — purpose16 | [unix-sockets/23-purpose16.md](unix-sockets/23-purpose16.md) |
| tenant 허용 저장 경로 메시지 | [unix-sockets/24-tenant.md](unix-sockets/24-tenant.md) |
| Ingress와 인증서 메시지 | [unix-sockets/25-ingress.md](unix-sockets/25-ingress.md) |
| 서비스 POST·Git probe 메시지 | [unix-sockets/26-post-git-probe.md](unix-sockets/26-post-git-probe.md) |
| 단독 컨테이너·Volume 파일 스트림 | [unix-sockets/27-volume.md](unix-sockets/27-volume.md) |
| 관리 자원·사용처 공개 조회 | [unix-sockets/28-section.md](unix-sockets/28-section.md) |
| Lifecycle 원본 편집·읽기 메시지 | [unix-sockets/29-lifecycle.md](unix-sockets/29-lifecycle.md) |

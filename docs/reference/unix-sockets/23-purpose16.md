## 이미지 내용 전송 — purpose16

수락 빌드의 source-owner 본문 읽기 kind16은 member QUIC 내부 실행용이며 Unix에서 거부한다. 로컬 사용자 `image pull-content`는 아래 kind1 경로를 유지한다. [kind16 형식·고정 root/child 검증](../image-content.md#수락된-빌드의-from-본문)을 참고한다.

manifest·config/history·layer blob은 [ImageContent 명세](../image-content.md)의 동일 handler를 Unix TLS와 QUIC에서 사용한다. 일반 User Reply나 Raft value에 큰 본문을 넣지 않는다. 요청 Envelope의 원 사용자 Session/연결 proof·tenant/신뢰·고정 run/source 승인을 검사하며, 해당 owner가 다른 노드이면 설치 member 간 QUIC kind3이 그 원 proof를 보존하여 전달한다. Unix에서 kind3을 받거나 node 키만으로 사용자 권한을 만들지 않는다.

요청 Body는 `{Schema:1,Tenant,Query:{Ref,Kind,Digest},ExpiresAt,Nonce}`다. Ref는 정규 `authority/repository@sha256:...`, Kind는 manifest/config/layer이고 Digest는 manifest에서 빈 문자열, config/layer에서는 해당 manifest가 가리키는 정확한 digest다. 임의 URL·mutable tag·별도 blob 경로를 받지 않는다. ExpiresAt은 Unix 초이며 원 Session 만료 이내, 현재부터 최대900초다. Nonce와32바이트 digest/key는 JSON 정수 배열이다. Envelope의 Body/Signature는 byte slice의 base64 문자열이다.

kind2의 TLV1은 `{Schema:1,Code,Info?}`, TLV2는 원 요청 Envelope digest다. ready와 최종 ok에는 `Info:{Schema:1,Ref,Kind,Digest,MediaType,Bytes}`가 있고 두 Info는 같아야 한다. 거부 코드는 denied/unavailable/unsupported/invalid/target-changed이며 Info가 없다. ready 뒤 kind4는 offset0부터 연속된 최대24KiB 원 바이트다. 전체 Bytes·SHA-256, 최종 ok, 서버 EOF가 모두 맞아야 성공이다. 잘린/변조/과다 본문·거부/취소·EOF만 도착한 결과는 성공으로 저장하지 않는다. 원문 본문을 일반 관리 JSON·오류/로그에 넣지 않는다.

header 파싱은 기존30초, 권한/계획은5초, 인증 뒤 I/O 유휴는60초·전체는 signed ExpiresAt/caller context로 제한한다. 동시에 노드당2개 handler다. 같은 연결의 일반 RPC보다 길게 읽기 위해 전용 local 연결을 사용하고 종료 후 연결을 재사용 cache에 남기지 않는다. 새 블록을 시작할 때 최대8MiB 또는1초 간격과 마지막 결과 전에 현재 quorum/사용자/원 source·run을 검사한다. 이 읽기는 새 pull/push credential이나 관리 operation을 발급하지 않는다. 상세 EOF·descriptor·소비자 commit 계약은 링크한 명세를 따른다.


cache 항목 조회의 cache-ID/node selector와 optional `Data.CacheScope`는
[보존 항목 조회](../image-build-jobs/13-cache-id.md)를 따른다. 원 job cursor는
유지하며 명시 cache cursor는 대표 job 교체와 구분한다. 관측의 원 native 증거 유실을
미관측/사용량0으로 처리하지 않는다.


member `image-build-cache-prune-report`는 [수동 정리의 서명 owner 보고](../image-build-jobs/14-section.md#수동-cache-정리의-owner-보고와-예산)를
사용한다. 원 intent/source와 설치 owner·CAS·epoch·현재 envelope 시각을 검사하며
running/unknown 예약은 실제 종료 보고 수락 전까지 유지한다. 원 Native 지문은 내부 증거로 보존하고 ClosedAt/SDK ACK 수량은 공개 완료 결과로 투영하되 사용자에게 원 Session/서명 보고를 노출하지 않는다.


`image-build-cache-prune-work`의 Blocked는 NOT_READY/TIMEOUT도 포함하며 원 정리
요청의 At와 Source 정책 Seconds로 기한을 판단한다. [native 실행 경계](../image-build-jobs/14-section.md#수동-정리의-유한-native-실행)의
private SDK 소켓은 컨테이너 내부 작업용이며 관리 Unix/SFCP 끝점을 추가하지 않는다.
주기 자동 정리는 [idle 정책 정리](../image-build-jobs/16-idle-cache.md)의
member `image-build-cache-automatic-report`로 수락하고 같은 work/report를 소비한다.
Unix 사용자 끝점은 이 member 메시지를 받지 않는다. 공개 cache-prunes 행에는 optional
`Automatic:true,Sequence`가 있으며 해당 내부 Filter.Mode는 policy다. 자동 작업의 기한은
이번 pass의 At와 별도로 고정된 현재 정책 Seconds로 계산한다.

tenant 종료의 내부 `tenant-retirement-work/report`는 기존 member 연결에 한정한다.
[물리 build cache 정산](../image-build-jobs/17-tenant.md)은 같은 원 tenant
종료 operation·owner/inventory 지문·index/epoch를 소비하며 새 Unix 메시지나 사용자
grant를 만들지 않는다. 공개 `tenant-retirement` 상태는 실제 cache 원 lease 반환까지
owner 미완료로 유지한다. 일반 context/policy 삭제는 namespace 물리 삭제가 아니다.


cache 항목/요약의 optional `ObservedKind:"cache-prune"`는 ObservedBy가 원 수동 정리
intent임을 뜻한다. 생략은 기존 build Spec digest다. [출처·원 관측/cursor/실패 계약](../image-build-jobs/14-section.md#수동-정리-관측과-조회의-출처)을
사용하며 Unix/네트워크 응답 형식은 같다. Raw native record·Source/사용자 승인·SDK
오류/Description을 응답에 추가하지 않는다.

User `build-context-content Part:file`는 원 immutable version의 canonical Path와 선택64-bit Offset 또는 After를 받는다. 응답 `Data.Page.File`은 `{Entry:{Path,Directory:false,Executable,Bytes,Digest:[32]},Offset,Total,Next,Data?:base64}`이며 byte offset/크기는64-bit, Data는 최대24KiB다. 기존 Page의 Offset/Total/Next는0이고 Entries/Data는 없다. 바깥 Next는 원 version/tree/Part/Path/epoch에 고정한다. `build-draft Kind:file`는 원 Scope·tree Revision/Digest·Path·Offset을 받고 같은 FilePage를 응답 `Data.Content`로 반환한다. 변경된 tree는 conflict, 미완료 파일은 Content 없이 PENDING이며 mutable 파일은 ManageRegistry가 필요하다. 두 요청의 [전체 포맷·EOF/지문·owner 오류 계약](../image-build-contexts/04-dockerfile.md#임의-regular-file의-페이지와-eof-확인)을 따른다. 새 목적 번호/socket은 추가하지 않는다.


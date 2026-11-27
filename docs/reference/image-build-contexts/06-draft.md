## 편집 draft의 사용자 메시지

RQ6 구현 중인 경계다. 파일/metadata 편집·조각 전송 경로와 보존 version 게시·물리 회수의 연결을 구분한다. 아래 편집을 이미지 빌드·push 성공으로 판단하지 않는다.

같은 User 목적8에서 method=`build-draft`, `Tenant`, `ImageBuildDraft: DraftRequest`를 보내고 `Reply.ImageBuildDraft: DraftResponse`를 받는다. Unix/QUIC가 같은 형식을 사용한다. 설치 member relay는 `image-build-draft-owner`이며 기존 관리 연결만 사용한다. 별도 socket/HTTP 파일 서버를 만들지 않는다.

| 요청 Kind | 추가 필드 | 응답 |
|---|---|---|
| `plan` | `Context`만 지정 | `Code:PLAN`, `Scope`. 디렉터리/초기 draft/새 root pin을 생성하지 않음 |
| `tree` | 원 `Scope`, 첫 페이지 Offset=0. 후속은 `Revision`, `Digest:[32]`, `Offset` | 최대8개 `Entries`, 원 `Revision/Digest`, `Offset/Total/Next`. native 미생성은 `NOT_INITIALIZED`; 변경된 revision/digest는 충돌 |
| `file` | 원 `Scope`, tree의 `Revision`, `Digest:[32]`, canonical `Path`, byte `Offset:uint32` | `Code:OK`, 같은 Revision/Digest와 `Content:{Entry,Offset:uint64,Total:uint64,Next:uint64,Data?}`. Data는 최대24KiB. tree 변경은 conflict, partial 파일은 내용 없이 PENDING, native 미생성은 NOT_INITIALIZED |
| `edit` | 원 `Scope`, `Edit`, 사용자 `Proof`, put이면 `Data` | `Code:OK`, 원 `EditResult`와 새 `Revision/Digest`. 미완료 원 파일은 `PENDING`이며 완료로 취급하지 않음 |
| `result` | 원 `Scope`, `Edit`, `Proof.Transfer:{Kind:"result"}`, Data 생략 | 저장된 원 `EditResult`의 `OK`, 미완료 `PENDING`, 폐기 `DISCARDED`, 기록 부재 `NOT_INITIALIZED`. 편집을 실행하지 않음 |

`Scope`는 `{Schema:1,Tenant,Context,Root,ContextRevision,PolicyRevision,Dockerfile,ExpandedLimit,Generation?}`다. `Generation`은 편집 데이터의 생성 수명이며 새 plan에서 반환한다. 일반 설정 변경에는 유지하고 삭제 후 재생성에는 새 값을 사용한다. 이 필드가 없는 과거 scope는 ContextRevision을 생성 수명으로 해석한다. Root는 plan의 등록 참조를 그대로 사용한다. 요청자가 임의 host path를 지정하는 입력이 아니다. 현재 tenant ManageRegistry·사용자의 put-build-context operation ceiling·허용 node/등록 root ACL·현재 context/policy revision·quorum을 확인한다. mutable draft 소스는 Read만으로 읽지 않으며 보존 version 조회의 Read 권한과 구분한다.

`Edit`는 `{ID,Kind,Path,To?,Expected,File?}`다. ID는 안정적인 원 편집 ID, Expected는 원 draft revision이다. 최초 편집의 Expected는1이며 성공은2다. `mkdir`은 빈 폴더 생성, `delete`는 해당 파일/하위 트리 삭제, `move`는 To로 전체 하위 트리를 이동한다. 이동 목적지 병합·덮어쓰기·자기 하위 이동·파일 아래 자식·경로 탈출을 거부한다. `put`의 File은 `{Path,Directory:false,Executable,Bytes,Digest:[32]}`이며 Data는 JSON base64다. 현재 inline put은24,576 bytes 이하의 완전한 파일만 받는다. 더 큰 파일은 아래 file-part/status/seal을 사용하며 부분 파일을 완성 파일로 등록하지 않는다. metadata 편집에는 File/Data가 없다.

`Proof`는 `{Schema:1,Scope:[32],Edit:[32],At,ExpiresAt,Nonce:[32],Signature:base64}`다. Scope/Edit는 도메인이 분리된 원 scope/편집 지문이다. 사용자 session key가 `sfc-imagebuild-draft-request-1\0`과 Signature=null인 표준 JSON의 연결을 Ed25519로 서명한다. 최대120초·session 만료 이내이며 owner가 서명과 현재 계정/권한을 다시 검사한다. 원 edit의 path/CAS/body 지문을 relay가 변경하지 못한다. proof 갱신은 같은 edit ID/내용의 재조회를 허용하는 것이며 다른 입력으로 바꾸지 않는다.

`DraftResponse`는 `{Schema:1,Scope,Code,Revision,Digest?,Offset,Total,Next,Entries?,Edit?,Content?}`다. Edit 결과는 `{Edit:[32],Draft:[32],Revision}`이며 같은 ID/내용은 이후 편집 뒤에도 원 결과를 반환한다. 같은 ID의 다른 내용은 pending 단계부터 거부한다. native 단절/응답 유실은 새 ID/빈 draft로 초기화하지 않는다. 원 inode나 journal이 유실됐으면 미생성으로 숨기지 않는다. 인자·CPU/메모리·Dockerfile 선택 등의 설정 변경은 편집 파일과 native revision을 초기화하지 않는다. 새 plan의 현재 Scope로 요청하면 같은 파일을 읽고 편집할 수 있다. snapshot 지문은 현재 Scope도 포함하므로 새 Scope에서 달라지며 이전 cursor를 자동 갱신하지 않는다. 과거 Scope의 요청은 현재 revision/권한을 우회하지 못한다. Generation 필드가 없던 서명 형식은 현재 설정과 유효 데이터 수명이 모두 일치할 때만 원 표현 그대로 확인한다. 원 edit ID/내용의 결과는 보존하고 자동으로 새로운 CAS에 맞추지 않는다. 과거 편집의 결과는 아래 result 경로로 조회한다. freeze/Git archive는 아래 과거 보관 결과 조회 경계를 따른다.

CLI([sfcli build draft](../../cli/build.md#초안draft)):

```sh
sfcli build draft ls editable
sfcli build draft cat editable Dockerfile
sfcli build draft put editable Dockerfile ./Dockerfile
sfcli build draft mv editable assets/old.png assets/new.png
sfcli build draft rm editable assets/new.png
```

### draft regular file 읽기

`read-file.json`은 `{Scope:<원 plan.Scope>,Revision:<원 tree.Revision>,Digest:<원 tree.Digest>,Path:"composer.json",Offset:0}`인64KiB 이하 regular JSON 파일이다. CLI는 plan/tree를 자동 갱신하지 않고 이 원 입력을 그대로 보낸다. `Content.Next`가0이 아니면 같은 Scope/Revision/Digest/Path와 그 Offset으로 다음 페이지를 읽는다. draft 파일은 기존 최대500MB이며 요청 Offset의32-bit 범위 안이다. tree 변경 뒤 과거 revision/digest는 native gate 안에서 conflict가 되며, 새 tree를 읽어 새 입력을 명시해야 한다. 디렉터리·링크·경로 탈출은 거부한다.

file 요청에는 Edit/Proof/Data/Freeze를 넣지 않는다. 현재 ManageRegistry·put-build-context ceiling·tenant/root/node/epoch·원 설정 Scope를 tree와 동일하게 확인하므로 Read-only 사용자는 mutable 소스를 읽지 못한다. 읽기로 root/draft/파일을 생성하지 않는다. 완전히 등록된 blob의 원 inode/size/Done을 확인하고 한 페이지를 ReadAt으로 복사하며 전체 파일 지문은 tree의 Entry에서 가져온다. 미완료 multipart put은 원 tree에 등록하기 전 partial bytes를 반환하지 않는다. PENDING/NOT_INITIALIZED 응답에는 Content·Revision/Digest 결과가 없고 CLI는 종료 코드3을 낸다. 소비자는 immutable file과 마찬가지로 EOF에서 전체 bytes의 SHA-256/길이를 원 Entry와 비교한다.

두 file 조회는 기존 owner relay를 재사용한다. 신규 file 종류의 member 응답만 `{Code:"ok"|"conflict"|"invalid"|"denied"|"unavailable",Content?:<ImageBuildContentPage>,Draft?:<DraftResponse>}`를 사용한다. 성공에는 요청에 맞는 결과 하나만, 실패에는 결과 없이 코드만 있다. 원 native 오류 문자열/호스트 경로를 노출하지 않는다. tree/Dockerfile/기존 draft 종류의 member 결과 형식은 유지한다. 진입 노드와 owner 모두 현재 원 사용자 Session·tenant·scope를 재검사한다.

### 과거 편집의 원 결과 조회

`result`는 설정 변경/삭제 뒤에도 원 Scope·Edit를 그대로 지정하는 metadata 전용 조회다.
현재 ManageRegistry·put-build-context operation ceiling·현재 node 소유자/tenant 권한을
검사하며 원 context/policy revision과 데이터 Generation이 현재 계보보다 앞서면 거부한다.
Scope의 root는 현재 context의 원 root와 같아야 한다. 현재 root의 새 build 배치 가능성과
결과 조회를 구분하므로 원 pin/디렉터리를 반환한 뒤에도 native 기록을 읽을 수 있다.

새 proof는 원 Scope/Edit 지문과 `Transfer:{Kind:"result"}`를 위와 같은 session-key
형식·120초 예산으로 서명한다. 조회 승인이며 과거 편집의 수락 승인을 대체하지 않는다.
편집 proof를 result로 바꾸거나 result proof를 edit/file-seal로 재사용할 수 없다. Data·
freeze·cursor·별도 revision/digest는 보내지 않는다. CLI는 원 EDIT.json의 Scope/Edit만
보내고 inline Data가 파일에 있어도 재전송하지 않는다. 새 plan·ID·CAS로 자동 갱신하지 않는다.

완료한 원 결과는 같은 Edit/Draft 지문과 Revision으로 반환한다. 미완료 intent는 PENDING,
본문 회수로 폐기됐거나 전체 수명 회수가 시작된 미완료 편집은 DISCARDED다. 완료 결과는
본문 회수 뒤에도 유지한다. NOT_INITIALIZED는 읽을 native 기록이 없다는 뜻이며 외부
효과 미실행이나 재제출 허가를 증명하지 않는다. 모든 조회는 read transaction만 사용하고
파일/root pin/draft를 생성·열거나 상태를 변경하지 않는다. CLI는 OK에0, 그 외 상태는
출력 후3을 반환한다. 이 연결은 RQ6 마지막 실행 검증 전이다.

편집 내용은 원 node의 private 입력이다. 공유 cluster context 정의 변경과 immutable version 게시·빌드 수락은 기존 signed User/Raft 경계를 사용한다. 저장소는 tenant/context·원 Root·Generation으로 원 namespace/inode를 찾고, 현재 설정 revision은 요청 권한·snapshot 경계로 사용한다. 기존 namespace/파일·freeze/서명을 이동·복사·재작성하지 않는다. 원 자료나 pin이 유실되거나 일치하는 과거 namespace가 모호하면 빈 draft로 초기화하지 않고 오류를 반환한다. 설정 한도가 낮아져도 기존 파일의 조회와 사용량을 늘리지 않는 편집을 허용하지만 freeze/새 빌드의 입력 검사는 현재 한도를 적용한다. draft metadata의8MiB reopen 예산은 메모리/decoder 경계이며 디스크 hard quota를 뜻하지 않는다. freeze의 공개 수락 경계는 아래 절을 따르며 미완료 blob/retained scope 전체 회수는 RQ6의 남은 구현이다. 현재 수명의 미사용 본문과 CAS가 지나간 미완료 파일 정리는 아래 절을 따른다.



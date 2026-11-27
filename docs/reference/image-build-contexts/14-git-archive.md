## Git archive와 보존 버전 게시

RQ6 구현 중·마지막 실행 검증 전이다. 원 Git plan의 User/owner relay·SDK/CLI와 관리 게시를 설명한다. 자동 관측·version/build 제출은 아래 절을 따르며 실제 BuildKit/push 전체 경로의 최종 검증은 RQ6 마지막에 수행한다. source 보관 성공을 이미지 빌드 성공으로 판단하지 않는다.

`GitSavePlan`은 `{Schema:1,Tenant,Context,ID,Creator,Root,ContextRevision,PolicyRevision,Dockerfile,ExpandedLimit,Commit,Tree:[32],CreatedAt,ExpiresAt}`다. Commit은 확인한 소문자40자리 Git SHA-1, Tree는 같은 ZIP/tree 해석의 지문이며 ID/기한·원 context/policy/root에 고정한다. 시간은 Unix seconds, 생성 이후 최대24시간이다. 저장 재개에서 ref를 다시 따라 다른 commit으로 바꾸지 않는다.

노드의 `SavedGit` 증거는 `{Schema:1,Plan,Scope,Fact,Signature}`다. Scope는 plan에서 유도한 기존 UploadScope와 실제 ZIP 길이/지문, Fact는 원 owner의 기존 SealReceipt다. Fact.Tree는 Plan.Tree와 일치해야 한다. Signature는 원 owner가 `sfc-imagebuild-saved-git-1\0`과 Signature=null인 표준 JSON을 Ed25519로 서명한 값이다. 증거는 원 파일이 보관됐다는 확인이며 사용자 관리 승인이 아니다.

관리 action `publish-build-git`의 payload는 `{Tenant,Context,Saved}`이고 Expected는 Plan.ContextRevision이다. 현재 ManageRegistry·operation ceiling·원 creator 서명·현재 context/policy/root와 기한을 검사한다. 같은 FSM 변경에서 closed artifact/version/다음 번호와 원 commit을 게시한다. archive bytes와 가짜 part slot은 Raft에 넣지 않는다. ID를 다른 plan으로 재사용하지 않으며 version의 optional Commit은 원 게시 증거와 일치해야 한다. 버전 조회와 빌드 Spec의 `{commit}` 태그에는 이 보존 commit을 사용한다.

Native 준비는 인증해 받은 같은 repository의 정확한 commit으로 WriteGitZIP을 한 번 수행하고 같은 InspectZIP/tree·실제 길이/지문을 확인한다. write-ahead intent와 inode를 유지하며 완전한 원 파일의 completion 기록만 복구한다. 부분 archive를 truncate/rebuild하거나 원 journal 없이 다른 파일을 채택하지 않는다. Draft/Git은 같은 inode 인계·seal·reader/GC 코어를 사용한다. 공개 owner는 현재 사용자·scope/quorum을 gate 전후에 확인하고 원 staging/artifact RootManager pin을 사용한다. 기록된 원 save의 필수 pin이 없으면 새 pin으로 대체하지 않는다. staging과 archive의 종료는 아래 독립 수명을 따른다.

### Git staging의 정산

원 sealed archive header와 inode 인계가 확인되면 staging pin만 반환한다. archive는
별도 pin으로 보존하며 version 게시/빌드 참조·삭제는 기존 artifact 계약을 따른다.
부분 stage는 최신 quorum의 context/policy revision 증가 또는 context 삭제로 원 게시가
불가능해진 경우에만 삭제한다. 완료된 준비 Scope가 있으면 위 archive 독립 회수를 먼저
정산한다. 현재 부분 stage는 시계상 만료만으로 지우지 않는다.

같은 native Git 기록에 원 grant·lease·Transferred·삭제 intent를 보존하고 원 inode의
unlink/fsync→Removed/Returning→실제 descriptor Close/원 Return→Returned로 정산한다.
삭제/반환 뒤 기록 실패는 같은 의도로 재개하며 그동안 tenant 종료 점검에 Pending을
유지한다. 교체 파일·의도 전 알려진 파일 유실·앞선 로컬 plan은 자동 복구하지 않는다.
아직 inode를 기록하지 못한 생성 intent는 원 파일 부재 또는 private 빈 파일만 회수한다.

반환된 Transferred plan의 재조회는 원 archive pin을 열어 같은 AdoptGit/ZIP 검사로
SavedGit을 반환한다. stage 재할당·source refetch·새 plan 생성은 하지 않는다. 폐기된
부분 plan의 ID는 재사용하지 않는다. 이 연결은 RQ6 마지막 실행 검증 전이며 전체
tenant 입력 반환의 완료를 뜻하지 않는다.


### Git 보관의 사용자 메시지와 CLI

User purpose8 method=`save-build-git`의 요청은 `{Tenant,ImageBuildGit:{Plan,Proof}}`다. Unix TLS/QUIC에서 같은 형식을 쓰고, 원 owner가 다르면 설치 member `image-build-git-owner`로 한 번 전달한다. 노드별 비인증 Git/파일 RPC를 만들지 않는다. 현재 tenant ManageRegistry·publish-build-git operation ceiling·creator·등록 root/owner·현재 context/policy revision과 원 plan 기한을 확인한다.

Proof는 `{Schema:1,Plan:[32],At,ExpiresAt,Nonce:[32],Signature:base64}`다. 사용자 session key가 `sfc-imagebuild-git-request-1\0`과 Signature=null인 표준 JSON을 서명한다. Plan은 `sfc-imagebuild-git-save-1\0`과 원 GitSavePlan JSON의 SHA-256이며 최대120초·현재 session 만료 이내다. 짧은 proof 갱신은 같은 원 plan을 재조회하는 것이며 plan의 ID/commit/기한·권한을 바꾸지 않는다.

Reply.ImageBuildGit은 `{Schema:1,Plan:[32],Code,Saved?}`다. Code=`SAVED|PENDING|SOURCE_FETCH|INVALID_CONTEXT`이며 Saved는 SAVED일 때만 앞 절의 원 owner 증거다. 외부 Git 오류 body/credential/파일 원문을 실패 응답에 넣지 않는다. fetch 전에 기록된 원 save를 조회하고 이미 준비된/부분 원본이면 network fetch/generator를 다시 실행하지 않는다. 새로운 fetch 실패는 native staging이나 root pin을 만들지 않는다. fetch 자체는 editor mutex 밖에서 수행하고 실제 파일 쓰기/인계는 draft와 같은 gate를 사용한다.

```sh
sfcli build context upload source --id publish-git-one
sfcli build context versions source
```



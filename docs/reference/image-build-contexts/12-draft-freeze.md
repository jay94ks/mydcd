## draft freeze와 보존 버전 게시

RQ6 구현 중·마지막 실행 검증 전이다. 같은 `build-draft`에 Kind=`freeze`, 원 Scope, Freeze(plan), Proof를 보낸다. Edit/Data/Revision/Digest/Offset은 별도로 지정하지 않는다. 성공은 `DraftResponse.Code:FROZEN`과 `Frozen`이며 PENDING은 원 미완료 archive를 보존한다. FROZEN을 공유 version이나 실제 build/push 성공으로 판단하지 않는다.

Freeze plan은 `{Schema:1,Scope,ID,Creator,Revision,Draft:[32],CreatedAt,ExpiresAt}`다. Scope는 draft-plan의 원 값, Revision/Draft는 선택한 draft-tree의 revision/지문, Creator는 현재 사용자 ID다. 시간은 Unix seconds이며 CreatedAt>0, ExpiresAt은 생성 이후 최대24시간이다. 값·ID·기한은 prepared JSON에서 고정하며 재실행에서 자동 최신화하지 않는다. Proof는 기존 형식에서 Edit=freeze plan 지문, Transfer=`{Kind:"freeze"}`를 사용한다. 사용자 서명/현재 ManageRegistry·publish-build-draft operation ceiling·등록 context/policy/root/owner·quorum을 확인한다. 짧은 transport proof의 갱신은 같은 freeze plan의 재조회를 허용할 뿐 snapshot이나 기한을 바꾸지 않는다.

최초 생성은 정확히 선택한 mutable revision/지문을 확인한다. 준비 완료 archive는 이후 편집이 진행돼도 그 원 snapshot을 유지한다. 완전한 원 파일은 ZIP/tree로 원 plan 지문을 재구성하여 중단 뒤 확인하며 부분 파일을 truncate/rebuild하거나 새 ID로 대체하지 않는다. native 원 inode를 rename-no-replace로 같은 Spool에 인계하고 원 source/destination 디렉터리를 fsync한다. 중간 인계는 기록된 원 inode·내용 지문만 채택하며 외부 destination을 덮지 않는다. source 파일이 없다는 이유로 새 archive를 만들지 않는다.

Frozen은 `{Schema:1,Plan,Scope:UploadScope,Fact:SealReceipt,Signature:base64}`다. Scope에는 실제 ZIP 길이/지문과 원 creator·context/policy revision·Root/기한이 들어간다. Fact와 Frozen을 원 node key가 서명한다. 노드 서명은 실제 저장 증거이며 관리 변경의 사용자 승인을 대체하지 않는다.

관리 action `publish-build-draft`의 payload는 `{Tenant,Context,Frozen}`이고 Expected는 freeze plan의 원 draft Revision이다. 원 creator의 기존 signed User operation·현재 권한·현재 context/policy/root·기한·저장 예산을 확인한다. 같은 FSM 변경으로 다음 context version 번호, closed artifact record, immutable version을 확정한다. 원 archive ID를 재사용하지 않으며 bytes/가짜 part 영수증·slot을 Raft에 넣지 않는다. 소비된 archive와 같은 버전 조회·build version 참조·reader pin·명시 삭제 후 owner GC/RootManager 반환 경계를 사용한다. 기존 build-uploads 조회는 원 archive metadata도 포함하며 생성한 context의 Kind로 구분한다.

```sh
mydc build draft freeze editable --id save-editable-one
mydc build context versions editable
```



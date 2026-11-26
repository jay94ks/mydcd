## Git 자동 관측

Git.Automatic=true인 컨텍스트는 담당 노드의 mydcd가 Git ref를 주기적으로 확인한다. 기본 재확인 간격은 해당 확인 종료 후 약 1분이며 같은 daemon에서는 자동 source 확인을 하나씩 처리한다. 수동 source 확인과 같은 Git 전송·경로/크기·Dockerfile/FROM 신뢰 검사와 node-local credential profile을 사용한다. 별도 Git listener·프로세스·호스트 자격 저장소를 만들지 않는다.

원 put-build-context 사용자 승인이 자동 관측의 근거다. 이미 수락한 정책은 로그인 세션 만료와 구분하며 현재 계정/credential·operation ceiling·ManageRegistry·node 업무 허가·등록 root/tenant ACL을 확인한다. context/policy/epoch가 fetch 중 바뀌면 그 결과를 새 정의에 붙이지 않는다. 계정/권한 철회·Automatic 해제는 새 관측을 중단한다. source 검사는 등록 root에 archive나 새 pin을 만들지 않는다.

기존 image-builds Part=contexts의 GitObservation은 선택 필드다. 값은 `{Revision,At,ContextRevision,PolicyRevision,Epoch,Code,Commit,Tree:[32],Entries,BaseSources,ExpandedBytes}`다. Code는 수동 source 확인과 같은 OK/SOURCE_FETCH/UNTRUSTED_BASE/INVALID_CONTEXT이며 실패에는 commit/tree/개수·파일 본문/외부 오류 body/credential을 넣지 않는다. Code=OK인 관측도 archive 게시·빌드 수락·이미지 push 성공을 뜻하지 않는다.

같은 정의·policy/epoch·결과는 공유 상태에 다시 기록하지 않는다. 따라서 At는 마지막으로 다른 결과가 저장된 Unix seconds이며, 마지막 연결 확인 시각이나 현재 Git 접근 가능성 보증이 아니다. 새 컨텍스트 정의는 기존 관측을 비우지만 보존 version/job·편집 데이터 수명은 초기화하지 않는다. 정책만 바뀌면 이전 관측의 PolicyRevision을 보존하고 다음 관측에서 현재 정책을 확인한다.

내부 member Management image-build-git-observation-report의 입력은 `{Schema:1,Kind:"git-observation",Cluster:[32],Owner:[32],Definition:[32],Tenant,Expected,RootRevision,Epoch,At,Result:ImageBuildSourceResult,Signature:base64}`다. Definition은 원 수락 put-build-context의 OperationBytes SHA-256이다. Owner는 `mydc-imagebuild-git-observation-1\0`과 Signature=null인 표준 JSON의 연결을 Ed25519로 서명한다. Expected는 이전 관측 Revision(최초0), RootRevision은 기존 ImageBuildKey의 전역 CAS다. 설치된 정확한 owner와 원 사용자 승인을 함께 검사하고 현재 epoch·context/policy revision·결과 shape·시각을 확인한 뒤 기존 ModuleReport/Raft로 저장한다. Unix 사용자 메시지로 노드 관측을 직접 입력하거나 새 User operation을 합성하지 않는다.

자동 관측 뒤의 보관/제출은 다음 절을 따른다. 관측·수동 source 확인·자동 제출의 실제 인증/Git/MYDCP 경로와 거부·종료는 RQ6 마지막 검증에 포함한다.



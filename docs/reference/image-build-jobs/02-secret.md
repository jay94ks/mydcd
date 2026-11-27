## 빌드 Secret 승인과 공급

Context.Secrets의 항목은 `{ID,Realm,Secret,Key}`다. Realm이 빈 문자열이면 기존 클러스터
Vault의 tenant ACL을 검사한다. Secret이 있는 빌드는 ManageRegistry와 별도로 현재 Deploy
권한이 필요하다. Plan.Uses는 realm별 `[]secrets.Use`이며 Purpose는 `image-build`, 서명하는
Target.Actions는 `["resolve","build"]`다. App/Deployment 필드는 빌드 전용 승인 namespace와
원 job ID이며 실제 앱이나 Task를 생성하지 않는다. 앱 mount·외부 registry 승인을 재사용하지 않는다.

```sh
sfcli build run source --id build-one
```

기존 Group 승인 경로를 사용하며 비밀번호는 원 operation·공유 상태에 넣지 않는다. 값은
이미 게시된 정확한 Secret/provider reference에서 읽는다. 동일 Secret의 여러 키는 한 번
읽고 선언한 ID의 `/input/secrets/ID`로만 공급한다. 빈 값은 허용하며 공개 ARG·컨텍스트 파일과
합치지 않는다. 수락된 job과 Vault usage를 같은 FSM 변경에서 예약한다. 원 operation을 먼저 서명·보관한 뒤
Group 승인을 완료하므로 승인 시각이 원 operation.At보다 뒤일 수 있다. 최초 usage 예약과
입력 read-set 검사에는 원 operation 시각을 하한으로, 현재 Vault에 이미 commit된 해당
purpose·요청자·job·Group의 서명 ApprovedAt만 사용해 모든 realm/중첩 Group이 함께 유효한
하나의 결정적 시각을 구한다. 뒤 승인 시각에 앞 승인 MaxApprovalAge가 지났으면 거부한다.
승인 대기로 원 operation/ID/서명·plan At·Spec을 바꾸거나 벽시계/임의 미래 값을 FSM에 넣지 않는다.
새 저장 필드를 추가하지 않으며 schema1의 기존 승인 원문·job JSON 형식을 유지한다.
수락 후 읽기는 원 Grant.Pins를 유지하고 실제 요청 시각으로 현재 권한·철회·최대 나이를
다시 검사한다. 새 matching 승인으로 기존 usage를 바꾸지 않는다. 취소·현재 권한 회수는
새 읽기를 막지만 원 usage를 반환하지 않는다. 실제 종료·Secret 파일 정리와 provider I/O join
후 owner의 `UseGone` 증거를 terminal 보고와 함께 확정해야 반환한다. 값과 matcher는
관리 JSON으로 직렬화하지 않으며, 원문은 TAR writer join 뒤 지우고 로그 matcher는 스트림
종료 뒤 폐기한다. 실제 worker·빌드/push와 수명 연결의 최종 검증은 아직 진행 전이다.

member `image-build-secret-inputs` 입력은 `{Selection:{Tenant,Job,Snapshot:[32]},At}`,
응답은 `{Selection,Inputs:{ReadSet:[32],Entries:[{Realm,Leaf,Provider}]},Index,Epoch}`다.
현재 설치 owner·running job·현재 권한/승인을 검사한다. 값 읽기는 기존 SecretFetch의
`AppInputFetch.ImageBuild:{Tenant,Job,Snapshot}`와 같은 ReadSet/MinimumIndex로 묶는다.
Task/Move/ExternalRegistry selector를 혼합하면 거부하며, 이 metadata 응답은 Secret 값이 아니다.


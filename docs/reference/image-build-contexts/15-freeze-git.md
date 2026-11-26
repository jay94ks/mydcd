## 과거 freeze·Git 보관 결과 조회

원 creator는 다음 명령으로 원 plan을 그대로 지정해 보관 결과를 조회한다. 현재 계정의
ManageRegistry와 각각 publish-build-draft/publish-build-git operation ceiling·node/tenant
권한을 확인한다. context/policy 변경·삭제 후에도 같은 root와 현재보다 앞서지 않는 원
revision/데이터 계보를 검사한다. root 배치 가능성·pin·Git fetcher/credential은 요구하지 않는다.

```sh
# CLI에는 따로 결과 조회 명령이 없다. 게시 작업은 작업 ID로 확인한다.
mydc op show save-editable-one
```

| 경로 | 요청 | 완료 응답 |
|---|---|---|
| User build-draft | Kind=freeze-result, 원 Scope/Freeze, Proof.Transfer={Kind:freeze-result} | 기존 DraftResponse의 FROZEN/Frozen, optional Reclaimed |
| User save-build-git | 원 Plan, Result=true와 Proof.Result=true | 기존 GitSaveResponse의 SAVED/Saved, optional Reclaimed |

freeze-result의 proof는 원 plan 지문을 Edit에 넣고 기존 Scope 지문/120초 서명 규격을
사용한다. Git proof는 기존 GitSaveProof에 optional Result=true를 포함한 signing bytes를
서명한다. Request와 Proof의 Result가 같아야 하며 false는 모두 생략하므로 기존 저장
요청/서명 바이트는 유지한다. 원 plan의 기한이 지나도 현재 조회 proof만 갱신할 수 있다.
creator·ID·commit/tree·Scope·revision·원 plan의 기한을 변경하거나 저장/게시 승인을
연장하지 않는다. result proof를 freeze/save에 재사용할 수 없다.

원 native seal이 DB에 기록된 경우에만 같은 owner의 결정적인 원 signing bytes로
Frozen/Saved 증거를 복원한다. ZIP을 다시 읽거나 fetch·파일/새 pin 생성·inode 인계·seal
저장·원 결과 변경을 하지 않는다. 준비 Scope/부분 intent만 있으면 PENDING, native 폐기
의도가 있으면 DISCARDED, 원 기록이 없으면 NOT_INITIALIZED다. 이 상태들은 완료 증거를
포함하지 않으며 기록 부재를 미실행/자동 재제출 허가로 해석하지 않는다.

Reclaimed=true는 기존 내구 tombstone으로 archive 본문 삭제가 확인된 완료 결과에만
표시한다. 이 필드가 없거나 false여도 현재 본문의 가용성을 보장하지 않는다. 파일 부재나
접속 실패만으로 이 값을 만들지 않는다. 과거 완료 결과를 현재 게시/빌드 성공으로 취급하지
않으며 새 게시에는 기존 creator 승인·현재 기한/CAS/참조 계약을 그대로 적용한다.

두 CLI는 원 결과 JSON만 출력하고 게시용 ChangeDocument를 만들지 않는다. FROZEN/SAVED는
종료 코드0, 나머지 위 상태는 출력 후3이다. 현재 권한·서명/전송 오류는 오류로 반환한다.
이 연결은 RQ6 마지막 실행 검증 전이다.


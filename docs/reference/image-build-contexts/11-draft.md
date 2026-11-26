## draft 파일 조각 전송

같은 `build-draft`의 Kind=`file-part`, `file-status`, `file-seal`과 optional `DraftResponse.File`을 사용한다. 새 socket/transport·Raft body 복제·DB를 만들지 않는다. 한 파일은500,000,000 bytes 이하이고 각 조각은24,576 bytes, 마지막은 잔여 길이다. 빈 파일은 기존 inline edit로 처리한다. 이 경로도 RQ6 마지막 실행 검증 전이며 freeze→보존 version 게시를 뜻하지 않는다.

| Kind | 요청의 추가 필드 | 응답과 효과 |
|---|---|---|
| `file-part` | 원 Scope, put Edit, `Data`, 사용자 Proof.Transfer | `Code:STAGED`, File.Part·Received/Parts·Complete. 순서와 무관하게 원 offset에 저장. draft revision은 변경하지 않음 |
| `file-status` | 원 Scope, put Edit, Offset(기본0). Proof/Data 없음 | `Code:STAGED`, 최대256개 Missing과 Next. native 원 intent가 없으면 NOT_INITIALIZED. 원 Edit ID/CAS를 바꿔 조회하지 않음 |
| `file-seal` | 원 Scope, put Edit, 사용자 Proof.Transfer. Data 없음 | 전체 파일 길이/지문/fsync 완료를 확인한 뒤 같은 Edit 코어에서 원 Expected CAS로 등록. 성공은 기존 Code:OK·EditResult. 미완료는 PENDING |

`Proof.Transfer`는 file-part일 때 `{Kind:"file-part",Part:{Index,Length,Digest:[32]}}`, seal일 때 `{Kind:"file-seal"}`이다. 같은 원 user signature가 이 필드까지 서명한다. index/조각 지문/길이 또는 part→seal로 바꾸면 서명이 유효하지 않다. 기존 inline proof의 Transfer는 생략되며 서명 바이트를 변경하지 않는다.

`DraftFileProgress`는 `{Edit:[32],Parts,Received,Offset,Next,Complete,Part?,Missing?}`다. Complete는 전체 원 파일의 검증 완료이며 draft metadata 등록 완료와 다르다. 모든 slot을 받았어도 전체 지문이 틀리면 Complete=false다. 마지막 slot fsync 뒤 complete 기록 전 중단은 seal에서 같은 inode를 읽어 복구한다. 기존 intent에 묶인 조각은 같은 bytes만 수락하고 다른 bytes/ID 재사용·다른 inode·목록 부재에 따른 새 파일 채택을 거부한다. pending 조각의 복구는 원 slot 지문과 일치하는 bytes에 한하며 receipt가 확인된 slot을 덮지 않는다.

최초 file intent는 원 draft CAS/경로/예산을 확인한다. 그 뒤 수락된 원 파일 bytes의 staging과 metadata 확정을 구분한다. 다른 편집으로 draft revision이 바뀌어도 seal은 원 Expected를 다시 검사하며 새 revision으로 자동 변경하지 않는다. 정리 전에는 원 bytes의 staging을 계속할 수 있지만, 확정 불가능한 편집의 미사용 본문을 owner가 회수하면 해당 원 edit는 폐기 상태로 남고 file-part/status/seal은 충돌을 반환한다. 원 ID·내용 지문·입력과 이미 완료된 edit의 원 결과는 보존한다. 모든 조각마다 전체 draft tree를 다시 직렬화하지 않고 작은 고정 slot만 갱신한다. 각 요청의 현재 사용자/operation ceiling·scope·owner/quorum 검사는 계속 수행한다.

```sh
# 큰 파일은 조각으로 보낸다. 끊기면 같은 --id로 다시 실행해 남은 조각만 보낸다.
mydc build draft put editable data/payload.bin ./payload.bin --id put-payload
```



## 원장 교체 (rotate-ledger, 시스템 관리자)

`POST /ledger/rotate {opId, expected}` → `rotate-ledger`(`control.LedgerWindow{NextEpoch: expected+1}`, Expected = `expected`). `expected`는 `GET /nodes`의 `ledgerEpoch`이다. 응답은 `{op}`이고 같은 `opId` 규칙은 위와 같다. 원장 root(StorageKey)에 거는 ModuleWindow 명령이라 데몬이 root revision으로 `LedgerRootRevision`을 쓴다(일반 `POST /ops`로 `rotate-ledger`를 보내도 `rootRevision`을 비우면 같게 고른다). `expected`가 0이면 422.

mydcd는 진행 중인 작업이 없을 때(storageQuiescent: 망 바꾸기, 수명 주기 검사, 등록소 작업 등)만 적용한다. 그 밖에는, 그리고 세대가 이미 바뀐 경우에도 op가 `failed`(결과 코드 condition-failed)이고 이유를 따로 알려 주지 않는다. 화면은 실패 뒤 `GET /nodes`를 다시 읽어 `ledgerEpoch`이 아직 `expected`이면 "진행 중인 작업이 있어 지금은 못 바꿈", 이미 올라갔으면 "다른 사람이 먼저 바꿈"으로 안내한다.


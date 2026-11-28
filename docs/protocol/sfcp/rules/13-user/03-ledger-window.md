### 사용자 ledger window

D5.03의 부분14시험은 schema1 Command kind4(ModuleWindow)의 명시 `rotate-ledger`를 같은 User 목적에서 처리한다. operation 서명에 원 epoch·control/storage root CAS·Change.Expected/NextEpoch를 포함하며 현재 system admin만 전환한다. whoami와 members의 optional ModuleEpoch는 epoch가2 이상일 때만 보내고, whoami의 LedgerRootRevision은 storage root CAS다. client Prepare는 이 확정 입력을 새 의도에만 사용하며 보관된 원 operation을 재서명하지 않는다. node membership report도 현재 module epoch를 서명한다.

만료된 원 operation의 result/resume/submit은 Code=expired, Found=false, Result 생략이다. 원 업무의 거부/미실행 결과가 아니며 로컬 Pending을 정산하지 않는다. 마지막 성공 전환만 정확한 원 digest/result로 조회할 수 있고 다음 명시 전환 때 만료된다. 실패 결과를 보존할 공간이 없으면 Code=ledger-full과 Result/Found 생략으로 응답한다. 미정산 공유 작업 또는 미검토 namespace가 있으면 전환을 거부한다. schema 번호와 issuer epoch는1을 유지한다.



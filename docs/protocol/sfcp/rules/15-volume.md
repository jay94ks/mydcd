## Volume 사용량 조회

User typed method `volume-usage`의 `Params:{Tenant,Volume:{App,ID}}`는 논리 App/ID이고 원 envelope 서명에 결합한다. 모르는 필드(native/path selector·After 포함)와 빈 Tenant를 거부한다. 현재 quorum/session/tenant Read에서 정확한 등록 NativeReady를 선택하고 owner 관측 뒤 다시 최신 quorum/current issuer·현재 user 권한·원 NativeReady 일치를 검사한다. `Data.Usage`는 schema1 Scope/Owner/물리 Generation·유한 계수/공유 filesystem 용량·QuotaMode=observe/Snapshot=false만 담는다. `Data.Index`는 마지막 권한 확인 view의 command index이며 파일 일관성 시점/내구 쓰기 완료가 아니다. `Data.RootRevision`은 같은 최종 view의 Volume 관리 CAS다.

원격 관측은 기존 SFCP Management를 사용한다. `volume-usage-observe`는 current member/read만 원 node에 Latest=false로 호출할 수 있고 Command/Key를 받지 않는다. native owner는 signed NativeReady와 자신을 대조하고 `volume-usage-permit`의 Latest=true/quorum/current member 경로로 앞뒤 허가를 받는다. permit은 원 caller key=확정 native owner와 동일 등록 materialization을 검사하고 source command index만 반환한다. node-local 응답의 Local/index를 권위 근거로 사용하지 않는다. 사용자에게 결과를 게시하는 control의 마지막 권한 검사와 별개이며 raw member 조회가 user 인증을 대체하지 않는다. native host path/새 TCP/RPC·합의 계층·별도 wire 번호는 추가하지 않는다.

node별 관측은 동시1개·100,000 entry·깊이64·원 요청 context 기한을 사용한다. field/body/stream 한도와 peer admission은 기존 Management/User 계약이다. 사용량은 읽기 전용이며 writer Start 허가·pin 반환·일관된 backup·물리 quota를 만들지 않는다. actual owner 관측이 없으면 cached/default0 응답으로 fallback하지 않는다.


## 관리 명령과 결과

전역 옵션은 명령 앞에 둔다. `--peer ID`는 지정 peer, 생략하면 설정 첫 peer 하나를 사용한다. 실패 시 다음 peer로 자동 재전송하지 않는다. 조회는 기본 최신/과반수 barrier이며 `--local`은 해당 노드의 로컬 committed view다. 출력은 JSON이며 바이너리 Value는 base64다.

```sh
build/mydc --config CLIENT.yaml status
build/mydc --config CLIENT.yaml --local get network/example
build/mydc --config CLIENT.yaml command --request request-1 --epoch 1 --expected 0 set network/example spec.json > request.bin
build/mydc --config CLIENT.yaml submit request.bin
build/mydc --config CLIENT.yaml result request.bin
```

`command`는 설정의 신원으로 정규 명령 파일만 생성하며 전송하지 않는다. action은 `set KEY VALUEFILE`, `delete KEY`, `grant PUBLIC_KEY`, `rotate PUBLIC_KEY`다. grant는 `--rights`의 network=1/workload=2/ingress=4/admin=8 비트, expected는 객체/정책 CAS revision이다. 요청 ID는 명시하며 actor당 ledger가 차면 관리자가 epoch을 전환한다. 모듈 spec의 문법/의미는 각 모듈 계약을 따른다.

submit/result는 같은 원 명령 파일과 호출자를 사용한다. 원 호출자의 서명·cluster·nonce·digest를 검증하며 follower는 원 증거를 유지해 리더로 한 번만 전달한다. 전달 권한으로 호출자의 쓰기 권한을 대체하지 않는다. 리더가 바뀌면 두 번째 전달을 하지 않는다. 송신 이후 단절/timeout은 불명이며 자동 재전송하지 않는다. result의 미보존/epoch 만료는 과거 미실행을 뜻하지 않는다.

`observe KEY`는 지정 peer의 로컬 관측이며 최신 barrier나 서비스 변경을 수행하지 않는다. node 키는 그 peer에 저장된 인증 보고, Bridge/task/TUN/Ingress는 원 소유 노드의 native/journal 상태를 반환한다. Ingress 관측은 실제 listener/health·요청 수·Drain/Gone을 포함한다. journal은 큰 spec을 반복 전송하지 않고 세대·digest·원 Pending·참조 수를 요약한다. Drain의 실제 native/참조 부재를 확인한 원 노드는 `Data.Retirement`에 서명된 정규 spec을 반환한다. 이를 일반 `command --expected DRAIN_REV set ...`와 `submit`으로 커밋한 뒤 삭제한다.

`plan FILE`은 [PlacementInput](../../../internal/workload/report.go)의 schema=1 정규 JSON을 받아 최신 리더에서 읽기 전용 후보를 반환한다. `--local`과 함께 사용하지 않는다. Template의 image/명령/CPU/메모리와 Network를 명시하며 node/Bridge/IP는 조건에 따라 채운다. `Data.Spec`은 후속 `command`/`submit`의 Value다. plan 성공이 IP 예약·컨테이너 실행은 아니며 CAS/확정 정책을 다시 통과해야 한다.

종료 코드는 성공0, 런타임/전송 오류1, 옵션/설정 오류2, 확정된 관리 거부3, submit의 불명4다. 데몬의 내구 적용 실패는 native owner를 중지하고 종료70을 반환한다. 정상 종료는 SIGINT/SIGTERM을 사용한다. daemon의 started 이벤트는 listener 기동이며 선거/복구·모듈 Ready를 뜻하지 않는다.



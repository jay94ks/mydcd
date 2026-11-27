# Engine 경계 시험용 컨테이너 앱

RV5의 사용자 exec 시험도 이 shell-free 이미지에서 수행한다. `--exec-args-fixture`는 이후 argv를 JSON으로 그대로 출력한다. `--exec-io-fixture`는 stdin의 줄을 stdout/stderr로 분리해 echo하고 EOF 뒤 marker/exit0, `exit N` 입력에는 해당0–255 exit, `size`에는 실제 TTY 크기를 반환한다. SIGINT는130으로 종료한다. 이 동작은 이미지 내부 fixture일 뿐 제품 엔진의 명령/경로 특례가 아니다.

`--exec-detach-fixture`는 ready marker 뒤30초간 실제로 살아 있고, `--exec-closed-output-fixture`는 marker/출력 FD 종료 뒤에도30초간 살아 있다. 전자는 연결 종료와 process kill을, 후자는 출력 EOF와 실제 exit를 구분한다. `--exec-burst-fixture`는 유한 약1MiB를 출력해 읽지 않는 client의 backpressure/쓰기 기한을 확인한다. Docker SDK의 정상 컨테이너 종료/제거로 남은 fixture process를 정리하며 별도 reaper나 host kill 로직을 제품에 넣지 않는다.

정적 backend와 Volume 이관 fixture의 컨테이너 내부 코드는 이 디렉터리에서 관리한다. 이미지 조립·실패 주입·원상 복구와 시험 실행은 `tests/` 및 실제 Engine 경계 시험이 담당한다. 제품 엔진은 이 앱의 이름·명령·포트·파일에 의존하지 않는다.

`--exit-code <0..255>`는 명시한 코드로 즉시 종료하는 단발 실행 입력이다. 실제 Docker Start 직후의 빠른 exit와 원 Task/DB 재개를 검증할 때 사용한다. HTTP health 검사인 `--probe`와 구분하며 종료 자체를 writer fence나 Volume 반환으로 간주하지 않는다.

`--shutdown-delay <duration>`는 HTTP backend를 실행하면서 SIGTERM/SIGQUIT 수신 후 명시한 유한 시간(0–1시간)을 기다리고 코드0으로 종료한다. 서비스별 stop signal/grace 안의 느린 종료와 유예 초과 강제 종료 입력에 사용한다. 지연은 이 fixture의 앱 동작이며 Seafield Cluster 엔진에 별도 이미지 특례를 넣지 않는다.

시험 이미지는 현재 소스로 명시 빌드하고 고정 digest를 사용한다. 다른 입력의 과거 이미지/검증 성공을 새 종료 모드의 실행 근거로 재사용하지 않는다. 빌드·실제 컨테이너 검증은 해당 마일스톤의 마지막 검증에서 수행한다.

`--route-serve`는 유한한 cross-tenant 시험 입력이다. TCP33100/33101과 IPv4 UDP53100/53101에서 최대1024바이트를 echo하며 TCP 동시 접속은8개로 제한한다. SIGTERM/SIGINT로 종료하고 컨테이너의 실제 Wait는 fixture가 확인한다. IP 패킷을 전달하거나 Seafield Cluster 권한/flow 정산을 대신하지 않는다.

`--route-probe <tcp|udp> <numeric-address:port> <local-port>`는 실제 컨테이너 소켓에서 원 source port를 고정해 한 번 보내고 같은 응답 bytes를 확인한다. 로컬 port는1024–65535이며 숫자 IPv6 주소는 `[주소]:port` 형식이다. 오류/불일치는 코드1이고 자동 재시도는 하지 않는다. TCP는 성공 뒤 linger0의 명시 RST로 닫으므로 정상 FIN/TIME_WAIT의 근거로 사용하지 않는다. 전체 기한12초·I/O10초의 유한 입력이며 부하 시험이 아니다.

`--route-dns <udp|tcp> <numeric-gateway:53> <zone>`는 고정된 miekg/dns client로 실제 SOA 질의를 한 번 수행한다. 정확한 question/ID·권위 있는 성공 SOA 응답은 코드0, socket timeout만 코드2, 잘못된 입력·거부된 연결·잘못된 응답은 코드1이다. 기한은3초이며 재시도하지 않는다. 각 컨테이너의 자기 gateway 성공을 먼저 확인한 후 다른 tenant의 같은 node gateway timeout을 검사한다. 비정상 DNS 응답이나 서버 부재를 격리 성공으로 간주하지 않는다.

route server는 실제 accept/read에서 `route peer tcp|udp <address:port>`를 stdout에 남긴다. fixture는 작은 tail과 유한 크기로 읽어 목적 컨테이너가 본 원 source IP/port를 대조한다. `--route-probe`의 socket timeout은 코드1과 `route socket timeout:` marker로 식별하며 잘못된 입력/주소 설정/서버 거부를 timeout으로 바꾸지 않는다. 이 로그만으로 native flow/참조 종료를 주장하지 않는다.

`SFC_SERVICE_CALL_FIXTURE=1`은 owned service-call 시험 입력으로 `/call`의 body 길이/SHA-256, `/call-large`의64KiB 초과 응답, `/call-redirect`의302를 제공하고(응답 전에256KiB까지의 요청 본문을 끝까지 소비), 같은 컨테이너의8443에서 HTTPS를 제공한다. TLS leaf는 실제 컨테이너 IP SAN을 포함하며 `tests/servicecallfixture`의 공개 시험 CA만 사용한다. 이 fixture의 고정 CA private seed는 제품 키나 신뢰로 사용할 수 없다. 제품 서비스 호출은 이미지 이름·환경 변수·포트 특례에 의존하지 않는다.

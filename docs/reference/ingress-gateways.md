# 공유 HTTP 게이트웨이와 backend 분배

Ingress는 외부 HTTP/1.1·HTTP/2와 HTTPS 위 HTTP/3를 처리한다. 관리 연결의 SFCP와 구분한다. 노드의 공유 수신 주소는 `sfcd`가 소유하고 앱은 그 이름을 참조한다. 별도 프록시 컨테이너나 앱별 프록시 프로세스를 요구하지 않는다.

## 노드 설정과 앱 선언

초기 파일 설정 뒤에는 시스템 관리자가 [gateway 관리 명령](../cli/ingress.md#운영-중-바꾸기)으로 클러스터의 노드별 설정을 변경할 수 있다. 클러스터 설정이 존재하면 파일보다 우선하며 앱은 이 설정을 생성·삭제하지 않는다.

아래는 노드의 `modules.ingress` 설정 일부다. 주소는 해당 노드에 실제 존재해야 한다. `addresses`와 `ports`는 허용 목록이며 `listeners`가 실제 수신 주소를 정한다.

```yaml
gateways:
  external:
    enabled: true
    addresses: [203.0.113.10]
    ports: [443]
    listeners:
      - id: public-https
        address: 203.0.113.10:443
        tls: true
        http3: true
  local:
    enabled: true
    addresses: [10.0.0.11]
    ports: [443]
    allowed_sources: [10.0.0.0/8]
    listeners:
      - id: internal-https
        address: 10.0.0.11:443
        tls: true
```

공유 수신 주소에는 `0.0.0.0`·`::`를 사용할 수 없으며 external/local 주소 목록은 겹칠 수 없다. `local.allowed_sources`를 생략하면 RFC1918, IPv6 ULA와 설정된 클러스터 노드 주소를 허용한다. 출발지 제한은 TCP accept와 UDP 수신에서 TLS·HTTP 처리 전에 적용한다. HTTP/3에도 같은 출발지 제한을 적용한다.

앱의 예시는 다음과 같다. `services`의 일반 컨테이너 선언과 이름 기반 네트워크 참조는 기존 app.yaml 계약을 따른다.

```yaml
x-sfc:
  ingress:
    node: node-a
    listeners:
      - shared: public-https
      - shared: internal-https
    routes:
      - id: web
        host: shop.example.com
        prefix: /
        service: web
        network: app
        port: 8080
        health_path: /ready
        gateway: both
      - id: admin
        host: shop.example.com
        prefix: /admin
        service: admin
        network: app
        port: 8081
        health_path: /ready
        gateway: local
```

위 예시는 `routes` 부분을 설명한다. 실제 배포에는 기존 `ingress.runtime`의 요청·연결·header/body/buffer·시간 예산을 함께 지정해야 한다. `host`와 `backend`의 기존 단일 규칙 형식도 유지한다. 명시 `routes`와 단일 `host` 형식을 혼합하면 오류다. 경로의 `gateway` 기본값은 local이다. port/network/health_path/balance는 ingress 기본값을 상속할 수 있다. 규칙에는 인증서 이름이 없다.

호스트 사용 권한은 시스템 관리자가 tenant별로 등록한다. external 노출은 기본 비허용이며 local 호스트도 명시 배정이 필요하다. [host 정책과 관리 명령](ingress-management.md)을 참고한다. 동일 노드·공유 수신 주소·게이트웨이의 같은 host+prefix를 두 앱에 배정할 수 없다. 공유 주소의 `*` 규칙은 시스템 관리자만 만든다. 앱 종료는 다른 앱의 규칙이나 공유 소켓을 제거하지 않는다.

## 경로·인증서 선택

요청은 정확한 host, 긴 접미사의 `*.` 패턴, `*` 순으로 고르고 같은 host에서는 긴 prefix를 우선한다. `/admin` 규칙을 차단해도 더 짧은 `/`로 우회하지 않는다. external과 local의 규칙 표는 분리한다. 공유 주소의 TLS는 SNI로 호스트를 고르고 HTTP는 Host로 고른다. 둘이 다른 tenant를 가리키면 421이다. 맞는 호스트가 없으면 평문은404, 공유 TLS는 handshake 거부다.

`tls: true`인 수신 주소는 TLS 연결마다 SNI 호스트로 보관함의 인증서를 고른다(정확한 호스트, 없으면 한 단계 `*.` 인증서). 수신 주소·규칙에 인증서 이름은 없고, 노드 파일에도 인증서 설정이 없다. SNI가 없거나 그 호스트의 인증서가 없으면 handshake를 거부한다. 같은 호스트에 키 알고리즘이 다른 인증서가 있으면 클라이언트가 받는 서명 방식에 맞춰 ECDSA를 먼저 고른다. HTTP/3는 `tls: true`일 때만 켤 수 있다. 인증서는 메모리에서 주기적으로 재확인하며 새 쌍의 검증·복호화가 실패하면 이전의 아직 유효한 쌍을 유지한다. 현재 quorum 조회에서 선택 부재·삭제·소비 권한 회수가 확인되면 만료 전이라도 기존 쌍을 제거하고 새 handshake를 거부한다. 현재 권한과 인증서 ID·공개 receipt digest가 같으면 이미 검증한 메모리 쌍을 재사용하여 반복 복호화를 피한다. 만료한 쌍은 새 handshake에 사용하지 않고 private key 참조를 회수한다. 이미 연결된 TLS 세션을 인증서 교체 때문에 끊지 않는다. 공개 관측에는 호스트·인증서 ID·만료·실패 코드만 포함한다. 보호 입력·연결 규칙은 [인증서 보관함](certificate-store.md)을 따른다.

## 인증서 자동화 경로

평문 HTTP 요청의 경로가 `/.well-known/acme-challenge/`로 시작하고 호스트가 등록된 도메인(`sfcli domain`) 안에 있으며 이 ingress가 그 호스트를 맡으면, 앱 규칙보다 먼저 클러스터의 ACME 응답기([`sfcli domain acme-responder`](../cli/domain.md#acme-http-01-응답기))로 HTTP/1.1로 넘긴다. Host 헤더와 경로는 바꾸지 않는다. GET·HEAD만 넘기고 다른 메서드와 응답기가 없을 때는 404다. 응답은 4KiB까지, 응답 헤더는 5초, 전체는 10초 안에 끝나야 한다. 연결할 수 없으면 502다. TLS(HTTPS·HTTP/3) 요청과 등록되지 않은 호스트의 요청은 앱 규칙을 그대로 따른다. 관측의 route는 `acme-challenge`다. 앱 경로를 고르지 않으므로 긴급 차단은 경로가 필요 없는 범위(서버·게이트웨이·작업 공간·인스턴스·호스트·출발지)만 맞춰 보고 맞으면 차단 응답을 준다. route·backend 범위 차단은 이 경로에 닿지 않는다. 요청 헤더 크기 제한(`MaxHeaderBytes`)도 앱 요청과 같이 적용한다.

앱의 규칙이 이 경로나 그 아래(`/.well-known/acme-challenge`, `/.well-known/acme-challenge/x`)를 쓰면 배포는 거절하지 않고 `app diff`·`app deploy`가 "등록된 도메인 호스트의 평문 HTTP에서는 무시된다"는 경고를 낸다(`AppDiff.IgnoredAutomationRoutes`). `/`, `/.well-known` 같은 상위 규칙은 경고 없이 받고, 자동화 경로만 응답기로 간다.

## 분배 정책

`routes[].balance`와 단일 ingress의 `balance`는 다음 정책을 받는다.

```yaml
balance:
  method: hash
  key: cookie:session
  locality: same-node
  warmup: 30s
  retry: 1
  weights:
    stable: 4
    canary: 1
  groups:
    stable:
      labels: {release: stable}
    canary:
      labels: {release: canary}
  match:
    - id: explicit-canary
      group: canary
      headers:
        X-Canary: {equal: "1"}
    - id: sampled-canary
      group: canary
      percent: 10
      key: cookie:session
  fallback: default
```

방식은 기본 smooth weighted `round-robin`, 활성 요청수/가중치의 `least-request`, weighted rendezvous `hash`, 가중 `random`이다. hash 키는 source-ip·cookie:name·header:name이고 키가 없으면 순환한다. `same-node`는 현재 노드의 사용 가능한 backend를 먼저 고른다. health 실패·drain·정원 도달 backend는 후보에서 빠진다. `warmup`은 시간(`30s`, 최대 `1h`)이며 backend가 새로 healthy가 된 뒤 비중을 점진적으로 높인다.

그룹은 labels·version·명시 backend ID로 정의한다. 조건은 위에서부터 처음 맞는 하나만 적용한다. header/cookie/query의 equal·prefix·present, methods, source CIDR, percent를 조합할 수 있다. 비율은 같은 키에 같은 결과를 주며 percent 합계100 초과·없는 그룹·잘못된 이름은 거부한다. 그룹이 비면 default는 전체 후보로,503은 실패로 끝낸다. weight 범위는1~1024다.

retry는 body 없는 GET/HEAD의 backend 연결 수립 실패에만 적용한다. 새 backend로 시도하기 전에 기존 backend lease를 내구 정산하며 응답을 시작했거나 본문을 전송한 요청을 재전송하지 않는다. 실행 중 요청은 선택 당시의 원 backend lease를 유지한다. 같은 물리 listener·owner·노드·backend 참조의 host/prefix/분배 정책 변경은 규칙을 교체하며 컨테이너를 재생성하지 않는다. listener 주소·TLS/HTTP3·backend 참조 변경은 이 좁은 갱신 경계에 포함하지 않는다.

기존 앱별 주소에서 같은 포트의 shared 수신 주소로 옮길 때는 단일 원 listener의 실제 socket/server 소유를 확인한다. 같은 앱·노드·owner·backend 참조와 generation을 유지하고 node 설정의 주소·TLS certificate ref·HTTP3가 정확히 같아야 한다. 이 경우 socket을 재bind하지 않고 HTTP handler와 새 TLS/QUIC handshake의 delegate를 공유 routing snapshot으로 넘긴다. 이미 실행 중인 요청은 원 backend lease로 마무리한다. 정적 TLS ref를 썼다면 전환할 앱의 규칙에도 같은 certificate ref를 명시한다. 다른 앱의 socket·실제 원 socket이 없는 journal·다른 주소/TLS/HTTP3는 인계할 수 없다. 전환 뒤 앱 종료가 다른 앱이 사용하는 공유 server를 닫지 않는다.

## 관측

[Ingress 조회·차단](ingress-management.md)은 실제 listener/route/service/backend와 최근60초 지표를 제공한다. 공유 주소의 unknown-host와 source 거부는 특정 앱에 임의 귀속하지 않고 노드 gateway에 누적한다. 기존 address 수신 주소는 노드의 주소 목록에 따라 external/local/unclassified로 분류하며 unclassified도 기존 방식으로 동작한다.

backend 전체 부재/복귀, 공유 listener 시작/종료, 인증서 missing/만료 임박/만료, 출발지 거부 급증은 기존 이벤트 경로에 전달한다. 웹훅 전송은 웹의 책임이다. 비율·지연 경보는 최근 요청 지표를 소비하는 클라이언트가 계산한다.

고정 컨테이너와 복제본을 같은 Ingress의 서로 다른 서비스로 함께 사용할 수 있다. 복제본을 따르는 동적 backend snapshot에서는 고정 backend도 원 Task revision을 표시한다. 이 값은 관측에 사용한 원본 위치이며, 고정 Task의 정확한 generation/revision 참조를 자동 추적 참조로 바꾸지 않는다. 고정 원본이 바뀌면 새 앱 계획 없이 조용히 따라가지 않는다.

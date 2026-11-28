# 서비스 호출과 Git 연결 검사

두 API는 로그인한 현재 사용자의 tenant 권한으로 실행한다. Unix TLS와 QUIC는 같은 User 메시지를 사용한다. 관리 변경용 operation journal이나 새 배포를 만들지 않는다. 서비스 호출은 외부 앱에 POST하므로 읽기 전용 조회로 취급하지 않는다.

## 논리 서비스에 POST

```sh
sfcli --tenant shop service-call storefront api --port 8080 --path /approve \
  --header Content-Type=application/json --body-file request.json
sfcli --tenant shop service-call storefront api --port 8443 --path /approve --scheme https
```

User Request는 다음 필드를 사용한다. `Schema`는1이며 `Nonce`는 SDK가 매 요청 생성하는 기존 32바이트 nonce다. 아래는 body가 UTF-8 `{}` 두 바이트인 예시다. 표시된 Nonce는 형식 설명용이며 실제 요청마다 새 값을 사용한다.

```json
{"Schema":1,"Method":"service-call","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Params":{"Tenant":"shop","Call":{"App":"storefront","Service":"api","Port":8080,"Path":"/approve","Method":"POST","Headers":{"Content-Type":"application/json"},"TimeoutMS":10000,"Scheme":"http"},"Input":{"Length":2,"Digest":[68,19,111,163,85,179,103,138,17,70,173,22,247,232,100,158,148,251,79,194,31,231,126,131,16,192,96,246,28,170,255,138]}}}
```

typed method다(`Params: ServiceCallQuery`, 응답은 `Data`). `Nonce`와 `Input.Digest`는 Go `[32]byte`의 32개 숫자 배열이며 hex/base64 문자열이 아니다. `Input.Digest`는 원 body의 SHA-256이고, frame tag2의 Envelope SHA-256과 구분한다. `Call.Body`를 JSON에 넣지 않는다. 최대256KiB body는 기존 User kind4의 순차 입력으로 보내며, 서버는 길이·digest·EOF를 모두 확인한 뒤에만 POST한다. 빈 body도 SHA-256(empty)와 EOF가 필요하다. SDK `Client.CallService(ctx, peer, session, tenant, servicecall.Request)`에는 `Body []byte`를 전달한다.

서버는 현재 앱 Binding·원 Task 세대/리비전·fresh Healthy 관측과 설치된 owner를 확인한다. 같은 서버의 후보를 우선하고 이후 노드/Task 이름순으로 선택한다. 실행 owner는 현재 quorum의 권한/원 Task를 재검사하고 실제 Docker native 신원·IP·process 상태를 확인하며 원 Task read lease를 I/O 종료까지 보유한다. 사용자에게 IP·host·proxy·redirect 대상·Task/native를 입력받지 않는다. 현재 단일 네트워크와 주소가 확정된 Task의 원 IP로 한 번 연결한다. 포트는 그 컨테이너의 TCP 포트이며 호스트 published port나 Ingress gateway를 선택하는 입력이 아니다.

권한은 tenant manager 또는 시스템 관리자의 현재 `call-service`다. Session의 명시 action scope와 credential의 허용 operation `service-call`도 함께 적용한다. `deploy`나 `read`만 있는 Session에는 허용하지 않는다. 노드 키 자체는 사용자 승인을 대신하지 않는다.

| 입력 | 범위 |
|---|---|
| `App`, `Service` | 현재 tenant의 앱/서비스 이름 |
| `Port` |1–65535, 선택 Task의 컨테이너 포트 |
| `Path` | 단일 `/`로 시작하는 상대 HTTP request URI, 최대4096바이트; 절대 URL/authority 금지 |
| `Method` | `POST` |
| `Headers` | `Content-Type`, `X-SFC-*`만; 최대32개·총8KiB, 중복 대소문자/개행 금지 |
| `Body` | 최대256KiB |
| `TimeoutMS` |0이면10초, 명시1–30000ms |
| `Scheme` | 생략/`http`, 또는 `https` |
| `InsecureSkipVerify` | HTTPS일 때만 명시 선택 가능, 기본 false |

HTTPS는 기본 OS 신뢰와 선택한 tenant의 **설치된 CA bundle**로 실제 Task IP SAN을 검사한다. hostname/Host를 임의 지정하거나 인증서를 자동 신뢰하지 않는다. 담당 노드의 설정 예시는 다음과 같다. CA 파일은 읽기 전용 신뢰 자료이며 private key/사용자 업로드가 아니다. 현재 설치 설정에 따라 daemon 시작 시 읽는다. 관리형 사용자 catalog 노드에서 tenant별 한 묶음, 최대64개를 설정하고 각 파일은 최대1MiB다. 상대 경로는 노드 설정 파일의 디렉터리를 기준으로 해석한다. 이 trust 설정은 Ingress의 [인증서 보관함](certificate-store.md)·`CertificateMaterial`과 독립적이며 사용자 호출이 인증서 항목이나 tenant CA를 생성·갱신하지 않는다.

```yaml
service_cas:
  - tenant: shop
    ca_file: /etc/sfc/shop-service-ca.pem
```

`--insecure-skip-verify`는 해당 HTTPS 한 호출에만 적용되며 저장된 신뢰를 변경하지 않는다. TLS 인증서·handshake 오류와 HTTP 포트에 HTTPS를 사용한 오류는 `SERVICE_CALL_TLS`, TCP 연결 실패는 `SERVICE_CALL_REFUSED`다.

응답 `Reply.Data`(`servicecall.Result`):

```json
{"Status":200,"Headers":{"Content-Type":"application/json"},"Body":"eyJvayI6dHJ1ZX0=","Task":"task/...","Node":"node-a","ElapsedMS":24}
```

Body는 Go `[]byte`의 JSON base64 문자열이다. 응답 body 최대64KiB, header는 `Content-Type` 하나만 반환한다. cookie/인증/header 원문은 반환하지 않는다. 3xx는 그대로 반환하며 따라가지 않는다. 초과 body는 부분 성공으로 반환하지 않는다.

| `Code` | 의미 |
|---|---|
| 생략 | HTTP 응답 수신; 4xx/5xx도 `Status`로 반환 |
| `SERVICE_NO_READY_TASK` | 현재 권한 범위에 실행 가능한 Healthy Task 없음 |
| `SERVICE_CALL_TIMEOUT` | 유한 호출 기한 초과 |
| `SERVICE_CALL_REFUSED` | 연결/응답 읽기 실패 |
| `SERVICE_CALL_TLS` | TLS 검증/handshake 실패 |
| `SERVICE_CALL_TOO_LARGE` | 요청 또는 응답 예산 초과 |
| `RATE_LIMITED` | 노드/tenant의 동시성·분당 admission 제한 |

오류 결과에는 HTTP Status/Headers/Body를 싣지 않는다. 호출 노드의 제한은 동시32개·분당600개, tenant별 분당120개다. 계수는 노드의 메모리 admission 지표이며 별도 Raft operation이나 요청별 보관 기록을 만들지 않는다. 중계 노드와 실행 owner가 각각 admission을 적용할 수 있다.

**timeout·연결 단절·결과 유실은 앱이 POST를 실행하지 않았다는 뜻이 아니다.** SDK/CLI는 자동 재시도·새 operation 생성·다른 Task로 재전송하지 않는다. 앱의 조회/업무 idempotency 정책으로 원 결과를 확인한 뒤 사용자가 다음 동작을 결정한다. daemon 재시작은 종료된 이전 HTTP reader의 해당 owner pin만 반환하며 업무 성공/미실행을 판정하지 않는다.

## read-only Git 연결 검사

```sh
sfcli --tenant shop cd probe storefront --repository https://git.example/team/app.git \
  --branch main --path app.yaml --credential git-read
```

`Client.ProbeCD(ctx, peer, session, tenant, deployment.GitProbeRequest)`는 typed User `cd-probe`를 보낸다.

```json
{"Schema":1,"Method":"cd-probe","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Params":{"Tenant":"shop","Probe":{"App":"storefront","Repository":"https://git.example/team/app.git","Branch":"main","Path":"app.yaml","Credential":"git-read"}}}
```

현재 tenant/app의 `deploy` 권한, **실제 Git provider 노드의 tenant 허용 노드 할당**, 명시 Session/위임 ceiling·credential operation `cd-probe`를 검사한다. 기존 앱이 필요하다. `Credential`은 해당 tenant/정확한 repository에 설치된 **자격 이름**이며 password/token/CA 경로·URL user-info/query를 받지 않는다. 공개 repository는 생략할 수 있다. 기존 CD HTTPS/provider·기한/pack 예산·redirect 금지를 재사용하며 `refs/heads/<Branch>`를 한 번 발견한 고정 commit의 regular file을 읽는다. Branch에는 `main`처럼 짧은 이름을 쓰고 `refs/heads/`는 붙이지 않는다.

응답 `Reply.Data`(deployment.GitProbeResult):

```json
{"Code":"","Commit":"0123456789abcdef0123456789abcdef01234567","Node":"node-a","Size":2048}
```

commit은 실제 발견/수신한 고정 SHA-1, Size는 해당 file의 실제 바이트 수다. 최대4MiB regular/executable file만 검사하며 내용/YAML을 실행·파싱하지 않는다. CD source cache·등록 policy·candidate·overlay·현재 앱/Task를 변경하지 않는다. 30초 기한, 노드 동시4개·분당120개, **안정된 사용자 ID당 분당10개**를 적용하므로 재로그인으로 한도가 초기화되지 않는다.

오류 `Code`는 `auth-failed`, `no-repository`, `no-branch`, `no-file`, `no-credential`, `timeout`, `rate-limited`, `too-large`, `source-error`다. 오류에는 Commit/Size 대신 코드·실행 노드만 반환하며 provider의 원 오류문·자격값을 반환하지 않는다. CLI는 HTTP/Git 응답 성공은0, 공개 서비스/probe 오류 결과는3, 인증/명령 입력 오류는 기존 CLI 종료 규칙을 사용한다.

## 내부 전달과 종료

User service-call은 기존 purpose8(kind1/3 요청, kind2 ready/결과, kind4 입력)을 사용한다. 원 Envelope digest에 request ID·각 입력 offset을 고정한다. relay는 원 Session·Body·사용자 서명을 바꾸지 않고 설치 member의 서명으로 원 caller/challenge·정확 목적 노드·새 연결 challenge와 선택 Task/IP/port/module epoch를 묶는다. target relay는 다른 User method에 허용하지 않는다.

owner의 `service-call-permit`은 기존 member Management 최신 quorum 읽기로 `{Session,Tenant,Request,Target,Epoch}`를 검사한다. 이 내부 Request.Body는 비어 있어야 한다. 응답은 권한 확인 index이며 owner native/HTTP 실행을 대신하지 않는다. 시작 직전과 결과 공개 전에 원 사용자·현재 계정/tenant·원 Binding·현재 Task/epoch를 다시 확인한다. 사용자 Unix 요청으로 이 member 전용 명령을 실행할 수 없다.

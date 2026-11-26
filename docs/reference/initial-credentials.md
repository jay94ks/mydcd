# 새 사용자의 최초 로그인 수단

RQ4 구현 단계이며 마지막 실행 검증 전이다. 시스템 관리자가 기존 계정에 처음 password 또는 일회용 token을 등록한다. CLI 로그인 키의 개인 저장소와 tenant/app Secret Vault는 이 기능의 저장소가 아니다.

## 사용자 경로

1. 기존 `put-user`로 일반 사용자(ID·Username·Enabled)를 만든다. Credentials가 비어 있는 일반 계정은 로그인할 수 없다. 인증 수단 없는 system-admin은 등록할 수 없다.
2. 시스템 관리자가 아래 명령으로 최초 password 또는 token을 발급한다. 대상 계정의 현재 revision과 새 credential ID를 명시한다.
3. 사용자는 기존 password/token 로그인으로 접속하고 본인 공개키를 등록할 수 있다. 현재 정책·scope·본인 키 소유 증명은 유지한다.

```sh
mydc user issue-password new.user --profile system [--node NODE]
mydc user issue-token new.user --profile system --out ./new.user.token [--node NODE]
```

비밀번호는 터미널에서 두 번 묻고, 터미널이 아니면 표준 입력의 첫 줄을 읽는다. 토큰은 `--out`의 새 파일(0600)에만 쓴다. `--node`는 provider가 설치된 서버다(기본: 연결한 서버). `--profile`은 그 서버에 명시 설치된 시스템 provider ID이며 주소·CA·provider token을 클라이언트가 바꾸지 못한다. 명령 사용법은 [mydc user](../cli/user.md)에 있다.

토큰은 **계정 적용의 Applied 결과를 확인한 현재 호출에서만** 파일에 쓴다. 이후 `op show`/`op resume`이나 provider 관측은 원문을 반환하지 않는다. 출력/응답 유실 시 원문 재조회는 불가능하다. 자동 재발급하지 않으며 관리자가 새 명시 계정 변경으로 정리해야 한다.

`disable_node_cli_operation=true`일 때는 기존 독립 등록 사용자 키의 관리 승인 정책을 그대로 적용한다. password/token 로그인만으로 승인 키 없는 사용자가 본인 첫 키 등록 제한을 우회할 수 없다. 이 경우 기존 관리자의 키 등록 경로로 별도 처리한다. password 변경 강제 표시·기존 수단 교체는 이 최초 발급 명령에 포함하지 않는다.

## 저장과 적용

현재 system-admin/ManageCluster와 credential 동작 제한 `issue-initial-credential`의 교집합을 검사한다. AutomationOnly 계정에 password/token을 발급하지 않는다. 같은 방식의 수단이 이미 있으면 비활성 여부와 관계없이 거부한다. 새 수단이 기존 공개키·다른 방식의 수단·tenant 소속·권한을 교체하지 않는다. 대상 계정 CAS가 달라지면 거부한다.

password는 기존 Argon2id 비용(64MiB·2회·1 thread)과 새 무작위 salt로 검증값을 만든다. token은 CSPRNG 32 byte의 base64url 값이며 보호 저장소에는 SHA-256 검증값만 둔다. 최초 token의 로그인 유효 기간은 원 발급 시각부터24시간이며, 현재 계정 권한과 교차 검사하는 기존 로그인 scope를 사용한다. 로그인에 성공한 Session의 수명은 기존 상한과 token 만료 중 짧은 값이다.

고정 설치된 시스템용 Vault KVv2의 `system/credentials/initial/<cluster hex>/<public-intent digest>`에 CAS=0·version1로 저장한다. digest는 아래 공개 InitialRequest만 대상으로 하며 password/token·검증값의 digest가 아니다. Raft에는 owner 서명 공개 write fact와 계정 verifier reference만 적용한다. 보호 입력·검증값·token 원문은 Raft·operation journal·일반 응답·이벤트에 넣지 않는다. 시스템 provider가 없거나 create/read 권한이 없으면 실패하며 tenant provider나 환경 변수·다른 revision으로 fallback하지 않는다.

OneTime=true token은 검증이 통과한 뒤 같은 보호 provider의 원 object 아래 `consumed` marker를 CAS=0으로 생성한다. 서로 다른 issuer·동시 요청·재시작에서도 한 번의 claim만 성공한다. 이 marker는 로그아웃으로 지우지 않는다. claim 응답 유실 또는 후속 quorum 확인 실패로 token이 소비될 수 있으며 자동 복구하지 않는다. 공개 Credential.Enabled는 관리자가 설정한 정책이고 소비 상태를 뜻하지 않는다. 이미 발급된 Session은 기존 계정 revision·수명·회수 규칙으로 검사한다. token 사용을 이유로 계정 revision을 바꾸어 방금 발급한 Session까지 무효화하지 않는다.

## 사용자 세션 메시지

모든 형식의 Schema/Wire/DB 번호는1이다. 아래 private method는 User kind1의 현재 Session·연결 challenge 서명을 요구하고 명시 pin된 owner에만 보낸다. member relay나 leader redirect로 보호 입력을 전달하지 않는다. owner가 follower라도 기존 quorum-backed authentication view를 읽는다.

### InitialRequest (공개 의도)

| 필드 | 형식·의미 |
|---|---|
| Schema | 1 |
| Cluster, Owner | 기존 32 byte 배열, 원 cluster와 설치 provider node public key |
| Operation | CSPRNG로 만든 원 32 byte nonce; private 입력을 해시한 값 금지 |
| User, Username | 대상 계정 ID와 정확한 로그인 이름 |
| Credential, Profile | 새 credential ID와 설치된 시스템 provider ID |
| Method | password 또는 token |
| ExpectedUserRevision | 대상 계정의 현재 revision, 양수 |
| At | 원 발급 요청 시각, Unix seconds |

`initial-credential-stage`는 `{InitialCredential:InitialRequest,Secret?:base64(password bytes)}`를 받는다. password에는 원문1–1024 byte가 필요하고 token에는 Secret을 넣지 않는다. 다른 선택자·Tenant·Node·Operation·Ticket은 허용하지 않는다. 새 private write는 At부터300초 안에만 시작한다. 응답의 `InitialCredentialFact={Request,Signature}`는 owner 서명이며 provider write를 관측했다는 사실만 증명한다. `InitialCredentialToken`은 token의 첫 성공 응답에만 있는 base64(byte[]) 필드다. 소비자는 token 원문을 최종 사용자에게 전달하기 전 아래 공개 계정 적용이 성공했는지 확인하고, 실패/종료 시 memory를 지운다.

`initial-credential-observe`는 동일 InitialRequest만 받고 Secret을 금지한다. 원 version1·공개 receipt·private record의 cluster/user/method/ref binding을 확인해 같은 owner 서명 fact를 돌려준다. token 원문은 반환하지 않는다. 없는 기록·timeout·거부는 미실행 증명이 아니며 `credential-write-unknown`이다. token 만료 뒤에는 새 적용을 허용하지 않는다.

공개 `submit`/`result`/`resume`은 기존 UserOperation의 `Change.Action=issue-initial-credential`, `Change.Expected=ExpectedUserRevision`, `Change.Payload=InitialCredentialFact`와 Catalog root CAS를 사용한다. 시스템 관리자 서명과 현재 권한·대상 CAS·설치 owner key·provider fact 서명을 다시 검사한 뒤 같은 access FSM으로 계정에 reference를 붙인다. fact만으로 노드가 관리 변경을 만들지 못한다. 여기의 Result는 공개 계정 적용 결과이며 private token을 보관하지 않는다.

## 원 기록과 복구

CLI는 Linux user·profile·관리자 계정별 원 operation 디렉터리에 `initial-<request hash>.json`을0600으로 저장한다. Request·Dispatched·owner fact만 있으며 private 입력은 없다. Dispatched를 동기 저장하기 전에는 provider를 호출하지 않는다. 원 파일이 존재하면 새 nonce/계정 revision/owner/profile로 다시 계획하지 않는다. 최대256개의 원 발급 의도를 보존한다.

provider 전송 뒤 불명이면 같은 공개 옵션에 `--observe-original`을 붙인다. private FD는 주지 않는다. 원 fact가 있으면 재사용하고, 없으면 같은 owner의 원 write만 관측한다. 공개 적용 operation을 이미 저장했다면 같은 ID의 result를 먼저 확인한다. `--resume-original`은 저장된 동일 공개 operation에만 사용하고 provider 쓰기를 다시 실행하지 않는다. 원 목표 계정·CAS나 현재 권한이 바뀐 상태를 새 값으로 우회하지 않는다.

현재 시험 코드는 보호 provider의 CAS/응답 유실·one-use 경쟁·재시작·계정 CAS·selector/relay 거부·원 journal을 다룬다. 실제 Vault와 MYDCP/CLI 발급→로그인→본인 키 등록의 수락 검증은 RQ4 마지막 검증으로 남아 있다.

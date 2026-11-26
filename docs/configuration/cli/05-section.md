## 로그인 계정 선택

접속할 곳은 [context](../../cli/context.md)로 고른다. 아래는 아직 새 명령으로 옮기지 않은 login의 설명이다.

login 성공 자격은 wallet에 계정별로 공존한다. 현재 클러스터의 후보가1개면 선택하고2개 이상이면 `--user USER` 없이는 오류다. 최근 로그인이나 context의 user로 고르지 않고, 명시 사용자 부재/만료/거부 뒤 다른 계정으로 넘어가지 않는다. wallet passphrase는 보호 TTY 또는 `--wallet-password-fd FD`로 입력하고 `--no-input`이면 자동 입력을 요구한다. login의 `--user`와 이전 `--username`은 전역 값과 일치해야 한다.

Secret 명령의 클러스터 Vault는 `secret ... --all`로 고른다([Secret 명령](../../cli/secret.md)).

### 로그인 자격과 독립 승인 키

private-key login은 선택한 등록 사용자 키로 정확한 발급 session을 승인한다. password/token 인증은 유지하며, 별도 승인 키가 필요하면 wallet 이름을 명시한다.

```sh
mydc --cluster production login --user alice --method password --approval-key alice-laptop
mydc --cluster production login --user alice --method token --credential robot --token-stdin --approval-key alice-laptop
```

`--approval-key`는 password/token login에서만 사용한다. profile의 기본 키나 wallet의 다른 키를 임의로 고르지 않으며, 생략하면 독립 승인 없는 password/token session이다. 승인 키는 같은 계정의 활성 private-key credential로 서버에 등록돼 있어야 한다. 사용자 키의 승인 증거를 wallet에 session과 함께 보존하고, password/token·사용자 키 원문을 요청에 넣지 않는다. 승인해도 token의 tenant/action/기한 상한은 그대로다. `disable_node_cli_operation=true`인 클러스터에서 새 관리 요청은 이 승인을 필수로 요구한다. password/token만으로 인증한 session도 발급되지만 승인 없는 관리 요청은 거부한다.

managed cluster의 non-voter/격리 노드에서 `not-session-issuer`를 받으면 pin된 활성 control voter에 명시 접속하여 로그인한다. 활성 follower는 leader의 최신 barrier에 해당하는 자기 복제본에서 직접 인증하므로 password/token을 leader로 전달하지 않는다. 이전 issuer가 제외된 session을 과거 발급 시각만으로 계속 허용하지 않는다. 원 accepted 작업·결과는 현재 유효한 동일 계정으로 복구한다.


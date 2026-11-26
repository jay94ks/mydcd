# mydc secret: Secret과 그룹

작업 공간마다 Vault 트리가 하나 있다. 트리는 그룹과 secret으로 이루어진다. secret은 바깥 Vault의 객체 하나를 가리키고, 값은 클러스터의 쓰기 서버가 그 객체에 써 넣는다. 그룹 비밀번호는 그 그룹의 secret을 쓰는 앱을 승인할 때 쓴다.

작업 공간은 `--tenant`가 먼저고, 없으면 지금 context의 작업 공간을 쓴다. `--all`은 클러스터 자체의 트리다(시스템 관리자).

## 보기

| 명령 | 하는 일 |
|---|---|
| `mydc secret list` | 트리의 그룹과 secret |
| `mydc secret show 이름` | 그룹이나 secret 하나 |
| `mydc secret usages 이름` | 이 그룹이나 secret을 쓰는 앱·서비스 |
| `mydc secret write list` | 값·비밀번호 쓰기와 그 상태 |
| `mydc secret approvals [--app 앱]` | 앱이 그룹 비밀번호로 받은 승인 |

어떤 명령도 secret 값이나 비밀번호를 보여 주지 않는다.

## 트리 만들기

```sh
mydc secret init root
mydc secret group create common --parent root
mydc secret create db-password --parent common --profile values --object values/shop/db --key DB_PASSWORD
mydc secret group reorder common db-password other
mydc secret group approval-age common 720h
```

- `init`은 트리와 맨 위 그룹을 만든다. 한 번만 한다.
- `create`는 secret을 만든다. `--object`는 쓰기 서버가 닿는 바깥 Vault의 mount 안 전체 경로다. 쓰기 서버의 node.yaml `vaults` 항목 `prefix`로 시작해야 한다. 위 예는 `prefix: values/shop`, `mount: secret`이고 값은 `secret/data/values/shop/db`에 놓인다. `--key`는 그 안의 값 이름이다(여러 번). 값은 아직 없다. `put`으로 쓴다.
- prefix는 쓰기 서버에만 있으므로 `create`는 이를 검사하지 못한다. prefix 밖의 경로면 `put`이 아무것도 쓰지 않고 `notapplied`로 끝나며, 쓰기 서버 로그에 이유가 남는다. `mydc secret write abandon ID`로 그 쓰기를 끝낸 뒤 경로를 고친 secret을 다시 만든다.
- `group reorder`에는 그룹 안의 모든 항목을 새 순서대로 적는다. 앱은 같은 이름의 값을 먼저 나오는 항목에서 가져온다.
- `group approval-age`는 비밀번호로 받은 승인이 유지되는 시간이다.

## 값과 비밀번호 쓰기

```sh
mydc secret put db-password --file DB_PASSWORD=./db-password.txt
printf %s "$PASSWORD" | mydc secret put db-password DB_PASSWORD
mydc secret group password common --profile auth --password-file ./common.txt
```

- `put 이름 [키...]`은 적은 키를 쓴다. 키를 적지 않으면 그 secret의 모든 키를 쓴다. 값은 `--file 키=경로`, 남은 키가 하나이고 표준 입력이 터미널이 아니면 표준 입력, 그 밖에는 보이지 않는 입력 칸에서 읽는다. `MYDC_NONINTERACTIVE=1`이면 묻지 않고 실패한다. 바이트를 그대로 쓰며 줄바꿈도 지우지 않는다.
- **바깥 Vault의 객체는 통째로 바뀐다.** 적지 않은 키는 그 객체에서 빠진다.
- `group password`는 `--password-file`, 터미널이 아닌 표준 입력, 보이지 않는 입력 칸(두 번 묻는다) 순서로 비밀번호를 읽는다. 클러스터에는 비밀번호 대신 검증 값만 남는다. `--profile`은 처음 정할 때만 적는다. 비밀번호를 바꾸면 옛 비밀번호로 받은 승인은 더 쓰이지 않는다. 검증 값은 `groups/<작업 공간>/<그룹>/<세대>` 경로에 놓이므로(클러스터 범위는 `groups/_cluster/...`), verifier를 쓰는 profile의 `prefix`는 `groups/<작업 공간>`이나 `groups`여야 한다.
- 바깥 Vault에는 각 값이 원래 바이트의 base64로 저장되고, `_mydc_receipt` 항목이 함께 놓인다. Vault를 직접 읽으면 base64를 풀어야 원래 값이 나온다.
- 쓰기는 준비, 보내기, 쓰기 서버에서 저장, 확인, 게시 순서로 간다. 명령은 끝까지 기다린다. 응답을 놓쳤으면 `mydc op resume ID`나 같은 `--id`로 다시 실행한다. 쓰기 서버에 닿았을지도 모르는 값은 다시 보내지 않는다.
- 저장되지 않은 쓰기는 `secret write abandon ID`로 포기한다. 끝난 쓰기 기록은 `secret write clear`로 정리한다. 저장된 값은 그대로다.

## 쓰는 사람과 정리

```sh
mydc secret acl common --allow-service shop/web --deny-user bob
mydc secret move db-password --parent db-admin
mydc secret revoke db-password
mydc secret retire db-password
```

- `acl`에서 적은 목록만 바뀌고 나머지는 그대로다. `--clear`는 모든 목록을 비우고 시작한다. 서비스는 `앱/서비스`로 적는다. `--grant-tenant`는 `--all`일 때 그 트리를 쓸 작업 공간이다.
- `revoke`는 새로 쓰는 것을 막는다.
- `retire`는 막아 둔 뒤 아무도 쓰지 않는 그룹이나 secret을 지운다.

## 쓰기 서버와 승인 서버 (시스템 관리자)

```sh
mydc secret profile set values --node node-a --values
mydc secret profile set auth --node node-a --verifiers
mydc secret profile set values --node node-a --values --disable
mydc secret issuer enable node-a
mydc secret issuer disable node-a
```

- 쓰기 프로필은 어느 서버가 바깥 Vault에 쓰는지다. 그 서버의 node.yaml에 그 프로필의 바깥 Vault 설정이 있어야 한다. 프로필은 트리에 붙으므로 `secret init`을 먼저 한다. `--values`는 secret 값을, `--verifiers`는 그룹 비밀번호 검증 값을 쓴다.
- 승인 서버(`issuer`)는 그룹 비밀번호를 확인하고 승인에 서명한다.

## 승인 철회

```sh
mydc secret approvals revoke 승인ID
```

- 그 승인이 속한 보관함(작업 공간)의 비밀값 관리자가 철회한다. 클러스터 보관함의 승인은 시스템 관리자가 철회한다.

## 공통

바꾸는 명령은 모두 `--id`, `--if-revision`, `--dry-run`을 받는다. 실행 전에 무엇이 바뀌는지 보여 주고 확인을 묻는다(`-y`면 묻지 않는다). 작업 기록에는 이름과 대상만 남고 값과 비밀번호는 남지 않는다.

## 종료 코드

0 성공, 1 실패, 2 잘못된 명령줄이나 빠진 입력, 3 서버가 거절했거나 실패로 끝남, 4 결과를 아직 모름(`mydc op show ID`로 확인).

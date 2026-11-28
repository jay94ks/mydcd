# VPS 서버 자동 가입 (.well-known, SSH)

클러스터가 만든 VPS 서버(`sfcli vps create`)가 클러스터의 외부 접속 경로(ingress)로 sfcd를 받고 가입하는 방법이다. 설계: VPS 서버 §4.

## 순서

1. 리더가 VPS를 만들고 공인 IP가 붙으면 서버가 `installing`이 된다. 이때 리더 자신의 sfcd(OS, 아키텍처, SHA-256)를 서버 기록에 남긴다.
2. VPS가 처음 켜질 때 공급자 사용자 스크립트가 아래 요청을 보낸다. 모든 요청은 HTTPS여야 하고, 연결이 온 주소가 그 서버의 공인 IPv4여야 한다. 아니면 404다. 헤더로 주소를 바꿀 수 없다.
3. `GET /.well-known/sfc/node/sfcd?name=NAME`: 1에서 남긴 바이너리와 똑같은 것만 돌려준다(`X-Sfc-Sha256` 헤더). 응답한 서버가 다른 빌드를 돌리고 있으면 503이니 잠시 뒤 다시 받는다.
4. `sfcd identity create DIR`로 키를 만든다. 개인키는 VPS 밖으로 나가지 않는다.
5. `POST /.well-known/sfc/node/enroll`에 `{"name":"NAME","key":"공개키 hex"}`를 보낸다.
   - `202`(`Retry-After: 5`): 받았다. 초대에 서명하는 중이니 같은 요청을 다시 보낸다.
   - `200`: 본문이 서명된 초대 파일 그대로다. 헤더 `X-Sfc-Cluster`, `X-Sfc-Source-Public-Key`, `X-Sfc-Node`, `X-Sfc-Endpoint`를 함께 준다.
   - `409`: 이 이름에 다른 키가 먼저 가입했다. 처음 보낸 키만 인정한다.
6. 초대를 받은 ingress 서버는 연결 주소를 증명하는 `vps-enroll` 멤버 보고만 보낸다. 서버를 초대하는 권한은 시스템 관리자가 서명한 `create-vps-node`다. 리더(투표 서버)가 초대에 서명해 서버 기록에 남긴다. 초대는 비밀이 아니다. 그 키의 개인키 없이는 가입할 수 없다.
7. 스크립트가 node.yaml을 쓰고 `sfcd join`, 그 뒤 `sfcd run`을 한다. 새 서버는 투표권 없이 들어오고 `inbound_only: true`다.

## 사용자 스크립트 예시

공급자 콘솔에 한 번 등록해 두고 `sfcli vps create --script ID`로 고른다. 모든 VPS에 같은 스크립트이고 비밀을 담지 않는다. `CLUSTER_HOST`만 클러스터의 외부 주소로 바꾼다. 서버 이름은 VPS를 만들 때 붙인 인스턴스 이름(호스트 이름)이다.

```sh
#!/bin/sh
set -eu
CLUSTER_HOST=sfc.example.com          # 클러스터 외부 주소
NAME=$(hostname -s)
BASE=https://$CLUSTER_HOST/.well-known/sfc/node
umask 077
mkdir -p /etc/sfc /var/lib/sfc /usr/local/bin
until curl -fsS -o /usr/local/bin/sfcd.new -D /tmp/sfcd.h "$BASE/sfcd?name=$NAME"; do sleep 10; done
want=$(sed -n 's/^[Xx]-[Ss]fc-[Ss]ha256: *\([0-9a-f]*\).*/\1/p' /tmp/sfcd.h)
echo "$want  /usr/local/bin/sfcd.new" | sha256sum -c -
chmod 755 /usr/local/bin/sfcd.new && mv /usr/local/bin/sfcd.new /usr/local/bin/sfcd
KEY=$(sfcd identity create /etc/sfc/identity)
while :; do
  code=$(curl -sS -o /etc/sfc/invitation.json -D /tmp/enroll.h -w '%{http_code}' \
    -H 'Content-Type: application/json' -d "{\"name\":\"$NAME\",\"key\":\"$KEY\"}" "$BASE/enroll")
  [ "$code" = 200 ] && break
  [ "$code" = 409 ] && exit 1
  sleep 5
done
h() { sed -n "s/^$1: *\([^[:space:]]*\).*/\1/Ip" /tmp/enroll.h; }
cat > /etc/sfc/node.yaml <<YAML
version: 1
node:
  id: $NAME
  state_dir: /var/lib/sfc
  identity_dir: /etc/sfc/identity
  listen: "$(h X-Sfc-Endpoint)"
  inbound_only: true
YAML
sfcd --config /etc/sfc/node.yaml join --cluster "$(h X-Sfc-Cluster)" \
  --source-public-key "$(h X-Sfc-Source-Public-Key)" --invitation /etc/sfc/invitation.json
cat > /etc/systemd/system/sfcd.service <<UNIT
[Unit]
Description=Seafield Cluster node daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sfcd --config /etc/sfc/node.yaml run
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sfcd
```

## 설치 명령 (보유 VPS, 직접 설치)

[보유 VPS](../cli/vps.md#보유-vps-hostinger)를 직접 설치로 붙였으면(`sfcli vps owned attach NAME ...`, `--ssh`·`--existing` 없이) 리더가 그 VPS를 확인한 뒤(`installing`, 공인 IP가 기록됨) VPS에서 root로 다음 한 줄을 실행한다. `CLUSTER_HOST`는 클러스터 외부 주소다.

```sh
curl -fsS "https://CLUSTER_HOST/.well-known/sfc/node/install.sh?name=NAME" | sh
```

- `GET /.well-known/sfc/node/install.sh?name=NAME`은 위 사용자 스크립트와 같은 순서의 스크립트를 돌려준다. 서버 이름과 요청한 주소가 이미 채워져 있다. 다른 요청과 같이 연결 주소가 그 서버의 공인 IPv4일 때만 주고, 아니면 404다. 비밀은 담지 않는다.
- 30분 안에 가입하지 않으면 `failed`·`TIMEOUT`이 된다. VPS는 그대로 남는다. `detach` 뒤 다시 붙이면 새로 시작한다.
- 다시 실행해도 된다. 키가 이미 있으면 그 키를 쓰고, 다른 키가 먼저 가입했으면 409로 멈춘다.

## SSH로 설치 (`--script` 없이 만든 서버)

외부 접속 경로가 없는 클러스터용이다. 사용자 스크립트를 쓰지 않고, 리더가 계정 SSH 키로 들어가 같은 일을 한다.

1. 계정마다 SSH 키가 있다. `vps account add`와 `rotate-key`를 할 때 봉인하는 투표 서버가 새로 만들고, 개인키는 공급자 키와 함께 봉인된다. 공개키는 `sfcli vps account ssh-key NAME`으로 보고, 공급자 콘솔에 등록한 뒤 `sfcli vps account set NAME --ssh-key-id ID`로 그 ID를 알려 준다. `rotate-key`를 하면 SSH 키도 바뀌므로 다시 등록한다.
2. `sfcli vps create`에 `--script`가 없으면 CLI가 계정 SSH 키를 서버 키 목록에 넣는다. 등록하지 않았으면 만들기가 거절된다.
3. 서버가 `installing`이 되면 리더(투표 서버)가 `root@공인IP:22`로 접속해 다음을 한다.
   - 자기 sfcd를 올리고 SHA-256을 확인한다.
   - `sfcd identity create`(다시 시도할 때는 `identity show`)로 키를 얻는다.
   - 자기가 그 주소에서 받은 키라고 `vps-enroll`을 보낸다.
4. 초대에 서명한 뒤 같은 연결 방식으로 초대 파일, 위 node.yaml, 서비스 파일을 쓰고 `sfcd join`을 한 뒤 서비스를 켠다. 실패하면 2분 뒤 다시 시도한다.
5. 새 서버의 호스트 키는 미리 알 수 없어서 처음 접속은 응답한 키를 그대로 믿는다. 그 뒤로 리더는 서버 이름과 공인 IP별로 그 키를 메모리에 기억하고, 다른 키가 응답하면 접속을 끊는다. 리더가 바뀌면 새 리더는 다시 처음 접속부터 믿는다. 중간에서 가로챈 쪽이 얻을 수 있는 것은 투표권 없는 가입 하나뿐이고, 클러스터 마스터 키나 공급자 키는 얻지 못한다. 그래서 SSH로 설치하는 서버는 투표 서버가 될 수 없다(`--script` 없이 `--voter`는 거절된다). 이상하면 `sfcli node remove`로 뺀다.

## 지우면 안 되는 패키지

iwinv의 Ubuntu 이미지(지금 Ubuntu 26.04 LTS 64bit, EOL 2031-04, 커널 7.0.0-14-generic)는 VPS를 만들 때 "iproute2, isc-dhcp, initscripts, systemd-resolve 패키지를 지우지 마세요"라고 알린다. 26.04에서는 DHCP를 `dhcpcd-base`와 `systemd-networkd`가 맡으므로, 지우면 안 되는 패키지는 `iproute2`, `isc-dhcp`(`isc-dhcp-client` 등), `initscripts`, `systemd-resolved`, `dhcpcd-base`, `systemd-networkd` 여섯 개다. 이 패키지나 이들이 의존하는 패키지가 지워지면 서버의 네트워크와 DNS가 끊긴다. 이미지에 없는 패키지는 없는 그대로 두고 새로 설치하지 않는다.

- SSH 설치는 패키지를 하나도 지우지 않는다. 리더의 SSH 셸은 `apt`/`apt-get`의 `remove`·`purge`·`autoremove`·`autopurge`, `dpkg -r`/`-P`가 든 명령과, 위 여섯 패키지를 설치하는 명령을 서버에 보내기 전에 거절한다.
- 사용자 스크립트에도 `apt autoremove`나 최소 설치 정리를 넣지 않는다. Docker를 지워야 하면 패키지 이름으로만 지우고 autoremove는 부르지 않는다. 먼저 `apt-get -s remove 이름`으로 위 여섯 패키지가 같이 지워지지 않는지 본다.
- 이 커널은 Seafield 엔진 요구 조건(6.5 이상, cgroup v2, PSI)을 만족한다.

## 실제 계정에서 확인할 것

- iwinv 인스턴스의 호스트 이름이 인스턴스 이름과 같은지, 공인 IP가 VPS 네트워크 장치에 직접 붙는지(`listen`에 쓸 수 있는지)
- 사용자 스크립트가 root로, 네트워크가 올라온 뒤에 도는지
- SSH 경로: 공급자가 넣은 키로 `root` 접속이 되는지, 이미지에 `sha256sum`과 systemd가 있는지

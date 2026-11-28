# 설치 패키지

Seafield Cluster의 deb·rpm·tar.gz를 만드는 정의다. 설계는 설치 패키지 설계(`devel/design/install-packages.md`)에 있다. 모든 빌드는 Docker 컨테이너 안에서 하고, 나온 패키지 파일만 꺼낸다. 빌드 이미지는 배포하지 않지만 그 Dockerfile은 여기 있으니 누구나 같은 패키지를 다시 만들 수 있다.

```sh
make notices                       # dist/THIRD_PARTY_NOTICES (go-licenses)
make webbundle VERSION=v0.1.0      # 선택: sfc-web-image 패키지용 서명 묶음 (SFC_RELEASE_KEY 필요)
make packages  VERSION=v0.1.0      # dist/ 에 .deb, .rpm, .tar.gz (GOARCH 하나)
# 프록시 뒤라면 docker 옵션을 더한다: make packages PKGDOCKERFLAGS="--network host ..."
```

`make packages`는 `GOARCH`(기본: 이 컴퓨터) 플랫폼의 컨테이너에서 돈다. 다른 아키텍처는 그 아키텍처의 컴퓨터에서 만든다(릴리스 workflow는 arm64 runner를 쓴다).

## 패키지

| 패키지 | 담는 것 | 의존 |
|---|---|---|
| `sfcli` | `/usr/bin/sfcli`, `/usr/share/sfc/SKILL.md` | 없음 |
| `sfcd` | `/usr/lib/sfc/bin/`의 `sfcd`, `sfed`, `sfe-runc`, 전용 `containerd`·`containerd-shim-runc-v2`·`runc`, `/usr/bin/sfcd` 링크, 유닛 `sfcd.service`·`sfed.service`, node.yaml 예시 | `sfcli` 같은 버전 |
| `sfc-web-image` | `/usr/lib/sfc/images/sfc-web/` (서명된 OCI layout) | `sfcd` 같은 버전 |

- Docker Engine, 시스템 `containerd`·`runc` 패키지에 의존하지 않는다. sfed는 `/usr/lib/sfc/bin`의 containerd·runc만 쓴다(sfed.service의 `PATH`, `SFE_RUNC`).
- 패키지는 다른 패키지를 지우거나 바꾸지 않는다. `Conflicts`·`Breaks`·`Replaces`·`Obsoletes`가 없고, 설치 스크립트는 패키지 관리자를 부르지 않는다. 호스트가 지키라는 기본 패키지(`iproute2`, `isc-dhcp*`, `initscripts`, `systemd-resolved`, `dhcpcd-base`, `systemd-networkd`)와 그에 의존하는 패키지를 지우지 않고, 없으면 새로 깔지도 않는다. `check-scripts.sh`가 빌드 때마다 확인한다.
- 처음 설치할 때 유닛을 켜거나 시작하지 않는다. 업그레이드 때는 돌고 있는 것만 다시 시작한다(`systemctl try-restart sfed sfcd`). 제거하면 두 유닛을 멈추고 끈다. purge(deb)나 erase(rpm)도 `/etc/sfc`, `/var/lib/sfc`, `/etc/sfe`, `/var/lib/sfe`는 지우지 않는다.

## tar.gz

`sfc_<버전>_linux_<arch>.tar.gz`는 `/usr/local` 아래 그대로의 트리다.

```sh
sudo tar -C /usr/local --strip-components=1 -xzf sfc_v0.1.0_linux_amd64.tar.gz
sudo cp /usr/local/share/sfc/systemd/sfcd.service /usr/local/share/sfc/systemd/sfed.service /etc/systemd/system/
sudo systemctl daemon-reload
```

`sfcd`는 자기 실행 파일 위치로 cluster app image 묶음을 찾는다(`/usr/lib/sfc/bin` → `/usr/lib/sfc/images`, `/usr/local/lib/sfc/bin` → `/usr/local/lib/sfc/images`).

## 파일

| 파일 | 하는 일 |
|---|---|
| [versions.env](versions.env) | 함께 넣는 containerd·runc 태그와 커밋 |
| [builder/Dockerfile](builder/Dockerfile) | 빌드 이미지(Go, cgo, libseccomp) |
| [build.sh](build.sh) | sfcd·sfcli, Seafield Engine(`seafield/prepare.sh`·`build.sh`), containerd·runc를 정적으로 빌드하고 엔진 쪽 라이선스를 모은다 |
| [layout.sh](layout.sh) | 패키지 하나의 파일을 접두어(`/usr`, `/usr/local`)에 맞춰 놓는다 |
| [systemd/](systemd) | 유닛 원본. `@LIBDIR@`를 `layout.sh`가 채운다 |
| [deb/](deb) | deb 이미지, `dpkg-deb`로 만드는 스크립트, 설명, maintainer script, lintian |
| [rpm/](rpm) | rpm 이미지, spec, `rpmbuild -bb` 스크립트, rpmlint |
| [tar.sh](tar.sh) | tar.gz |
| [check-scripts.sh](check-scripts.sh) | 패키지 정의가 다른 패키지를 지우지 않는지 확인 |
| [man/](man) | `sfcli(1)`, `sfcd(8)` |
| [test.sh](test.sh), [test-in-container.sh](test-in-container.sh) | 설치 시험 |

## 서명

릴리스의 `SHA256SUMS`는 릴리스 키(cluster app 묶음 서명과 같은 Ed25519 키)로 서명해 `SHA256SUMS.sig`(서명 hex 한 줄)로 함께 올린다. 확인:

```sh
go run ./tools/clusterapp-bundle verify-file -builtin -file SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Go 없이 `openssl`(3.0 이상)로 확인하려면 hex를 바이너리로 바꾼다. 공개키는 `74217e280459642c3d18ff6bc66e1f09a04797681cbf4c39131bd6b1df55aa7c`(hex)이다.

```sh
unhex() { python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'; }
printf '302a300506032b6570032100%s' 74217e280459642c3d18ff6bc66e1f09a04797681cbf4c39131bd6b1df55aa7c | unhex > release.der
unhex < SHA256SUMS.sig > SHA256SUMS.sig.bin
openssl pkeyutl -verify -pubin -keyform DER -inkey release.der -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig.bin
```

## 시험

```sh
packaging/test.sh dist 0.1.0 0.1.1 amd64
```

깨끗한 컨테이너(deb: Ubuntu 24.04·26.04, Debian trixie / rpm: Fedora 43, Rocky 10 / tar.gz: Ubuntu 24.04)에서 두 버전을 설치·업그레이드·제거·purge하고, 파일 위치, 링크, 유닛 경로, `sfcli --help`의 SKILL.md 위치, 운영자 상태(`/etc/sfc`, `/var/lib/sfc`, `/var/lib/sfe`)가 남는지, 다른 패키지 목록이 그대로인지 확인한다. 패키지 파일만으로 설치하므로 네트워크가 필요 없다.

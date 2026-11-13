# 배포와 Tailscale

이 문서는 macOS·Linux·Windows(WSL2) 사용자가 자신의 호스트에서 API를 운영하는 방법입니다. 예제의 경로·계정·접근 정책을 자신의 환경에 맞게 수정하세요.

접근 경로는 **허용된 tailnet 노드 → Tailscale Serve HTTPS 443 → loopback API 8787**입니다. Tailscale의 사용자 헤더로 API 인증을 생략하지 않습니다. 서비스마다 만료·권한·방 제한이 있는 Bearer 토큰을 발급하고, 발송용 토큰은 조회용과 분리합니다.

## Linux 단독 호스트

1. 전용 `kakao-rust` 서비스 계정과 `/var/lib/kakao-rust`(0700)를 준비합니다. `cargo build --release --locked` 결과를 `/usr/local/bin/kakao-rust`에 설치합니다.
2. 서비스 계정으로 `kakao-rust --data-dir /var/lib/kakao-rust init`를 실행합니다. 카탈로그로 `device init`를 한 번 실행합니다. 기존 저장소가 있다면 같은 데이터 디렉터리를 복원하고 `init`로 대체하지 않습니다.
3. `kakao-rust.service`를 systemd에 설치해 API를 시작합니다. `kakao-rust-collector.service`도 설치해 수집기를 시작합니다. 두 unit은 같은 DB를 사용합니다. 로그인과 선택한 복원은 시작 전에 끝냅니다.
4. 호스트를 기존 tailnet에 등록하고 HTTPS/MagicDNS를 준비합니다. 인증키는 문서·저장소·쉘 명령 인수에 넣지 않습니다. tailnet의 실제 운영 방식에 따라 로그인합니다.
5. `tag:kakao-api`를 이 노드에 부여하고 `grants.example.hujson`을 기존 정책에 병합합니다. 예제 이메일을 실제 접근 주체로 바꿉니다. 기존의 전체 허용 규칙이 있으면 이 fragment만으로 접근이 제한되지는 않습니다.
6. `scripts/tailscale-serve.sh`를 실행합니다. 기존 Serve 설정이 있으면 변경하지 않고 종료합니다. Funnel 공개 노출은 설정하지 않습니다.

## 컨테이너 사용 시

`serve.json`은 Tailscale containerboot의 `TS_SERVE_CONFIG`용 템플릿입니다. 공식 containerboot는 `${TS_CERT_DOMAIN}`을 실제 노드 FQDN으로 치환합니다. Rust API와 Tailscale이 같은 네트워크 namespace를 사용해야 `127.0.0.1:8787`에 연결됩니다. `TS_STATE_DIR`을 영구 private volume으로 두고 `TS_AUTH_ONCE=true`를 사용합니다. 호스트 port를 공개하는 설정은 필요하지 않습니다. 현재 완성된 배포용 컨테이너 이미지는 제공하지 않습니다. Linux 빌드·테스트와 실제 계정 상시 배포는 별개입니다.

## 배포 후 검증

- 허용된 노드에서 HTTPS 접속, 무토큰 요청 401, 정상 토큰과 scope/방 제한 확인.
- 만료·회수된 토큰, 잘못된 계정·방, scope 밖 요청 실패 확인.
- 비허용 tailnet 노드와 tailnet 외부에서 접근 실패 확인.
- 재시작 후 기기 ID·토큰·인덱스 보존 및 `tailscale serve status` 확인.

실제 계정 세션과 메시지 데이터에는 암호화된 디스크/volume과 별도 백업이 필요합니다. 현재 프로그램 자체의 DB/로그인 토큰 암호화 저장은 미구현입니다. 백업·복원은 [상세 사용법](../docs/USAGE.md)의 SQLite WAL 및 초기화 marker 조건을 따릅니다.

근거: [Serve 공식 문서](https://tailscale.com/docs/reference/examples/serve), [grants](https://tailscale.com/docs/features/access-control/grants), [containerboot 환경변수](https://github.com/tailscale/tailscale/blob/main/cmd/containerboot/main.go), [ServeConfig 타입](https://github.com/tailscale/tailscale/blob/main/ipn/serve.go). 대상에 설치된 Tailscale 버전의 CLI와 설정 형식을 배포 전에 확인합니다.

## macOS에서 연결

동일한 Rust 바이너리를 private 데이터 경로로 실행한 뒤 Tailscale 앱/daemon을 본인 tailnet에 로그인합니다. CLI가 PATH에 없다면 설치 방식에 맞는 실제 CLI 경로를 `TAILSCALE_BIN`으로 지정합니다. 별도 daemon socket은 `TAILSCALE_SOCKET`으로 지정합니다. Python3도 스크립트의 기존 Serve 설정 확인에 필요합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" serve
# 다른 터미널에서, Tailscale CLI가 준비된 뒤:
./scripts/tailscale-serve.sh
```

스크립트는 인증된 Running 상태인지 확인하고, 다른 Serve 구성이 있으면 덮어쓰지 않습니다. 새 설정은 tailnet 내부 HTTPS443 → loopback8787입니다. 서비스 사용이 끝나면 본인이 생성한 Serve 구성을 확인하고 제거합니다. 기존 다른 서비스의 설정 전체를 reset하지 않습니다.

## 수집기 자동 시작

Linux는 두 unit을 설치한 뒤 실행합니다.

```sh
sudo systemctl enable --now kakao-rust.service kakao-rust-collector.service
journalctl -u kakao-rust-collector.service
```

네트워크 재접속은 수집기가 처리합니다. 인증 거절과 서버의 종료 지시는 재실행으로 반복하지 않도록 collector unit은 비정상 신호 종료 때만 재시작합니다.

macOS는 `dev.kakao-rust.collector.plist`의 바이너리·데이터 절대 경로를 바꾸고 `~/Library/LaunchAgents/`에 설치합니다. 셸의 `$HOME`이나 `~`는 plist에서 확장되지 않습니다.

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.kakao-rust.collector.plist"
launchctl print "gui/$(id -u)/dev.kakao-rust.collector"
# 종료 및 등록 해제
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.kakao-rust.collector.plist"
```

로그인 시 자동 시작하며 프로세스 충돌 때 재시작합니다. 일반 종료나 인증 오류 뒤에는 원인을 해결한 후 `launchctl kickstart gui/UID/dev.kakao-rust.collector`로 시작합니다. API는 `dev.kakao-rust.api.plist`도 같은 방식으로 경로를 수정해 설치합니다. 컴퓨터가 잠자기 상태이거나 꺼져 있으면 수집할 수 없습니다.

## Windows(WSL2)

Windows에서는 WSL2의 Ubuntu 환경을 사용합니다. 관리자 PowerShell에서 설치합니다.

```powershell
wsl --install -d Ubuntu
```

설치 후 Ubuntu 터미널에서 Rust를 준비하고 [README의 설치 절차](../README.md#설치)를 진행합니다. 소스와 데이터는 WSL의 Linux 파일시스템에 둡니다. 데이터 경로 예시는 `$HOME/.local/share/kakao-rust/data`입니다. `/mnt/c`와 Windows 동기화 폴더는 파일 권한·DB 잠금 차이를 피하기 위해 사용하지 않습니다.

수집기·API·Tailscale은 WSL 안에서 실행하고 위의 Linux 배포 절차를 따릅니다. 자동 실행에 systemd를 사용하려면 WSL의 systemd가 활성화되어 있어야 합니다. 필요하면 `/etc/wsl.conf`에 아래 설정을 추가하고 PowerShell에서 `wsl --shutdown` 후 Ubuntu를 다시 시작합니다.

```ini
[boot]
systemd=true
```

systemd 서비스 활성화만으로 Windows 부팅 시 WSL이 자동 시작되지는 않습니다. 상시 수집이 필요하면 Windows 작업 스케줄러에서 로그인 시 해당 WSL 배포판을 시작하도록 설정합니다. Windows가 절전 상태이거나 WSL이 종료되어 있으면 수집도 중단됩니다.

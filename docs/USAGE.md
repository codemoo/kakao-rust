# 설치와 운영

[API 참조](API.md) · [배포](../deploy/README.md) · [지원 범위](PARITY.md) · [검증](TESTING.md)

## 설치와 빌드

Rust **1.88 이상**, Cargo, C 컴파일러·링커가 필요합니다. SQLite는 bundled 빌드, TLS는 rustls를 사용합니다. 시스템 SQLite나 OpenSSL 개발 패키지를 별도로 설치할 필요는 없습니다.

- macOS: Xcode Command Line Tools를 준비하고 Rust 도구 체인을 설치합니다.
- Linux: GCC/Clang 등 빌드 도구를 준비합니다. Ubuntu/Debian에서는 `build-essential`이 해당합니다.

```sh
cargo build --release --locked
./target/release/kakao-rust --help
./scripts/check.sh
```

`check.sh`는 포맷 검사, 전체 테스트, Clippy를 실행합니다. `CARGO_HOME`, `CARGO_TARGET_DIR`, `TMPDIR` 등 표준 환경변수를 존중합니다. 프로젝트 전용 `KAKAO_RUST_CARGO_HOME`, `KAKAO_RUST_TARGET_DIR`를 지정하면 해당 Cargo 경로만 덮어씁니다. 테스트는 합성 데이터와 로컬 mock을 사용하며 실제 로그인이나 메시지 발송을 수행하지 않습니다.

OS별 검사 결과는 검증 문서에 기록합니다. [검증 결과와 한계](TESTING.md)를 참고하세요. GitHub Actions에서는 macOS/Linux와 최소 Rust 버전/최신 stable 조합으로 같은 검사를 실행하도록 구성합니다. CI 통과는 실제 계정의 로그인·복원·서버 요청 호환성까지 보증하지 않습니다.

## 데이터 디렉터리

모든 명령에 절대 경로 `--data-dir`가 필요합니다. 소스 저장소와 Dropbox 밖에 두세요. 프로그램은 디렉터리 0700, 민감 파일 0600 권한을 요구합니다.

예를 들어 macOS는 `~/Library/Application Support/kakao-rust/data`, Linux는 `~/.local/share/kakao-rust/data`를 사용할 수 있습니다. 아래는 두 OS에서 쓸 수 있는 예입니다.

```sh
export KAKAO_DATA_DIR="$HOME/.local/share/kakao-rust/data"
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" init
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" device init \
  --catalog config/device-catalog.json
```

같은 디렉터리에서 `init`를 반복해도 정상 기존 상태를 초기화하지 않습니다. DB가 사라지거나 손상된 경우 새 계정 상태로 덮어쓰지 않고 복구를 요구합니다. 같은 세션을 여러 호스트에서 동시에 실행하지 마세요.

## 카카오톡 인증

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" auth login
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" auth status
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" auth session
```

1. 계정과 비밀번호를 숨김 터미널 입력으로 받습니다. 명령행 인수나 환경변수로 비밀번호를 전달하지 않습니다.
2. 서버가 기기 승인을 요구하면 CLI에 승인 번호를 표시합니다.
3. 본인 휴대전화 카카오톡에서 해당 번호로 승인합니다.
4. CLI가 로그인 완료를 안내하면 저장된 로그인 상태로 이후 명령을 실행합니다. API를 사용할 때마다 로그인할 필요는 없습니다.

승인 대기는 기본 180초이며 `--timeout-seconds`로 1~600초 범위에서 지정할 수 있습니다. 추가 이메일 인증·약관 동의 등 지원하지 않는 분기는 상태만 반환합니다. 요청 결과가 불명확하면 무조건 재시도하지 않고 복구 필요 상태를 유지합니다.

기본 로그인 명령은 `auth login`입니다. 선택 기능의 지원 여부는 [검증 문서](TESTING.md)를 참고하세요.

## 초기 상태 관찰과 기존 대화 복원

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native bootstrap --observe-seconds 180
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native restore
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native restore-key
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native restore-download --max-pages 10000
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native restore-followup
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native restore-status
```

`bootstrap`은 복원 전 상태 확인 명령입니다. 상시 수집에는 `native run`을 사용합니다. `restore-key`에서 안내하는 **카카오 지갑 My 비밀번호 6자리**를 숨김 입력으로 입력하세요. 로그인 비밀번호·톡서랍 보안코드와 혼동하지 마세요.

비밀번호는 저장하지 않습니다. `--pin-stdin`은 전용 비공개 입력 파이프를 위한 옵션입니다. 다운로드 오류 후 같은 명령을 다시 실행하면 마지막 성공 페이지에서 이어갑니다. `--max-pages`는 이번 실행의 페이지 수 상한입니다. 백업 안내 건수와 실제 반환 건수는 다를 수 있습니다.

현재 검색 가능한 메시지는 텍스트·답장 중심입니다. 이미지·파일 등 다른 형식은 원본 보존과 다운로드 지원을 구분해야 합니다. 일부 첨부파일 형식과 미리보기 렌더링은 지원하지 않습니다.

`restore-followup`은 녹음 메타데이터·방 상태·메시지 메타데이터 후처리를 진행합니다. 현재 녹음이 0건인 경로만 끝까지 구현되어 있습니다. 양수인 경우 `recording_metadata_required`에서 멈추고 복원 완료 통지를 보내지 않습니다. 완료 POST 결과가 불명확한 경우 자동 재전송하지 않습니다.

`native skip-restore`는 복원 건너뛰기를 기록하는 **서버 상태 변경 요청**입니다. 단순 로컬 오류 해제 명령이 아닙니다. 이미 복원을 선택했다면 거부합니다.

## 친구 목록과 이름

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native friends-sync
```

저장된 세션으로 친구 동기화 API를 읽고, 원본 응답·친구 및 채널 신원·이름·관계 상태를 DB에 저장합니다. 최초 요청은 `since=0`, 이후는 정상 반영·검증된 동기화 시점을 사용합니다. 서버 건수와 로컬 친구 건수가 맞지 않으면 완료로 표시하지 않고 다음 요청을 전체 동기화로 남깁니다. 건수가 다르면 consistency diff로 보정하고 원래 응답의 건수와 다시 비교합니다. 보정에 실패하면 전체 동기화부터 다시 시작합니다.

친구가 아닌 과거 발신자도 이름 조회를 위해 신원을 보존할 수 있으므로 `/v1/friends`의 각 항목에서 `is_friend`, `relation`, `is_channel`을 함께 확인하세요. 증분 응답에 없다는 이유만으로 친구를 삭제하지 않습니다.

이름은 다음을 구분합니다.

- `profile_name`: 카카오 프로필 이름.
- `friend_name`: 서버의 `friendNickName`. 친구 별명이며 **휴대전화 연락처 이름과 같은 필드가 아닙니다**.
- `display_name` / `name_source`: API에서 선택한 표시 이름과 출처.
- 메시지의 `sender_name` / `sender_name_source`: 조회 시점의 친구 DB와 연결한 현재 이름과 출처. 발송 당시 이름의 스냅샷은 아닙니다.

우선순위는 확인된 연락처 백업의 이름 → 친구 별명 → 프로필 이름입니다. 친구 목록 응답만으로 연락처 이름이 확인되지는 않습니다. 기존 톡서랍 연락처 백업을 읽어 보완하려면 다음 명령을 사용합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native contacts-sync
# 특정 백업을 명시하려면:
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native contacts-sync --snapshot-id SNAPSHOT_ID
```

기본 선택은 전체 snapshot 목록에서 생성 timestamp가 가장 큰 백업입니다. 휴대전화의 현재 주소록과 백업 시점이 다를 수 있습니다. 연락처 백업이 없으면 친구 별명·프로필 이름을 사용합니다. 전체 페이지와 고유 연락처 건수가 맞아야 이름을 교체하므로 중간 오류가 기존 이름을 지우지 않습니다. 연락처를 업로드하거나 호스트/휴대전화 주소록을 변경하지 않습니다.

이름 출처 `drawer_contact_name`은 기존 톡서랍 백업의 표시 이름입니다. 전화번호 매칭은 기호 제거·국제 `+` 형식 비교, 한국 계정의 국내 번호 변환을 지원하며 번호 뒷자리만으로 연결하지 않습니다. 다른 국가의 국내 번호는 같은 국가 문맥에서만 그대로 비교합니다. 같은 번호를 여러 연락처가 공유하면 연락처 이름을 사용하지 않습니다. 일반 카카오 친구 동기화가 켜져 있다는 사실만으로 톡서랍 연락처 백업이 존재하는 것은 아닙니다. 이름을 모르는 경우 `null`과 원래 발신자 ID를 반환합니다. 전화번호 자체는 현재 조회 API에 노출하지 않습니다.

## 상시 수집

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native run
# 관찰 시간을 제한하려면:
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native run --run-seconds 60
```

새 메시지를 계속 수집하며 텍스트·답장 본문을 저장하고 검색에 반영합니다. 연결이 끊기면 재접속 후 누락 구간을 조회합니다. 재시작 후에도 저장된 기록에서 이어가며, 수집 때문에 읽음 표시가 올라가지는 않습니다.

네트워크 오류는 간격을 늘려 재시도합니다. 로그인 거절·서버의 종료 지시·로컬 저장 오류는 수집을 중단하므로 원인을 확인해야 합니다. Ctrl+C/SIGTERM으로 종료합니다. `serve`는 별도 프로세스로 실행할 수 있습니다.

`/v1/status`의 `collector`에 연결 상태, 마지막 패킷 시각, 미처리 패킷·방 수가 나옵니다. `pending_packets`에는 미지원 앱 설정·비텍스트 이벤트도 포함됩니다. `pending_rooms`는 아직 완료를 확인하지 못한 방 수입니다. 서버가 구간을 완료하지 못하면 해당 방은 5분 뒤 재조회하며 다른 방과 새 메시지 수신을 계속합니다. 별도 보관소의 누락 복구 fallback은 미구현입니다. `native_sync`는 수집 기능 제공 여부이며 전체 앱 동작의 구현·검증 완료를 뜻하지 않습니다. 친구·연락처 갱신 명령은 수집기를 잠시 멈춘 뒤 실행합니다.

## 자동 갱신

`native run`은 메시지 연결과 별도로 친구·연락처·설정을 갱신합니다. 친구는 기본 10분, 일반 설정은 24시간, 부가 설정·연락처는 6시간 주기입니다. 친구·설정 주기는 유효한 서버 설정값으로 갱신하며, 연락처 주기는 호스트 기본값을 사용합니다. 방 정보는 변경 알림·수신 메시지·재접속과 주기적 갱신에 따라 조회합니다.

유지 작업 실패 시 재시도 간격은 1분부터 최대 30분까지 늘어납니다. `/v1/status`의 `maintenance`에서 작업별 마지막 성공·다음 시도·실패 횟수를 확인할 수 있습니다. 텍스트 발송 설정은 갱신 알림에 따라 받아 저장하며, 준비되지 않았으면 발송 API가 503을 반환합니다.

수신 수정·삭제는 원문과 검색 인덱스에 반영합니다. 수정 본문이 없으면 다시 조회합니다. 누락 상태와 첨부파일·참여자 조회 방법은 [API 참조](API.md)를 참고하세요.

## API 인증과 실행

카카오 인증 토큰과 별개인 API 토큰을 서비스별로 발급합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" token issue \
  --label personal-reader --session-account \
  --scope status:read,rooms:read,messages:read,friends:read \
  --all-rooms --expires-in 86400
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" serve --bind 127.0.0.1:8787
```

`token issue`는 비밀 토큰을 한 번 출력합니다. DB에는 검증용 해시를 저장합니다. 토큰을 저장소·로그·스크린샷에 포함하지 마세요. `--session-account`는 저장된 세션의 실제 사용자 ID에 토큰을 연결합니다. 합성 데이터 테스트에는 `--account-id synthetic-account`를 사용할 수 있습니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" token list
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" token revoke --id TOKEN_ID
```

서버는 loopback 주소로만 바인딩합니다. 만료·회수된 토큰은 거부하며 SSE에서도 주기적으로 재검증합니다. 응답에 `Cache-Control: no-store`를 사용하고 요청 본문이나 인증 헤더를 로그에 남기지 않습니다.

조회에는 `messages:read`, 발송에는 `messages:write`가 필요합니다. 발송 토큰은 `--all-rooms` 대신 `--room ROOM_ID`로 제한하세요. 전체 권한과 경로·조회 조건·발송 절차는 [API 참조](API.md)에 정리되어 있습니다.

## 카카오 계정 없이 시험하기

```sh
KAKAO_DEMO_DIR="$(mktemp -d)"
cargo run --locked -- --data-dir "$KAKAO_DEMO_DIR" init
cargo run --locked -- --data-dir "$KAKAO_DEMO_DIR" import --file examples/synthetic.jsonl
cargo run --locked -- --data-dir "$KAKAO_DEMO_DIR" token issue \
  --label demo --account-id synthetic-account \
  --scope status:read,rooms:read,messages:read,friends:read --all-rooms
cargo run --locked -- --data-dir "$KAKAO_DEMO_DIR" serve
```

이 경로는 외부 카카오 서버에 접속하지 않습니다. 임시 디렉터리는 시험용입니다. 실제 계정 데이터에는 영구 private 경로를 사용하세요. 외부 JSONL은 `offline_import` 출처만 주장할 수 있으며 native 출처를 위조할 수 없습니다.

## Tailscale과 실행 관리

자세한 설정은 [배포 안내](../deploy/README.md)를 참고하세요. 기본 구성이 loopback API → Tailscale Serve HTTPS → 허용된 tailnet 노드입니다. **Tailscale에 연결되어 있어도 API Bearer 인증은 필요합니다.** Funnel이나 공개 인터넷 포트 개방은 기본 설정에 포함하지 않습니다.

Linux용 systemd 예제는 API와 수집기를 각각 관리합니다. macOS에서는 같은 바이너리를 터미널에서 실행할 수 있습니다. Windows에서는 WSL2의 Linux 배포 절차를 사용합니다.

## 보관·백업·복구

데이터 디렉터리에는 개인 메시지와 로그인 정보가 포함되며 **애플리케이션 수준 저장 암호화는 구현되지 않았습니다.** 운영 호스트의 암호화된 디스크·볼륨, 계정 권한, private 백업을 준비하세요.

백업은 SQLite의 일관된 snapshot 또는 모든 프로세스를 정상 종료한 상태에서 진행하세요. 실행 중인 `state.sqlite3` 파일만 복사하면 WAL의 최신 데이터가 누락될 수 있습니다. DB만 분리하지 말고 데이터 디렉터리 전체를 같은 시점으로 보존하세요. 손상·불완전 초기화·결과 불명 상태에서 marker나 lock을 임의로 삭제하면 기존 인증 상태를 잃을 수 있습니다.

원본 네트워크 응답·세션·DB·개인 대화는 저장소나 이슈에 첨부하지 마세요. 버그 보고에는 OS/Rust 버전, 민감정보를 제거한 상태 코드, 합성 데이터 재현 절차를 사용하세요.

## 운영 상태 관찰

Python 3으로 인증된 상태 API를 주기적으로 기록할 수 있습니다. 토큰 파일은 `token` 문자열을 포함한 JSON이며 `0600` 권한이 필요합니다. `status:read`만 허용한 별도 토큰을 사용하세요.

```sh
python3 scripts/observe.py --token-file /private/path/health-reader.json \
  --output /private/path/health-observation.jsonl --seconds 259200 --interval 60
```

기존 출력 파일을 덮어쓰지 않습니다. 기록에는 연결 여부·수집 건수·대기 구간·갱신 실패 횟수만 포함하고, 대화 내용·사용자 이름·토큰은 포함하지 않습니다. 절전·종료로 생긴 관찰 공백은 연속 정상 운영으로 계산하지 않습니다.

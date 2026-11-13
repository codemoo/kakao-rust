# kakao-rust

[![CI](https://github.com/codemoo/kakao-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/codemoo/kakao-rust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

카카오톡 메시지와 친구 목록을 별도 SQLite에 저장하고, 인증된 API로 조회·검색·텍스트 발송을 제공하는 Rust 셀프 호스팅 서버입니다. macOS·Linux·Windows(WSL2)를 지원합니다.

- 새 메시지 상시 수집, 수정·삭제 반영과 연결 복구
- 채팅방·발신자·기간별 조회, 본문 검색과 변경 알림(SSE)
- 친구·연락처 이름, 참여자·차단 목록 조회
- 일반 1:1·그룹 채팅의 텍스트 발송과 결과 확인
- 이미지·파일 메타데이터 조회, API 요청 시에만 내용 다운로드
- 서비스별 토큰·권한·방 제한, Tailscale 비공개 HTTPS 접근

## 설치

Rust 1.88 이상과 C 컴파일러·링커가 필요합니다. Windows에서는 [WSL2의 Ubuntu 환경](deploy/README.md#windowswsl2)을 사용합니다.

```sh
git clone https://github.com/codemoo/kakao-rust.git
cd kakao-rust
cargo build --release --locked
export KAKAO_DATA_DIR="$HOME/.local/share/kakao-rust/data"
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" init
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" device init --catalog config/device-catalog.json
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" auth login
```

계정·비밀번호는 터미널에서 입력하고 휴대전화 승인은 CLI 안내를 따릅니다. 이후에는 저장된 세션을 사용합니다. 데이터 경로는 저장소·동기화 폴더 밖에 두세요. DB·세션은 자체 암호화되지 않으므로 호스트의 디스크 암호화와 접근 제한이 필요합니다.

## 실행

기존 대화가 필요하면 수집기 시작 전에 [복원 절차](docs/USAGE.md#초기-상태-관찰과-기존-대화-복원)를 진행합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" native run
```

다른 터미널에서 조회 토큰을 발급하고 API를 실행합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" token issue \
  --label reader --session-account --all-rooms \
  --scope status:read,rooms:read,messages:read,friends:read,attachments:read \
  --expires-in 86400
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" serve --bind 127.0.0.1:8787
```

수집기와 API는 같은 데이터 디렉터리를 사용합니다. 수집기는 계정당 하나만 실행합니다. 토큰은 발급 시 한 번 표시되며 모든 API 요청에 `Authorization: Bearer <API_TOKEN>`이 필요합니다. Tailscale 접근에도 API 인증이 적용됩니다.

## API

```sh
curl -fsS -G 'http://127.0.0.1:8787/v1/messages' \
  -H "Authorization: Bearer $API_TOKEN" \
  --data-urlencode 'room_id=ROOM_ID' \
  --data-urlencode 'sender_id=USER_ID' \
  --data-urlencode 'limit=100'
```

방·발신자 조건을 생략하면 토큰에 허용된 전체 메시지를 조회합니다. ID는 문자열이며 시간은 Unix 밀리초입니다. 목록 응답의 `next_cursor`로 다음 페이지를 조회합니다.

발송 범위는 일반 텍스트입니다. 별도 `messages:write` 권한과 `Idempotency-Key`가 필요하며, 접수 응답 후 상태가 `sent`인지 확인해야 합니다. [API 참조](docs/API.md)에 전체 경로·권한·조회 조건과 [텍스트 발송 절차](docs/API.md#텍스트-발송)를 정리했습니다.

## 문서

| 문서 | 내용 |
| --- | --- |
| [설치와 운영](docs/USAGE.md) | 인증·복원·수집·백업 |
| [API 참조](docs/API.md) | 조회·발송·첨부파일·변경 알림 |
| [배포](deploy/README.md) | 자동 시작·Tailscale·Windows(WSL2) |
| [지원 범위](docs/PARITY.md) | 기능별 제한과 미지원 조건 |
| [검증 기록](docs/TESTING.md) | 합성 검사와 실계정 확인 범위 |
| [프로젝트 범위](PLAN.md) · [개발 지침](AGENTS.md) | 현재 범위·보류 항목·유지할 계약 |

로컬 검사: `./scripts/check.sh`

## 책임과 라이선스

이 프로젝트는 카카오톡 서비스와의 상호운용성을 위한 독립적인 비공식 Rust 구현입니다. 카카오와 제휴 관계가 없으며, 카카오의 승인이나 보증을 받지 않았습니다. 관련 법률과 서비스 이용약관을 준수할 책임은 사용자 본인에게 있습니다.

[MIT 라이선스](LICENSE)로 제공하며 동작을 보증하지 않습니다.

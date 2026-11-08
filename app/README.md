# SigmaDesk

Parsec처럼 쓰는 원격 데스크톱: 로그인 → 내 컴퓨터 목록 → **접속** 한 번. 화면 송출은 RustDesk 엔진이 맡고,
계정과 노드 목록은 직접 운영하는 SigmaDesk 서버가 맡습니다. 분석 내용은 `MECHANICS.md`에 있습니다.

## Docker로 한 번에 실행

```
docker compose up -d --build     # 시작 (RustDesk hbbs + hbbr + SigmaDesk 서버)
docker compose ps                # 상태
docker compose logs sigmadesk-server   # 웹 주소가 출력됩니다
docker compose down              # 중지 (데이터는 볼륨에 남음)
```

`.env` 의 `PUBLIC_HOST` 를 다른 컴퓨터가 이 서버에 닿는 주소로 바꾸세요. 열리는 포트: 21115-21119(TCP), 21116(UDP), 21180(TCP).
웹: `http://PUBLIC_HOST:21180/account` (사용자), `/admin` (관리자), `/g/<노드>/<비밀값>/` (공유 링크).

## 원격 노드 설치 (예: 10.10.1.92) — RDP 대신 SigmaDesk로 제어

1. 관리자 콘솔(`http://10.10.3.7:21180/admin`) → **노드 등록 키** → 이름을 넣고 **키 만들기**.
2. 표시된 두 줄을, 지금 RDP로 들어가 있는 그 노드에서 **관리자 PowerShell** 로 실행합니다.
   (RustDesk 설치 → SigmaDesk 클라이언트 설치 → 서버 자동 등록 → 부팅 시 자동 실행)
   무인 접속을 원하면 끝에 `-NodePassword <비밀번호>` 를 붙입니다.
   노드가 인터넷에 못 나가면 `-RustDeskInstaller <설치파일 경로>` 로 RustDesk 설치 파일을 직접 줍니다.
3. 관리자 콘솔 노드 목록에 그 컴퓨터(주소 10.10.1.92)가 나타나면 **SigmaDesk로 제어** 를 누릅니다.
   관리자 PC에는 SigmaDesk 앱(관리자 계정 로그인, 설정 → 'sigmadesk:// 링크 등록')과 RustDesk가 있어야 합니다.
4. 제거: 노드에서 `install-node.ps1 -Uninstall`.

## 서버 구성 (자체 서버)

1. RustDesk 서버(`hbbs`, `hbbr`)를 서버 컴퓨터에 띄웁니다. 포트 21115-21117 (TCP), 21116 (UDP).
2. SigmaDesk 서버를 띄웁니다:

   ```
   sigmadesk-server --port 21180 --rustdesk-host my.server.com --rustdesk-key <hbbs의 id_ed25519.pub 내용>
   ```

   * `http://my.server.com:21180/` : 설치 안내 웹
   * `http://my.server.com:21180/nodes` : 공개된 온라인 노드 (접속 버튼 = `sigmadesk://connect/<노드>`)
   * `http://my.server.com:21180/account` : 사용자별 웹 페이지 — 내 컴퓨터 목록·공개/제거, 비밀번호 변경,
     모든 기기 로그아웃 (`/login` 에서 로그인 또는 가입)
   * `http://my.server.com:21180/admin` : 전체 관리자 콘솔 — 사용자 정지/해제, 관리자 지정, 비밀번호 초기화,
     삭제, 모든 노드 관리, 서버 설정 보기. **이 서버에서 처음 만든 계정이 관리자**가 됩니다.
   * API: `POST /v2/signup`, `POST /v2/auth`, `GET /me`, `GET /v2/hosts?mode=desktop`,
     `POST /v2/hosts/heartbeat`, `POST /v2/hosts/remove`
   * 데이터는 `sigmadesk-server.json`에 저장됩니다.

## 앱

* `sigmadesk` : 로그인 화면에서 서버 주소를 넣고 가입/로그인.
* 원격으로 들어갈 PC: **호스트** 탭에서 '온라인에 등록'을 켜고 RustDesk ID를 넣습니다 (30초마다 하트비트).
* 접속하는 PC: **컴퓨터** 탭에서 **접속**. 설정 탭의 'RustDesk에 서버 적용'으로 RustDesk가 자체 서버를 쓰게 합니다.
* 옵션: `--demo` (체험 데이터), `--tab host|settings|guide`, `--screenshot 파일.png`.

# SigmaDesk — what we learned from Parsec (150-104a)

All values below come from static reading of `parsec-windows.exe` (NSIS installer) and the
app library it installs, `parsecd-150-104a.dll` (sha256 `8c8c4299…8f6f`, x64). Addresses are in
that DLL unless marked "installer". Nothing was run. "estimated" means we looked and did not find
it, so SigmaDesk picks its own value.

## 1. What gets installed (installer script, block 0 of the NSIS data)

| Part | Role |
|---|---|
| `parsecd.exe` | small loader; reads `appdata.json` → `{so_name: "parsecd-150-104a.dll", entry_symbol: "wx_main", hash}` and starts the DLL. Lets the app update itself by swapping the DLL. |
| `parsecd-150-104a.dll` | the whole app: UI, hosting, client, network |
| `pservice.exe` | Windows service `Parsec` (`sc create Parsec … start= auto`), lets the host work on the login screen ("Per Computer" install) |
| `parsec-vud.exe`, `parsec-vdd.exe` | optional virtual USB and virtual display drivers (headless hosts) |
| `teams.exe` | team-computer provisioning (`/team_computer_key= /team_id= /team_group_id= /user_email=`) |

Installer also: firewall rule `Parsec` for `parsecd.exe` (in, all profiles); URL protocols
`parsec://` and `parsecd://` → `parsecd.exe "%1"`; `HKCU\…\Run` autostart; `config.txt` /
`config.json` in `%APPDATA%\Parsec` (or ProgramData for per-computer).
Two install types: **Per User** and **Per Computer** (same account for all users, works on the
Windows login screen).

Team computers (installer script + `FUN_180005d60`): installer flags `/team_id=`,
`/team_computer_key=`, `/team_group_id=`, `/user_email=`, `/guest_access=`, `/percomputer`,
`/silent`. Per Computer writes `setup.json` `{"useProgramData": true}`. The app registers the
machine with `POST /teams/%s/machines`, header `X-Machine-Key: <key>`, body
`{name: <computer name>, team_guest_access: false}`. Start-up is the `HKCU\…\Run` entry
`parsecd.exe app_silent=1`, plus the `Parsec` service (`pservice.exe`) for the login screen.

**SigmaDesk:** one program `sigmadesk.exe` (client + host UI) and one `sigmadesk-server.exe`
(our own back-end). The engine is the installed RustDesk program.
Nodes are set up the team-computer way:
* The admin console makes a **node key** (`/admin`, "노드 등록 키": key, team, owner = that
  admin, use count).
* `install-node.ps1` is downloaded from the server. It fetches `sigmadesk.exe` from
  `/download/`, installs RustDesk silently if missing and can set a permanent RustDesk password.
* It runs `sigmadesk.exe --provision <server> <team> <key> --per-computer`. That calls
  `POST /teams/<team>/machines` with `X-Machine-Key` and the same body as Parsec. It saves the
  session in `%ProgramData%\SigmaDesk\config.json` (Parsec's useProgramData), turns hosting on and
  points RustDesk at our hbbs/hbbr.
* It registers a start-up task that runs `sigmadesk.exe --host-service` as SYSTEM. This is our
  stand-in for `app_silent=1` plus the service: no window, heartbeats every 30 s, Parsec's retry
  rule on failure.
* The reply rule comes from Ghidra `FUN_180005f60`, called from the login screen
  `sub_18001bc56`:
  * Only **HTTP 201** (0xc9) is success. The body must be `{"data": {"id": "<string>"}}` (keys
    at 0x18027f644 "data" and 0x18027f69c "id"); the id is copied into a 0x41-byte buffer.
  * On 401 it shows the body's `"error"` text with "Error [%d]".
  * Otherwise it shows "Failed request to %s. %s" with: -800 → "Please check your internet
    connection.", 401/403 → "Please try logging out and logging back in.", 412 → "You must
    re-authenticate.", anything else → "Please wait a moment and try again.".
  * SigmaDesk's server answers exactly `201 {"data":{"id": <machine session>}}`. The client
    accepts only that, then reads the owner from `/me`, and shows the same per-code advice (in
    Korean) for every failed request.
* Sessions: `user.bin` keeps `session_id` in a 0x41-byte buffer (`FUN_1800c6220`; it also reads
  `team_id` and the SAML `sso_url` / `saml_request_id`), so ids are up to 64 characters. SigmaDesk
  sessions are now exactly 64.
* Silent start (Ghidra `FUN_1800731f0`): Parsec relaunches itself with `"app_silent=1"`, joined to
  any other arguments as `%s:%s`. Starts from its service or loader (`SERVICE_LAUNCHED_`,
  `LOADER_V`, `PARSEC_IPC_` in the arguments) are always silent. `sigmadesk.exe` treats
  `app_silent=1` like `--host-service`.

Admins see **every** node in the app and in the console. Each node row shows the address the node
reports (`lan_ip`) and a "SigmaDesk로 제어" button (`sigmadesk://connect/<peer_id>`). The button
opens the SigmaDesk app on the admin's computer, which starts RustDesk for that node, instead of an
RDP session.

## 2. Accounts and the computer list (REST API, "kessel-api")

* API host = `kessel-api.` + environment domain (`parsec.app` by default; `app_environment`
  picks one of 6 environments) — `sub_18004c820`.
* Every request carries headers `X-Parsec-OS`, `X-Parsec-OS-Version`, `X-Parsec-Platform: windows`,
  `X-Parsec-App-Version: 150-104a`, `X-Parsec-Device-ID` (`sub_180003d20`).
* **Login** `POST /v2/auth` JSON `{email, password, session_scopes:["ws.host","ws.client","api.writer"], host_peer_id?}`
  (`sub_180003d20`). Also `/auth/sessions`, `/auth/sessions/elevate`, `/v2/saml/login/%s` (SSO),
  `/me/send-confirmation-email`. Error codes include `TFA_REQUIRED`, `USER_UNCONFIRMED`,
  `INVALID_SESSION`, `NO_PERMISSION`.
* **Computer list** `GET /v2/hosts?mode=desktop` with `Authorization: Bearer <session>`
  (Ghidra `FUN_18002dd60`; the call sits at 0x18002dd85). Refreshed every **20000 ms** (double
  at 0x180362be0). After a failed request the wait is multiplied by **1.5** (double at
  0x180362aa0) up to **60000 ms** (0x180362c10); a success resets it to 20000 ms. HTTP **429**
  (0x1ad) raises a "rate limited" event.
  Response `data[]` items (parser `sub_18000389c`, at most **256** hosts):
  `players`, `name`, `peer_id`, `build`, `self`, `guest_access`, `event_name`,
  `user{name,id}`, `team_id`, `has_avatar`. Control characters in names become `?`.
* **Log out** = `DELETE /auth/sessions` with the Bearer session (Ghidra `FUN_180031a60`, the
  "DELETE" string is used at 0x180031ec8). It sits behind a "Log Out / Cancel" confirmation and the
  `app_can_logout` config key; in client-mode the button reads "Disable client-mode to log out".
* **Re-confirm ("elevate")** = `PATCH /auth/sessions/elevate` with `{password, tfa?}` and the
  Bearer session (Ghidra `FUN_18002f860`; "PATCH" used at 0x18002feb1 / 0x18003006e). The popup
  title is "Authentication Required"; the text is "You must re-authenticate to make connections",
  or "…, but can still host" when hosting is allowed (`FUN_180030150`). So a session can be
  valid for hosting but not for connecting until the password (and a "Multi-factor
  Authentication Code" when required) is entered again. SSO accounts use `/v2/saml/elevate`.
  The login body also carries `tfa` (key at 0x18027f730, used by `sub_180003d20`).
* **How an account is shown**: `name#id` ("Log in as %s#%u to connect to other computers.",
  `FUN_18002f860`).
* **Confirm e-mail**: `POST /me/send-confirmation-email` with an empty JSON body
  (`FUN_18002e220`). **Team computer provisioning**: `POST /teams/%s/machines` with an
  `X-Machine-Key` header and `{name, team_guest_access:false}` (`FUN_180005d60`).
* Error codes kept together in .rdata from 0x180362660: `HOST_NOT_FOUND`, `TFA_REQUIRED`,
  `USER_UNCONFIRMED`, `INVALID_MSG`, `NO_PERMISSION`, `ACCESSLINK_*`, `TEAM_DEACTIVATED`,
  `INVALID_SESSION`, `OUT_OF_COMPLIANCE` (read through a table; no direct references).
* **Web links** (Ghidra): Settings ends with an "Account" entry that opens
  `https://dash.parsec.app` (`FUN_1800192e0`; the other sections are Client, Host, Approved Apps,
  Network, Secret, Hotkeys, Gamepad, Experimental). The API domain comes from a 6-entry environment
  table (0x144-byte rows starting with "parsec.app"); unknown names fall back to `parsec.app`, and
  hosts are built as `kessel-api.` / `kessel-ws.` + domain (`FUN_18004c820`, `FUN_18004c8b0`).
* **Share links** (`FUN_18002ad10`): your own computer's card has "Share". It makes
  `ws_secret` = random number in [0x7fffffff, 0xffffffff] printed with `%x` (format at
  0x18034dfe8). It builds `https://parsec.gg/g/<peer_id>/<ws_secret>/`, copies it and shows "Share
  link generated and copied to clipboard." for **10000 ms** (double 0x40c3880000000000). "Stop
  Sharing" clears `ws_secret` and shows "Your share link has been invalidated." for **5000 ms**
  (0x40b3880000000000).
* **Card captions** (same function): "This Computer" for the local machine, "Your Computer" when
  the owner is you, "Shared Computer" when there is no owner, otherwise the owner as `%s#%u`;
  badges "TEAMS" / "GUEST ACCESS"; "%u guest%s connected"; an info popup lists PEER ID and BUILD.
* **Links handed to a running app**: the text is searched for `peer_id=` to start a connection
  (`FUN_180091e50`), in the form `peer_id=%s:host_secret=%s:connection_name=%s` (`sub_180055bb0`).
* **/me** polled by a host every random **1 800 000–2 400 000 ms** (30–40 min); it also pushes
  config values (`value` / `default`) for the 139 config keys; HTTP 401/403 logs out
  (`sub_180073500`).
* Others: `/friendships`, `/teams/%s/machines`, `/metrics`, `/me/app-config`.

**SigmaDesk server** keeps this shape: `POST /v2/auth`, `POST /v2/signup`, `GET /v2/hosts?mode=desktop`,
`POST /v2/hosts/heartbeat` (our replacement for the WebSocket `conn_update`), `GET /me`,
`DELETE /auth/sessions` (the app calls it on log out) and `PATCH /auth/sessions/elevate`, plus
an install page `/`, public nodes `/nodes`, each user's page `/account` and the admin console
`/admin` (our stand-in for dash.parsec.app). Accounts show as `name#id` in the pages and the app.
Share links follow Parsec's rule on our server: `<server>/g/<peer_id>/<secret>/`, with the secret
made the same way (random 0x7fffffff–0xffffffff, hex). It reaches the server with the heartbeat,
and is cleared by "공유 중지". The notices last 10000 / 5000 ms. Cards use Parsec's captions
(이 컴퓨터 / 내 컴퓨터 / 공유된 컴퓨터 / name#id), and links may also carry `peer_id=<id>`.
The server prints all web addresses at start-up (using `PUBLIC_HOST` when set). It runs in Docker
next to RustDesk's hbbs and hbbr (`docker compose up -d --build`).
Parsec's elevate rule becomes: an admin may always look at the console, but suspending, deleting,
granting admin or resetting passwords needs a session re-confirmed with the password within the
last 900000 ms (15 min, **estimated** — Parsec keeps its own lifetime on the server). Signing in
with the password counts as a re-confirmation; a server restart forgets them. TOTP codes (`tfa`)
are not implemented yet.

## 3. Signalling (WebSocket, "kessel-ws")

* URL `wss://kessel-ws.<env>/?session_id=%s&role=%s&version=1&build=150-104a&sdk_version=393216`
  (`sub_1800cf9c0`), connect timeout **10000 ms**.
* Reconnect rule (Ghidra `FUN_1800cf9c0`): wait random(t, 2t). t starts at **30000 ms**; after
  each failure, while the failure counter is below **51** (`< 0x33`), t = min(2t, **300000**);
  after that t = **3 600 000 ms** (the wait becomes 1–2 hours). Counter and t reset once the socket
  connects. HTTP 401 on upgrade = bad session; 412 maps to another error; close code 1001 is a
  normal shutdown.
* Messages: `{version:1, action, payload:{from, to, data, attempt_id}}`. Actions dispatched in
  Ghidra `FUN_1800cee50` (code at 0x1800ceed0): `sdk`, `close`, `offer_relay`,
  `offer_cancel_relay`, `answer_relay` (jump table) and `candex_relay` (parsed inline).
  Candidate data: `ip`, `port`, `lan`, `from_stun`, `sync`; an unparsable message gives -8000.
  Offer data carries `ice_ufrag`, `ice_pwd`, `fingerprint`, `aes256`, `creds`, `ver_data`.
* Host status `conn_update` (`sub_1800d0050`): `loader_v, service_v, os_v, platform, app_v,
  sdk_v=393216, device_id, mode (desktop|game), name, desc, game_id, secret, max_players, players,
  public, guests[{guest_id,user_id,gamepad,keyboard,mouse}]`.
* **Connect** (Ghidra `FUN_180034680`, the card's Connect button):
  * It puts the target `peer_id`, an optional `host_secret` and `connection_name` into a
    temporary config layer (3) and forces `client_png_cursor` on in that layer.
  * It calls `FUN_1800d0800` and shows an error for results other than 0 / -4.
  * Then it clears `peer_id` and `host_secret` again, so they are one-shot.
* **Offer** (Ghidra `FUN_1800d0800`):
  * `attempt_id` = 24 random bytes written `%08x-%08x-%08x-%08x-%08x-%08x`.
  * The offer carries `attempt_id` plus `secret` and `access_link_id`. The host secret goes into
    `access_link_id` when it is exactly **27** characters of `0-9A-Za-z`, otherwise into `secret`.
  * With no stream settings, defaults are filled in (several 1s and a 10).
* **SigmaDesk**: every connect makes an attempt id the same way and reports it to
  `POST /v2/attempts` `{attempt_id, peer_id, secret | access_link_id}`. The secret is split by the
  27-character rule.
  * The server accepts it from the node's owner, an admin, anyone for a public node, or anyone
    holding the node's current share secret; others get 403 `NO_PERMISSION`.
  * It keeps the last 200 attempts (**estimated**) as the admin console's "최근 제어 기록"
    (when, who as name#id, node, 직접 / 공유 링크 / 접근 링크, attempt id).
  * Links may carry the secret: `peer_id=..:host_secret=..` (Parsec's form) or
    `sigmadesk://connect/<peer>?secret=..` (used by the share page's 접속 button).
* Incoming connection request (`sub_1800cebc0`): `from, attempt_id, is_owner, skip_approval,
  permissions{gamepad,keyboard,mouse}, user{name,id,has_avatar}, mode`.

**SigmaDesk** reuses these numbers for its own server link: 10000 ms connect timeout; the
computer list follows the x1.5 / 60000 ms rule; heartbeat and /me failures follow the reconnect
rule above exactly (random(t, 2t), doubling to 300000 ms for 51 tries, then 3 600 000 ms).
It re-reads `/me` every random 1 800 000–2 400 000 ms
to pick up engine-server settings, like Parsec's host does.

RustDesk already has the signalling layer — `hbbs` (rendezvous/ID server) plays kessel-ws,
`hbbr` plays the relay. Our server only stores accounts and the node list, and tells the client
which RustDesk ID to dial.

## 4. NAT traversal and ports

* STUN Binding request, magic cookie **0x2112A442**, to `stun.parsec.app` / `stun6.parsec.app`
  port **3478** (`sub_18009c020`), candidates `STUN_RFLX` and `STUN_P2P` (`sub_18009bbd5`).
* **Relays** (Ghidra `FUN_18009adc0`): the relay/STUN list comes from `app_stun_address` as
  `host@port,host@port` — entries split by `,` (byte at 0x180357868), host and port by `@`
  (0x180358bdc), missing port = 3478, at most **20** entries. With no entries (or room left and
  force-relay off) `stun.parsec.app@3478` is added. Parsec's relays are the same hosts as its
  STUN servers; `app_stun_address` / `app_client_stun_address` point it at your own
  (`FUN_180050230`).
* **Force relay** `app_force_relay`: 0 = off ("Force Relay Mode: Off"), odd = "All connections",
  other non-zero = "WAN connections". `network_fast_relay_ping` is read in the same place.

**SigmaDesk:** the relay box in Settings takes the same `host@port,…` list (max 20; ':' also
accepted) and force-relay has Parsec's three modes. RustDesk takes the first relay and has one
"always relay" switch, so both force modes turn it on (that RustDesk option name is estimated).
* Host UDP port = `network_server_start_port`, or when 0, **21000 + random % 2000**
  (`sub_180073500`, `sub_180097480`). UPnP with `network_upnp`. `whitelist.txt` limits guests.

**SigmaDesk:** RustDesk server ports (from RustDesk, not from Parsec — estimated here):
hbbs 21115/21116 (TCP+UDP), hbbr 21117, web 21118/21119. Our registry server defaults to 21180
(estimated, chosen to sit next to them).

## 5. Our own timings (estimated)

* Host heartbeat to our server every 30 s (Parsec sends `conn_update` on change over the socket).
* Server marks a node offline after 90 s without a heartbeat.
* peer_id: 26 base62 characters (Parsec buffer is 32 bytes; exact format unknown).

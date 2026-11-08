//! SigmaDesk registry server: accounts, sessions and the online node list, plus the install web
//! page, a web page for each user (/account) and an admin console for the whole server (/admin).
//! It plays the part of Parsec's "kessel-api" and its dash.parsec.app web site; RustDesk's own
//! hbbs/hbbr servers do the signalling and relaying (MECHANICS.md sections 2-3).
//!
//! sigmadesk-server [--port 21180] [--data sigmadesk-server.json]
//!                  [--rustdesk-host my.server.com] [--rustdesk-key <public key>]
//!
//! The first account created becomes the administrator.

use sha2::{Digest, Sha256};
use sigmadesk::consts::*;
use sigmadesk::proto::*;
use sigmadesk::{account_tag, clean_name, random_id, share_url};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct User {
    id: u32,
    email: String,
    name: String,
    salt: String,
    pw_hash: String,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    disabled: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct HostRec {
    owner: u32,
    beat: Heartbeat,
    last_seen_ms: u64,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Store {
    next_user_id: u32,
    users: Vec<User>,
    hosts: HashMap<String, HostRec>,
    /// session token -> user id
    sessions: HashMap<String, u32>,
    /// Keys that let a computer register itself without a person signing in (Parsec's team
    /// computer provisioning: POST /teams/%s/machines with X-Machine-Key, FUN_180005d60).
    #[serde(default)]
    machine_keys: Vec<MachineKey>,
    /// Recent connect attempts, newest last (the admin console's control log).
    #[serde(default)]
    attempts: Vec<AttemptRec>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AttemptRec {
    attempt_id: String,
    user: u32,
    peer_id: String,
    node_name: String,
    at_ms: u64,
    /// "secret", "access_link" or "" (owner/admin), by Parsec's 27-character rule.
    #[serde(default)]
    via: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct MachineKey {
    key: String,
    team: String,
    /// Account the registered computers belong to (the admin who made the key).
    owner: u32,
    label: String,
    created_ms: u64,
    #[serde(default)]
    uses: u32,
}

#[derive(serde::Deserialize, Default)]
struct MachineRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    team_guest_access: bool,
}

struct State {
    store: Store,
    data_path: String,
    app_config: AppConfig,
    /// session token -> when it was last re-confirmed with the password (Parsec's "elevate");
    /// kept in memory only, so a restart asks again.
    elevated: HashMap<String, u64>,
    /// Folder whose installer files are served at /download/<name>.
    download_dir: String,
    /// "http://<public host>:<port>", used in the install commands the admin console shows.
    public_base: String,
}

impl State {
    fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&self.store) {
            let _ = std::fs::write(&self.data_path, text);
        }
    }
    fn user_by_session(&self, req: &Request) -> Option<User> {
        let token = header(req, "Authorization")?.strip_prefix("Bearer ")?.trim().to_string();
        self.user_by_token(&token)
    }
    /// The signed-in user of a web page (session cookie).
    fn web_user(&self, req: &Request) -> Option<User> {
        self.user_by_token(&cookie_token(req)?)
    }
    fn user_by_token(&self, token: &str) -> Option<User> {
        let uid = *self.store.sessions.get(token)?;
        self.store.users.iter().find(|u| u.id == uid && !u.disabled).cloned()
    }
    fn find_by_email(&self, email: &str) -> Option<User> {
        self.store.users.iter().find(|u| u.email.eq_ignore_ascii_case(email.trim())).cloned()
    }
    /// A new account; the very first one is the administrator.
    fn create_user(&mut self, email: &str, password: &str, name: &str) -> Result<User, (&'static str, &'static str)> {
        let email = email.trim();
        if !email.contains('@') || password.len() < 6 {
            return Err(("INVALID_MSG", "이메일과 6자 이상 비밀번호가 필요합니다"));
        }
        if self.find_by_email(email).is_some() {
            return Err(("EMAIL_TAKEN", "이미 등록된 이메일입니다"));
        }
        self.store.next_user_id += 1;
        let salt = random_id(16);
        let user = User {
            id: self.store.next_user_id,
            email: email.to_string(),
            name: if name.trim().is_empty() { email.to_string() } else { clean_name(name.trim()) },
            pw_hash: hash_pw(&salt, password),
            salt,
            admin: self.store.users.is_empty(),
            disabled: false,
        };
        self.store.users.push(user.clone());
        Ok(user)
    }
    /// A new session. Signing in with the password also counts as a fresh re-confirmation.
    fn new_session(&mut self, uid: u32) -> String {
        let token = random_id(SESSION_ID_LEN);
        self.store.sessions.insert(token.clone(), uid);
        self.elevated.insert(token.clone(), now_ms());
        token
    }
    fn end_sessions_of(&mut self, uid: u32) {
        let gone: Vec<String> = self.store.sessions.iter().filter(|(_, u)| **u == uid).map(|(t, _)| t.clone()).collect();
        for t in gone {
            self.end_session(&t);
        }
    }
    fn end_session(&mut self, token: &str) {
        self.store.sessions.remove(token);
        self.elevated.remove(token);
    }
    fn is_elevated(&self, token: &str) -> bool {
        self.elevated.get(token).map(|t| now_ms().saturating_sub(*t) < ELEVATE_TTL_MS).unwrap_or(false)
    }
    /// PATCH /auth/sessions/elevate: the password again re-confirms this session.
    fn elevate(&mut self, token: &str, user: &User, password: &str) -> bool {
        if hash_pw(&user.salt, password) == user.pw_hash {
            self.elevated.insert(token.to_string(), now_ms());
            true
        } else {
            false
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn hash_pw(salt: &str, pw: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(pw.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn json_reply<T: serde::Serialize>(code: u16, body: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    Response::from_string(text)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
}

fn error(code: u16, err: &str, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_reply(code, &ErrorResponse { error: err.into(), message: msg.into() })
}

fn html(body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
}

fn host_view(rec: &HostRec, users: &[User], viewer_peer: &str, now: u64) -> Host {
    let owner = users.iter().find(|u| u.id == rec.owner);
    let age = now.saturating_sub(rec.last_seen_ms);
    Host {
        peer_id: rec.beat.peer_id.clone(),
        name: clean_name(&rec.beat.name),
        build: rec.beat.app_v.clone(),
        players: rec.beat.players,
        max_players: rec.beat.max_players,
        is_self: rec.beat.peer_id == viewer_peer,
        guest_access: rec.beat.public,
        event_name: String::new(),
        user: HostUser {
            id: rec.owner,
            name: owner.map(|u| u.name.clone()).unwrap_or_default(),
        },
        team_id: String::new(),
        has_avatar: false,
        rustdesk_id: rec.beat.rustdesk_id.clone(),
        online: age < OFFLINE_AFTER_MS,
        public: rec.beat.public,
        desc: rec.beat.desc.clone(),
        platform: rec.beat.platform.clone(),
        last_seen_secs: age / 1000,
    }
}

fn read_json<T: serde::de::DeserializeOwned>(req: &mut Request) -> Option<T> {
    let mut body = String::new();
    req.as_reader().take(64 * 1024).read_to_string(&mut body).ok()?;
    serde_json::from_str(&body).ok()
}

fn handle(state: &Arc<Mutex<State>>, mut req: Request) {
    let url = req.url().to_string();
    let (path, _query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let method = req.method().clone();
    let host_hdr = header(&req, "Host").unwrap_or_else(|| format!("localhost:{REGISTRY_PORT}"));
    let resp = match (&method, path) {
        (Method::Get, "/") => html(install_page(state, &host_hdr)),
        (Method::Get, "/nodes") => html(nodes_page(state)),
        (Method::Post, "/v2/signup") => match read_json::<SignupRequest>(&mut req) {
            Some(s) => {
                let mut st = state.lock().unwrap();
                match st.create_user(&s.email, &s.password, &s.name) {
                    Ok(user) => {
                        let token = st.new_session(user.id);
                        st.save();
                        json_reply(201, &AuthResponse { session_id: token, user_id: user.id, user_name: user.name })
                    }
                    Err((code, msg)) => error(if code == "EMAIL_TAKEN" { 409 } else { 400 }, code, msg),
                }
            }
            None => error(400, "INVALID_MSG", "이메일과 6자 이상 비밀번호가 필요합니다"),
        },
        (Method::Post, "/v2/auth") => match read_json::<AuthRequest>(&mut req) {
            Some(a) => {
                let mut st = state.lock().unwrap();
                match st.find_by_email(&a.email) {
                    Some(u) if u.disabled => error(403, "USER_DISABLED", "관리자가 정지한 계정입니다"),
                    Some(u) if hash_pw(&u.salt, &a.password) == u.pw_hash => {
                        let token = st.new_session(u.id);
                        st.save();
                        json_reply(200, &AuthResponse { session_id: token, user_id: u.id, user_name: u.name })
                    }
                    _ => error(401, "INVALID_CREDENTIALS", "이메일 또는 비밀번호가 맞지 않습니다"),
                }
            }
            None => error(400, "INVALID_MSG", "잘못된 요청"),
        },
        (Method::Get, "/me") => {
            let st = state.lock().unwrap();
            match st.user_by_session(&req) {
                Some(u) => json_reply(200, &MeResponse { id: u.id, name: u.name, email: u.email, admin: u.admin, app_config: st.app_config.clone() }),
                None => error(401, "INVALID_SESSION", "다시 로그인하세요"),
            }
        }
        (Method::Get, "/v2/hosts") => {
            let st = state.lock().unwrap();
            match st.user_by_session(&req) {
                Some(u) => {
                    let viewer = header(&req, "X-SigmaDesk-Peer-Id").unwrap_or_default();
                    let now = now_ms();
                    let mut data: Vec<Host> = st
                        .store
                        .hosts
                        .values()
                        // Admins see every node so the admin tools can control any of them.
                        .filter(|r| u.admin || r.owner == u.id || r.beat.public)
                        .map(|r| host_view(r, &st.store.users, &viewer, now))
                        .collect();
                    data.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
                    data.truncate(MAX_HOSTS);
                    json_reply(200, &HostsResponse { data })
                }
                None => error(401, "INVALID_SESSION", "다시 로그인하세요"),
            }
        }
        (Method::Post, "/v2/hosts/heartbeat") => {
            let beat = read_json::<Heartbeat>(&mut req);
            let mut st = state.lock().unwrap();
            match (st.user_by_session(&req), beat) {
                (Some(u), Some(b)) if !b.peer_id.is_empty() => {
                    if let Some(old) = st.store.hosts.get(&b.peer_id) {
                        if old.owner != u.id {
                            return respond(req, error(403, "NO_PERMISSION", "다른 계정의 컴퓨터입니다"));
                        }
                    }
                    st.store.hosts.insert(b.peer_id.clone(), HostRec { owner: u.id, beat: b, last_seen_ms: now_ms() });
                    st.save();
                    json_reply(200, &serde_json::json!({"ok": true}))
                }
                (None, _) => error(401, "INVALID_SESSION", "다시 로그인하세요"),
                _ => error(400, "INVALID_MSG", "peer_id가 필요합니다"),
            }
        }
        (Method::Post, "/v2/hosts/remove") => {
            let rm = read_json::<RemoveHost>(&mut req);
            let mut st = state.lock().unwrap();
            match (st.user_by_session(&req), rm) {
                (Some(u), Some(r)) => {
                    let owned = st.store.hosts.get(&r.peer_id).map(|h| h.owner == u.id).unwrap_or(false);
                    if owned {
                        st.store.hosts.remove(&r.peer_id);
                        st.save();
                        json_reply(200, &serde_json::json!({"ok": true}))
                    } else {
                        error(404, "HOST_NOT_FOUND", "컴퓨터를 찾을 수 없습니다")
                    }
                }
                _ => error(401, "INVALID_SESSION", "다시 로그인하세요"),
            }
        }
        // ---- team computer provisioning (Parsec: POST /teams/%s/machines + X-Machine-Key)
        (Method::Post, p) if p.starts_with("/teams/") && p.ends_with("/machines") => {
            let team = p.trim_start_matches("/teams/").trim_end_matches("/machines").to_string();
            let key = header(&req, "X-Machine-Key").unwrap_or_default();
            let body: MachineRequest = read_json(&mut req).unwrap_or_default();
            let mut st = state.lock().unwrap();
            let found = st.store.machine_keys.iter().position(|k| !key.is_empty() && k.key == key && k.team == team);
            match found {
                Some(i) => {
                    let owner = st.store.machine_keys[i].owner;
                    match st.store.users.iter().find(|u| u.id == owner && !u.disabled).cloned() {
                        Some(u) => {
                            st.store.machine_keys[i].uses += 1;
                            let token = st.new_session(u.id);
                            st.save();
                            println!("팀 컴퓨터 등록: '{}' (팀 {team}, 게스트 접근 {})", clean_name(&body.name), body.team_guest_access);
                            // Parsec's client accepts only 201 with {"data": {"id": ...}} here.
                            json_reply(MACHINE_CREATED_STATUS, &MachineResponse { data: MachineData { id: token } })
                        }
                        None => error(403, "TEAM_DEACTIVATED", "키를 만든 계정이 정지되었거나 없습니다"),
                    }
                }
                None => error(401, "NO_PERMISSION", "노드 등록 키 또는 팀이 맞지 않습니다"),
            }
        }
        // ---- connect attempts (our record of Parsec's offer + attempt_id, FUN_1800d0800)
        (Method::Post, "/v2/attempts") => {
            let report = read_json::<AttemptReport>(&mut req);
            let mut st = state.lock().unwrap();
            match (st.user_by_session(&req), report) {
                (Some(u), Some(a)) => {
                    let host = st.store.hosts.get(&a.peer_id).cloned();
                    match host {
                        Some(h) => {
                            let shared = !h.beat.share_secret.is_empty()
                                && (a.secret == h.beat.share_secret || a.access_link_id == h.beat.share_secret);
                            if !(u.admin || h.owner == u.id || h.beat.public || shared) {
                                error(403, "NO_PERMISSION", "이 노드를 제어할 권한이 없습니다")
                            } else {
                                let via = if !a.access_link_id.is_empty() { "access_link" } else if !a.secret.is_empty() { "secret" } else { "" };
                                st.store.attempts.push(AttemptRec {
                                    attempt_id: a.attempt_id.chars().take(64).collect(),
                                    user: u.id,
                                    peer_id: a.peer_id.clone(),
                                    node_name: h.beat.name.clone(),
                                    at_ms: now_ms(),
                                    via: via.into(),
                                });
                                let excess = st.store.attempts.len().saturating_sub(ATTEMPT_LOG_KEEP);
                                st.store.attempts.drain(..excess);
                                st.save();
                                json_reply(201, &serde_json::json!({"ok": true}))
                            }
                        }
                        None => error(404, "HOST_NOT_FOUND", "노드를 찾을 수 없습니다"),
                    }
                }
                (None, _) => error(401, "INVALID_SESSION", "다시 로그인하세요"),
                _ => error(400, "INVALID_MSG", "attempt_id와 peer_id가 필요합니다"),
            }
        }
        // ---- installer files for nodes: /download/<name>
        (Method::Get, p) if p.starts_with("/download/") => {
            let name = p.trim_start_matches("/download/");
            let allowed = ["sigmadesk.exe", "install-node.ps1"];
            let st = state.lock().unwrap();
            let path = std::path::Path::new(&st.download_dir).join(name);
            match (allowed.contains(&name), std::fs::read(&path)) {
                (true, Ok(bytes)) => {
                    let kind = if name.ends_with(".ps1") { "text/plain; charset=utf-8" } else { "application/octet-stream" };
                    Response::from_data(bytes)
                        .with_header(Header::from_bytes("Content-Type", kind).unwrap())
                        .with_header(Header::from_bytes("Content-Disposition", format!("attachment; filename={name}")).unwrap())
                }
                _ => error(404, "NOT_FOUND", "설치 파일이 서버에 없습니다 (download 폴더 확인)"),
            }
        }
        // ---- share links: /g/<peer_id>/<secret>/ (Parsec: parsec.gg/g/%s/%s/)
        (Method::Get, p) if p.starts_with("/g/") => {
            let parts: Vec<&str> = p.trim_matches('/').split('/').collect();
            let st = state.lock().unwrap();
            let found = match parts.as_slice() {
                ["g", peer, secret] => st
                    .store
                    .hosts
                    .get(*peer)
                    .filter(|h| !h.beat.share_secret.is_empty() && h.beat.share_secret == *secret),
                _ => None,
            };
            match found {
                Some(rec) => html(share_page(&st, rec)),
                None => html(layout(
                    "공유 링크",
                    None,
                    "",
                    false,
                    "<h1>링크가 만료되었습니다</h1><div class=sub>이 공유 링크는 중지되었거나 잘못되었습니다. 컴퓨터 주인에게 새 링크를 받으세요.</div>",
                ))
                .with_status_code(404),
            }
        }
        // ---- Parsec's session endpoints: log out, and re-confirm with the password
        (Method::Delete, LOGOUT_PATH) => {
            let mut st = state.lock().unwrap();
            match header(&req, "Authorization").and_then(|h| h.strip_prefix("Bearer ").map(|t| t.trim().to_string())) {
                Some(token) if st.store.sessions.contains_key(&token) => {
                    st.end_session(&token);
                    st.save();
                    json_reply(200, &serde_json::json!({"ok": true}))
                }
                _ => error(401, "INVALID_SESSION", "이미 로그아웃되었습니다"),
            }
        }
        (Method::Patch, ELEVATE_PATH) => {
            let body = read_json::<ElevateRequest>(&mut req);
            let mut st = state.lock().unwrap();
            let token = header(&req, "Authorization").and_then(|h| h.strip_prefix("Bearer ").map(|t| t.trim().to_string()));
            match (st.user_by_session(&req), token, body) {
                (Some(u), Some(t), Some(b)) if st.elevate(&t, &u, &b.password) => json_reply(200, &serde_json::json!({"ok": true})),
                (Some(_), _, _) => error(401, "INVALID_CREDENTIALS", "비밀번호가 맞지 않습니다"),
                _ => error(401, "INVALID_SESSION", "다시 로그인하세요"),
            }
        }
        // ---- web pages: sign-in, each user's own page, the admin console
        (Method::Get, "/login") => {
            let st = state.lock().unwrap();
            match st.web_user(&req) {
                Some(_) => redirect("/account", None),
                None => html(login_page("")),
            }
        }
        (Method::Post, "/login") | (Method::Post, "/signup") if !same_origin(&req) => forbidden(),
        (Method::Post, "/login") => {
            let f = read_form(&mut req);
            let mut st = state.lock().unwrap();
            match st.find_by_email(field(&f, "email")) {
                Some(u) if u.disabled => html(login_page("관리자가 정지한 계정입니다")),
                Some(u) if hash_pw(&u.salt, field(&f, "password")) == u.pw_hash => {
                    let token = st.new_session(u.id);
                    st.save();
                    redirect(if u.admin { "/admin" } else { "/account" }, Some(&token))
                }
                _ => html(login_page("이메일 또는 비밀번호가 맞지 않습니다")),
            }
        }
        (Method::Post, "/signup") => {
            let f = read_form(&mut req);
            let mut st = state.lock().unwrap();
            match st.create_user(field(&f, "email"), field(&f, "password"), field(&f, "name")) {
                Ok(u) => {
                    let token = st.new_session(u.id);
                    st.save();
                    redirect(if u.admin { "/admin" } else { "/account" }, Some(&token))
                }
                Err((_, msg)) => html(login_page(msg)),
            }
        }
        (Method::Get, "/logout") => {
            let mut st = state.lock().unwrap();
            if let Some(t) = cookie_token(&req) {
                st.end_session(&t);
                st.save();
            }
            redirect("/login", Some(""))
        }
        (Method::Get, "/account") => {
            let st = state.lock().unwrap();
            match st.web_user(&req) {
                Some(u) => html(account_page(&st, &u, &host_hdr, "")),
                None => redirect("/login", None),
            }
        }
        (Method::Post, p) if p.starts_with("/account/") || p.starts_with("/admin/") => {
            let p = p.to_string();
            let f = read_form(&mut req);
            let mut st = state.lock().unwrap();
            match st.web_user(&req) {
                None => redirect("/login", None),
                Some(_) if !same_origin(&req) => forbidden(),
                Some(u) if p.starts_with("/account/") => account_action(&mut st, &u, &p, &f, &host_hdr),
                Some(u) if u.admin => {
                    let token = cookie_token(&req).unwrap_or_default();
                    if p == "/admin/elevate" {
                        let msg = if st.elevate(&token, &u, field(&f, "password")) {
                            "다시 확인했습니다. 관리 작업을 할 수 있습니다."
                        } else {
                            "비밀번호가 맞지 않습니다"
                        };
                        html(admin_page(&st, &u, msg, st.is_elevated(&token)))
                    } else if !st.is_elevated(&token) {
                        // Parsec's rule: a session that isn't re-confirmed may look, not act.
                        html(admin_page(&st, &u, "인증이 필요합니다: 관리 작업 전에 비밀번호를 다시 입력하세요", false))
                    } else {
                        admin_action(&mut st, &u, &p, &f, true)
                    }
                }
                Some(_) => forbidden(),
            }
        }
        (Method::Get, "/admin") => {
            let st = state.lock().unwrap();
            match st.web_user(&req) {
                Some(u) if u.admin => {
                    let elevated = st.is_elevated(&cookie_token(&req).unwrap_or_default());
                    html(admin_page(&st, &u, "", elevated))
                }
                Some(_) => forbidden(),
                None => redirect("/login", None),
            }
        }
        (Method::Options, _) => Response::from_string("")
            .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
            .with_header(Header::from_bytes("Access-Control-Allow-Headers", "Authorization, Content-Type, X-SigmaDesk-Peer-Id").unwrap()),
        _ => error(404, "NOT_FOUND", "없는 주소입니다"),
    };
    respond(req, resp);
}

fn respond(req: Request, resp: Response<std::io::Cursor<Vec<u8>>>) {
    let _ = req.respond(resp);
}

const PAGE_STYLE: &str = "body{font-family:'Malgun Gothic',system-ui,sans-serif;background:#111318;color:#e6e8ee;margin:0}\
main{max-width:860px;margin:0 auto;padding:40px 24px}h1{font-size:30px;margin:0 0 6px}\
.sub{color:#9aa1b2;margin-bottom:32px}.card{background:#1b1e26;border-radius:12px;padding:20px 24px;margin:14px 0}\
.n{display:inline-block;width:28px;height:28px;border-radius:14px;background:#3b82f6;color:#fff;text-align:center;line-height:28px;margin-right:10px;font-weight:700}\
code{background:#0c0e12;padding:2px 6px;border-radius:5px;color:#9fd0ff}a{color:#6cb2ff}\
.btn{display:inline-block;background:#3b82f6;color:#fff;padding:9px 16px;border-radius:8px;text-decoration:none;font-weight:600}\
.node{display:flex;justify-content:space-between;align-items:center}.dot{display:inline-block;width:9px;height:9px;border-radius:5px;margin-right:8px}\
nav a{margin-right:18px}";

fn install_page(state: &Arc<Mutex<State>>, host_hdr: &str) -> String {
    let st = state.lock().unwrap();
    let id_server = if st.app_config.rustdesk_id_server.is_empty() {
        format!("(설정 안 됨: --rustdesk-host 로 지정, 포트 {RUSTDESK_ID_PORT})")
    } else {
        st.app_config.rustdesk_id_server.clone()
    };
    let online = st.store.hosts.values().filter(|h| now_ms().saturating_sub(h.last_seen_ms) < OFFLINE_AFTER_MS).count();
    format!(
        "<!doctype html><html lang=ko><head><meta charset=utf-8><title>SigmaDesk 설치</title><style>{PAGE_STYLE}</style></head><body><main>\
<nav><a href=\"/\">설치</a><a href=\"/nodes\">온라인 노드</a><a href=\"/account\">내 페이지 / 로그인</a></nav>\
<h1>SigmaDesk 설치</h1><div class=sub>자체 서버로 운영되는 원격 데스크톱. 지금 온라인 노드 {online}대.</div>\
<div class=card><span class=n>1</span><b>RustDesk 설치</b><p>원격 화면 엔진입니다. <a href=\"https://github.com/rustdesk/rustdesk/releases\">RustDesk 릴리스</a>에서 설치하세요.</p></div>\
<div class=card><span class=n>2</span><b>SigmaDesk 앱 실행</b><p>로그인 화면의 <b>서버 주소</b>에 <code>http://{host_hdr}</code> 를 넣고 계정을 만드세요.</p></div>\
<div class=card><span class=n>3</span><b>엔진 서버 적용</b><p>설정 → <b>RustDesk에 서버 적용</b>을 누르면 ID 서버 <code>{id_server}</code> 와 릴레이가 자동으로 들어갑니다.</p></div>\
<div class=card><span class=n>4</span><b>호스팅 켜기</b><p>원격으로 들어갈 컴퓨터에서 <b>호스트</b> 탭의 '이 컴퓨터를 온라인에 등록'을 켜면 목록에 나타납니다. 다른 컴퓨터에서는 목록의 <b>접속</b> 한 번이면 됩니다.</p></div>\
<div class=card><b>웹 주소</b><p>사용자 페이지: <a href=\"/account\">http://{host_hdr}/account</a> &nbsp;(로그인 <a href=\"/login\">http://{host_hdr}/login</a>)<br>\
관리자 콘솔: <a href=\"/admin\">http://{host_hdr}/admin</a> &nbsp;<span class=sub>이 서버에서 처음 만든 계정이 관리자입니다.</span></p></div>\
<p><a class=btn href=\"/nodes\">공개된 온라인 노드 보기</a></p></main></body></html>"
    )
}

fn nodes_page(state: &Arc<Mutex<State>>) -> String {
    let st = state.lock().unwrap();
    let now = now_ms();
    let mut rows: Vec<Host> = st
        .store
        .hosts
        .values()
        .filter(|h| h.beat.public)
        .map(|h| host_view(h, &st.store.users, "", now))
        .collect();
    rows.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
    let mut list = String::new();
    for h in &rows {
        let color = if h.online { "#22c55e" } else { "#6b7280" };
        let state_text = if h.online { "온라인".to_string() } else { format!("오프라인 · {}초 전", h.last_seen_secs) };
        list.push_str(&format!(
            "<div class='card node'><div><span class=dot style='background:{color}'></span><b>{}</b> <span class=sub>· {} · {}</span><br><small>RustDesk ID <code>{}</code></small></div>\
<a class=btn href=\"sigmadesk://connect/{}\">접속</a></div>",
            escape(&h.name), escape(&h.user.name), state_text, escape(&h.rustdesk_id), escape(&h.peer_id)
        ));
    }
    if rows.is_empty() {
        list.push_str("<div class=card>아직 공개된 노드가 없습니다. 호스트 탭에서 '설치 웹에 공개'를 켜면 여기에 보입니다.</div>");
    }
    format!(
        "<!doctype html><html lang=ko><head><meta charset=utf-8><meta http-equiv=refresh content=20><title>SigmaDesk 노드</title><style>{PAGE_STYLE}</style></head><body><main>\
<nav><a href=\"/\">설치</a><a href=\"/nodes\">온라인 노드</a><a href=\"/account\">내 페이지 / 로그인</a></nav><h1>온라인 노드</h1>\
<div class=sub>'접속'을 누르면 SigmaDesk 앱이 열리고 바로 연결합니다 (앱 설정에서 링크 등록 필요).</div>{list}</main></body></html>"
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

// ---------------------------------------------------------------- web console

type Page = Response<std::io::Cursor<Vec<u8>>>;
type Form = HashMap<String, String>;

const COOKIE: &str = "sd_session";

const CONSOLE_STYLE: &str = "main.wide{max-width:1100px}table{width:100%;border-collapse:collapse;font-size:14px}\
th{color:#9aa1b2;font-weight:600;text-align:left;padding:8px 10px;border-bottom:1px solid #2a2e3a}\
td{padding:9px 10px;border-bottom:1px solid #22262f;vertical-align:middle}\
form.inline{display:inline;margin:0 2px}button,input[type=submit]{background:#2a2f3c;color:#e6e8ee;border:1px solid #3a4050;border-radius:7px;padding:5px 10px;cursor:pointer;font:inherit;font-size:13px}\
button.primary{background:#3b82f6;border-color:#3b82f6;color:#fff;padding:9px 16px;font-size:15px}button.danger{color:#f87171;border-color:#5b2a2a}\
input[type=text],input[type=email],input[type=password]{background:#0c0e12;border:1px solid #2f3442;border-radius:8px;color:#e6e8ee;padding:9px 11px;font:inherit;width:100%;box-sizing:border-box;margin:4px 0 12px}\
label{color:#9aa1b2;font-size:13px}.badge{display:inline-block;font-size:12px;padding:2px 8px;border-radius:10px;background:#263049;color:#9fc2ff;margin-left:6px}\
.badge.off{background:#3a2323;color:#fca5a5}.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{background:#1b1e26;border-radius:12px;padding:16px 20px;min-width:140px}\
.stat b{display:block;font-size:26px}.msg{background:#16314f;border:1px solid #2b5a8f;border-radius:10px;padding:12px 16px;margin:12px 0}\
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}nav{display:flex;align-items:center;margin-bottom:26px}nav a{text-decoration:none}nav .right{margin-left:auto}";

fn layout(title: &str, user: Option<&User>, msg: &str, wide: bool, body: &str) -> String {
    let nav_user = match user {
        Some(u) => {
            let admin = if u.admin { "<a href=\"/admin\">관리자 콘솔</a>" } else { "" };
            format!("<a href=\"/account\">내 페이지</a>{admin}<span class=right>{} · <a href=\"/logout\">로그아웃</a></span>", escape(&account_tag(&u.name, u.id)))
        }
        None => "<span class=right><a href=\"/login\">로그인</a></span>".to_string(),
    };
    let msg = if msg.is_empty() { String::new() } else { format!("<div class=msg>{}</div>", escape(msg)) };
    format!(
        "<!doctype html><html lang=ko><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{} · SigmaDesk</title><style>{PAGE_STYLE}{CONSOLE_STYLE}</style></head><body><main{}>\
<nav><a href=\"/\">설치</a><a href=\"/nodes\">온라인 노드</a>{nav_user}</nav>{msg}{body}</main></body></html>",
        escape(title),
        if wide { " class=wide" } else { "" }
    )
}

fn redirect(to: &str, cookie: Option<&str>) -> Page {
    let mut r = Response::from_string("").with_status_code(303).with_header(Header::from_bytes("Location", to).unwrap());
    if let Some(token) = cookie {
        let value = if token.is_empty() {
            format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        } else {
            format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax")
        };
        r = r.with_header(Header::from_bytes("Set-Cookie", value).unwrap());
    }
    r
}

fn forbidden() -> Page {
    html(layout("권한 없음", None, "", false, "<h1>권한이 없습니다</h1><div class=sub>이 페이지는 관리자만 볼 수 있습니다.</div>")).with_status_code(403)
}

fn cookie_token(req: &Request) -> Option<String> {
    let cookies = header(req, "Cookie")?;
    cookies
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Form posts must come from this site's own pages (the cookie is also SameSite=Lax).
fn same_origin(req: &Request) -> bool {
    let host = header(req, "Host").unwrap_or_default();
    match header(req, "Origin") {
        Some(o) => o.split("://").nth(1).map(|h| h == host).unwrap_or(false),
        None => true,
    }
}

fn read_form(req: &mut Request) -> Form {
    let mut body = String::new();
    let _ = req.as_reader().take(64 * 1024).read_to_string(&mut body);
    body.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (url_decode(k), url_decode(v)))
        .collect()
}

fn field<'a>(f: &'a Form, key: &str) -> &'a str {
    f.get(key).map(|s| s.as_str()).unwrap_or("")
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()).ok_or(()) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}초 전"),
        60..=3599 => format!("{}분 전", secs / 60),
        3600..=86399 => format!("{}시간 전", secs / 3600),
        _ => format!("{}일 전", secs / 86400),
    }
}

fn status_cell(h: &Host) -> String {
    if h.online {
        "<span class=dot style='background:#22c55e'></span>온라인".into()
    } else {
        format!("<span class=dot style='background:#6b7280'></span>오프라인 · {}", ago(h.last_seen_secs))
    }
}

fn login_page(msg: &str) -> String {
    layout(
        "로그인",
        None,
        msg,
        false,
        "<h1>SigmaDesk 계정</h1><div class=sub>내 컴퓨터를 관리하는 웹 페이지입니다. 앱과 같은 계정을 씁니다.</div>\
<div class=grid2><div class=card><h3>로그인</h3><form method=post action=/login>\
<label>이메일</label><input type=email name=email required><label>비밀번호</label><input type=password name=password required>\
<button class=primary>로그인</button></form></div>\
<div class=card><h3>계정 만들기</h3><form method=post action=/signup>\
<label>이름</label><input type=text name=name><label>이메일</label><input type=email name=email required>\
<label>비밀번호 (6자 이상)</label><input type=password name=password minlength=6 required>\
<button class=primary>계정 만들기</button></form><p class=sub>이 서버의 첫 계정은 관리자가 됩니다.</p></div></div>",
    )
}

fn account_page(st: &State, u: &User, host_hdr: &str, msg: &str) -> String {
    let now = now_ms();
    let mut mine: Vec<Host> = st.store.hosts.values().filter(|h| h.owner == u.id).map(|h| host_view(h, &st.store.users, "", now)).collect();
    mine.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
    let mut rows = String::new();
    for h in &mine {
        let (toggle, toggle_text) = if h.public { ("private", "공개 끄기") } else { ("public", "공개하기") };
        let share = st
            .store
            .hosts
            .get(&h.peer_id)
            .map(|r| r.beat.share_secret.clone())
            .filter(|s| !s.is_empty())
            .map(|s| {
                let url = share_url(&format!("http://{host_hdr}"), &h.peer_id, &s);
                format!("<br><small>공유 링크 <a href=\"{0}\">{0}</a></small>", escape(&url))
            })
            .unwrap_or_default();
        rows.push_str(&format!(
            "<tr><td><b>{name}</b>{public}{share}</td><td>{status}</td><td><code>{rd}</code></td><td>{max}명</td><td>\
<a class=btn style='padding:5px 12px;font-size:13px' href=\"sigmadesk://connect/{peer}\">접속</a>\
<form class=inline method=post action=/account/node><input type=hidden name=peer_id value=\"{peer}\"><button name=action value={toggle}>{toggle_text}</button></form>\
<form class=inline method=post action=/account/node onsubmit=\"return confirm('목록에서 지울까요?')\"><input type=hidden name=peer_id value=\"{peer}\"><button class=danger name=action value=remove>제거</button></form></td></tr>",
            name = escape(&h.name),
            public = if h.public { "<span class=badge>공개</span>" } else { "" },
            status = status_cell(h),
            rd = escape(&h.rustdesk_id),
            max = h.max_players,
            peer = escape(&h.peer_id),
        ));
    }
    let table = if mine.is_empty() {
        "<p class=sub>아직 등록한 컴퓨터가 없습니다. 원격으로 들어갈 컴퓨터의 SigmaDesk 앱에서 '호스트' 탭을 켜세요.</p>".to_string()
    } else {
        format!("<table><tr><th>이름</th><th>상태</th><th>RustDesk ID</th><th>동시 접속</th><th></th></tr>{rows}</table>")
    };
    let sessions = st.store.sessions.values().filter(|id| **id == u.id).count();
    let role = if u.admin { "<span class=badge>관리자</span>" } else { "" };
    let body = format!(
        "<h1>{name}<span style='color:#6b7280'>#{uid}</span>{role}</h1><div class=sub>{email}</div>\
<div class=card><h3>내 컴퓨터 ({count}대, 온라인 {online}대)</h3>{table}</div>\
<div class=grid2><div class=card><h3>앱 연결</h3><p>SigmaDesk 앱 로그인 화면의 <b>서버 주소</b>에 <code>http://{host}</code> 를 넣고 이 계정으로 로그인하세요.</p>\
<p class=sub>RustDesk ID 서버: <code>{idsrv}</code></p></div>\
<div class=card><h3>로그인된 기기</h3><p>앱과 브라우저를 합쳐 {sessions}곳에서 로그인되어 있습니다.</p>\
<form method=post action=/account/sessions onsubmit=\"return confirm('모든 기기에서 로그아웃할까요?')\"><button class=danger>모든 기기에서 로그아웃</button></form></div></div>\
<div class=card><h3>비밀번호 바꾸기</h3><form method=post action=/account/password style='max-width:360px'>\
<label>지금 비밀번호</label><input type=password name=current required><label>새 비밀번호 (6자 이상)</label><input type=password name=new minlength=6 required>\
<label>새 비밀번호 다시</label><input type=password name=new2 minlength=6 required><button class=primary>바꾸기</button></form></div>",
        name = escape(&u.name),
        uid = u.id,
        email = escape(&u.email),
        count = mine.len(),
        online = mine.iter().filter(|h| h.online).count(),
        host = escape(host_hdr),
        idsrv = if st.app_config.rustdesk_id_server.is_empty() { "(서버에 설정 안 됨)".to_string() } else { escape(&st.app_config.rustdesk_id_server) },
    );
    layout("내 페이지", Some(u), msg, false, &body)
}

fn account_action(st: &mut State, u: &User, path: &str, f: &Form, host_hdr: &str) -> Page {
    let msg: String = match path {
        "/account/node" => {
            let peer = field(f, "peer_id").to_string();
            let owned = st.store.hosts.get(&peer).map(|h| h.owner == u.id).unwrap_or(false);
            if !owned {
                "컴퓨터를 찾을 수 없습니다".into()
            } else {
                match field(f, "action") {
                    "remove" => {
                        st.store.hosts.remove(&peer);
                        "목록에서 지웠습니다. 그 컴퓨터가 호스팅을 계속 켜 두면 다시 나타납니다.".into()
                    }
                    a @ ("public" | "private") => {
                        if let Some(h) = st.store.hosts.get_mut(&peer) {
                            h.beat.public = a == "public";
                        }
                        if a == "public" { "공개 노드 목록에 보이게 했습니다".into() } else { "공개를 껐습니다".into() }
                    }
                    _ => "알 수 없는 요청".into(),
                }
            }
        }
        "/account/password" => {
            if hash_pw(&u.salt, field(f, "current")) != u.pw_hash {
                "지금 비밀번호가 맞지 않습니다".into()
            } else if field(f, "new").len() < 6 || field(f, "new") != field(f, "new2") {
                "새 비밀번호가 6자 미만이거나 두 칸이 다릅니다".into()
            } else {
                if let Some(me) = st.store.users.iter_mut().find(|x| x.id == u.id) {
                    me.salt = random_id(16);
                    me.pw_hash = hash_pw(&me.salt, field(f, "new"));
                }
                "비밀번호를 바꿨습니다".into()
            }
        }
        "/account/sessions" => {
            st.end_sessions_of(u.id);
            st.save();
            return redirect("/login", Some(""));
        }
        _ => "알 수 없는 요청".into(),
    };
    st.save();
    let fresh = st.store.users.iter().find(|x| x.id == u.id).cloned().unwrap_or_else(|| u.clone());
    html(account_page(st, &fresh, host_hdr, &msg))
}

/// The page a share link opens: who is sharing which computer, and a connect button.
fn share_page(st: &State, rec: &HostRec) -> String {
    let h = host_view(rec, &st.store.users, "", now_ms());
    let body = format!(
        "<h1>{name}</h1><div class=sub>{owner} 님이 이 컴퓨터를 공유했습니다.</div>\
<div class='card node'><div>{status}<br><small>RustDesk ID <code>{rd}</code></small></div>\
<a class=btn href=\"sigmadesk://connect/{peer}?secret={secret}\">접속</a></div>\
<div class=card><b>처음이라면</b><p>RustDesk와 SigmaDesk 앱을 설치하고(<a href=\"/\">설치 안내</a>), 앱 설정에서 'sigmadesk:// 링크 등록'을 누른 뒤 위의 '접속'을 누르세요. \
앱 없이도 RustDesk에서 위 ID로 직접 접속할 수 있습니다.</p></div>",
        name = escape(&h.name),
        owner = escape(&account_tag(&h.user.name, h.user.id)),
        status = status_cell(&h),
        rd = escape(&h.rustdesk_id),
        peer = escape(&h.peer_id),
        secret = escape(&rec.beat.share_secret),
    );
    layout("공유된 컴퓨터", None, "", false, &body)
}

fn admin_page(st: &State, me: &User, msg: &str, elevated: bool) -> String {
    let now = now_ms();
    let mut hosts: Vec<Host> = st.store.hosts.values().map(|h| host_view(h, &st.store.users, "", now)).collect();
    hosts.sort_by(|a, b| b.online.cmp(&a.online).then(a.user.name.cmp(&b.user.name)).then(a.name.cmp(&b.name)));
    let online = hosts.iter().filter(|h| h.online).count();
    let disabled = st.store.users.iter().filter(|u| u.disabled).count();
    let stats = format!(
        "<div class=stats><div class=stat>사용자<b>{}</b></div><div class=stat>정지된 사용자<b>{disabled}</b></div>\
<div class=stat>등록된 노드<b>{}</b></div><div class=stat>온라인 노드<b>{online}</b></div><div class=stat>로그인 세션<b>{}</b></div></div>",
        st.store.users.len(),
        hosts.len(),
        st.store.sessions.len()
    );
    let mut users = String::new();
    for u in &st.store.users {
        let total = hosts.iter().filter(|h| h.user.id == u.id).count();
        let up = hosts.iter().filter(|h| h.user.id == u.id && h.online).count();
        let sessions = st.store.sessions.values().filter(|id| **id == u.id).count();
        let btn = |action: &str, text: &str, danger: bool| {
            format!(
                "<form class=inline method=post action=/admin/user{confirm}><input type=hidden name=user_id value={id}><button{cls} name=action value={action}>{text}</button></form>",
                confirm = if danger { " onsubmit=\"return confirm('정말 할까요?')\"" } else { "" },
                id = u.id,
                cls = if danger { " class=danger" } else { "" }
            )
        };
        let actions = if u.id == me.id {
            "<span class=sub>나</span>".to_string()
        } else {
            [
                if u.disabled { btn("enable", "정지 해제", false) } else { btn("disable", "정지", true) },
                if u.admin { btn("unadmin", "관리자 해제", false) } else { btn("admin", "관리자로", false) },
                btn("reset", "비밀번호 초기화", true),
                btn("delete", "삭제", true),
            ]
            .concat()
        };
        users.push_str(&format!(
            "<tr><td>{id}</td><td><b>{name}</b>{role}{state}</td><td>{email}</td><td>{up} / {total}</td><td>{sessions}</td><td>{actions}</td></tr>",
            id = u.id,
            name = escape(&account_tag(&u.name, u.id)),
            role = if u.admin { "<span class=badge>관리자</span>" } else { "" },
            state = if u.disabled { "<span class='badge off'>정지</span>" } else { "" },
            email = escape(&u.email),
        ));
    }
    let mut nodes = String::new();
    for h in &hosts {
        let (toggle, toggle_text) = if h.public { ("private", "공개 끄기") } else { ("public", "공개") };
        let ip = st.store.hosts.get(&h.peer_id).map(|r| r.beat.lan_ip.clone()).unwrap_or_default();
        // Opening sigmadesk:// hands the node to the SigmaDesk app on the admin's computer, which
        // starts the RustDesk engine for it (instead of a Windows RDP session).
        let control = if h.online && !h.rustdesk_id.is_empty() {
            format!("<a class=btn style='padding:5px 12px;font-size:13px' href=\"sigmadesk://connect/{}\">SigmaDesk로 제어</a>", escape(&h.peer_id))
        } else {
            "<button disabled>오프라인</button>".to_string()
        };
        nodes.push_str(&format!(
            "<tr><td><b>{name}</b>{public}</td><td>{ip}</td><td>{owner}</td><td><code>{rd}</code></td><td>{status}</td><td>{platform}</td><td>{control}\
<form class=inline method=post action=/admin/node><input type=hidden name=peer_id value=\"{peer}\"><button name=action value={toggle}>{toggle_text}</button></form>\
<form class=inline method=post action=/admin/node onsubmit=\"return confirm('이 노드를 지울까요?')\"><input type=hidden name=peer_id value=\"{peer}\"><button class=danger name=action value=remove>제거</button></form></td></tr>",
            name = escape(&h.name),
            public = if h.public { "<span class=badge>공개</span>" } else { "" },
            owner = escape(&h.user.name),
            rd = escape(&h.rustdesk_id),
            status = status_cell(h),
            platform = escape(&h.platform),
            peer = escape(&h.peer_id),
            ip = if ip.is_empty() { "-".to_string() } else { escape(&ip) },
        ));
    }
    if nodes.is_empty() {
        nodes = "<tr><td colspan=7 class=sub>등록된 노드가 없습니다</td></tr>".into();
    }
    // Team computer provisioning keys, with the command to run on a node (Parsec's installer
    // flags /team_id= /team_computer_key= /percomputer /silent; FUN_180005d60 registers it).
    let mut keys = String::new();
    for k in &st.store.machine_keys {
        let cmd = format!(
            "irm {base}/download/install-node.ps1 -OutFile $env:TEMP\\install-node.ps1\npowershell -ExecutionPolicy Bypass -File $env:TEMP\\install-node.ps1 -Server {base} -Team {team} -Key {key}",
            base = st.public_base,
            team = k.team,
            key = k.key
        );
        keys.push_str(&format!(
            "<tr><td><b>{label}</b><br><small class=sub>팀 {team} · 등록 {uses}대</small></td><td><pre style='white-space:pre-wrap;margin:0;font-size:12px'><code>{cmd}</code></pre></td><td>\
<form class=inline method=post action=/admin/key onsubmit=\"return confirm('이 키를 폐기할까요? 이미 등록된 노드는 그대로입니다.')\"><input type=hidden name=key value=\"{key}\"><button class=danger name=action value=revoke>폐기</button></form></td></tr>",
            label = escape(&k.label),
            team = escape(&k.team),
            uses = k.uses,
            cmd = escape(&cmd),
            key = escape(&k.key),
        ));
    }
    if keys.is_empty() {
        keys = "<tr><td colspan=3 class=sub>아직 키가 없습니다. 아래에서 만드세요.</td></tr>".into();
    }
    // Control log: who opened which node, with Parsec-format attempt ids.
    let mut log_rows = String::new();
    for a in st.store.attempts.iter().rev().take(20) {
        let who = st.store.users.iter().find(|u| u.id == a.user).map(|u| account_tag(&u.name, u.id)).unwrap_or_else(|| format!("#{}", a.user));
        let via = match a.via.as_str() {
            "access_link" => "접근 링크",
            "secret" => "공유 링크",
            _ => "직접",
        };
        log_rows.push_str(&format!(
            "<tr><td>{when}</td><td>{who}</td><td><b>{node}</b></td><td>{via}</td><td><code style='font-size:11px'>{id}</code></td></tr>",
            when = ago(now_ms().saturating_sub(a.at_ms) / 1000),
            who = escape(&who),
            node = escape(&a.node_name),
            id = escape(&a.attempt_id),
        ));
    }
    if log_rows.is_empty() {
        log_rows = "<tr><td colspan=5 class=sub>아직 제어 기록이 없습니다</td></tr>".into();
    }
    let log_card = format!(
        "<div class=card><h3>최근 제어 기록</h3><table><tr><th>언제</th><th>누가</th><th>노드</th><th>방법</th><th>시도 ID</th></tr>{log_rows}</table></div>"
    );
    let keys_card = format!(
        "<div class=card><h3>노드 등록 키 (팀 컴퓨터)</h3><p class=sub>원격으로 제어할 컴퓨터(예: RDP로 들어가 있는 노드)에서, 관리자 PowerShell로 아래 두 줄을 실행하면 \
RustDesk와 SigmaDesk가 설치되고 이 서버에 자동 등록됩니다. 그 뒤로는 노드 목록의 'SigmaDesk로 제어'로 접속합니다.</p>\
<table><tr><th>이름</th><th>노드에서 실행할 명령</th><th></th></tr>{keys}</table>\
<form method=post action=/admin/key style='display:flex;gap:8px;align-items:end;margin-top:12px'><div style='flex:1'><label>키 이름</label><input type=text name=label placeholder='예: 개발실 PC'></div>\
<div style='width:160px'><label>팀</label><input type=text name=team value=default></div><button class=primary name=action value=create style='margin-bottom:12px'>키 만들기</button></form></div>"
    );
    let cfg = &st.app_config;
    let show = |v: &str| if v.is_empty() { "(설정 안 됨)".to_string() } else { escape(v) };
    let key = if cfg.rustdesk_key.len() > 16 { format!("{}…", &cfg.rustdesk_key[..16]) } else { cfg.rustdesk_key.clone() };
    // Parsec's "Authentication Required" step (FUN_180030150): look freely, re-confirm to act.
    let auth = if elevated {
        format!("<p class=sub>비밀번호 확인됨 · 관리 작업은 확인 후 {}분 동안 할 수 있습니다.</p>", ELEVATE_TTL_MS / 60000)
    } else {
        format!(
            "<div class=card style='border:1px solid #2b5a8f'><h3>인증이 필요합니다</h3><p>{} 님으로 관리 작업을 하려면 비밀번호를 다시 입력하세요.</p>\
<form method=post action=/admin/elevate style='max-width:360px'><label>비밀번호</label><input type=password name=password required><button class=primary>다시 확인</button></form></div>",
            escape(&account_tag(&me.name, me.id))
        )
    };
    let body = format!(
        "<h1>관리자 콘솔</h1><div class=sub>이 서버의 모든 사용자와 노드를 관리합니다.</div>{auth}{stats}\
<div class=card><h3>사용자</h3><table><tr><th>#</th><th>이름</th><th>이메일</th><th>노드 (온라인/전체)</th><th>세션</th><th></th></tr>{users}</table></div>\
<div class=card><h3>노드</h3><table><tr><th>이름</th><th>주소</th><th>소유자</th><th>RustDesk ID</th><th>상태</th><th>OS</th><th></th></tr>{nodes}</table></div>{log_card}{keys_card}\
<div class=card><h3>서버 설정</h3><table><tr><td>RustDesk ID 서버</td><td><code>{id}</code></td></tr><tr><td>RustDesk 릴레이</td><td><code>{relay}</code></td></tr>\
<tr><td>공개 키</td><td><code>{key}</code></td></tr><tr><td>데이터 파일</td><td><code>{data}</code></td></tr>\
<tr><td>오프라인 판정</td><td>하트비트 없이 {off}초</td></tr></table>\
<p class=sub>바꾸려면 서버를 --rustdesk-host / --rustdesk-key 옵션으로 다시 시작하세요.</p></div>",
        id = show(&cfg.rustdesk_id_server),
        relay = show(&cfg.rustdesk_relay_server),
        key = show(&key),
        data = escape(&st.data_path),
        off = OFFLINE_AFTER_MS / 1000,
    );
    layout("관리자 콘솔", Some(me), msg, true, &body)
}

fn admin_action(st: &mut State, me: &User, path: &str, f: &Form, elevated: bool) -> Page {
    let msg: String = match path {
        "/admin/user" => {
            let id: u32 = field(f, "user_id").parse().unwrap_or(0);
            let action = field(f, "action").to_string();
            match st.store.users.iter().position(|u| u.id == id) {
                None => "사용자를 찾을 수 없습니다".into(),
                Some(_) if id == me.id => "자기 자신은 바꿀 수 없습니다".into(),
                Some(i) => {
                    let name = st.store.users[i].name.clone();
                    match action.as_str() {
                        "disable" => {
                            st.store.users[i].disabled = true;
                            st.end_sessions_of(id);
                            format!("{name} 계정을 정지했습니다 (모든 기기에서 로그아웃됨)")
                        }
                        "enable" => {
                            st.store.users[i].disabled = false;
                            format!("{name} 계정 정지를 풀었습니다")
                        }
                        "admin" => {
                            st.store.users[i].admin = true;
                            format!("{name} 님을 관리자로 만들었습니다")
                        }
                        "unadmin" => {
                            st.store.users[i].admin = false;
                            format!("{name} 님의 관리자 권한을 뺐습니다")
                        }
                        "reset" => {
                            let temp = random_id(10);
                            let u = &mut st.store.users[i];
                            u.salt = random_id(16);
                            u.pw_hash = hash_pw(&u.salt, &temp);
                            st.end_sessions_of(id);
                            format!("{name} 님의 임시 비밀번호: {temp}  (본인에게 전달하고 바꾸게 하세요)")
                        }
                        "delete" => {
                            st.store.users.remove(i);
                            st.store.hosts.retain(|_, h| h.owner != id);
                            st.end_sessions_of(id);
                            format!("{name} 계정과 그 노드를 삭제했습니다")
                        }
                        _ => "알 수 없는 요청".into(),
                    }
                }
            }
        }
        "/admin/key" => match field(f, "action") {
            "create" => {
                let team: String = field(f, "team").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
                let team = if team.is_empty() { "default".to_string() } else { team };
                let label = if field(f, "label").trim().is_empty() { "노드".to_string() } else { clean_name(field(f, "label").trim()) };
                st.store.machine_keys.push(MachineKey { key: random_id(32), team, owner: me.id, label: label.clone(), created_ms: now_ms(), uses: 0 });
                format!("'{label}' 키를 만들었습니다. 아래 명령을 노드에서 실행하세요.")
            }
            "revoke" => {
                let before = st.store.machine_keys.len();
                st.store.machine_keys.retain(|k| k.key != field(f, "key"));
                if st.store.machine_keys.len() < before { "키를 폐기했습니다".into() } else { "키를 찾을 수 없습니다".into() }
            }
            _ => "알 수 없는 요청".into(),
        },
        "/admin/node" => {
            let peer = field(f, "peer_id").to_string();
            match field(f, "action") {
                "remove" if st.store.hosts.remove(&peer).is_some() => "노드를 지웠습니다".into(),
                a @ ("public" | "private") if st.store.hosts.contains_key(&peer) => {
                    if let Some(h) = st.store.hosts.get_mut(&peer) {
                        h.beat.public = a == "public";
                    }
                    "공개 여부를 바꿨습니다".into()
                }
                _ => "노드를 찾을 수 없습니다".into(),
            }
        }
        _ => "알 수 없는 요청".into(),
    };
    st.save();
    html(admin_page(st, me, &msg, elevated))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let port: u16 = arg("--port").and_then(|p| p.parse().ok()).unwrap_or(REGISTRY_PORT);
    let data_path = arg("--data").unwrap_or_else(|| "sigmadesk-server.json".into());
    let rd_host = arg("--rustdesk-host").unwrap_or_default();
    let app_config = AppConfig {
        rustdesk_id_server: if rd_host.is_empty() { String::new() } else { format!("{rd_host}:{RUSTDESK_ID_PORT}") },
        rustdesk_relay_server: if rd_host.is_empty() { String::new() } else { format!("{rd_host}:{RUSTDESK_RELAY_PORT}") },
        rustdesk_key: arg("--rustdesk-key").unwrap_or_default(),
    };
    let mut store: Store = std::fs::read_to_string(&data_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    // Data from before admins existed: the first account becomes the administrator.
    if !store.users.iter().any(|u| u.admin) {
        if let Some(first) = store.users.first_mut() {
            first.admin = true;
        }
    }
    // The address people actually type: a given public host (in Docker the detected address is
    // the container's), else this computer's LAN address (found by asking the OS which local
    // address it would route out of; nothing is sent).
    let lan = if !rd_host.is_empty() && rd_host != "localhost" {
        rd_host.clone()
    } else {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
            .and_then(|s| s.local_addr())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "127.0.0.1".into())
    };
    let download_dir = arg("--download-dir").unwrap_or_else(|| "downloads".into());
    let public_base = format!("http://{lan}:{port}");
    let state = Arc::new(Mutex::new(State { store, data_path, app_config, elevated: HashMap::new(), download_dir, public_base }));
    let server = match Server::http(("0.0.0.0", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("포트 {port} 를 열 수 없습니다: {e}");
            std::process::exit(1);
        }
    };
    println!("SigmaDesk 서버가 포트 {port} 에서 시작했습니다.");
    for host in [lan.as_str(), "localhost"] {
        let base = format!("http://{host}:{port}");
        println!("  설치 안내     {base}/");
        println!("  사용자 페이지 {base}/account   (로그인: {base}/login)");
        println!("  관리자 콘솔   {base}/admin     (처음 만든 계정이 관리자)");
        println!("  공개 노드     {base}/nodes");
        println!("  공유 링크     {base}{SHARE_PATH}/<노드>/<비밀값>/   (호스트 탭의 '공유 링크 만들기')");
    }
    for req in server.incoming_requests() {
        let st = state.clone();
        std::thread::spawn(move || handle(&st, req));
    }
}

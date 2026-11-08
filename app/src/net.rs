//! Talks to the SigmaDesk registry server on a background thread, the way Parsec's client calls
//! kessel-api (MECHANICS.md section 2). The UI sends a Job and reads Replies each frame.

use sigmadesk::consts::{
    APP_VERSION, CONNECT_TIMEOUT_MS, HTTP_RATE_LIMITED, LOGOUT_PATH, MACHINE_CREATED_STATUS, MAX_HOSTS, NO_CONNECTION_CODE,
    SESSION_ID_LEN, SESSION_SCOPES,
};
use sigmadesk::proto::*;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

pub enum Job {
    Login { server: String, email: String, password: String, peer_id: String },
    Signup { server: String, email: String, password: String, name: String },
    Hosts { server: String, session: String, peer_id: String },
    Me { server: String, session: String },
    Heartbeat { server: String, session: String, beat: Heartbeat },
    Remove { server: String, session: String, peer_id: String },
    /// End this session on the server too (Parsec: DELETE /auth/sessions).
    Logout { server: String, session: String },
    /// Record a connect attempt (Parsec's offer carries the same attempt_id).
    Attempt { server: String, session: String, report: AttemptReport },
    /// Register this computer with a node key (Parsec: POST /teams/%s/machines, X-Machine-Key).
    Provision { server: String, team: String, key: String, name: String },
}

/// Which kind of request failed, so each can follow its own retry rule.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Account,
    Hosts,
    Background,
}

impl Job {
    fn kind(&self) -> Kind {
        match self {
            Job::Login { .. } | Job::Signup { .. } | Job::Remove { .. } | Job::Logout { .. } | Job::Provision { .. } => Kind::Account,
            Job::Hosts { .. } => Kind::Hosts,
            Job::Me { .. } | Job::Heartbeat { .. } | Job::Attempt { .. } => Kind::Background,
        }
    }
}

pub enum Reply {
    LoggedIn(AuthResponse),
    Hosts(Vec<Host>),
    Me(MeResponse),
    HeartbeatOk,
    Removed(String),
    /// The server-side logout finished (or there was nothing to end).
    LoggedOut,
    /// A machine registration gave this session id.
    Provisioned(String),
    /// The server recorded this connect attempt.
    AttemptLogged(String),
    /// error text, and whether the session is no longer valid (HTTP 401/403 log out, like Parsec)
    Failed(String, bool, Kind),
}

pub struct Net {
    tx: Sender<Job>,
    pub rx: Receiver<Reply>,
}

impl Net {
    pub fn start(ctx: eframe::egui::Context) -> Net {
        let (tx, jobs) = channel::<Job>();
        let (out, rx) = channel::<Reply>();
        std::thread::spawn(move || {
            let agent = new_agent();
            for job in jobs {
                if out.send(run_tagged(&agent, job)).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        Net { tx, rx }
    }

    pub fn send(&self, job: Job) {
        let _ = self.tx.send(job);
    }
}

fn new_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(CONNECT_TIMEOUT_MS * 2))
        .build()
}

fn run_tagged(agent: &ureq::Agent, job: Job) -> Reply {
    let kind = job.kind();
    match run(agent, job) {
        Reply::Failed(text, logout, _) => Reply::Failed(text, logout, kind),
        other => other,
    }
}

/// Run one request and wait for it (for the windowless provisioning and host-service modes).
pub fn run_once(job: Job) -> Reply {
    run_tagged(&new_agent(), job)
}

fn base(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

fn with_headers(req: ureq::Request, session: &str) -> ureq::Request {
    let req = req
        .set("X-SigmaDesk-OS", std::env::consts::OS)
        .set("X-SigmaDesk-Platform", std::env::consts::OS)
        .set("X-SigmaDesk-App-Version", APP_VERSION);
    if session.is_empty() {
        req
    } else {
        req.set("Authorization", &format!("Bearer {session}"))
    }
}

fn fail(e: ureq::Error) -> Reply {
    match e {
        ureq::Error::Status(code, resp) => {
            let body: Option<ErrorResponse> = resp.into_json().ok();
            let text = body
                .map(|b| if b.message.is_empty() { b.error } else { b.message })
                .unwrap_or_else(|| format!("서버 오류 {code}"));
            let text = if code == HTTP_RATE_LIMITED { "요청이 너무 많습니다 (서버가 잠시 쉬라고 했습니다)".to_string() } else { text };
            // Parsec's message shape: "Error [code]" + what to do about it (FUN_180005f60).
            let text = format!("오류 [{code}] {text}. {}", sigmadesk::request_advice(code as i32));
            Reply::Failed(text, code == 401 || code == 403, Kind::Account)
        }
        ureq::Error::Transport(t) => Reply::Failed(
            format!("오류 [{NO_CONNECTION_CODE}] 서버에 연결할 수 없습니다 ({}). {}", t.kind(), sigmadesk::request_advice(NO_CONNECTION_CODE)),
            false,
            Kind::Account,
        ),
    }
}

fn run(agent: &ureq::Agent, job: Job) -> Reply {
    match job {
        Job::Login { server, email, password, peer_id } => {
            let body = AuthRequest {
                email,
                password,
                session_scopes: SESSION_SCOPES.iter().map(|s| s.to_string()).collect(),
                host_peer_id: Some(peer_id),
            };
            match with_headers(agent.post(&format!("{}/v2/auth", base(&server))), "").send_json(&body) {
                Ok(r) => r.into_json().map(Reply::LoggedIn).unwrap_or_else(|e| Reply::Failed(e.to_string(), false, Kind::Account)),
                Err(e) => fail(e),
            }
        }
        Job::Signup { server, email, password, name } => {
            let body = SignupRequest { email, password, name };
            match with_headers(agent.post(&format!("{}/v2/signup", base(&server))), "").send_json(&body) {
                Ok(r) => r.into_json().map(Reply::LoggedIn).unwrap_or_else(|e| Reply::Failed(e.to_string(), false, Kind::Account)),
                Err(e) => fail(e),
            }
        }
        Job::Hosts { server, session, peer_id } => {
            let req = with_headers(agent.get(&format!("{}/v2/hosts?mode=desktop", base(&server))), &session)
                .set("X-SigmaDesk-Peer-Id", &peer_id);
            match req.call() {
                Ok(r) => match r.into_json::<HostsResponse>() {
                    Ok(mut h) => {
                        h.data.truncate(MAX_HOSTS);
                        Reply::Hosts(h.data)
                    }
                    Err(e) => Reply::Failed(e.to_string(), false, Kind::Account),
                },
                Err(e) => fail(e),
            }
        }
        Job::Me { server, session } => match with_headers(agent.get(&format!("{}/me", base(&server))), &session).call() {
            Ok(r) => r.into_json().map(Reply::Me).unwrap_or_else(|e| Reply::Failed(e.to_string(), false, Kind::Account)),
            Err(e) => fail(e),
        },
        Job::Heartbeat { server, session, beat } => {
            match with_headers(agent.post(&format!("{}/v2/hosts/heartbeat", base(&server))), &session).send_json(&beat) {
                Ok(_) => Reply::HeartbeatOk,
                Err(e) => fail(e),
            }
        }
        Job::Attempt { server, session, report } => {
            match with_headers(agent.post(&format!("{}/v2/attempts", base(&server))), &session).send_json(&report) {
                Ok(_) => Reply::AttemptLogged(report.attempt_id),
                Err(e) => fail(e),
            }
        }
        Job::Provision { server, team, key, name } => {
            let body = serde_json::json!({ "name": name, "team_guest_access": false });
            match with_headers(agent.post(&format!("{}/teams/{team}/machines", base(&server))), "")
                .set("X-Machine-Key", &key)
                .send_json(&body)
            {
                // Like Parsec, only 201 with {"data": {"id": ...}} is a success.
                Ok(r) if r.status() == MACHINE_CREATED_STATUS => match r.into_json::<MachineResponse>() {
                    Ok(m) if !m.data.id.is_empty() && m.data.id.len() <= SESSION_ID_LEN => Reply::Provisioned(m.data.id),
                    _ => Reply::Failed("등록 응답에 data.id가 없습니다".into(), false, Kind::Account),
                },
                Ok(r) => Reply::Failed(format!("오류 [{}] 예상하지 못한 응답. {}", r.status(), sigmadesk::request_advice(r.status() as i32)), false, Kind::Account),
                Err(e) => fail(e),
            }
        }
        Job::Logout { server, session } => {
            let _ = with_headers(agent.delete(&format!("{}{}", base(&server), LOGOUT_PATH)), &session).call();
            Reply::LoggedOut
        }
        Job::Remove { server, session, peer_id } => {
            match with_headers(agent.post(&format!("{}/v2/hosts/remove", base(&server))), &session)
                .send_json(&RemoveHost { peer_id: peer_id.clone() })
            {
                Ok(_) => Reply::Removed(peer_id),
                Err(e) => fail(e),
            }
        }
    }
}

//! Windowless modes for nodes that are controlled remotely:
//!
//! * `--provision <server> <team> <key> [--per-computer]` registers this computer with a node key
//!   from the admin console (Parsec: installer flags /team_id= /team_computer_key= and
//!   POST /teams/%s/machines with X-Machine-Key, FUN_180005d60), turns hosting on, reads its
//!   RustDesk ID and points RustDesk at our servers.
//! * `--host-service` keeps the node in the online list with heartbeats and no window, the way
//!   Parsec's installer starts `parsecd.exe app_silent=1` from the Run key.

use crate::config::{machine_path, Config};
use crate::engine;
use crate::net::{run_once, Job, Reply};
use sigmadesk::consts::*;
use sigmadesk::proto::Heartbeat;
use std::io::Write;
use std::time::{Duration, Instant};

/// What a host tells the server each heartbeat.
pub fn heartbeat_of(cfg: &Config) -> Heartbeat {
    Heartbeat {
        peer_id: cfg.peer_id.clone(),
        name: cfg.host_name.clone(),
        desc: cfg.host_desc.clone(),
        rustdesk_id: cfg.rustdesk_id.clone(),
        players: 0,
        max_players: cfg.max_guests,
        public: cfg.host_public,
        app_v: APP_VERSION.into(),
        os_v: std::env::consts::OS.into(),
        platform: std::env::consts::OS.into(),
        device_id: cfg.device_id.clone(),
        mode: "desktop".into(),
        share_secret: cfg.share_secret.clone(),
        lan_ip: sigmadesk::lan_ip(),
    }
}

/// A line to the console and to a log file beside the settings (the release build has no console).
fn log(line: &str) {
    println!("{line}");
    let dir = machine_path()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("sigmadesk.log")) {
        let _ = writeln!(f, "{line}");
    }
}

/// `--provision`: returns the process exit code.
pub fn provision(server: &str, team: &str, key: &str, per_computer: bool) -> i32 {
    let mut cfg = Config::load();
    cfg.server_url = server.trim().trim_end_matches('/').to_string();
    cfg.host_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| cfg.host_name.clone());
    log(&format!("[provision] {} 를 {} (팀 {team}) 에 등록합니다", cfg.host_name, cfg.server_url));
    // Parsec's reply: 201 + {"data": {"id": ...}}; the id is this machine's session.
    cfg.session_id = match run_once(Job::Provision {
        server: cfg.server_url.clone(),
        team: team.into(),
        key: key.into(),
        name: cfg.host_name.clone(),
    }) {
        Reply::Provisioned(id) => id,
        Reply::Failed(text, _, _) => {
            log(&format!("[provision] 실패: {text}"));
            return 2;
        }
        _ => return 2,
    };
    cfg.host_enabled = true;
    // Who the machine belongs to, and the engine servers, as Parsec's /me pushes config.
    match run_once(Job::Me { server: cfg.server_url.clone(), session: cfg.session_id.clone() }) {
        Reply::Me(me) => {
            cfg.user_name = me.name;
            cfg.user_id = me.id;
            cfg.is_admin = me.admin;
            cfg.id_server = me.app_config.rustdesk_id_server;
            cfg.relay_server = me.app_config.rustdesk_relay_server;
            cfg.server_key = me.app_config.rustdesk_key;
            log(&format!("[provision] 소유 계정: {}", sigmadesk::account_tag(&cfg.user_name, cfg.user_id)));
        }
        Reply::Failed(text, _, _) => log(&format!("[provision] 계정 정보를 못 읽었습니다: {text}")),
        _ => {}
    }
    match engine::find(&cfg.rustdesk_path) {
        Some(exe) => {
            match engine::apply_servers(&exe, &cfg.id_server, &cfg.relay_server, &cfg.server_key, cfg.force_relay) {
                Ok(()) => log("[provision] RustDesk가 자체 서버를 쓰도록 설정했습니다"),
                Err(e) => log(&format!("[provision] RustDesk 서버 설정 경고: {e}")),
            }
            match engine::get_id(&exe) {
                Ok(id) => {
                    log(&format!("[provision] RustDesk ID: {id}"));
                    cfg.rustdesk_id = id;
                }
                Err(e) => log(&format!("[provision] RustDesk ID를 아직 못 읽었습니다 (host-service가 다시 시도): {e}")),
            }
        }
        None => log("[provision] 경고: RustDesk가 설치되어 있지 않습니다"),
    }
    let saved = if per_computer { cfg.save_per_computer().map(|p| p.display().to_string()) } else {
        cfg.save();
        Ok("사용자 설정".into())
    };
    match saved {
        Ok(where_) => log(&format!("[provision] 설정 저장: {where_}")),
        Err(e) => {
            log(&format!("[provision] 설정 저장 실패: {e}"));
            return 3;
        }
    }
    match run_once(Job::Heartbeat { server: cfg.server_url.clone(), session: cfg.session_id.clone(), beat: heartbeat_of(&cfg) }) {
        Reply::HeartbeatOk => log(&format!("[provision] 완료: '{}' 가 온라인 목록에 올라갔습니다 (노드 ID {})", cfg.host_name, cfg.peer_id)),
        Reply::Failed(text, _, _) => log(&format!("[provision] 등록은 됐지만 첫 하트비트 실패: {text}")),
        _ => {}
    }
    0
}

/// `--host-service`: heartbeats forever, retrying with Parsec's reconnect rule on failure.
pub fn host_service() -> i32 {
    log(&format!("[host-service] 시작 (하트비트 {}초마다)", HEARTBEAT_MS / 1000));
    let mut failures = 0u32;
    let mut next_me = Instant::now();
    loop {
        let mut cfg = Config::load();
        if cfg.session_id.is_empty() || !cfg.host_enabled {
            std::thread::sleep(Duration::from_millis(HEARTBEAT_MS));
            continue;
        }
        if cfg.rustdesk_id.trim().is_empty() {
            if let Some(Ok(id)) = engine::find(&cfg.rustdesk_path).map(|exe| engine::get_id(&exe)) {
                cfg.rustdesk_id = id;
                // Per-computer files need admin rights; if this fails the ID is still sent below.
                if cfg.save_per_computer().is_err() {
                    cfg.save();
                }
            }
        }
        if Instant::now() >= next_me {
            next_me = Instant::now() + Duration::from_millis(sigmadesk::me_poll_ms());
            let _ = run_once(Job::Me { server: cfg.server_url.clone(), session: cfg.session_id.clone() });
        }
        let wait = match run_once(Job::Heartbeat { server: cfg.server_url.clone(), session: cfg.session_id.clone(), beat: heartbeat_of(&cfg) }) {
            Reply::HeartbeatOk => {
                failures = 0;
                HEARTBEAT_MS
            }
            Reply::Failed(text, logout, _) => {
                failures += 1;
                let wait = sigmadesk::retry_delay_ms(failures);
                log(&format!("[host-service] 하트비트 실패 ({text}){} · {}초 뒤 다시", if logout { " · 세션 만료" } else { "" }, wait / 1000));
                wait
            }
            _ => HEARTBEAT_MS,
        };
        std::thread::sleep(Duration::from_millis(wait));
    }
}

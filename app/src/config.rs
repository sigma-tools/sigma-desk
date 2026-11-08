//! Settings kept between runs in %APPDATA%\SigmaDesk\config.json (Parsec keeps its own in
//! %APPDATA%\Parsec\config.json, MECHANICS.md section 1).

use serde::{Deserialize, Serialize};
use sigmadesk::consts::{PEER_ID_LEN, REGISTRY_PORT};
use sigmadesk::random_id;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server_url: String,
    pub email: String,
    pub session_id: String,
    pub user_name: String,
    /// This computer's id in the node list.
    pub peer_id: String,
    pub device_id: String,
    pub host_enabled: bool,
    pub host_name: String,
    pub host_desc: String,
    pub host_public: bool,
    pub max_guests: u32,
    /// This computer's RustDesk ID, sent with each heartbeat.
    pub rustdesk_id: String,
    pub rustdesk_path: String,
    pub id_server: String,
    pub relay_server: String,
    pub server_key: String,
    /// Parsec's app_force_relay: 0 off, 1 all connections, 2 internet (WAN) connections only.
    pub force_relay: u32,
    /// The server says this account is an administrator (shows the admin console button).
    pub is_admin: bool,
    /// Account number, shown Parsec-style as name#id.
    pub user_id: u32,
    /// Share-link secret of this computer; empty when not sharing.
    pub share_secret: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_url: format!("http://127.0.0.1:{REGISTRY_PORT}"),
            email: String::new(),
            session_id: String::new(),
            user_name: String::new(),
            peer_id: random_id(PEER_ID_LEN),
            device_id: random_id(PEER_ID_LEN),
            host_enabled: false,
            host_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "내 컴퓨터".into()),
            host_desc: String::new(),
            host_public: false,
            max_guests: 1,
            rustdesk_id: String::new(),
            rustdesk_path: String::new(),
            id_server: String::new(),
            relay_server: String::new(),
            server_key: String::new(),
            force_relay: 0,
            is_admin: false,
            user_id: 0,
            share_secret: String::new(),
        }
    }
}

/// Per-computer settings in %ProgramData%, like Parsec's "Per Computer" install
/// (setup.json {"useProgramData": true}): one account for every user, works before anyone logs in.
pub fn machine_path() -> Option<PathBuf> {
    std::env::var("ProgramData").ok().map(|d| PathBuf::from(d).join("SigmaDesk").join("config.json"))
}

/// The per-computer file wins when it exists; otherwise each user's own %APPDATA% file.
fn path() -> PathBuf {
    if let Some(m) = machine_path().filter(|m| m.is_file()) {
        return m;
    }
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    base.join("SigmaDesk").join("config.json")
}

impl Config {
    pub fn load() -> Config {
        std::fs::read_to_string(path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Write the per-computer file (needs administrator rights, as the installer has).
    pub fn save_per_computer(&self) -> Result<PathBuf, String> {
        let p = machine_path().ok_or("ProgramData 폴더를 찾을 수 없습니다")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(p)
    }

    pub fn save(&self) {
        let p = path();
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(p, text);
        }
    }
}

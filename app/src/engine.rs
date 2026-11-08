//! The RustDesk engine bridge. SigmaDesk does accounts and the node list; the installed RustDesk
//! program does the screen, input and NAT traversal (its hbbs/hbbr servers take the place of
//! Parsec's kessel-ws signalling, STUN and relay, MECHANICS.md sections 3-4).
//!
//! The command-line flags used here (--connect, --password, --get-id, --option) are RustDesk's
//! public behaviour, not something read from Parsec, so they are marked estimated in the sheet.

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Find rustdesk.exe: the path from settings, then the usual install folders, then PATH.
pub fn find(configured: &str) -> Option<PathBuf> {
    if !configured.trim().is_empty() {
        let p = PathBuf::from(configured.trim());
        if p.is_file() {
            return Some(p);
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Ok(dir) = std::env::var(var) {
            candidates.push(Path::new(&dir).join("RustDesk").join("rustdesk.exe"));
        }
    }
    candidates.push(PathBuf::from("/usr/bin/rustdesk"));
    candidates.push(PathBuf::from("/Applications/RustDesk.app/Contents/MacOS/RustDesk"));
    if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(p);
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|d| d.join(if cfg!(windows) { "rustdesk.exe" } else { "rustdesk" }))
        .find(|p| p.is_file())
}

fn quiet(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Open a remote session to a RustDesk ID.
pub fn connect(exe: &Path, rustdesk_id: &str, password: &str) -> Result<(), String> {
    let id: String = rustdesk_id.chars().filter(|c| !c.is_whitespace()).collect();
    if id.is_empty() {
        return Err("이 컴퓨터에는 RustDesk ID가 등록되어 있지 않습니다".into());
    }
    let mut cmd = Command::new(exe);
    cmd.arg("--connect").arg(&id);
    if !password.is_empty() {
        cmd.arg("--password").arg(password);
    }
    cmd.spawn().map(|_| ()).map_err(|e| format!("RustDesk를 열 수 없습니다: {e}"))
}

/// Ask RustDesk for this computer's ID.
pub fn get_id(exe: &Path) -> Result<String, String> {
    let out = quiet(&mut Command::new(exe)).arg("--get-id").output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let id: String = text.lines().map(str::trim).find(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric())).unwrap_or("").into();
    if id.is_empty() {
        Err("RustDesk가 ID를 알려주지 않았습니다 (RustDesk를 한 번 실행하거나 ID를 직접 입력하세요)".into())
    } else {
        Ok(id)
    }
}

/// Point RustDesk at our own ID/relay servers. RustDesk asks for administrator rights for this.
/// The relay list follows Parsec's rules (see `parse_relay_list`); RustDesk takes one relay, the first.
/// Force relay: RustDesk has a single "always relay" switch, so both Parsec modes turn it on.
pub fn apply_servers(exe: &Path, id_server: &str, relays: &str, key: &str, force_relay: u32) -> Result<(), String> {
    let relay = sigmadesk::parse_relay_list(relays, sigmadesk::consts::RUSTDESK_RELAY_PORT)
        .first()
        .map(|(h, p)| format!("{h}:{p}"))
        .unwrap_or_default();
    let always = if force_relay == sigmadesk::consts::FORCE_RELAY_OFF { "N" } else { "Y" };
    let mut done = 0;
    for (opt, val) in [
        ("custom-rendezvous-server", id_server),
        ("relay-server", relay.as_str()),
        ("key", key),
        ("force-always-relay", always),
    ] {
        if val.trim().is_empty() {
            continue;
        }
        let status = quiet(&mut Command::new(exe))
            .args(["--option", opt, val.trim()])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("RustDesk가 '{opt}' 설정을 거절했습니다 (관리자 권한이 필요할 수 있습니다)"));
        }
        done += 1;
    }
    if done == 0 {
        Err("적용할 서버 주소가 없습니다".into())
    } else {
        Ok(())
    }
}

/// Register the sigmadesk:// link so the install web's "connect" buttons open this app
/// (Parsec registers parsec:// the same way, MECHANICS.md section 1). Current user only.
pub fn register_link() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.display().to_string();
    let open = format!("\"{exe}\" \"%1\"");
    let steps: [Vec<&str>; 3] = [
        vec!["add", r"HKCU\Software\Classes\sigmadesk", "/ve", "/d", "URL:sigmadesk Protocol", "/f"],
        vec!["add", r"HKCU\Software\Classes\sigmadesk", "/v", "URL Protocol", "/d", "", "/f"],
        vec!["add", r"HKCU\Software\Classes\sigmadesk\shell\open\command", "/ve", "/d", &open, "/f"],
    ];
    for args in steps.iter() {
        let ok = quiet(&mut Command::new("reg")).args(args).status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            return Err("링크 등록에 실패했습니다".into());
        }
    }
    Ok(())
}

/// Pull the peer id out of `sigmadesk://connect/<peer_id>`.
/// The host_secret part of a link: "peer_id=..:host_secret=<s>" (Parsec's form, sub_180055bb0)
/// or "sigmadesk://connect/<peer>?secret=<s>".
pub fn link_secret(arg: &str) -> Option<String> {
    let start = arg.find("host_secret=").map(|p| p + "host_secret=".len()).or_else(|| arg.find("secret=").map(|p| p + "secret=".len()))?;
    let s: String = arg[start..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    if s.is_empty() { None } else { Some(s) }
}

/// Parsec's own form is also accepted: an argument holding "peer_id=<id>" (FUN_180091e50
/// looks for "peer_id=" in what the second instance passes on).
pub fn link_target(arg: &str) -> Option<String> {
    let id = if let Some(pos) = arg.find("peer_id=") {
        arg[pos + "peer_id=".len()..].split([':', '&', '/']).next().unwrap_or("")
    } else {
        let rest = arg.strip_prefix("sigmadesk://")?;
        let rest = rest.split('?').next().unwrap_or("").trim_end_matches('/');
        rest.strip_prefix("connect/").unwrap_or(rest)
    };
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        None
    } else {
        Some(id.to_string())
    }
}

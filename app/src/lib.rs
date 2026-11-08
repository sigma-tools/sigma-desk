//! Shared pieces of SigmaDesk: the numbers from MECHANICS.md and the JSON shapes the client and
//! the registry server exchange. The shapes follow what Parsec's client sends and parses
//! (see MECHANICS.md section 2), plus a `rustdesk_id` so the RustDesk engine knows whom to dial.

pub mod consts {
    /// Computer-list refresh rule (Parsec: function 0x18002dd60, the code around 0x18002dd85):
    /// every 20000 ms; after a failed request the wait grows x1.5 (double at 0x180362aa0) up to
    /// 60000 ms (0x180362c10), and a success puts it back to 20000 ms (0x180362be0).
    pub const HOSTS_REFRESH_MS: u64 = 20000;
    pub const HOSTS_BACKOFF_FACTOR: f64 = 1.5;
    pub const HOSTS_REFRESH_MAX_MS: u64 = 60000;
    /// HTTP status Parsec treats as "too many requests" on the list call (0x1ad, same function).
    pub const HTTP_RATE_LIMITED: u16 = 429;
    /// Account endpoints (Ghidra): log out = DELETE /auth/sessions (FUN_180031a60, call at
    /// 0x180031ec8); re-confirm = PATCH /auth/sessions/elevate with {password, tfa}
    /// (FUN_18002f860, FUN_180030150). A session that isn't re-confirmed may still host.
    pub const LOGOUT_PATH: &str = "/auth/sessions";
    pub const ELEVATE_PATH: &str = "/auth/sessions/elevate";
    /// Share links (Ghidra FUN_18002ad10): "https://parsec.gg/g/%s/%s/" with the peer id and a
    /// secret = random number in [0x7fffffff, 0xffffffff] printed with "%x" (0x18034dfe8).
    /// "Share link generated and copied" shows for 10000 ms; "Stop Sharing" invalidates the link
    /// and shows "Your share link has been invalidated." for 5000 ms.
    pub const SHARE_PATH: &str = "/g";
    pub const SHARE_SECRET_MIN: u32 = 2147483647;
    pub const SHARE_SECRET_MAX: u32 = 4294967295;
    pub const SHARE_COPIED_NOTICE_MS: u64 = 10000;
    pub const SHARE_STOPPED_NOTICE_MS: u64 = 5000;
    /// Machine registration reply (Ghidra FUN_180005f60): only HTTP 201 counts as success, and
    /// the body is {"data": {"id": "<string>"}} read into a 0x41-byte buffer.
    pub const MACHINE_CREATED_STATUS: u16 = 201;
    /// Session ids are kept in 0x41-byte buffers (user.bin "session_id", FUN_1800c6220), so up to
    /// 64 characters; ours are exactly 64.
    pub const SESSION_ID_LEN: usize = 64;
    /// Parsec's code for "no connection" in its request errors (FUN_180005f60).
    pub const NO_CONNECTION_CODE: i32 = -800;
    /// The start argument Parsec gives itself for a silent background start (FUN_1800731f0).
    pub const SILENT_START_ARG: &str = "app_silent=1";
    /// Connect attempts (Ghidra FUN_1800d0800): 24 random bytes (0x18) written as six 8-digit hex
    /// groups "%08x-%08x-%08x-%08x-%08x-%08x" become the offer's attempt_id.
    pub const ATTEMPT_ID_BYTES: usize = 24;
    /// A host secret of exactly 27 (0x1b) characters, all 0-9A-Za-z, is sent as access_link_id;
    /// anything else as secret (same function).
    pub const ACCESS_LINK_ID_LEN: usize = 27;
    /// Control log entries the server keeps (estimated).
    pub const ATTEMPT_LOG_KEEP: usize = 200;
    /// How long a re-confirmation lasts for admin actions (estimated; Parsec keeps it server-side).
    pub const ELEVATE_TTL_MS: u64 = 900_000;
    /// Most hosts kept from one list response (Parsec: function 0x18000389c).
    pub const MAX_HOSTS: usize = 256;
    /// Scopes asked for at login (Parsec: function 0x180003d20).
    pub const SESSION_SCOPES: [&str; 3] = ["ws.host", "ws.client", "api.writer"];
    /// Host heartbeat to our server (estimated; Parsec pushes conn_update on change).
    pub const HEARTBEAT_MS: u64 = 30_000;
    /// A node with no heartbeat for this long is shown offline (estimated).
    pub const OFFLINE_AFTER_MS: u64 = 90_000;
    /// Default port of the SigmaDesk registry server (estimated).
    pub const REGISTRY_PORT: u16 = 21_180;
    /// RustDesk rendezvous (ID) and relay server ports (estimated, RustDesk defaults).
    pub const RUSTDESK_ID_PORT: u16 = 21_116;
    pub const RUSTDESK_RELAY_PORT: u16 = 21_117;
    /// Length of a generated peer id (estimated; Parsec's buffer is 32 bytes).
    pub const PEER_ID_LEN: usize = 26;
    /// Parsec's host port rule: base + random % range (function 0x180073500).
    pub const HOST_PORT_BASE: u16 = 21_000;
    pub const HOST_PORT_RANGE: u16 = 2_000;
    /// Parsec's STUN port and magic cookie 0x2112A442 (function 0x18009c020), shown in the guide.
    pub const STUN_PORT: u16 = 3_478;
    pub const STUN_MAGIC_COOKIE: u32 = 554869826;
    /// /me is re-read at a random time in this window (Parsec: function 0x180073500).
    pub const ME_POLL_MIN_MS: u64 = 1800000;
    pub const ME_POLL_MAX_MS: u64 = 2400000;
    /// Connect timeout for server requests (Parsec's signalling socket: function 0x1800cf9c0).
    pub const CONNECT_TIMEOUT_MS: u64 = 10000;
    /// Retry rule after failures (function 0x1800cf9c0): wait a random time between t and 2t.
    /// t starts at 30000 ms; after each failure it doubles up to 300000 ms while the failure
    /// counter (before counting this one) is below 51 (`< 0x33`), and is 3600000 ms after that.
    pub const RETRY_START_MS: u64 = 30000;
    pub const RETRY_CAP_MS: u64 = 300000;
    pub const RETRY_LONG_WAIT_MS: u64 = 3600000;
    pub const RETRY_DOUBLING_TRIES: u32 = 51;
    /// Parsec SDK version its host reports in conn_update (function 0x1800d0050), shown in the guide.
    pub const PARSEC_SDK_VERSION: u32 = 393216;

    /// Relay list rules (Parsec: function 0x18009adc0 reading app_stun_address): entries are
    /// separated by ',' and host and port by '@'; at most 20 entries; a missing port means 3478;
    /// with no entries Parsec uses "stun.parsec.app@3478".
    pub const MAX_RELAYS: usize = 20;
    pub const RELAY_LIST_SEP: char = ',';
    pub const RELAY_PORT_SEP: char = '@';
    pub const PARSEC_DEFAULT_RELAY: &str = "stun.parsec.app@3478";
    /// Force-relay modes (app_force_relay, functions 0x180050230 and 0x18009adc0): 0 = off,
    /// odd = all connections, other non-zero = WAN connections only.
    pub const FORCE_RELAY_OFF: u32 = 0;
    pub const FORCE_RELAY_ALL: u32 = 1;
    pub const FORCE_RELAY_WAN: u32 = 2;
    pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
}

pub mod proto {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AuthRequest {
        pub email: String,
        pub password: String,
        #[serde(default)]
        pub session_scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host_peer_id: Option<String>,
    }

    /// Body of PATCH /auth/sessions/elevate, as Parsec sends it (`tfa` only when asked for).
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ElevateRequest {
        pub password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tfa: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct SignupRequest {
        pub email: String,
        pub password: String,
        pub name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AuthResponse {
        pub session_id: String,
        pub user_id: u32,
        pub user_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct HostUser {
        pub id: u32,
        pub name: String,
    }

    /// One computer in the list, with the fields Parsec's list parser reads.
    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct Host {
        pub peer_id: String,
        pub name: String,
        #[serde(default)]
        pub build: String,
        #[serde(default)]
        pub players: u32,
        #[serde(default)]
        pub max_players: u32,
        #[serde(rename = "self", default)]
        pub is_self: bool,
        #[serde(default)]
        pub guest_access: bool,
        #[serde(default)]
        pub event_name: String,
        #[serde(default)]
        pub user: HostUser,
        #[serde(default)]
        pub team_id: String,
        #[serde(default)]
        pub has_avatar: bool,
        #[serde(default)]
        pub rustdesk_id: String,
        #[serde(default)]
        pub online: bool,
        #[serde(default)]
        pub public: bool,
        #[serde(default)]
        pub desc: String,
        #[serde(default)]
        pub platform: String,
        #[serde(default)]
        pub last_seen_secs: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct HostsResponse {
        pub data: Vec<Host>,
    }

    /// What a host sends every heartbeat (our stand-in for Parsec's conn_update payload).
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct Heartbeat {
        pub peer_id: String,
        pub name: String,
        #[serde(default)]
        pub desc: String,
        pub rustdesk_id: String,
        #[serde(default)]
        pub players: u32,
        #[serde(default)]
        pub max_players: u32,
        #[serde(default)]
        pub public: bool,
        #[serde(default)]
        pub app_v: String,
        #[serde(default)]
        pub os_v: String,
        #[serde(default)]
        pub platform: String,
        #[serde(default)]
        pub device_id: String,
        #[serde(default)]
        pub mode: String,
        /// Current share-link secret; empty when not sharing (Parsec keeps it as ws_secret).
        #[serde(default)]
        pub share_secret: String,
        /// The node's own LAN address, so admins can tell which machine it is (e.g. 10.10.1.92).
        #[serde(default)]
        pub lan_ip: String,
    }

    /// A connect attempt the app reports (our record of Parsec's "offer"): which node, with which
    /// attempt id, and the share secret used if any (split into secret / access_link_id by
    /// Parsec's 27-character rule).
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AttemptReport {
        pub attempt_id: String,
        pub peer_id: String,
        #[serde(default)]
        pub secret: String,
        #[serde(default)]
        pub access_link_id: String,
    }

    /// Reply of POST /teams/<team>/machines, in Parsec's shape: {"data": {"id": "..."}}.
    /// SigmaDesk puts the new machine session in `id`.
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct MachineResponse {
        pub data: MachineData,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct MachineData {
        pub id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct RemoveHost {
        pub peer_id: String,
    }

    /// Engine settings the server hands out, like Parsec's /me pushing config values.
    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct AppConfig {
        #[serde(default)]
        pub rustdesk_id_server: String,
        #[serde(default)]
        pub rustdesk_relay_server: String,
        #[serde(default)]
        pub rustdesk_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct MeResponse {
        pub id: u32,
        pub name: String,
        pub email: String,
        #[serde(default)]
        pub admin: bool,
        #[serde(default)]
        pub app_config: AppConfig,
    }

    /// Ask the server for a relayed connection to a node (like Parsec's offer_relay).
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct RelayOfferRequest {
        pub peer_id: String,
    }

    /// A relay ticket: which relay to dial, and the one-time ticket that pairs the two sides.
    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct RelayOffer {
        pub attempt_id: String,
        pub relay: String,
        pub ticket: String,
        #[serde(default)]
        pub from_name: String,
        #[serde(default)]
        pub host_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct RelayPollRequest {
        pub peer_id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct RelayPollResponse {
        pub offers: Vec<RelayOffer>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct AdminUser {
        pub id: u32,
        pub name: String,
        pub email: String,
        pub admin: bool,
        pub disabled: bool,
        pub nodes: u32,
        pub online_nodes: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AdminUsersResponse {
        pub users: Vec<AdminUser>,
        #[serde(default)]
        pub relay_sessions: u64,
        #[serde(default)]
        pub relay_active: u32,
        #[serde(default)]
        pub relay_bytes: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AdminSetDisabled {
        pub user_id: u32,
        pub disabled: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ErrorResponse {
        /// Parsec-style error code: INVALID_SESSION, NO_PERMISSION, HOST_NOT_FOUND...
        pub error: String,
        #[serde(default)]
        pub message: String,
    }
}

/// How long to wait after `failures` failed requests in a row, by Parsec's retry rule.
pub fn retry_delay_ms(failures: u32) -> u64 {
    use consts::*;
    use rand::Rng;
    if failures == 0 {
        return 0;
    }
    let mut t = RETRY_START_MS;
    for counter in 0..failures - 1 {
        t = if counter < RETRY_DOUBLING_TRIES { (t * 2).min(RETRY_CAP_MS) } else { RETRY_LONG_WAIT_MS };
    }
    rand::thread_rng().gen_range(t..=t * 2)
}

/// The next computer-list wait after a request: back to the start on success, x1.5 on failure.
pub fn next_hosts_interval_ms(current_ms: u64, ok: bool) -> u64 {
    use consts::*;
    if ok {
        HOSTS_REFRESH_MS
    } else {
        ((current_ms as f64 * HOSTS_BACKOFF_FACTOR) as u64).min(HOSTS_REFRESH_MAX_MS)
    }
}

/// Read a relay list the way Parsec reads app_stun_address: "host@port,host@port", at most 20
/// entries, `default_port` when an entry has none. ':' is also accepted between host and port.
pub fn parse_relay_list(list: &str, default_port: u16) -> Vec<(String, u16)> {
    use consts::*;
    list.split(RELAY_LIST_SEP)
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (host, port) = match e.rsplit_once(RELAY_PORT_SEP).or_else(|| e.rsplit_once(':')) {
                Some((h, p)) => (h.trim(), p.trim().parse().ok()?),
                None => (e, default_port),
            };
            if host.is_empty() { None } else { Some((host.to_string(), port)) }
        })
        .take(MAX_RELAYS)
        .collect()
}

/// A random wait before the next /me read.
pub fn me_poll_ms() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen_range(consts::ME_POLL_MIN_MS..=consts::ME_POLL_MAX_MS)
}

/// A random id from the 0-9A-Za-z alphabet Parsec keeps beside its credentials code.
pub fn random_id(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

/// This computer's LAN address: asks the OS which local address it would route out of
/// (no packet is sent). Empty when there is no network.
pub fn lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

/// A connect attempt id, Parsec's way: 24 random bytes as six "%08x" groups joined by '-'.
pub fn new_attempt_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; consts::ATTEMPT_ID_BYTES];
    rand::thread_rng().fill(&mut bytes);
    bytes
        .chunks(4)
        .map(|c| format!("{:08x}", u32::from_le_bytes([c[0], c[1], c[2], c[3]])))
        .collect::<Vec<_>>()
        .join("-")
}

/// Parsec's rule for a host secret: exactly 27 characters of 0-9A-Za-z means an access link id.
pub fn is_access_link_id(secret: &str) -> bool {
    secret.len() == consts::ACCESS_LINK_ID_LEN && secret.chars().all(|c| c.is_ascii_alphanumeric())
}

/// What to tell the person after a failed request, by Parsec's rule (FUN_180005f60):
/// -800 no connection, 401/403 sign in again, 412 re-authenticate, anything else wait and retry.
pub fn request_advice(status: i32) -> &'static str {
    match status {
        consts::NO_CONNECTION_CODE => "인터넷(네트워크) 연결을 확인하세요.",
        401 | 403 => "로그아웃했다가 다시 로그인해 보세요.",
        412 => "다시 인증해야 합니다.",
        _ => "잠시 뒤 다시 시도하세요.",
    }
}

/// A new share secret, Parsec's way: random in [0x7fffffff, 0xffffffff], as lowercase hex.
pub fn new_share_secret() -> String {
    use rand::Rng;
    format!("{:x}", rand::thread_rng().gen_range(consts::SHARE_SECRET_MIN..=consts::SHARE_SECRET_MAX))
}

/// The share link of a node on our server: "<server>/g/<peer_id>/<secret>/".
pub fn share_url(server: &str, peer_id: &str, secret: &str) -> String {
    format!("{}{}/{peer_id}/{secret}/", server.trim().trim_end_matches('/'), consts::SHARE_PATH)
}

/// How Parsec shows an account: "name#id" ("Log in as %s#%u", FUN_18002f860).
pub fn account_tag(name: &str, id: u32) -> String {
    format!("{name}#{id}")
}

/// Names from the network become safe to show: control characters turn into '?', as Parsec does.
pub fn clean_name(s: &str) -> String {
    s.chars().map(|c| if (c as u32) < 0x20 { '?' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_id_has_parsec_shape() {
        let id = new_attempt_id();
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 8 && g.chars().all(|c| c.is_ascii_hexdigit())));
    }

    #[test]
    fn access_link_rule() {
        assert!(is_access_link_id("ABCDEFGHIJKLMNOPQRSTUVWXYZa"));
        assert!(!is_access_link_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!is_access_link_id("ABCDEFGHIJKLMNOPQRSTUVWXY-a"));
        assert!(!is_access_link_id("a1b2c3d4"));
    }

    #[test]
    fn share_secret_in_range() {
        let s = new_share_secret();
        let v = u64::from_str_radix(&s, 16).unwrap();
        assert!(v >= consts::SHARE_SECRET_MIN as u64 && v <= consts::SHARE_SECRET_MAX as u64);
    }

    #[test]
    fn retry_rule_long_wait_after_51_doublings() {
        assert!((30000..=60000).contains(&retry_delay_ms(1)));
        assert!((300000..=600000).contains(&retry_delay_ms(10)));
        assert!((3600000..=7200000).contains(&retry_delay_ms(53)));
    }
}

//! The window: sign-in screen, then a left rail (Computers, Host, Settings, How it works) with the
//! computer cards grid, like Parsec's desktop app. Look and wording are SigmaDesk's own.

use crate::config::Config;
use crate::engine;
use crate::net::{Job, Kind, Net, Reply};
use crate::Args;
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Rounding, Sense, Stroke, Vec2};
use sigmadesk::consts::*;
use sigmadesk::proto::{AttemptReport, Host, HostUser};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

const BG: Color32 = Color32::from_rgb(16, 18, 24);
const RAIL: Color32 = Color32::from_rgb(10, 12, 17);
const CARD: Color32 = Color32::from_rgb(26, 29, 37);
const CARD_HOVER: Color32 = Color32::from_rgb(34, 38, 49);
const FIELD: Color32 = Color32::from_rgb(12, 14, 19);
const ACCENT: Color32 = Color32::from_rgb(59, 130, 246);
const TEXT: Color32 = Color32::from_rgb(230, 232, 238);
const DIM: Color32 = Color32::from_rgb(154, 161, 178);
const GREEN: Color32 = Color32::from_rgb(34, 197, 94);
const RED: Color32 = Color32::from_rgb(239, 68, 68);
const GREY: Color32 = Color32::from_rgb(107, 114, 128);

const CARD_W: f32 = 236.0;
const CARD_H: f32 = 212.0;

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Login,
    Main,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Computers,
    Host,
    Settings,
    Guide,
}

enum Action {
    Connect(Host),
    Remove(String),
    Refresh,
    Direct,
    Logout,
    FindId,
    ApplyServers,
    RegisterLink,
    ShareStart,
    ShareStop,
    FindEngine,
}

#[derive(Default)]
struct LoginForm {
    email: String,
    password: String,
    name: String,
    signup: bool,
    busy: bool,
    error: String,
}

pub struct App {
    cfg: Config,
    net: Net,
    screen: Screen,
    tab: Tab,
    login: LoginForm,
    hosts: Vec<Host>,
    hosts_loaded: bool,
    last_hosts: Option<Instant>,
    hosts_interval_ms: u64,
    last_beat: Option<Instant>,
    next_me: Instant,
    failures: u32,
    backoff_until: Option<Instant>,
    search: String,
    direct_id: String,
    direct_pw: String,
    status: String,
    status_err: bool,
    status_until: Option<Instant>,
    /// Text to put on the clipboard at the end of this frame.
    pending_copy: Option<String>,
    host_status: String,
    engine_path: Option<PathBuf>,
    pending_link: Option<String>,
    /// host_secret that came with the link, if any.
    pending_secret: Option<String>,
    id_rx: Option<Receiver<Result<String, String>>>,
    demo: bool,
    screenshot: Option<PathBuf>,
    frames: u32,
    shot_requested: bool,
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // Hangul needs a system font; Malgun Gothic ships with Windows.
    for path in [r"C:\Windows\Fonts\malgun.ttf", "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert("hangul".into(), egui::FontData::from_owned(bytes));
            if let Some(f) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                f.insert(0, "hangul".into());
            }
            if let Some(f) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                f.push("hangul".into());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn setup_style(ctx: &egui::Context) {
    // Always dark, whatever the system theme is.
    ctx.set_theme(egui::Theme::Dark);
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = FIELD;
    v.widgets.noninteractive.fg_stroke.color = TEXT;
    v.widgets.inactive.fg_stroke.color = TEXT;
    v.widgets.inactive.bg_fill = CARD_HOVER;
    v.widgets.inactive.weak_bg_fill = CARD_HOVER;
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(44, 49, 62);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(52, 58, 74);
    for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.noninteractive] {
        w.rounding = Rounding::same(8.0);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(38, 42, 54));
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(72, 79, 96));
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(110, 120, 145));
    v.selection.bg_fill = ACCENT;
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(10.0, 10.0);
        s.spacing.button_padding = Vec2::new(14.0, 7.0);
        s.spacing.interact_size.y = 30.0;
        s.text_styles.insert(egui::TextStyle::Body, FontId::proportional(15.0));
        s.text_styles.insert(egui::TextStyle::Button, FontId::proportional(15.0));
        s.text_styles.insert(egui::TextStyle::Small, FontId::proportional(12.5));
    });
}

fn demo_hosts() -> Vec<Host> {
    let me = HostUser { id: 1, name: "데모 사용자".into() };
    let mk = |peer: &str, name: &str, rd: &str, online: bool, is_self: bool, public: bool, players: u32, owner: &HostUser| Host {
        peer_id: peer.into(),
        name: name.into(),
        build: APP_VERSION.into(),
        players,
        max_players: 2,
        is_self,
        guest_access: public,
        user: owner.clone(),
        rustdesk_id: rd.into(),
        online,
        public,
        platform: "windows".into(),
        last_seen_secs: if online { 4 } else { 3600 },
        ..Default::default()
    };
    let team = HostUser { id: 2, name: "디자인팀".into() };
    vec![
        mk("DemoStudioPC00000000000001", "스튜디오 워크스테이션", "184 223 901", true, false, false, 0, &me),
        mk("DemoOfficeRender0000000002", "렌더 서버 #2", "512 007 338", true, false, true, 1, &team),
        mk("DemoLaptop0000000000000003", "이 노트북", "903 114 270", true, true, false, 0, &me),
        mk("DemoHomePC0000000000000004", "집 데스크톱", "771 450 112", false, false, false, 0, &me),
    ]
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, args: Args) -> App {
        setup_fonts(&cc.egui_ctx);
        setup_style(&cc.egui_ctx);
        let cfg = Config::load();
        cfg.save();
        let net = Net::start(cc.egui_ctx.clone());
        let engine_path = engine::find(&cfg.rustdesk_path);
        let mut app = App {
            login: LoginForm { email: cfg.email.clone(), ..Default::default() },
            screen: if cfg.session_id.is_empty() && !args.demo { Screen::Login } else { Screen::Main },
            cfg,
            net,
            tab: match args.tab.as_deref() {
                Some("host") => Tab::Host,
                Some("settings") => Tab::Settings,
                Some("guide") => Tab::Guide,
                _ => Tab::Computers,
            },
            hosts: Vec::new(),
            hosts_loaded: false,
            last_hosts: None,
            hosts_interval_ms: HOSTS_REFRESH_MS,
            last_beat: None,
            next_me: Instant::now() + Duration::from_millis(sigmadesk::me_poll_ms()),
            failures: 0,
            backoff_until: None,
            search: String::new(),
            direct_id: String::new(),
            direct_pw: String::new(),
            status: String::new(),
            status_err: false,
            status_until: None,
            pending_copy: None,
            host_status: "꺼짐".into(),
            engine_path,
            pending_link: args.link,
            pending_secret: args.secret,
            id_rx: None,
            demo: args.demo,
            screenshot: args.screenshot,
            frames: 0,
            shot_requested: false,
        };
        if app.demo {
            app.hosts = demo_hosts();
            app.hosts_loaded = true;
            app.cfg.user_name = "데모 사용자".into();
        } else if app.screen == Screen::Main {
            app.net.send(Job::Me { server: app.cfg.server_url.clone(), session: app.cfg.session_id.clone() });
        }
        app
    }

    fn signed_in(&self) -> bool {
        self.demo || !self.cfg.session_id.is_empty()
    }

    /// A notice that clears itself after `ms`, like Parsec's toasts.
    fn say_for(&mut self, text: impl Into<String>, ms: u64) {
        self.say(text, false);
        self.status_until = Some(Instant::now() + Duration::from_millis(ms));
    }

    fn say(&mut self, text: impl Into<String>, err: bool) {
        self.status_until = None;
        self.status = text.into();
        self.status_err = err;
    }

    fn handle_replies(&mut self) {
        while let Ok(reply) = self.net.rx.try_recv() {
            match reply {
                Reply::LoggedIn(a) => {
                    self.login.busy = false;
                    self.login.error.clear();
                    self.login.password.clear();
                    self.cfg.session_id = a.session_id;
                    self.cfg.user_name = a.user_name;
                    self.cfg.user_id = a.user_id;
                    self.cfg.email = self.login.email.trim().to_string();
                    self.cfg.save();
                    self.screen = Screen::Main;
                    self.last_hosts = None;
                    self.last_beat = None;
                    self.net.send(Job::Me { server: self.cfg.server_url.clone(), session: self.cfg.session_id.clone() });
                    self.say(format!("{} 님, 환영합니다", self.cfg.user_name), false);
                }
                Reply::Hosts(list) => {
                    self.hosts_interval_ms = sigmadesk::next_hosts_interval_ms(self.hosts_interval_ms, true);
                    self.ok();
                    self.hosts = list;
                    self.hosts_loaded = true;
                    if let Some(peer) = self.pending_link.take() {
                        match self.hosts.iter().find(|h| h.peer_id == peer).cloned() {
                            Some(h) => self.connect(&h),
                            None => self.say("링크의 컴퓨터를 목록에서 찾을 수 없습니다", true),
                        }
                    }
                }
                Reply::Me(me) => {
                    self.ok();
                    let c = me.app_config;
                    let mut changed = false;
                    for (dst, src) in [
                        (&mut self.cfg.id_server, c.rustdesk_id_server),
                        (&mut self.cfg.relay_server, c.rustdesk_relay_server),
                        (&mut self.cfg.server_key, c.rustdesk_key),
                    ] {
                        if !src.is_empty() && *dst != src {
                            *dst = src;
                            changed = true;
                        }
                    }
                    self.cfg.user_name = me.name;
                    self.cfg.is_admin = me.admin;
                    self.cfg.user_id = me.id;
                    self.cfg.save();
                    if changed {
                        self.say("서버에서 RustDesk 서버 설정을 받았습니다 (설정 탭에서 적용)", false);
                    }
                }
                Reply::HeartbeatOk => {
                    self.ok();
                    self.host_status = format!("온라인에 등록됨 · {}초마다 갱신", HEARTBEAT_MS / 1000);
                }
                Reply::AttemptLogged(id) => {
                    let short: String = id.chars().take(8).collect();
                    self.say(format!("{} · 제어 기록됨 (시도 ID {short}…)", self.status.clone()), false);
                }
                Reply::LoggedOut | Reply::Provisioned(_) => {}
                Reply::Removed(peer) => {
                    self.hosts.retain(|h| h.peer_id != peer);
                    self.say("목록에서 제거했습니다", false);
                }
                Reply::Failed(text, logout, kind) => {
                    self.login.busy = false;
                    if logout {
                        self.cfg.session_id.clear();
                        self.cfg.save();
                        self.screen = Screen::Login;
                        self.login.error = text;
                    } else if self.screen == Screen::Login {
                        self.login.error = text;
                    } else if kind == Kind::Hosts {
                        // Parsec's list rule: wait x1.5 longer after each failure, up to 60 s.
                        self.hosts_interval_ms = sigmadesk::next_hosts_interval_ms(self.hosts_interval_ms, false);
                        self.say(format!("{text} · 목록은 {}초 뒤 다시", self.hosts_interval_ms / 1000), true);
                    } else if kind == Kind::Background {
                        // Parsec's reconnect rule for the always-on link.
                        self.failures += 1;
                        let wait = sigmadesk::retry_delay_ms(self.failures);
                        self.backoff_until = Some(Instant::now() + Duration::from_millis(wait));
                        self.say(format!("{text} · {}초 뒤 다시 시도", wait / 1000), true);
                    } else {
                        self.say(text, true);
                    }
                }
            }
        }
        if let Some(rx) = &self.id_rx {
            if let Ok(res) = rx.try_recv() {
                self.id_rx = None;
                match res {
                    Ok(id) => {
                        self.cfg.rustdesk_id = id;
                        self.cfg.save();
                        self.say("RustDesk ID를 찾았습니다", false);
                    }
                    Err(e) => self.say(e, true),
                }
            }
        }
    }

    fn tick(&mut self) {
        if self.demo || self.cfg.session_id.is_empty() || self.screen != Screen::Main {
            return;
        }
        let due = |t: Option<Instant>, ms: u64| t.map(|t| t.elapsed() >= Duration::from_millis(ms)).unwrap_or(true);
        if due(self.last_hosts, self.hosts_interval_ms) {
            self.last_hosts = Some(Instant::now());
            self.refresh();
        }
        if self.backoff_until.map(|t| Instant::now() < t).unwrap_or(false) {
            return;
        }
        if Instant::now() >= self.next_me {
            self.next_me = Instant::now() + Duration::from_millis(sigmadesk::me_poll_ms());
            self.net.send(Job::Me { server: self.cfg.server_url.clone(), session: self.cfg.session_id.clone() });
        }
        if self.cfg.host_enabled && due(self.last_beat, HEARTBEAT_MS) {
            self.last_beat = Some(Instant::now());
            if self.cfg.rustdesk_id.trim().is_empty() {
                self.host_status = "RustDesk ID가 없어 등록하지 못했습니다".into();
            } else {
                self.net.send(Job::Heartbeat {
                    server: self.cfg.server_url.clone(),
                    session: self.cfg.session_id.clone(),
                    beat: crate::service::heartbeat_of(&self.cfg),
                });
            }
        }
    }

    fn ok(&mut self) {
        if self.failures > 0 {
            self.failures = 0;
            self.backoff_until = None;
            self.status.clear();
        }
    }

    fn refresh(&mut self) {
        if self.demo {
            return;
        }
        self.net.send(Job::Hosts {
            server: self.cfg.server_url.clone(),
            session: self.cfg.session_id.clone(),
            peer_id: self.cfg.peer_id.clone(),
        });
    }

    fn connect(&mut self, h: &Host) {
        if h.is_self {
            self.say("이 컴퓨터 자신에게는 접속할 수 없습니다", true);
            return;
        }
        // Each connection gets a Parsec-format attempt id and is reported to the server, which
        // keeps the admin console's control log (FUN_1800d0800 sends it in the offer).
        if !self.demo && !self.cfg.session_id.is_empty() {
            let secret = self.pending_secret.take().unwrap_or_default();
            let (secret, access_link_id) =
                if sigmadesk::is_access_link_id(&secret) { (String::new(), secret) } else { (secret, String::new()) };
            self.net.send(Job::Attempt {
                server: self.cfg.server_url.clone(),
                session: self.cfg.session_id.clone(),
                report: AttemptReport { attempt_id: sigmadesk::new_attempt_id(), peer_id: h.peer_id.clone(), secret, access_link_id },
            });
        }
        self.connect_id(&h.rustdesk_id.clone(), "", &h.name.clone());
    }

    fn connect_id(&mut self, id: &str, pw: &str, label: &str) {
        if self.demo {
            self.say(format!("데모: '{label}' ({id}) 에 RustDesk로 접속합니다"), false);
            return;
        }
        let Some(exe) = self.engine_path.clone().or_else(|| engine::find(&self.cfg.rustdesk_path)) else {
            self.say("RustDesk가 설치되어 있지 않습니다. 설정 탭에서 경로를 지정하세요", true);
            return;
        };
        match engine::connect(&exe, id, pw) {
            Ok(()) => self.say(format!("'{label}' 에 접속하는 중… (RustDesk 창이 열립니다)"), false),
            Err(e) => self.say(e, true),
        }
    }

    fn run(&mut self, action: Action) {
        match action {
            Action::Connect(h) => self.connect(&h),
            Action::Remove(peer) => {
                if peer == self.cfg.peer_id {
                    self.cfg.host_enabled = false;
                    self.cfg.save();
                }
                if self.demo {
                    self.hosts.retain(|h| h.peer_id != peer);
                } else {
                    self.net.send(Job::Remove { server: self.cfg.server_url.clone(), session: self.cfg.session_id.clone(), peer_id: peer });
                }
            }
            Action::Refresh => {
                self.backoff_until = None;
                self.last_hosts = Some(Instant::now());
                self.refresh();
                self.say("목록을 새로 고쳤습니다", false);
            }
            Action::Direct => {
                let (id, pw) = (self.direct_id.clone(), self.direct_pw.clone());
                self.connect_id(&id, &pw, &id);
            }
            Action::Logout => {
                if !self.demo && !self.cfg.session_id.is_empty() {
                    self.net.send(Job::Logout { server: self.cfg.server_url.clone(), session: self.cfg.session_id.clone() });
                }
                self.cfg.session_id.clear();
                self.cfg.is_admin = false;
                self.cfg.save();
                self.demo = false;
                self.hosts.clear();
                self.hosts_loaded = false;
                self.screen = Screen::Login;
            }
            Action::FindId => match self.engine_path.clone() {
                Some(exe) => {
                    let (tx, rx) = std::sync::mpsc::channel();
                    std::thread::spawn(move || {
                        let _ = tx.send(engine::get_id(&exe));
                    });
                    self.id_rx = Some(rx);
                    self.say("RustDesk에 ID를 묻는 중…", false);
                }
                None => self.say("RustDesk를 찾지 못했습니다", true),
            },
            Action::ApplyServers => match self.engine_path.clone() {
                Some(exe) => match engine::apply_servers(&exe, &self.cfg.id_server, &self.cfg.relay_server, &self.cfg.server_key, self.cfg.force_relay) {
                    Ok(()) => self.say("RustDesk가 이제 자체 서버를 사용합니다", false),
                    Err(e) => self.say(e, true),
                },
                None => self.say("RustDesk를 찾지 못했습니다", true),
            },
            // Parsec's Share / Stop Sharing (FUN_18002ad10): a fresh secret each time, link copied,
            // the next heartbeat tells the server; stopping clears it so old links stop working.
            Action::ShareStart => {
                self.cfg.share_secret = sigmadesk::new_share_secret();
                self.cfg.save();
                self.last_beat = None;
                let url = sigmadesk::share_url(&self.cfg.server_url, &self.cfg.peer_id, &self.cfg.share_secret);
                self.pending_copy = Some(url);
                self.say_for("공유 링크를 만들어 클립보드에 복사했습니다. 접속하게 할 사람에게 보내세요.", SHARE_COPIED_NOTICE_MS);
            }
            Action::ShareStop => {
                self.cfg.share_secret.clear();
                self.cfg.save();
                self.last_beat = None;
                self.say_for("공유 링크를 무효로 만들었습니다.", SHARE_STOPPED_NOTICE_MS);
            }
            Action::RegisterLink => match engine::register_link() {
                Ok(()) => self.say("sigmadesk:// 링크를 등록했습니다. 설치 웹의 '접속' 버튼이 이 앱을 엽니다", false),
                Err(e) => self.say(e, true),
            },
            Action::FindEngine => {
                self.engine_path = engine::find(&self.cfg.rustdesk_path);
                self.cfg.save();
                match &self.engine_path {
                    Some(p) => self.say(format!("RustDesk 찾음: {}", p.display()), false),
                    None => self.say("RustDesk를 찾지 못했습니다", true),
                }
            }
        }
    }

    // ---------------------------------------------------------------- screens

    fn login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(egui::Frame::none().fill(BG)).show(ctx, |ui| {
            let full = ui.max_rect();
            paint_backdrop(ui.painter(), full);
            let h = if self.login.signup { 600.0 } else { 540.0 };
            let rect = Rect::from_center_size(full.center(), Vec2::new(400.0, h));
            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                ui.vertical_centered(|ui| {
                    let (logo, _) = ui.allocate_exact_size(Vec2::splat(64.0), Sense::hover());
                    paint_logo(ui.painter(), logo);
                    ui.add_space(4.0);
                    ui.label(RichText::new("SigmaDesk").size(30.0).strong());
                    ui.label(RichText::new("어디서든, 내 컴퓨터를 바로 앞에 있는 것처럼").color(DIM));
                });
                ui.add_space(18.0);
                egui::Frame::none().fill(CARD).rounding(14.0).inner_margin(26.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let fw = ui.available_width();
                    field_label(ui, "서버 주소");
                    ui.add(egui::TextEdit::singleline(&mut self.cfg.server_url).desired_width(fw).margin(Vec2::new(10.0, 8.0)));
                    if self.login.signup {
                        field_label(ui, "이름");
                        ui.add(egui::TextEdit::singleline(&mut self.login.name).hint_text("표시될 이름").desired_width(fw).margin(Vec2::new(10.0, 8.0)));
                    }
                    field_label(ui, "이메일");
                    ui.add(egui::TextEdit::singleline(&mut self.login.email).hint_text("you@example.com").desired_width(fw).margin(Vec2::new(10.0, 8.0)));
                    field_label(ui, "비밀번호");
                    let pw = ui.add(egui::TextEdit::singleline(&mut self.login.password).password(true).desired_width(fw).margin(Vec2::new(10.0, 8.0)));
                    let enter = pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.add_space(8.0);
                    let label = if self.login.busy { "확인 중…" } else if self.login.signup { "계정 만들기" } else { "로그인" };
                    let go = ui
                        .add_enabled(!self.login.busy, egui::Button::new(RichText::new(label).color(Color32::WHITE).strong()).fill(ACCENT).min_size(Vec2::new(fw, 40.0)))
                        .clicked();
                    if (go || enter) && !self.login.busy {
                        self.login.busy = true;
                        self.login.error.clear();
                        self.cfg.save();
                        let job = if self.login.signup {
                            Job::Signup {
                                server: self.cfg.server_url.clone(),
                                email: self.login.email.trim().into(),
                                password: self.login.password.clone(),
                                name: self.login.name.trim().into(),
                            }
                        } else {
                            Job::Login {
                                server: self.cfg.server_url.clone(),
                                email: self.login.email.trim().into(),
                                password: self.login.password.clone(),
                                peer_id: self.cfg.peer_id.clone(),
                            }
                        };
                        self.net.send(job);
                    }
                    if !self.login.error.is_empty() {
                        ui.label(RichText::new(&self.login.error).color(RED));
                    }
                    ui.add_space(4.0);
                    ui.vertical_centered(|ui| {
                        let switch = if self.login.signup { "이미 계정이 있나요? 로그인" } else { "계정이 없나요? 가입하기" };
                        if ui.link(RichText::new(switch).color(ACCENT)).clicked() {
                            self.login.signup = !self.login.signup;
                            self.login.error.clear();
                        }
                    });
                });
                ui.add_space(14.0);
                ui.vertical_centered(|ui| {
                    if ui.button("서버 없이 ID로 바로 접속").clicked() {
                        self.screen = Screen::Main;
                        self.tab = Tab::Computers;
                    }
                    ui.add_space(2.0);
                    if ui.link(RichText::new("체험 모드로 둘러보기").color(DIM).small()).clicked() {
                        self.demo = true;
                        self.hosts = demo_hosts();
                        self.hosts_loaded = true;
                        self.cfg.user_name = "데모 사용자".into();
                        self.screen = Screen::Main;
                    }
                });
            });
        });
    }

    fn rail(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        egui::SidePanel::left("rail")
            .exact_width(84.0)
            .resizable(false)
            .frame(egui::Frame::none().fill(RAIL).inner_margin(egui::Margin::symmetric(10.0, 18.0)))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    let (logo, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                    paint_logo(ui.painter(), logo);
                    ui.add_space(22.0);
                    for (tab, icon, label) in [
                        (Tab::Computers, "🖥", "컴퓨터"),
                        (Tab::Host, "📡", "호스트"),
                        (Tab::Settings, "⚙", "설정"),
                        (Tab::Guide, "ℹ", "작동 원리"),
                    ] {
                        if rail_button(ui, icon, label, self.tab == tab).clicked() {
                            self.tab = tab;
                        }
                        ui.add_space(6.0);
                    }
                });
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.spacing_mut().button_padding = Vec2::new(6.0, 3.0);
                    if self.signed_in() {
                        if ui.add(egui::Button::new(RichText::new("로그아웃").small()).wrap_mode(egui::TextWrapMode::Extend)).clicked() {
                            actions.push(Action::Logout);
                        }
                    } else if ui.add(egui::Button::new(RichText::new("로그인").small()).wrap_mode(egui::TextWrapMode::Extend)).clicked() {
                        self.screen = Screen::Login;
                    }
                    let (r, resp) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                    let name = if self.cfg.user_name.is_empty() { "?" } else { &self.cfg.user_name };
                    ui.painter().circle_filled(r.center(), 19.0, tint(name));
                    ui.painter().text(r.center(), Align2::CENTER_CENTER, initial(name), FontId::proportional(17.0), Color32::WHITE);
                    resp.on_hover_text(name.to_string());
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .exact_height(34.0)
            .frame(egui::Frame::none().fill(RAIL).inner_margin(egui::Margin::symmetric(16.0, 2.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (dot, text) = if self.demo {
                        (ACCENT, "체험 모드".to_string())
                    } else if self.cfg.session_id.is_empty() {
                        (GREY, "로그인 안 됨 · ID 직접 접속만 가능".to_string())
                    } else {
                        (GREEN, format!("{} · {}", sigmadesk::account_tag(&self.cfg.user_name, self.cfg.user_id), self.cfg.server_url))
                    };
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, dot);
                    ui.label(RichText::new(text).small().color(DIM));
                    ui.separator();
                    let engine = if self.engine_path.is_some() { "RustDesk 엔진 준비됨" } else { "RustDesk 엔진 없음" };
                    ui.label(RichText::new(engine).small().color(if self.engine_path.is_some() { DIM } else { RED }));
                    if self.status_until.map(|t| Instant::now() >= t).unwrap_or(false) {
                        self.status.clear();
                        self.status_until = None;
                    }
                    if !self.status.is_empty() {
                        ui.separator();
                        ui.label(RichText::new(&self.status).small().color(if self.status_err { RED } else { TEXT }));
                    }
                });
            });
    }

    fn computers_tab(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("컴퓨터").size(28.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.signed_in() && ui.button("⟳ 새로 고침").clicked() {
                    actions.push(Action::Refresh);
                }
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("🔍 이름으로 찾기").desired_width(220.0).margin(Vec2::new(10.0, 6.0)));
            });
        });
        let online = self.hosts.iter().filter(|h| h.online).count();
        let sub = if self.signed_in() {
            format!("내 컴퓨터와 공유받은 컴퓨터 · {}대 중 {}대 온라인", self.hosts.len(), online)
        } else {
            "로그인하면 등록된 컴퓨터가 여기에 보입니다".to_string()
        };
        ui.label(RichText::new(sub).color(DIM));
        ui.add_space(10.0);

        egui::Frame::none().fill(CARD).rounding(12.0).inner_margin(egui::Margin::symmetric(18.0, 14.0)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("ID로 바로 접속").strong());
                ui.add(egui::TextEdit::singleline(&mut self.direct_id).hint_text("RustDesk ID (예: 123 456 789)").desired_width(220.0).margin(Vec2::new(10.0, 6.0)));
                ui.add(egui::TextEdit::singleline(&mut self.direct_pw).hint_text("비밀번호 (선택)").password(true).desired_width(150.0).margin(Vec2::new(10.0, 6.0)));
                let ok = !self.direct_id.trim().is_empty();
                if ui.add_enabled(ok, egui::Button::new(RichText::new("접속").color(Color32::WHITE)).fill(ACCENT)).clicked() {
                    actions.push(Action::Direct);
                }
            });
        });
        ui.add_space(16.0);

        let q = self.search.trim().to_lowercase();
        let shown: Vec<Host> = self.hosts.iter().filter(|h| q.is_empty() || h.name.to_lowercase().contains(&q)).cloned().collect();
        let my_id = if self.demo { 1 } else { self.cfg.user_id };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if !self.signed_in() {
                return;
            }
            if shown.is_empty() {
                let text = if !self.hosts_loaded {
                    "목록을 불러오는 중…"
                } else if q.is_empty() {
                    "아직 등록된 컴퓨터가 없습니다. 원격으로 들어갈 컴퓨터에서 '호스트' 탭을 켜세요."
                } else {
                    "찾는 이름의 컴퓨터가 없습니다."
                };
                ui.label(RichText::new(text).color(DIM));
                return;
            }
            let gap = 16.0;
            let cols = (((ui.available_width() + gap) / (CARD_W + gap)).floor() as usize).max(1);
            for row in shown.chunks(cols) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for h in row {
                        host_card(ui, h, my_id, actions);
                    }
                });
                ui.add_space(gap);
            }
        });
    }

    fn host_tab(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.label(RichText::new("호스트").size(28.0).strong());
        ui.label(RichText::new("이 컴퓨터를 온라인 목록에 올려 다른 곳에서 접속할 수 있게 합니다").color(DIM));
        ui.add_space(12.0);
        let mut changed = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            section(ui, "호스팅", |ui| {
                changed |= ui.checkbox(&mut self.cfg.host_enabled, RichText::new("이 컴퓨터를 온라인에 등록 (호스팅)").strong()).changed();
                let color = if self.cfg.host_enabled { GREEN } else { GREY };
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, color);
                    let text = if self.cfg.host_enabled { self.host_status.clone() } else { "꺼짐".to_string() };
                    ui.label(RichText::new(text).color(DIM));
                });
                if !self.signed_in() {
                    ui.label(RichText::new("등록하려면 먼저 로그인하세요").color(RED));
                }
            });
            section(ui, "이 컴퓨터", |ui| {
                egui::Grid::new("host_grid").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    ui.label("이름");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.host_name).desired_width(320.0)).changed();
                    ui.end_row();
                    ui.label("설명");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.host_desc).hint_text("예: 3층 렌더링 PC").desired_width(320.0)).changed();
                    ui.end_row();
                    ui.label("RustDesk ID");
                    ui.horizontal(|ui| {
                        changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.rustdesk_id).hint_text("RustDesk 창에 보이는 ID").desired_width(200.0)).changed();
                        if ui.button("자동으로 찾기").clicked() {
                            actions.push(Action::FindId);
                        }
                    });
                    ui.end_row();
                    ui.label("동시 접속");
                    changed |= ui.add(egui::Slider::new(&mut self.cfg.max_guests, 1..=10).suffix(" 명")).changed();
                    ui.end_row();
                });
                changed |= ui.checkbox(&mut self.cfg.host_public, "설치 웹의 공개 노드 목록에도 표시").changed();
                ui.label(RichText::new(format!("노드 ID {}", self.cfg.peer_id)).small().color(DIM));
            });
            section(ui, "공유 링크", |ui| {
                ui.label(RichText::new("링크를 받은 사람이 웹에서 이 컴퓨터를 보고 바로 접속할 수 있습니다. 중지하면 링크가 무효가 됩니다.").color(DIM));
                if self.cfg.share_secret.is_empty() {
                    if ui.add_enabled(self.signed_in(), egui::Button::new("🔗 공유 링크 만들기")).clicked() {
                        actions.push(Action::ShareStart);
                    }
                } else {
                    let url = sigmadesk::share_url(&self.cfg.server_url, &self.cfg.peer_id, &self.cfg.share_secret);
                    ui.horizontal(|ui| {
                        if ui.link(RichText::new(&url).monospace()).clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(url.clone()));
                        }
                        if ui.small_button("복사").clicked() {
                            ui.ctx().copy_text(url.clone());
                        }
                    });
                    if ui.button(RichText::new("공유 중지").color(RED)).clicked() {
                        actions.push(Action::ShareStop);
                    }
                }
                if !self.cfg.host_enabled {
                    ui.label(RichText::new("링크가 동작하려면 위의 호스팅을 켜 두세요.").small().color(DIM));
                }
            });
            section(ui, "목록에서 빼기", |ui| {
                ui.label(RichText::new("호스팅을 끄고 온라인 목록에서 이 컴퓨터를 지웁니다").color(DIM));
                if ui.add_enabled(self.signed_in(), egui::Button::new(RichText::new("이 컴퓨터 제거").color(RED))).clicked() {
                    actions.push(Action::Remove(self.cfg.peer_id.clone()));
                }
            });
        });
        if changed {
            self.last_beat = None;
            self.cfg.save();
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.label(RichText::new("설정").size(28.0).strong());
        ui.add_space(12.0);
        let mut changed = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            section(ui, "계정", |ui| {
                if self.signed_in() {
                    let role = if self.cfg.is_admin { "  ·  관리자" } else { "" };
                    ui.label(format!("{}  ·  {}{role}", self.cfg.user_name, if self.demo { "체험 모드" } else { &self.cfg.email }));
                    let base = self.cfg.server_url.trim().trim_end_matches('/').to_string();
                    ui.horizontal(|ui| {
                        if ui.button("🌐 내 웹 페이지").on_hover_text(format!("{base}/account")).clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(format!("{base}/account")));
                        }
                        if self.cfg.is_admin && ui.button("🛠 관리자 콘솔").on_hover_text(format!("{base}/admin")).clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(format!("{base}/admin")));
                        }
                        if ui.button("로그아웃").clicked() {
                            actions.push(Action::Logout);
                        }
                    });
                    ui.label(RichText::new("웹 페이지에서 내 컴퓨터 공개/제거, 비밀번호 변경, 모든 기기 로그아웃을 할 수 있습니다.").small().color(DIM));
                } else {
                    ui.label(RichText::new("로그인하지 않았습니다").color(DIM));
                }
            });
            section(ui, "웹 주소", |ui| {
                let base = self.cfg.server_url.trim().trim_end_matches('/').to_string();
                ui.label(RichText::new("브라우저로 여는 SigmaDesk 서버의 페이지입니다. 앱과 같은 계정으로 로그인합니다.").color(DIM));
                egui::Grid::new("web_urls").num_columns(3).spacing([14.0, 8.0]).show(ui, |ui| {
                    for (label, path, note) in [
                        ("사용자 페이지", "/account", "내 컴퓨터 · 비밀번호 · 로그아웃"),
                        ("관리자 콘솔", "/admin", "관리자 계정만 (처음 만든 계정)"),
                        ("로그인 / 가입", "/login", ""),
                        ("설치 안내", "/", ""),
                    ] {
                        let url = format!("{base}{path}");
                        ui.label(label);
                        ui.horizontal(|ui| {
                            if ui.link(RichText::new(&url).monospace()).clicked() {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(url.clone()));
                            }
                            if ui.small_button("복사").clicked() {
                                ui.ctx().copy_text(url.clone());
                            }
                        });
                        ui.label(RichText::new(note).small().color(DIM));
                        ui.end_row();
                    }
                });
            });
            section(ui, "SigmaDesk 서버", |ui| {
                ui.label(RichText::new("계정과 노드 목록을 보관하는 자체 서버 (sigmadesk-server)").color(DIM));
                changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.server_url).desired_width(360.0)).changed();
                ui.label(RichText::new(format!("설치 웹: {}/  ·  공개 노드: {}/nodes", self.cfg.server_url.trim_end_matches('/'), self.cfg.server_url.trim_end_matches('/'))).small().color(DIM));
            });
            section(ui, "RustDesk 엔진", |ui| {
                ui.horizontal(|ui| {
                    let (c, t) = match &self.engine_path {
                        Some(p) => (GREEN, format!("찾음: {}", p.display())),
                        None => (RED, "설치되지 않았거나 찾지 못함".to_string()),
                    };
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, c);
                    ui.label(t);
                });
                ui.horizontal(|ui| {
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.rustdesk_path).hint_text("rustdesk.exe 경로 (비우면 자동)").desired_width(320.0)).changed();
                    if ui.button("다시 찾기").clicked() {
                        actions.push(Action::FindEngine);
                    }
                });
                ui.add_space(6.0);
                egui::Grid::new("rd_grid").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                    ui.label("ID 서버");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.id_server).hint_text(format!("host:{RUSTDESK_ID_PORT}")).desired_width(300.0)).changed();
                    ui.end_row();
                    ui.label("릴레이 서버");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.relay_server).hint_text(format!("host@{RUSTDESK_RELAY_PORT}, host2@포트 …")).desired_width(300.0)).changed();
                    ui.end_row();
                    ui.label("공개 키");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.cfg.server_key).hint_text("hbbs의 id_ed25519.pub").desired_width(300.0)).changed();
                    ui.end_row();
                });
                let relays = sigmadesk::parse_relay_list(&self.cfg.relay_server, RUSTDESK_RELAY_PORT);
                ui.label(
                    RichText::new(format!(
                        "릴레이 {}개 (최대 {MAX_RELAYS}개, ','로 구분, 호스트@포트). RustDesk에는 첫 번째가 들어갑니다.",
                        relays.len()
                    ))
                    .small()
                    .color(DIM),
                );
                ui.horizontal(|ui| {
                    ui.label("릴레이 강제");
                    for (mode, text) in [(FORCE_RELAY_OFF, "끔"), (FORCE_RELAY_ALL, "모든 연결"), (FORCE_RELAY_WAN, "인터넷 연결만")] {
                        changed |= ui.radio_value(&mut self.cfg.force_relay, mode, text).changed();
                    }
                });
                if ui.button("RustDesk에 서버 적용").clicked() {
                    actions.push(Action::ApplyServers);
                }
            });
            section(ui, "웹 링크", |ui| {
                ui.label(RichText::new("설치 웹의 '접속' 버튼(sigmadesk://)이 이 앱을 열도록 등록합니다").color(DIM));
                if ui.button("sigmadesk:// 링크 등록").clicked() {
                    actions.push(Action::RegisterLink);
                }
            });
        });
        if changed {
            self.cfg.save();
        }
    }

    fn guide_tab(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("작동 원리").size(28.0).strong());
        ui.label(RichText::new("Parsec 분석에서 배운 구조와, SigmaDesk가 같은 일을 하는 방법").color(DIM));
        ui.add_space(12.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width().min(860.0), 250.0), Sense::hover());
            paint_diagram(ui.painter(), r);
            ui.add_space(10.0);
            section(ui, "1. 로그인과 컴퓨터 목록", |ui| {
                ui.label(format!(
                    "Parsec 앱은 API 서버에 POST /v2/auth 로 로그인하고, GET /v2/hosts?mode=desktop 로 컴퓨터 목록을 {}초마다 다시 받습니다 (최대 {}대). 실패하면 기다림을 {HOSTS_BACKOFF_FACTOR}배씩 늘려 최대 {}초까지 기다리고, 성공하면 다시 {}초로 돌아옵니다. SigmaDesk도 똑같이 합니다.",
                    HOSTS_REFRESH_MS / 1000,
                    MAX_HOSTS,
                    HOSTS_REFRESH_MAX_MS / 1000,
                    HOSTS_REFRESH_MS / 1000
                ));
            });
            section(ui, "2. 연결 신호", |ui| {
                ui.label(format!(
                    "Parsec은 웹소켓 신호 서버(SDK 버전 {PARSEC_SDK_VERSION})로 offer / answer / candex(후보 주소) 메시지를 주고받아 두 컴퓨터를 이어 줍니다. 끊기면 {}초~두 배 사이 임의 시간 뒤 다시 붙고 그 시간을 두 배씩(최대 {}초) 늘리며, {RETRY_DOUBLING_TRIES}번을 넘게 실패하면 {}~{}분 기다립니다. SigmaDesk에서는 RustDesk의 hbbs 서버가 신호를 맡고, 앱은 같은 규칙으로 서버에 다시 붙습니다.",
                    RETRY_START_MS / 1000,
                    RETRY_CAP_MS / 1000,
                    RETRY_LONG_WAIT_MS / 60000,
                    RETRY_LONG_WAIT_MS * 2 / 60000
                ));
            });
            section(ui, "3. 방화벽 넘기와 릴레이", |ui| {
                ui.label(format!(
                    "Parsec은 STUN(포트 {STUN_PORT}, 매직 쿠키 0x{STUN_MAGIC_COOKIE:08X})으로 바깥 주소를 알아내 직접 연결하고, 안 되면 릴레이로 우회합니다. 호스트 포트는 {HOST_PORT_BASE}+임의값(0~{}) 입니다. 릴레이는 '호스트@포트'를 ','로 이은 목록(최대 {MAX_RELAYS}개, 기본 {PARSEC_DEFAULT_RELAY})이고, 릴레이 강제는 끔 / 모든 연결 / 인터넷 연결만 세 가지입니다. SigmaDesk에서는 같은 규칙의 목록으로 RustDesk hbbr 릴레이(포트 {RUSTDESK_RELAY_PORT})를 씁니다.",
                    HOST_PORT_RANGE - 1
                ));
            });
            section(ui, "4. 호스팅", |ui| {
                ui.label(format!(
                    "호스트는 자기 상태(이름, 접속 인원, 공개 여부)를 서버에 알립니다. SigmaDesk는 {}초마다 하트비트를 보내고, {}초 동안 소식이 없으면 오프라인으로 표시합니다 (추정값).",
                    HEARTBEAT_MS / 1000,
                    OFFLINE_AFTER_MS / 1000
                ));
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_replies();
        self.tick();

        let mut actions = Vec::new();
        match self.screen {
            Screen::Login => self.login_screen(ctx),
            Screen::Main => {
                self.rail(ctx, &mut actions);
                self.status_bar(ctx);
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(BG).inner_margin(egui::Margin::symmetric(32.0, 26.0)))
                    .show(ctx, |ui| match self.tab {
                        Tab::Computers => self.computers_tab(ui, &mut actions),
                        Tab::Host => self.host_tab(ui, &mut actions),
                        Tab::Settings => self.settings_tab(ui, &mut actions),
                        Tab::Guide => self.guide_tab(ui),
                    });
            }
        }
        for a in actions {
            self.run(a);
        }
        if let Some(text) = self.pending_copy.take() {
            ctx.copy_text(text);
        }

        if let Some(path) = self.screenshot.clone() {
            self.frames += 1;
            ctx.request_repaint();
            if self.frames >= 120 && !self.shot_requested {
                self.shot_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            }
            let shot = ctx.input(|i| {
                i.raw.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = shot {
                let [w, h] = image.size;
                let bytes: Vec<u8> = image.pixels.iter().flat_map(|c| c.to_array()).collect();
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) = image::save_buffer(&path, &bytes, w as u32, h as u32, image::ExtendedColorType::Rgba8) {
                    eprintln!("screenshot failed: {e}");
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        } else {
            ctx.request_repaint_after(Duration::from_millis(1000));
        }
    }
}

// ---------------------------------------------------------------- drawing helpers

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.add_space(2.0);
    ui.label(RichText::new(text).small().color(DIM));
}

fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none().fill(CARD).rounding(12.0).inner_margin(egui::Margin::symmetric(20.0, 16.0)).show(ui, |ui| {
        ui.set_width(ui.available_width().min(860.0));
        ui.label(RichText::new(title).size(17.0).strong());
        ui.add_space(4.0);
        body(ui);
    });
    ui.add_space(12.0);
}

fn rail_button(ui: &mut egui::Ui, icon: &str, label: &str, selected: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(62.0, 58.0), Sense::click());
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, 10.0, Color32::from_rgb(30, 41, 66));
        p.rect_filled(Rect::from_min_size(Pos2::new(rect.left() - 10.0, rect.top() + 14.0), Vec2::new(3.0, 30.0)), 2.0, ACCENT);
    } else if resp.hovered() {
        p.rect_filled(rect, 10.0, Color32::from_rgb(22, 25, 33));
    }
    let col = if selected { Color32::WHITE } else { DIM };
    p.text(rect.center() - Vec2::new(0.0, 9.0), Align2::CENTER_CENTER, icon, FontId::proportional(21.0), col);
    p.text(rect.center() + Vec2::new(0.0, 16.0), Align2::CENTER_CENTER, label, FontId::proportional(11.5), col);
    resp
}

fn initial(name: &str) -> String {
    name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_else(|| "?".into())
}

/// A stable colour per name, for avatars and thumbnails.
fn tint(name: &str) -> Color32 {
    let h = name.bytes().fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
    const PALETTE: [Color32; 6] = [
        Color32::from_rgb(79, 70, 229),
        Color32::from_rgb(14, 116, 144),
        Color32::from_rgb(190, 24, 93),
        Color32::from_rgb(21, 128, 61),
        Color32::from_rgb(180, 83, 9),
        Color32::from_rgb(37, 99, 235),
    ];
    PALETTE[(h % PALETTE.len() as u32) as usize]
}

fn gradient(p: &egui::Painter, rect: Rect, top: Color32, bottom: Color32) {
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), top);
    mesh.colored_vertex(rect.right_top(), top);
    mesh.colored_vertex(rect.right_bottom(), bottom);
    mesh.colored_vertex(rect.left_bottom(), bottom);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    p.add(egui::Shape::mesh(mesh));
}

fn darker(c: Color32, f: f32) -> Color32 {
    Color32::from_rgb((c.r() as f32 * f) as u8, (c.g() as f32 * f) as u8, (c.b() as f32 * f) as u8)
}

fn paint_logo(p: &egui::Painter, r: Rect) {
    p.rect_filled(r, r.width() * 0.26, ACCENT);
    let inner = r.shrink(r.width() * 0.22);
    p.rect_filled(Rect::from_min_max(inner.left_top(), Pos2::new(inner.right(), inner.top() + inner.height() * 0.62)), 3.0, Color32::from_rgba_unmultiplied(255, 255, 255, 235));
    p.rect_filled(
        Rect::from_center_size(Pos2::new(inner.center().x, inner.bottom() - inner.height() * 0.12), Vec2::new(inner.width() * 0.5, inner.height() * 0.1)),
        2.0,
        Color32::from_rgba_unmultiplied(255, 255, 255, 235),
    );
    p.text(
        Pos2::new(inner.center().x, inner.top() + inner.height() * 0.31),
        Align2::CENTER_CENTER,
        "Σ",
        FontId::proportional(r.width() * 0.28),
        ACCENT,
    );
}

fn paint_monitor(p: &egui::Painter, c: Pos2, s: f32, col: Color32) {
    let screen = Rect::from_center_size(c - Vec2::new(0.0, s * 0.12), Vec2::new(s * 1.3, s * 0.82));
    p.rect_stroke(screen, 4.0, Stroke::new(2.5_f32, col));
    p.line_segment([Pos2::new(c.x, screen.bottom()), Pos2::new(c.x, screen.bottom() + s * 0.2)], Stroke::new(2.5_f32, col));
    p.line_segment([Pos2::new(c.x - s * 0.3, screen.bottom() + s * 0.22), Pos2::new(c.x + s * 0.3, screen.bottom() + s * 0.22)], Stroke::new(2.5_f32, col));
}

fn paint_backdrop(p: &egui::Painter, r: Rect) {
    p.circle_filled(Pos2::new(r.left() + r.width() * 0.18, r.top() + r.height() * 0.22), 260.0, Color32::from_rgba_unmultiplied(59, 130, 246, 14));
    p.circle_filled(Pos2::new(r.right() - r.width() * 0.12, r.bottom() - r.height() * 0.15), 320.0, Color32::from_rgba_unmultiplied(124, 58, 237, 12));
}

fn pill(p: &egui::Painter, at: Pos2, text: &str, dot: Color32) -> f32 {
    let font = FontId::proportional(11.5);
    let galley = p.layout_no_wrap(text.to_string(), font, Color32::WHITE);
    let w = galley.size().x + 26.0;
    let rect = Rect::from_min_size(at, Vec2::new(w, 22.0));
    p.rect_filled(rect, 11.0, Color32::from_rgba_unmultiplied(0, 0, 0, 120));
    p.circle_filled(Pos2::new(rect.left() + 10.0, rect.center().y), 3.5, dot);
    p.galley(Pos2::new(rect.left() + 18.0, rect.center().y - galley.size().y / 2.0), galley, Color32::WHITE);
    w
}

/// Parsec's card caption (FUN_18002ad10): "This Computer" for this machine, "Your Computer" when
/// you own it, "Shared Computer" when it has no owner, otherwise the owner as name#id.
fn card_caption(h: &Host, my_id: u32) -> String {
    if h.is_self {
        "이 컴퓨터".into()
    } else if my_id != 0 && h.user.id == my_id {
        "내 컴퓨터".into()
    } else if h.user.id == 0 && h.user.name.is_empty() {
        "공유된 컴퓨터".into()
    } else {
        sigmadesk::account_tag(&h.user.name, h.user.id)
    }
}

fn host_card(ui: &mut egui::Ui, h: &Host, my_id: u32, actions: &mut Vec<Action>) {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(CARD_W, CARD_H), Sense::hover());
    let p = ui.painter().clone();
    p.rect_filled(rect, 12.0, if resp.hovered() { CARD_HOVER } else { CARD });

    let thumb = Rect::from_min_size(rect.min + Vec2::splat(8.0), Vec2::new(CARD_W - 16.0, 104.0));
    let base = tint(&h.name);
    let (top, bottom) = if h.online { (base, darker(base, 0.45)) } else { (Color32::from_rgb(55, 60, 72), Color32::from_rgb(32, 35, 44)) };
    p.rect_filled(thumb, 8.0, bottom);
    gradient(&p, thumb.shrink2(Vec2::new(0.0, 6.0)), top, bottom);
    p.rect_filled(Rect::from_min_size(thumb.min, Vec2::new(thumb.width(), 10.0)), Rounding { nw: 8.0, ne: 8.0, sw: 0.0, se: 0.0 }, top);
    paint_monitor(&p, thumb.center() + Vec2::new(0.0, 6.0), 34.0, Color32::from_rgba_unmultiplied(255, 255, 255, if h.online { 200 } else { 90 }));
    let mut x = thumb.left() + 8.0;
    x += pill(&p, Pos2::new(x, thumb.top() + 8.0), if h.online { "온라인" } else { "오프라인" }, if h.online { GREEN } else { GREY }) + 6.0;
    if h.is_self {
        pill(&p, Pos2::new(x, thumb.top() + 8.0), "이 컴퓨터", ACCENT);
    } else if h.public {
        pill(&p, Pos2::new(x, thumb.top() + 8.0), "공개", Color32::from_rgb(250, 204, 21));
    }

    let ty = thumb.bottom() + 12.0;
    let name_galley = p.layout(h.name.clone(), FontId::proportional(16.0), TEXT, CARD_W - 24.0);
    p.galley(Pos2::new(rect.left() + 12.0, ty), name_galley, TEXT);
    let owner = card_caption(h, my_id);
    p.text(Pos2::new(rect.left() + 12.0, ty + 26.0), Align2::LEFT_TOP, owner, FontId::proportional(12.5), DIM);
    if h.max_players > 0 {
        p.text(
            Pos2::new(rect.right() - 12.0, ty + 26.0),
            Align2::RIGHT_TOP,
            format!("{}/{} 접속 중", h.players, h.max_players),
            FontId::proportional(12.5),
            DIM,
        );
    }

    let btn = Rect::from_min_size(Pos2::new(rect.left() + 12.0, rect.bottom() - 44.0), Vec2::new(CARD_W - 24.0 - 40.0, 32.0));
    let can = h.online && !h.is_self && !h.rustdesk_id.is_empty();
    let label = if h.is_self { "호스팅 중" } else if h.online { "접속" } else { "오프라인" };
    // The buttons are painted here and only sensed with `interact`, so they take no layout space
    // and the cards in a row stay aligned.
    let sense = if can { Sense::click() } else { Sense::hover() };
    let go = ui.interact(btn, ui.make_persistent_id(("go", &h.peer_id)), sense);
    let fill = if !can { CARD_HOVER } else if go.hovered() { Color32::from_rgb(96, 155, 250) } else { ACCENT };
    p.rect_filled(btn, 8.0, fill);
    p.text(btn.center(), Align2::CENTER_CENTER, label, FontId::proportional(15.0), if can { Color32::WHITE } else { DIM });
    if can && go.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if go.on_hover_text(format!("RustDesk ID {}", if h.rustdesk_id.is_empty() { "-" } else { &h.rustdesk_id })).clicked() {
        actions.push(Action::Connect(h.clone()));
    }
    let more = Rect::from_min_size(Pos2::new(btn.right() + 8.0, btn.top()), Vec2::new(32.0, 32.0));
    let menu = ui.interact(more, ui.make_persistent_id(("menu", &h.peer_id)), Sense::click());
    p.rect_filled(more, 8.0, if menu.hovered() { Color32::from_rgb(44, 49, 62) } else { CARD_HOVER });
    for dx in [-6.0, 0.0, 6.0] {
        p.circle_filled(more.center() + Vec2::new(dx, 0.0), 2.0, TEXT);
    }
    let popup = ui.make_persistent_id(("more", &h.peer_id));
    if menu.clicked() {
        ui.memory_mut(|m| m.toggle_popup(popup));
    }
    egui::popup::popup_below_widget(ui, popup, &menu, egui::PopupCloseBehavior::CloseOnClick, |ui| {
        ui.set_min_width(170.0);
        ui.label(RichText::new(format!("RustDesk ID {}", h.rustdesk_id)).small());
        if !h.desc.is_empty() {
            ui.label(RichText::new(&h.desc).small().color(DIM));
        }
        if ui.button("ID 복사").clicked() {
            ui.ctx().copy_text(h.rustdesk_id.clone());
        }
        if ui.button(RichText::new("목록에서 제거").color(RED)).clicked() {
            actions.push(Action::Remove(h.peer_id.clone()));
        }
    });
}

fn paint_diagram(p: &egui::Painter, r: Rect) {
    p.rect_filled(r, 12.0, CARD);
    let gap = 96.0;
    let bw = (r.width() - 40.0 - gap * 2.0) / 3.0;
    let bh = 62.0;
    let boxes = [
        (Pos2::new(r.left() + 20.0, r.top() + 24.0), "SigmaDesk 앱 (내 PC)", "로그인 · 목록 · 접속 버튼", ACCENT),
        (Pos2::new(r.left() + 20.0 + gap + bw, r.top() + 24.0), "SigmaDesk 서버", "계정 · 노드 등록 · 설치 웹", Color32::from_rgb(124, 58, 237)),
        (Pos2::new(r.left() + 20.0 + (gap + bw) * 2.0, r.top() + 24.0), "SigmaDesk 앱 (원격 PC)", "호스팅 · 하트비트", ACCENT),
        (Pos2::new(r.left() + 20.0, r.bottom() - 24.0 - bh), "RustDesk 엔진", "화면 · 입력 · 소리", Color32::from_rgb(14, 116, 144)),
        (Pos2::new(r.left() + 20.0 + gap + bw, r.bottom() - 24.0 - bh), "hbbs / hbbr", "ID·신호 · 릴레이", Color32::from_rgb(21, 128, 61)),
        (Pos2::new(r.left() + 20.0 + (gap + bw) * 2.0, r.bottom() - 24.0 - bh), "RustDesk 엔진", "원격 화면 송출", Color32::from_rgb(14, 116, 144)),
    ];
    let rects: Vec<Rect> = boxes.iter().map(|b| Rect::from_min_size(b.0, Vec2::new(bw, bh))).collect();
    let arrow = |a: Pos2, b: Pos2, label: &str| {
        p.line_segment([a, b], Stroke::new(2.0_f32, DIM));
        let dir = (b - a).normalized();
        let n = Vec2::new(-dir.y, dir.x);
        p.line_segment([b, b - dir * 8.0 + n * 5.0], Stroke::new(2.0_f32, DIM));
        p.line_segment([b, b - dir * 8.0 - n * 5.0], Stroke::new(2.0_f32, DIM));
        let mid = a + (b - a) * 0.5;
        if (b.y - a.y).abs() < 1.0 {
            p.text(mid - Vec2::new(0.0, 11.0), Align2::CENTER_CENTER, label, FontId::proportional(11.0), DIM);
        } else {
            p.text(mid + Vec2::new(8.0, 0.0), Align2::LEFT_CENTER, label, FontId::proportional(11.0), DIM);
        }
    };
    arrow(rects[0].right_center(), rects[1].left_center(), "/v2/hosts");
    arrow(rects[2].left_center(), rects[1].right_center(), "하트비트");
    arrow(rects[0].center_bottom(), rects[3].center_top(), "--connect ID");
    arrow(rects[3].right_center(), rects[4].left_center(), "신호");
    arrow(rects[4].right_center(), rects[5].left_center(), "P2P/릴레이");
    for (b, rect) in boxes.iter().zip(&rects) {
        p.rect_filled(*rect, 10.0, darker(b.3, 0.55));
        p.rect_stroke(*rect, 10.0, Stroke::new(1.5_f32, b.3));
        p.text(rect.center() - Vec2::new(0.0, 10.0), Align2::CENTER_CENTER, b.1, FontId::proportional(14.0), Color32::WHITE);
        p.text(rect.center() + Vec2::new(0.0, 13.0), Align2::CENTER_CENTER, b.2, FontId::proportional(11.5), DIM);
    }
}

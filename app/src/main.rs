#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! SigmaDesk: a Parsec-style remote desktop app. Sign in, see your computers, press Connect.
//! Hosting registers this computer in the online list; the RustDesk engine does the streaming.

mod config;
mod engine;
mod net;
mod service;
mod ui;

use eframe::egui;
use std::path::PathBuf;

pub struct Args {
    pub screenshot: Option<PathBuf>,
    pub demo: bool,
    pub link: Option<String>,
    /// Open on this tab: computers, host, settings, guide.
    pub tab: Option<String>,
    /// host_secret from a Parsec-style link ("peer_id=..:host_secret=..").
    pub secret: Option<String>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args { screenshot: None, demo: false, link: None, tab: None, secret: None };
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--screenshot" => {
                args.screenshot = argv.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--demo" => args.demo = true,
            "--tab" => {
                args.tab = argv.get(i + 1).cloned();
                i += 1;
            }
            other => {
                if let Some(peer) = engine::link_target(other) {
                    args.link = Some(peer);
                    args.secret = engine::link_secret(other);
                }
            }
        }
        i += 1;
    }
    args
}

fn main() -> eframe::Result<()> {
    // Windowless node modes (used by the node installer and its start-up entry).
    let argv: Vec<String> = std::env::args().collect();
    if let Some(i) = argv.iter().position(|a| a == "--provision") {
        let (server, team, key) = match (argv.get(i + 1), argv.get(i + 2), argv.get(i + 3)) {
            (Some(s), Some(t), Some(k)) => (s.clone(), t.clone(), k.clone()),
            _ => {
                eprintln!("사용법: sigmadesk --provision <서버 주소> <팀> <노드 등록 키> [--per-computer]");
                std::process::exit(1);
            }
        };
        let per_computer = argv.iter().any(|a| a == "--per-computer");
        std::process::exit(service::provision(&server, &team, &key, per_computer));
    }
    // Parsec starts itself silently with "app_silent=1" (FUN_1800731f0); accept it as well.
    if argv.iter().any(|a| a == "--host-service" || a.contains(sigmadesk::consts::SILENT_START_ARG)) {
        std::process::exit(service::host_service());
    }
    let args = parse_args();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SigmaDesk")
            .with_inner_size([1180.0, 740.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("SigmaDesk", options, Box::new(move |cc| Ok(Box::new(ui::App::new(cc, args)))))
}

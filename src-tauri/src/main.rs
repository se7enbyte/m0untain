// m0untain — host firewall app entry point.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod active_connections;
mod settings;
mod wfp;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sentinel_core::{
    build_tick, Action, Config, Direction, Engine, Metrics, NetEvent, Proto, Talkers, Verdict,
};
use serde::Serialize;
use settings::{AppSettings, PersistentState, ProgramRule};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, State, WindowEvent};

use active_connections::ActiveConnection;
use wfp::{AppProtocol, Firewall, PlatformFirewall, RawConn};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgramPrompt {
    id: String,
    app_path: String,
    app_name: String,
    direction: String,
    protocol: String,
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
    first_connection_may_have_passed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionSeen {
    id: String,
    ts_ms: u64,
    app_path: Option<String>,
    app_name: String,
    direction: String,
    protocol: String,
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
    pid: u32,
    verdict: String,
    reason: Option<String>,
    is_new_conn: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppQuarantine {
    app_path: String,
    app_name: String,
    protocol: String,
    status: String,
    active: bool,
    temporary: bool,
}

struct PendingProgram {
    prompt: ProgramPrompt,
    app_id: Vec<u8>,
    temporary_handle: Option<u64>,
}

#[derive(Debug, Clone)]
struct RuntimeAppBlock {
    handle: u64,
    app_path: String,
    app_name: String,
    protocol: String,
    temporary: bool,
}

#[derive(Debug, Clone)]
struct KnownApp {
    app_path: String,
    app_name: String,
    app_id: Vec<u8>,
}

struct Shared {
    engine: Mutex<Engine>,
    metrics: Mutex<Metrics>,
    talkers: Mutex<Talkers>,
    fw: PlatformFirewall,
    enforced: Mutex<HashMap<IpAddr, (u64, u64)>>,
    app_settings: Mutex<AppSettings>,
    program_rules: Mutex<HashMap<String, ProgramRule>>,
    session_program_rules: Mutex<HashMap<String, ProgramRule>>,
    pending_programs: Mutex<HashMap<String, PendingProgram>>,
    app_blocks: Mutex<HashMap<String, RuntimeAppBlock>>,
    known_apps: Mutex<HashMap<String, KnownApp>>,
    persistence_path: PathBuf,
}

impl Shared {
    fn raw_to_event(raw: &RawConn) -> NetEvent {
        NetEvent {
            ts_ms: raw.ts_ms,
            direction: if raw.inbound {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
            proto: if raw.udp { Proto::Udp } else { Proto::Tcp },
            local_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            local_port: raw.local_port,
            remote_ip: raw.remote_ip,
            remote_port: raw.remote_port,
            pid: raw.pid,
            app_path: raw.app_path.clone(),
            service_sid: None,
            is_new_conn: raw.is_new,
            action: Action::Allow,
        }
    }

    fn save(&self) -> Result<(), String> {
        let state = PersistentState {
            settings: self.app_settings.lock().unwrap().clone(),
            rules: self.program_rules.lock().unwrap().clone(),
        };
        settings::save(&self.persistence_path, &state)
    }
}

fn app_key(path: &str) -> String {
    path.trim().to_lowercase()
}

fn app_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn find_rule_in(
    rules: &HashMap<String, ProgramRule>,
    key: &str,
    app_id: &[u8],
) -> Option<(String, ProgramRule)> {
    rules
        .get(key)
        .cloned()
        .map(|rule| (key.to_string(), rule))
        .or_else(|| {
            rules
                .iter()
                .find(|(_, rule)| !rule.app_id.is_empty() && rule.app_id == app_id)
                .map(|(rule_key, rule)| (rule_key.clone(), rule.clone()))
        })
}

fn find_program_rule(shared: &Shared, key: &str, app_id: &[u8]) -> Option<(String, ProgramRule)> {
    find_rule_in(&shared.program_rules.lock().unwrap(), key, app_id)
        .or_else(|| find_rule_in(&shared.session_program_rules.lock().unwrap(), key, app_id))
}

fn has_pending_program(shared: &Shared, key: &str, app_id: &[u8]) -> bool {
    let pending = shared.pending_programs.lock().unwrap();
    pending.contains_key(key)
        || pending
            .values()
            .any(|pending| !pending.app_id.is_empty() && pending.app_id == app_id)
}

fn remove_rules_with_app_id(rules: &mut HashMap<String, ProgramRule>, key: &str, app_id: &[u8]) {
    let duplicates: Vec<String> = rules
        .iter()
        .filter(|(rule_key, rule)| {
            rule_key.as_str() == key || (!rule.app_id.is_empty() && rule.app_id == app_id)
        })
        .map(|(rule_key, _)| rule_key.clone())
        .collect();
    for duplicate in duplicates {
        rules.remove(&duplicate);
    }
}

fn parse_protocol(value: &str) -> Result<AppProtocol, String> {
    match value {
        "all" => Ok(AppProtocol::All),
        "tcp" => Ok(AppProtocol::Tcp),
        "udp" => Ok(AppProtocol::Udp),
        _ => Err("protocol must be all, tcp or udp".to_string()),
    }
}

fn protocol_str(raw: &RawConn) -> &'static str {
    if raw.udp {
        "udp"
    } else {
        "tcp"
    }
}

fn remember_known_app(shared: &Shared, raw: &RawConn) {
    let Some(path) = raw
        .app_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    else {
        return;
    };
    let Some(app_id) = raw.app_id.as_ref().filter(|id| !id.is_empty()) else {
        return;
    };

    let key = app_key(path);
    shared.known_apps.lock().unwrap().insert(
        key,
        KnownApp {
            app_path: path.to_string(),
            app_name: app_name(path),
            app_id: app_id.clone(),
        },
    );
}

fn connection_seen(raw: &RawConn, verdict: &Verdict) -> ConnectionSeen {
    let (verdict_name, reason) = match verdict {
        Verdict::Pass => ("allow".to_string(), None),
        Verdict::Block { reason, .. } => ("block".to_string(), Some(format!("{reason:?}"))),
    };
    ConnectionSeen {
        id: format!(
            "{}-{}-{}-{}",
            raw.ts_ms, raw.pid, raw.remote_ip, raw.remote_port
        ),
        ts_ms: raw.ts_ms,
        app_path: raw.app_path.clone(),
        app_name: raw
            .app_path
            .as_deref()
            .map(app_name)
            .unwrap_or_else(|| format!("pid {}", raw.pid)),
        direction: if raw.inbound { "inbound" } else { "outbound" }.to_string(),
        protocol: protocol_str(raw).to_string(),
        remote_ip: raw.remote_ip.to_string(),
        remote_port: raw.remote_port,
        local_port: raw.local_port,
        pid: raw.pid,
        verdict: verdict_name,
        reason,
        is_new_conn: raw.is_new,
    }
}

fn active_to_raw(conn: &ActiveConnection, ts_ms: u64) -> RawConn {
    let app_id = conn.app_path.as_deref().and_then(wfp::app_id_from_path);
    RawConn {
        ts_ms,
        inbound: false,
        is_new: true,
        udp: conn.protocol == "udp",
        remote_ip: conn.remote_ip,
        remote_port: conn.remote_port,
        local_port: conn.local_port,
        pid: conn.pid,
        app_id,
        app_path: conn.app_path.clone(),
    }
}

fn snapshot_seen(conn: &ActiveConnection, ts_ms: u64) -> ConnectionSeen {
    ConnectionSeen {
        id: format!(
            "snapshot-{}-{}-{}-{}-{}",
            conn.protocol, conn.pid, conn.local_port, conn.remote_ip, conn.remote_port
        ),
        ts_ms,
        app_path: conn.app_path.clone(),
        app_name: conn.app_name.clone(),
        direction: "outbound".to_string(),
        protocol: conn.protocol.to_string(),
        remote_ip: conn.remote_ip.to_string(),
        remote_port: conn.remote_port,
        local_port: conn.local_port,
        pid: conn.pid,
        verdict: "allow".to_string(),
        reason: Some("active-snapshot".to_string()),
        is_new_conn: false,
    }
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn install_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "show", "m0untain'ı aç", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Çıkış", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;

    let mut tray = TrayIconBuilder::with_id("m0untain-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("m0untain · protection active");
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn quarantine_snapshot(shared: &Shared) -> Vec<AppQuarantine> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let app_blocks = shared.app_blocks.lock().unwrap();
    let rules = shared.program_rules.lock().unwrap();

    for (key, rule) in rules.iter() {
        if rule.decision != "quarantine" {
            continue;
        }
        let active = app_blocks.contains_key(key);
        seen.insert(key.clone());
        out.push(AppQuarantine {
            app_path: rule.app_path.clone(),
            app_name: rule.app_name.clone(),
            protocol: rule.protocol.clone(),
            status: if active { "enforced" } else { "remembered" }.to_string(),
            active,
            temporary: false,
        });
    }

    for (key, block) in app_blocks.iter() {
        if seen.contains(key) {
            continue;
        }
        seen.insert(key.clone());
        out.push(AppQuarantine {
            app_path: block.app_path.clone(),
            app_name: block.app_name.clone(),
            protocol: block.protocol.clone(),
            status: if block.temporary {
                "session"
            } else {
                "enforced"
            }
            .to_string(),
            active: true,
            temporary: block.temporary,
        });
    }
    drop(rules);
    drop(app_blocks);

    for (key, pending) in shared.pending_programs.lock().unwrap().iter() {
        if seen.contains(key) {
            continue;
        }
        out.push(AppQuarantine {
            app_path: pending.prompt.app_path.clone(),
            app_name: pending.prompt.app_name.clone(),
            protocol: "all".to_string(),
            status: "waiting".to_string(),
            active: pending.temporary_handle.is_some(),
            temporary: true,
        });
    }

    out.sort_by(|a, b| {
        let a_rank = match a.status.as_str() {
            "waiting" => 0,
            "session" => 1,
            "enforced" => 2,
            _ => 3,
        };
        let b_rank = match b.status.as_str() {
            "waiting" => 0,
            "session" => 1,
            "enforced" => 2,
            _ => 3,
        };
        a_rank
            .cmp(&b_rank)
            .then_with(|| a.app_name.to_lowercase().cmp(&b.app_name.to_lowercase()))
    });
    out
}

// ---- Tauri commands -------------------------------------------------------

#[tauri::command]
fn get_state(state: State<Arc<Shared>>) -> serde_json::Value {
    let eng = state.engine.lock().unwrap();
    let cfg = eng.config();
    let pending: Vec<ProgramPrompt> = state
        .pending_programs
        .lock()
        .unwrap()
        .values()
        .map(|pending| pending.prompt.clone())
        .collect();
    let rules: Vec<serde_json::Value> = state
        .program_rules
        .lock()
        .unwrap()
        .values()
        .map(|rule| {
            serde_json::json!({
                "appPath": rule.app_path,
                "appName": rule.app_name,
                "decision": rule.decision,
                "protocol": rule.protocol,
            })
        })
        .collect();
    let session_rules: Vec<serde_json::Value> = state
        .session_program_rules
        .lock()
        .unwrap()
        .values()
        .map(|rule| {
            serde_json::json!({
                "appPath": rule.app_path,
                "appName": rule.app_name,
                "decision": rule.decision,
                "protocol": rule.protocol,
                "temporary": true,
            })
        })
        .collect();
    serde_json::json!({
        "backend": state.fw.backend(),
        "toggles": { "ddos": cfg.ddos.enabled, "scan": cfg.scan.enabled },
        "config": cfg,
        "appSettings": state.app_settings.lock().unwrap().clone(),
        "programRules": rules,
        "sessionProgramRules": session_rules,
        "appQuarantines": quarantine_snapshot(&state),
        "pendingPrograms": pending,
    })
}

#[tauri::command]
fn set_protection(module: String, enabled: bool, state: State<Arc<Shared>>) {
    let mut eng = state.engine.lock().unwrap();
    match module.as_str() {
        "ddos" => eng.set_ddos_enabled(enabled),
        "scan" => eng.set_scan_enabled(enabled),
        _ => {}
    }
}

#[tauri::command]
fn set_config(config: Config, state: State<Arc<Shared>>) {
    state.engine.lock().unwrap().set_config(config);
}

#[tauri::command]
fn set_app_settings(settings: AppSettings, state: State<Arc<Shared>>) -> Result<(), String> {
    settings::set_autostart(settings.launch_on_startup)?;
    *state.app_settings.lock().unwrap() = settings;
    state.save()
}

#[tauri::command]
fn decide_program(
    request_id: String,
    decision: String,
    protocol: String,
    remember: bool,
    state: State<Arc<Shared>>,
) -> Result<(), String> {
    if decision != "allow" && decision != "quarantine" {
        return Err("decision must be allow or quarantine".to_string());
    }
    let scope = parse_protocol(&protocol)?;
    let pending = state
        .pending_programs
        .lock()
        .unwrap()
        .remove(&request_id)
        .ok_or_else(|| "connection request is no longer pending".to_string())?;

    if let Some(handle) = pending.temporary_handle {
        let _ = state.fw.unblock(handle);
    }
    if decision == "quarantine" {
        let handle = state.fw.block_app(&pending.app_id, scope)?;
        state.app_blocks.lock().unwrap().insert(
            request_id.clone(),
            RuntimeAppBlock {
                handle,
                app_path: pending.prompt.app_path.clone(),
                app_name: pending.prompt.app_name.clone(),
                protocol: protocol.clone(),
                temporary: !remember,
            },
        );
    }

    let rule = ProgramRule {
        app_path: pending.prompt.app_path,
        app_name: pending.prompt.app_name,
        app_id: pending.app_id,
        decision,
        protocol,
    };
    let key = request_id;
    if remember {
        {
            let mut session_rules = state.session_program_rules.lock().unwrap();
            remove_rules_with_app_id(&mut session_rules, &key, &rule.app_id);
        }
        {
            let mut rules = state.program_rules.lock().unwrap();
            remove_rules_with_app_id(&mut rules, &key, &rule.app_id);
            rules.insert(key, rule);
        }
        state.save()?;
    } else {
        let mut session_rules = state.session_program_rules.lock().unwrap();
        remove_rules_with_app_id(&mut session_rules, &key, &rule.app_id);
        session_rules.insert(key, rule);
    }
    Ok(())
}

#[tauri::command]
fn remove_program_rule(app_path: String, state: State<Arc<Shared>>) -> Result<(), String> {
    let key = app_key(&app_path);
    state.program_rules.lock().unwrap().remove(&key);
    state.session_program_rules.lock().unwrap().remove(&key);
    if let Some(block) = state.app_blocks.lock().unwrap().remove(&key) {
        let _ = state.fw.unblock(block.handle);
    }
    state.save()
}

#[tauri::command]
fn set_program_rule_decision(
    app_path: String,
    decision: String,
    protocol: String,
    state: State<Arc<Shared>>,
) -> Result<(), String> {
    if decision != "allow" && decision != "quarantine" {
        return Err("decision must be allow or quarantine".to_string());
    }
    let scope = parse_protocol(&protocol)?;
    let key = app_key(&app_path);
    let known = state.known_apps.lock().unwrap().get(&key).cloned();
    let (rule_key, mut rule) = if let Some(known) = known {
        if let Some((rule_key, rule)) = find_program_rule(&state, &key, &known.app_id) {
            (rule_key, rule)
        } else {
            (
                key.clone(),
                ProgramRule {
                    app_path: known.app_path,
                    app_name: known.app_name,
                    app_id: known.app_id,
                    decision: "allow".to_string(),
                    protocol: "all".to_string(),
                },
            )
        }
    } else if let Some(rule) = state.program_rules.lock().unwrap().get(&key).cloned() {
        (key.clone(), rule)
    } else {
        return Err("program was not observed in this session yet".to_string());
    };

    if decision == "allow" {
        if let Some(block) = state.app_blocks.lock().unwrap().remove(&rule_key) {
            let _ = state.fw.unblock(block.handle);
        }
    } else {
        let handle = state.fw.block_app(&rule.app_id, scope)?;
        if let Some(old) = state.app_blocks.lock().unwrap().insert(
            rule_key.clone(),
            RuntimeAppBlock {
                handle,
                app_path: rule.app_path.clone(),
                app_name: rule.app_name.clone(),
                protocol: protocol.clone(),
                temporary: false,
            },
        ) {
            let _ = state.fw.unblock(old.handle);
        }
    }

    rule.decision = decision;
    rule.protocol = protocol;
    {
        let mut session_rules = state.session_program_rules.lock().unwrap();
        remove_rules_with_app_id(&mut session_rules, &rule_key, &rule.app_id);
    }
    {
        let mut rules = state.program_rules.lock().unwrap();
        remove_rules_with_app_id(&mut rules, &rule_key, &rule.app_id);
        rules.insert(rule_key, rule);
    }
    state.save()
}

#[tauri::command]
fn block_remote_ip(ip: String, minutes: u64, state: State<Arc<Shared>>) -> Result<(), String> {
    let addr: IpAddr = ip.parse().map_err(|_| "invalid IP".to_string())?;
    let block_ms = minutes.max(1).saturating_mul(60_000);
    let until_ms = now_ms().saturating_add(block_ms);
    let handle = state.fw.block_ip(addr)?;
    if let Some((old_handle, _)) = state
        .enforced
        .lock()
        .unwrap()
        .insert(addr, (handle, until_ms))
    {
        let _ = state.fw.unblock(old_handle);
    }
    state.engine.lock().unwrap().block_manual(addr, until_ms);
    Ok(())
}

#[tauri::command]
fn whitelist_add(ip: String, state: State<Arc<Shared>>) -> Result<(), String> {
    let addr: IpAddr = ip.parse().map_err(|_| "invalid IP".to_string())?;
    state.engine.lock().unwrap().whitelist_add(addr);
    Ok(())
}

#[tauri::command]
fn unblock_ip(ip: String, state: State<Arc<Shared>>) -> Result<(), String> {
    let addr: IpAddr = ip.parse().map_err(|_| "invalid IP".to_string())?;
    state.engine.lock().unwrap().unblock(&addr);
    if let Some((handle, _)) = state.enforced.lock().unwrap().remove(&addr) {
        let _ = state.fw.unblock(handle);
    }
    Ok(())
}

// ---- background workers ---------------------------------------------------

fn inspect_program(shared: &Arc<Shared>, app: &tauri::AppHandle, raw: &RawConn) {
    if raw.inbound {
        return;
    }
    let Some(path) = raw
        .app_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    else {
        return;
    };
    let Some(app_id) = raw.app_id.as_ref().filter(|id| !id.is_empty()) else {
        return;
    };
    let key = app_key(path);

    if let Some((rule_key, rule)) = find_program_rule(shared, &key, app_id) {
        if rule.decision == "quarantine"
            && !shared.app_blocks.lock().unwrap().contains_key(&rule_key)
        {
            if let Ok(handle) = shared.fw.block_app(
                &rule.app_id,
                parse_protocol(&rule.protocol).unwrap_or(AppProtocol::All),
            ) {
                shared.app_blocks.lock().unwrap().insert(
                    rule_key,
                    RuntimeAppBlock {
                        handle,
                        app_path: rule.app_path,
                        app_name: rule.app_name,
                        protocol: rule.protocol,
                        temporary: false,
                    },
                );
            }
        }
        return;
    }
    if !shared.app_settings.lock().unwrap().ask_new_apps
        || has_pending_program(shared, &key, app_id)
        || shared.app_blocks.lock().unwrap().contains_key(&key)
    {
        return;
    }

    // User-mode WFP subscriptions observe classification after it happens. We
    // immediately quarantine future attempts, then ask the user for a rule.
    let temporary_handle = shared.fw.block_app(app_id, AppProtocol::All).ok();
    let prompt = ProgramPrompt {
        id: key.clone(),
        app_path: path.to_string(),
        app_name: app_name(path),
        direction: "outbound".to_string(),
        protocol: if raw.udp { "udp" } else { "tcp" }.to_string(),
        remote_ip: raw.remote_ip.to_string(),
        remote_port: raw.remote_port,
        local_port: raw.local_port,
        first_connection_may_have_passed: true,
    };
    shared.pending_programs.lock().unwrap().insert(
        key,
        PendingProgram {
            prompt: prompt.clone(),
            app_id: app_id.clone(),
            temporary_handle,
        },
    );
    let _ = app.emit("program-connection-request", prompt);
    show_main(app);
}

fn consumer(shared: Arc<Shared>, app: tauri::AppHandle, rx: std::sync::mpsc::Receiver<RawConn>) {
    for raw in rx {
        remember_known_app(&shared, &raw);
        inspect_program(&shared, &app, &raw);
        let ev = Shared::raw_to_event(&raw);
        let verdict = { shared.engine.lock().unwrap().inspect(&ev) };

        if let Verdict::Block { until_ms, .. } = verdict {
            let mut enforced = shared.enforced.lock().unwrap();
            if let std::collections::hash_map::Entry::Vacant(entry) = enforced.entry(ev.remote_ip) {
                match shared.fw.block_ip(ev.remote_ip) {
                    Ok(handle) => {
                        entry.insert((handle, until_ms));
                    }
                    Err(error) => eprintln!("block_ip failed for {}: {error}", ev.remote_ip),
                }
            }
        }

        shared.metrics.lock().unwrap().record(&ev, &verdict);
        shared
            .talkers
            .lock()
            .unwrap()
            .record(ev.remote_ip, ev.ts_ms);
        let _ = app.emit("connection-seen", connection_seen(&raw, &verdict));
    }
}

fn ticker(shared: Arc<Shared>, app: tauri::AppHandle) {
    loop {
        thread::sleep(Duration::from_millis(1000));
        let now = now_ms();

        {
            let mut enforced = shared.enforced.lock().unwrap();
            let expired: Vec<IpAddr> = enforced
                .iter()
                .filter(|(_, (_, until))| now >= *until)
                .map(|(ip, _)| *ip)
                .collect();
            for ip in expired {
                if let Some((handle, _)) = enforced.remove(&ip) {
                    let _ = shared.fw.unblock(handle);
                }
            }
        }

        let payload = {
            let mut eng = shared.engine.lock().unwrap();
            eng.tick(now);
            let blocks = eng.active_blocks(now);
            let metrics = shared.metrics.lock().unwrap();
            let mut talkers = shared.talkers.lock().unwrap();
            talkers.cleanup(now);
            build_tick(metrics.latest().as_ref(), &blocks, &talkers, now)
        };
        let _ = app.emit("metrics-tick", payload);
    }
}

fn snapshotter(shared: Arc<Shared>, app: tauri::AppHandle) {
    loop {
        thread::sleep(Duration::from_millis(1200));
        let now = now_ms();
        let mut emitted = Vec::new();
        let mut seen = HashSet::new();

        for conn in active_connections::snapshot() {
            let id = format!(
                "{}:{}:{}:{}:{}",
                conn.protocol, conn.pid, conn.local_port, conn.remote_ip, conn.remote_port
            );
            if !seen.insert(id) {
                continue;
            }

            let raw = active_to_raw(&conn, now);
            remember_known_app(&shared, &raw);
            if !raw.udp && !raw.remote_ip.is_unspecified() {
                inspect_program(&shared, &app, &raw);
            }
            emitted.push(snapshot_seen(&conn, now));
        }

        let _ = app.emit("connection-snapshot", emitted);
    }
}

fn main() {
    tauri::Builder::default()
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|app, event| {
            if let TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } = event
            {
                show_main(app);
            }
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    let close_to_tray = window
                        .state::<Arc<Shared>>()
                        .app_settings
                        .lock()
                        .unwrap()
                        .close_to_tray;
                    if close_to_tray {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
            }
        })
        .setup(|app| {
            let cfg = Config::default();
            let config_dir = app.path().app_config_dir()?;
            let persistence_path = settings::default_path(config_dir);
            let persistent = settings::load(&persistence_path);
            let (tx, rx) = channel::<RawConn>();
            let fw = wfp::start(tx).map_err(|error| {
                eprintln!("firewall backend failed to start: {error}");
                error
            })?;

            let shared = Arc::new(Shared {
                engine: Mutex::new(Engine::new(cfg)),
                metrics: Mutex::new(Metrics::new(1000, 180)),
                talkers: Mutex::new(Talkers::new(60_000)),
                fw,
                enforced: Mutex::new(HashMap::new()),
                app_settings: Mutex::new(persistent.settings),
                program_rules: Mutex::new(persistent.rules),
                session_program_rules: Mutex::new(HashMap::new()),
                pending_programs: Mutex::new(HashMap::new()),
                app_blocks: Mutex::new(HashMap::new()),
                known_apps: Mutex::new(HashMap::new()),
                persistence_path,
            });

            // Restore remembered quarantine rules before consuming new events.
            for (key, rule) in shared.program_rules.lock().unwrap().clone() {
                if rule.decision == "quarantine" {
                    if let Ok(handle) = shared.fw.block_app(
                        &rule.app_id,
                        parse_protocol(&rule.protocol).unwrap_or(AppProtocol::All),
                    ) {
                        shared.app_blocks.lock().unwrap().insert(
                            key,
                            RuntimeAppBlock {
                                handle,
                                app_path: rule.app_path,
                                app_name: rule.app_name,
                                protocol: rule.protocol,
                                temporary: false,
                            },
                        );
                    }
                }
            }

            app.manage(shared.clone());
            install_tray(app)?;

            {
                let shared = shared.clone();
                let handle = app.handle().clone();
                thread::spawn(move || consumer(shared, handle, rx));
            }
            {
                let shared = shared.clone();
                let handle = app.handle().clone();
                thread::spawn(move || ticker(shared, handle));
            }
            {
                let shared = shared.clone();
                let handle = app.handle().clone();
                thread::spawn(move || snapshotter(shared, handle));
            }

            if std::env::args().any(|arg| arg == "--hidden") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            set_protection,
            set_config,
            set_app_settings,
            decide_program,
            remove_program_rule,
            set_program_rule_decision,
            block_remote_ip,
            whitelist_add,
            unblock_ip
        ])
        .run(tauri::generate_context!())
        .expect("error while running m0untain");
}

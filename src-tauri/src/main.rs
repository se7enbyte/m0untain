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
use settings::{
    AppSettings, NotificationRecord, PersistentState, ProgramRule, RuleProfile, RuleTarget,
    GLOBAL_PROFILE_ID,
};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, State, WindowEvent};

use active_connections::ActiveConnection;
use wfp::{AppProtocol, Firewall, RawConn, RemoteMatch};

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
    pid: u32,
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
    risk_labels: Vec<String>,
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
    app_package_sid: Vec<u8>,
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
    app_package_sid: Vec<u8>,
}

struct DisabledFirewall {
    message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceControlStatus {
    installed: bool,
    running: bool,
    mode: String,
    message: String,
    pid: Option<u32>,
    binary_path: Option<String>,
}

const SERVICE_NAME: &str = "m0untain-service";

impl DisabledFirewall {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl Firewall for DisabledFirewall {
    fn block_ip(&self, _ip: IpAddr) -> Result<u64, String> {
        Err(self.message.clone())
    }

    fn block_app(&self, _app_id: &[u8], _protocol: AppProtocol) -> Result<u64, String> {
        Err(self.message.clone())
    }

    fn block_package(&self, _package_sid: &[u8], _protocol: AppProtocol) -> Result<u64, String> {
        Err(self.message.clone())
    }

    fn unblock(&self, _handle: u64) -> Result<(), String> {
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "Unavailable"
    }
}

struct Shared {
    engine: Mutex<Engine>,
    metrics: Mutex<Metrics>,
    talkers: Mutex<Talkers>,
    fw: Box<dyn Firewall>,
    backend_error: Option<String>,
    enforced: Mutex<HashMap<IpAddr, (u64, u64)>>,
    app_settings: Mutex<AppSettings>,
    program_rules: Mutex<HashMap<String, ProgramRule>>,
    session_program_rules: Mutex<HashMap<String, ProgramRule>>,
    profiles: Mutex<Vec<RuleProfile>>,
    notifications: Mutex<Vec<NotificationRecord>>,
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
            app_path: raw_app_path(raw),
            service_sid: None,
            is_new_conn: raw.is_new,
            action: Action::Allow,
        }
    }

    fn save(&self) -> Result<(), String> {
        let state = PersistentState {
            schema_version: 2,
            settings: self.app_settings.lock().unwrap().clone(),
            rules: self.program_rules.lock().unwrap().clone(),
            profiles: self.profiles.lock().unwrap().clone(),
            notifications: self.notifications.lock().unwrap().clone(),
        };
        settings::save(&self.persistence_path, &state)
    }
}

fn app_key(path: &str) -> String {
    path.trim().to_lowercase()
}

fn app_name(path: &str) -> String {
    if let Some(package_sid) = path.strip_prefix("package:") {
        return format!("Packaged app {}", shorten_sid(package_sid));
    }
    path.rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn shorten_sid(value: &str) -> String {
    if value.len() <= 18 {
        value.to_string()
    } else {
        format!(
            "{}…{}",
            &value[..8],
            &value[value.len().saturating_sub(8)..]
        )
    }
}

fn raw_app_path(raw: &RawConn) -> Option<String> {
    raw.app_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            raw.app_package_sid_string
                .as_deref()
                .filter(|sid| !sid.trim().is_empty())
                .map(|sid| format!("package:{sid}"))
        })
}

fn raw_app_name(raw: &RawConn, app_path: &str) -> String {
    raw.app_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| app_name(app_path))
}

fn normalize_protocol(value: &str) -> String {
    match value.to_lowercase().as_str() {
        "tcp" => "tcp".to_string(),
        "udp" => "udp".to_string(),
        _ => "all".to_string(),
    }
}

fn normalize_direction(value: &str) -> String {
    match value.to_lowercase().as_str() {
        "inbound" => "inbound".to_string(),
        "both" => "both".to_string(),
        _ => "outbound".to_string(),
    }
}

fn normalize_decision(value: &str) -> Result<String, String> {
    match value.to_lowercase().as_str() {
        "allow" => Ok("allow".to_string()),
        "block" => Ok("block".to_string()),
        "quarantine" => Ok("quarantine".to_string()),
        _ => Err("decision must be allow, block or quarantine".to_string()),
    }
}

fn hex_id(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn target_is_specific(target: &Option<RuleTarget>) -> bool {
    target.as_ref().is_some_and(|target| {
        target.kind != "any" || !target.value.trim().is_empty() || target.port.is_some()
    })
}

fn target_key(target: &Option<RuleTarget>) -> String {
    let Some(target) = target else {
        return "any".to_string();
    };
    format!(
        "{}:{}:{}",
        target.kind.to_lowercase(),
        target.value.to_lowercase(),
        target
            .port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "*".to_string())
    )
}

fn rule_storage_key(rule: &ProgramRule) -> String {
    let profile = if rule.profile_id.trim().is_empty() {
        GLOBAL_PROFILE_ID
    } else {
        rule.profile_id.as_str()
    };
    let app = if !rule.app_path.trim().is_empty() {
        app_key(&rule.app_path)
    } else {
        format!("app-id:{}", hex_id(&rule.app_id))
    };
    format!(
        "{profile}|{}|{}|{}|{}",
        app,
        normalize_protocol(&rule.protocol),
        normalize_direction(&rule.direction),
        target_key(&rule.target)
    )
}

fn runtime_block_key(rule_key: &str, rule: &ProgramRule) -> String {
    if target_is_specific(&rule.target) {
        rule_key.to_string()
    } else {
        app_key(&rule.app_path)
    }
}

fn normalize_rule(mut rule: ProgramRule, active_profile_id: &str, now: u64) -> ProgramRule {
    rule.decision = normalize_decision(&rule.decision).unwrap_or_else(|_| "allow".to_string());
    rule.protocol = normalize_protocol(&rule.protocol);
    rule.direction = normalize_direction(&rule.direction);
    if rule.profile_id.trim().is_empty() {
        rule.profile_id = active_profile_id.to_string();
    }
    if rule.created_at_ms == 0 {
        rule.created_at_ms = now;
    }
    rule.updated_at_ms = now;
    if rule.app_name.trim().is_empty() && !rule.app_path.trim().is_empty() {
        rule.app_name = app_name(&rule.app_path);
    }
    rule
}

fn remote_match_from_target(target: &Option<RuleTarget>) -> Result<Option<RemoteMatch>, String> {
    let Some(target) = target else {
        return Ok(None);
    };
    match target.kind.to_lowercase().as_str() {
        "any" => Ok(None),
        "ip" => target
            .value
            .parse::<IpAddr>()
            .map(RemoteMatch::Ip)
            .map(Some)
            .map_err(|_| "invalid target IP".to_string()),
        "cidr" => {
            let Some((network, prefix)) = target.value.split_once('/') else {
                return Err("invalid CIDR target".to_string());
            };
            let network = network
                .parse::<IpAddr>()
                .map_err(|_| "invalid CIDR network".to_string())?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| "invalid CIDR prefix".to_string())?;
            match network {
                IpAddr::V4(_) if prefix <= 32 => Ok(Some(RemoteMatch::Cidr { network, prefix })),
                IpAddr::V6(_) if prefix <= 128 => Ok(Some(RemoteMatch::Cidr { network, prefix })),
                _ => Err("CIDR prefix is out of range".to_string()),
            }
        }
        // Domain rules stay in the V2 rule engine until DNS cache correlation
        // can prove an IP/domain relationship. Do not widen to app-wide block.
        "domain" => Ok(None),
        _ => Ok(None),
    }
}

fn is_domain_target(target: &Option<RuleTarget>) -> bool {
    target
        .as_ref()
        .is_some_and(|target| target.kind.eq_ignore_ascii_case("domain"))
}

fn install_block_for_rule(
    shared: &Shared,
    rule_key: &str,
    rule: &ProgramRule,
) -> Result<(), String> {
    if rule.app_id.is_empty() && rule.app_package_sid.is_empty() {
        return Err("rule has no WFP application or package id".to_string());
    }
    if is_domain_target(&rule.target) {
        return Ok(());
    }
    let protocol = parse_protocol(&rule.protocol).unwrap_or(AppProtocol::All);
    let remote = remote_match_from_target(&rule.target)?;
    let remote_port = rule.target.as_ref().and_then(|target| target.port);
    let handle = if !rule.app_package_sid.is_empty() {
        if remote.is_some() || remote_port.is_some() {
            shared
                .fw
                .block_package_target(&rule.app_package_sid, protocol, remote, remote_port)?
        } else {
            shared.fw.block_package(&rule.app_package_sid, protocol)?
        }
    } else if remote.is_some() || remote_port.is_some() {
        shared
            .fw
            .block_app_target(&rule.app_id, protocol, remote, remote_port)?
    } else {
        shared.fw.block_app(&rule.app_id, protocol)?
    };
    let block_key = runtime_block_key(rule_key, rule);
    if let Some(old) = shared.app_blocks.lock().unwrap().insert(
        block_key,
        RuntimeAppBlock {
            handle,
            app_path: rule.app_path.clone(),
            app_name: rule.app_name.clone(),
            protocol: rule.protocol.clone(),
            temporary: rule.expires_at_ms.is_some(),
        },
    ) {
        let _ = shared.fw.unblock(old.handle);
    }
    Ok(())
}

fn remove_runtime_blocks_for_app(shared: &Shared, key: &str) {
    let block_keys: Vec<String> = shared
        .app_blocks
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, block)| app_key(&block.app_path) == key)
        .map(|(block_key, _)| block_key.clone())
        .collect();
    for block_key in block_keys {
        if let Some(block) = shared.app_blocks.lock().unwrap().remove(&block_key) {
            let _ = shared.fw.unblock(block.handle);
        }
    }
}

fn protocol_matches(rule_protocol: &str, observed_protocol: &str) -> bool {
    let rule_protocol = normalize_protocol(rule_protocol);
    let observed_protocol = normalize_protocol(observed_protocol);
    rule_protocol == "all" || observed_protocol == "all" || rule_protocol == observed_protocol
}

fn direction_matches(rule_direction: &str, observed_direction: &str) -> bool {
    let rule_direction = normalize_direction(rule_direction);
    let observed_direction = normalize_direction(observed_direction);
    rule_direction == "both" || observed_direction == "both" || rule_direction == observed_direction
}

fn app_matches(rule: &ProgramRule, key: &str, app_id: &[u8], app_package_sid: &[u8]) -> bool {
    (!rule.app_path.trim().is_empty() && app_key(&rule.app_path) == key)
        || (!rule.app_id.is_empty() && rule.app_id == app_id)
        || (!rule.app_package_sid.is_empty() && rule.app_package_sid == app_package_sid)
}

fn ip_in_cidr(remote_ip: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match (remote_ip, base.parse::<IpAddr>()) {
        (IpAddr::V4(remote), Ok(IpAddr::V4(base))) if prefix <= 32 => {
            let remote = u32::from(remote);
            let base = u32::from(base);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            remote & mask == base & mask
        }
        (IpAddr::V6(remote), Ok(IpAddr::V6(base))) if prefix <= 128 => {
            let remote = u128::from(remote);
            let base = u128::from(base);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            remote & mask == base & mask
        }
        _ => false,
    }
}

fn target_matches(
    target: &Option<RuleTarget>,
    remote_ip: Option<IpAddr>,
    remote_port: u16,
) -> bool {
    let Some(target) = target else {
        return true;
    };
    if let Some(port) = target.port {
        if port != remote_port {
            return false;
        }
    }
    let value = target.value.trim();
    match target.kind.to_lowercase().as_str() {
        "any" => true,
        "ip" => remote_ip.is_some_and(|remote_ip| remote_ip.to_string() == value),
        "cidr" => remote_ip.is_some_and(|remote_ip| ip_in_cidr(remote_ip, value)),
        // Offline-first: domain rules are stored now. Runtime DNS correlation is
        // intentionally conservative until the DNS cache mapper can prove an
        // IP/domain relationship.
        "domain" => false,
        _ => value.is_empty(),
    }
}

fn rule_is_active(rule: &ProgramRule, now: u64) -> bool {
    rule.expires_at_ms.is_none_or(|expires_at| expires_at > now)
}

fn rule_score(
    rule: &ProgramRule,
    active_profile_id: &str,
    is_session_rule: bool,
    now: u64,
) -> Option<(u8, u8, u64)> {
    if !rule_is_active(rule, now) {
        return None;
    }
    let target_rank = if target_is_specific(&rule.target) {
        0
    } else {
        1
    };
    let profile = if rule.profile_id.trim().is_empty() {
        GLOBAL_PROFILE_ID
    } else {
        rule.profile_id.as_str()
    };
    let precedence = if is_session_rule || rule.expires_at_ms.is_some() {
        1
    } else if profile == active_profile_id && target_rank == 0 {
        2
    } else if profile == active_profile_id {
        3
    } else if profile == GLOBAL_PROFILE_ID && target_rank == 0 {
        4
    } else if profile == GLOBAL_PROFILE_ID {
        5
    } else if target_rank == 1 {
        // Backward compatibility for prompt-created app-wide rules that were
        // stored under the active profile before app decisions became global.
        // Target-specific rules remain profile-bound.
        6
    } else {
        return None;
    };
    Some((precedence, target_rank, rule.updated_at_ms))
}

fn find_rule_in(
    rules: &HashMap<String, ProgramRule>,
    key: &str,
    app_id: &[u8],
    app_package_sid: &[u8],
    protocol: &str,
    direction: &str,
    remote_ip: Option<IpAddr>,
    remote_port: u16,
    active_profile_id: &str,
    now: u64,
    is_session_rule: bool,
) -> Option<(String, ProgramRule)> {
    let mut best: Option<(String, ProgramRule, (u8, u8, u64))> = None;
    for (rule_key, rule) in rules {
        if !app_matches(rule, key, app_id, app_package_sid)
            || !protocol_matches(&rule.protocol, protocol)
            || !direction_matches(&rule.direction, direction)
            || !target_matches(&rule.target, remote_ip, remote_port)
        {
            continue;
        }
        let Some(score) = rule_score(rule, active_profile_id, is_session_rule, now) else {
            continue;
        };
        let is_better = best.as_ref().is_none_or(|(_, _, best_score)| {
            score.0 < best_score.0
                || (score.0 == best_score.0 && score.1 < best_score.1)
                || (score.0 == best_score.0 && score.1 == best_score.1 && score.2 > best_score.2)
        });
        if is_better {
            best = Some((rule_key.clone(), rule.clone(), score));
        }
    }
    best.map(|(rule_key, rule, _)| (rule_key, rule))
}

fn find_program_rule(
    shared: &Shared,
    key: &str,
    app_id: &[u8],
    app_package_sid: &[u8],
) -> Option<(String, ProgramRule)> {
    find_program_rule_for(
        shared,
        key,
        app_id,
        app_package_sid,
        "all",
        "outbound",
        None,
        0,
        now_ms(),
    )
}

fn find_program_rule_for(
    shared: &Shared,
    key: &str,
    app_id: &[u8],
    app_package_sid: &[u8],
    protocol: &str,
    direction: &str,
    remote_ip: Option<IpAddr>,
    remote_port: u16,
    now: u64,
) -> Option<(String, ProgramRule)> {
    let active_profile_id = shared
        .app_settings
        .lock()
        .unwrap()
        .active_profile_id
        .clone();
    find_rule_in(
        &shared.session_program_rules.lock().unwrap(),
        key,
        app_id,
        app_package_sid,
        protocol,
        direction,
        remote_ip,
        remote_port,
        &active_profile_id,
        now,
        true,
    )
    .or_else(|| {
        find_rule_in(
            &shared.program_rules.lock().unwrap(),
            key,
            app_id,
            app_package_sid,
            protocol,
            direction,
            remote_ip,
            remote_port,
            &active_profile_id,
            now,
            false,
        )
    })
}

fn has_pending_program(shared: &Shared, key: &str, app_id: &[u8], app_package_sid: &[u8]) -> bool {
    let pending = shared.pending_programs.lock().unwrap();
    pending.contains_key(key)
        || pending.values().any(|pending| {
            (!pending.app_id.is_empty() && pending.app_id == app_id)
                || (!pending.app_package_sid.is_empty()
                    && pending.app_package_sid == app_package_sid)
        })
}

fn remove_rules_with_identity(
    rules: &mut HashMap<String, ProgramRule>,
    key: &str,
    app_id: &[u8],
    app_package_sid: &[u8],
) {
    let duplicates: Vec<String> = rules
        .iter()
        .filter(|(rule_key, rule)| {
            rule_key.as_str() == key
                || app_matches(rule, key, app_id, app_package_sid)
                || (!rule.app_id.is_empty() && rule.app_id == app_id)
                || (!rule.app_package_sid.is_empty() && rule.app_package_sid == app_package_sid)
        })
        .map(|(rule_key, _)| rule_key.clone())
        .collect();
    for duplicate in duplicates {
        rules.remove(&duplicate);
    }
}

fn remove_rules_for_app(rules: &mut HashMap<String, ProgramRule>, key: &str) -> Vec<ProgramRule> {
    let duplicates: Vec<String> = rules
        .iter()
        .filter(|(rule_key, rule)| rule_key.as_str() == key || app_key(&rule.app_path) == key)
        .map(|(rule_key, _)| rule_key.clone())
        .collect();
    duplicates
        .into_iter()
        .filter_map(|duplicate| rules.remove(&duplicate))
        .collect()
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
    let Some(path) = raw_app_path(raw) else {
        return;
    };
    let app_id = raw.app_id.clone().unwrap_or_default();
    let app_package_sid = raw.app_package_sid.clone().unwrap_or_default();
    if app_id.is_empty() && app_package_sid.is_empty() {
        return;
    }

    let key = app_key(&path);
    shared.known_apps.lock().unwrap().insert(
        key,
        KnownApp {
            app_name: raw_app_name(raw, &path),
            app_path: path,
            app_id,
            app_package_sid,
        },
    );
}

fn risk_labels_for(
    path: Option<&str>,
    remote_port: u16,
    has_rule: bool,
    had_block_history: bool,
) -> Vec<String> {
    let mut labels = Vec::new();
    if !has_rule {
        labels.push("first-seen-app".to_string());
    }
    if had_block_history {
        labels.push("blocked-or-quarantined-history".to_string());
    }
    if let Some(path) = path {
        let lower = path.to_lowercase();
        if lower.contains("\\temp\\")
            || lower.contains("/temp/")
            || lower.contains("\\appdata\\local\\temp\\")
            || lower.contains("\\downloads\\")
        {
            labels.push("suspicious-path".to_string());
        }
        if !(lower.starts_with("c:\\program files\\")
            || lower.starts_with("c:\\program files (x86)\\")
            || lower.starts_with("c:\\windows\\"))
        {
            labels.push("unknown-publisher-offline".to_string());
        }
    }
    let usual_ports = [0, 53, 80, 123, 443, 853, 1935, 3478, 5228, 8080, 8443];
    if !usual_ports.contains(&remote_port) {
        labels.push("unusual-port".to_string());
    }
    labels
}

fn state_has_rule_for_app(shared: &Shared, key: &str) -> bool {
    shared
        .program_rules
        .lock()
        .unwrap()
        .values()
        .any(|rule| app_key(&rule.app_path) == key)
        || shared
            .session_program_rules
            .lock()
            .unwrap()
            .values()
            .any(|rule| app_key(&rule.app_path) == key)
}

fn state_has_block_history_for_app(shared: &Shared, key: &str) -> bool {
    shared
        .program_rules
        .lock()
        .unwrap()
        .values()
        .any(|rule| app_key(&rule.app_path) == key && rule.is_blocking())
        || shared
            .session_program_rules
            .lock()
            .unwrap()
            .values()
            .any(|rule| app_key(&rule.app_path) == key && rule.is_blocking())
}

fn risk_labels_for_raw(shared: &Shared, raw: &RawConn) -> Vec<String> {
    let app_path = raw_app_path(raw);
    let key = app_path.as_deref().map(app_key).unwrap_or_default();
    let app_id = raw.app_id.as_deref().unwrap_or(&[]);
    let package_sid = raw.app_package_sid.as_deref().unwrap_or(&[]);
    let has_rule = (!app_id.is_empty() || !package_sid.is_empty() || !key.is_empty()) && {
        find_program_rule_for(
            shared,
            &key,
            app_id,
            package_sid,
            protocol_str(raw),
            if raw.inbound { "inbound" } else { "outbound" },
            Some(raw.remote_ip),
            raw.remote_port,
            now_ms(),
        )
        .is_some()
    };
    let had_block_history = shared
        .program_rules
        .lock()
        .unwrap()
        .values()
        .any(|rule| app_key(&rule.app_path) == key && rule.is_blocking());
    risk_labels_for(
        app_path.as_deref(),
        raw.remote_port,
        has_rule,
        had_block_history,
    )
}

fn connection_seen(raw: &RawConn, verdict: &Verdict, risk_labels: Vec<String>) -> ConnectionSeen {
    let (verdict_name, reason) = match verdict {
        Verdict::Pass => ("allow".to_string(), None),
        Verdict::Block { reason, .. } => ("block".to_string(), Some(format!("{reason:?}"))),
    };
    let app_path = raw_app_path(raw);
    let app_name = app_path
        .as_deref()
        .map(|path| raw_app_name(raw, path))
        .unwrap_or_else(|| format!("pid {}", raw.pid));
    ConnectionSeen {
        id: format!(
            "{}-{}-{}-{}",
            raw.ts_ms, raw.pid, raw.remote_ip, raw.remote_port
        ),
        ts_ms: raw.ts_ms,
        app_path,
        app_name,
        direction: if raw.inbound { "inbound" } else { "outbound" }.to_string(),
        protocol: protocol_str(raw).to_string(),
        remote_ip: raw.remote_ip.to_string(),
        remote_port: raw.remote_port,
        local_port: raw.local_port,
        pid: raw.pid,
        verdict: verdict_name,
        reason,
        is_new_conn: raw.is_new,
        risk_labels,
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
        app_package_sid: None,
        app_package_sid_string: None,
        app_name: Some(conn.app_name.clone()),
    }
}

fn snapshot_seen(conn: &ActiveConnection, ts_ms: u64, risk_labels: Vec<String>) -> ConnectionSeen {
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
        risk_labels,
    }
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(windows)]
mod service_control {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;

    use super::{ServiceControlStatus, SERVICE_NAME};

    const DELETE_ACCESS: u32 = 0x0001_0000;

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn service_binary_path() -> Result<PathBuf, String> {
        let current = std::env::current_exe().map_err(|error| error.to_string())?;
        let sibling = current.with_file_name("m0untain-service.exe");
        if sibling.exists() {
            return Ok(sibling);
        }
        Err(format!(
            "m0untain-service.exe was not found next to {}. Build the service binary or include it in the app bundle first.",
            current.display()
        ))
    }

    unsafe fn open_manager(access: u32) -> Result<SC_HANDLE, String> {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access).map_err(|error| error.to_string())
    }

    unsafe fn open_service(manager: SC_HANDLE, access: u32) -> Result<SC_HANDLE, String> {
        let name = wide(SERVICE_NAME);
        OpenServiceW(manager, PCWSTR(name.as_ptr()), access).map_err(|error| error.to_string())
    }

    unsafe fn close(handle: SC_HANDLE) {
        let _ = CloseServiceHandle(handle);
    }

    fn command_line(binary: &Path, state_path: &Path) -> String {
        format!(
            "\"{}\" --state \"{}\"",
            binary.display(),
            state_path.display()
        )
    }

    pub fn install(state_path: &Path) -> Result<(), String> {
        let binary = service_binary_path()?;
        let command = command_line(&binary, state_path);
        let name = wide(SERVICE_NAME);
        let display = wide("m0untain default-deny firewall service");
        let command = wide(command);
        unsafe {
            let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
            let existing = open_service(
                manager,
                SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START,
            );
            if let Ok(service) = existing {
                ChangeServiceConfigW(
                    service,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(command.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR(display.as_ptr()),
                )
                .map_err(|error| error.to_string())?;
                close(service);
                close(manager);
                return Ok(());
            }

            let service = CreateServiceW(
                manager,
                PCWSTR(name.as_ptr()),
                PCWSTR(display.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(command.as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
            .map_err(|error| error.to_string())?;
            close(service);
            close(manager);
        }
        Ok(())
    }

    pub fn start() -> Result<(), String> {
        unsafe {
            let manager = open_manager(SC_MANAGER_CONNECT)?;
            let service = open_service(manager, SERVICE_START | SERVICE_QUERY_STATUS)?;
            let result = StartServiceW(service, None);
            close(service);
            close(manager);
            result.map_err(|error| error.to_string())
        }
    }

    pub fn stop() -> Result<(), String> {
        unsafe {
            let manager = open_manager(SC_MANAGER_CONNECT)?;
            let service = open_service(manager, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
            let mut status = SERVICE_STATUS::default();
            let result = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            close(service);
            close(manager);
            result.map_err(|error| error.to_string())
        }
    }

    pub fn uninstall() -> Result<(), String> {
        unsafe {
            let manager = open_manager(SC_MANAGER_CONNECT)?;
            let service =
                open_service(manager, DELETE_ACCESS | SERVICE_STOP | SERVICE_QUERY_STATUS)?;
            let mut status = SERVICE_STATUS::default();
            let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            let result = DeleteService(service);
            close(service);
            close(manager);
            result.map_err(|error| error.to_string())
        }
    }

    pub fn status() -> ServiceControlStatus {
        unsafe {
            let manager = match open_manager(SC_MANAGER_CONNECT) {
                Ok(manager) => manager,
                Err(error) => {
                    return ServiceControlStatus {
                        installed: false,
                        running: false,
                        mode: "unavailable".to_string(),
                        message: format!("SCM unavailable: {error}"),
                        pid: None,
                        binary_path: service_binary_path()
                            .ok()
                            .map(|path| path.display().to_string()),
                    }
                }
            };
            let service = match open_service(manager, SERVICE_QUERY_STATUS) {
                Ok(service) => service,
                Err(_) => {
                    close(manager);
                    return ServiceControlStatus {
                        installed: false,
                        running: false,
                        mode: "not-installed".to_string(),
                        message: "Default-deny service is not installed.".to_string(),
                        pid: None,
                        binary_path: service_binary_path()
                            .ok()
                            .map(|path| path.display().to_string()),
                    };
                }
            };
            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut needed = 0;
            let buffer = std::slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            );
            let query =
                QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed);
            close(service);
            close(manager);
            if let Err(error) = query {
                return ServiceControlStatus {
                    installed: true,
                    running: false,
                    mode: "unknown".to_string(),
                    message: format!("Service installed, status query failed: {error}"),
                    pid: None,
                    binary_path: service_binary_path()
                        .ok()
                        .map(|path| path.display().to_string()),
                };
            }
            let running = status.dwCurrentState == SERVICE_RUNNING;
            ServiceControlStatus {
                installed: true,
                running,
                mode: if running {
                    "default-deny-service".to_string()
                } else {
                    "installed-stopped".to_string()
                },
                message: if running {
                    "Default-deny service is running at boot/service level.".to_string()
                } else {
                    "Default-deny service is installed but stopped.".to_string()
                },
                pid: (status.dwProcessId != 0).then_some(status.dwProcessId),
                binary_path: service_binary_path()
                    .ok()
                    .map(|path| path.display().to_string()),
            }
        }
    }
}

#[cfg(not(windows))]
mod service_control {
    use std::path::Path;

    use super::ServiceControlStatus;

    pub fn install(_state_path: &Path) -> Result<(), String> {
        Err("Windows service install is only available on Windows".to_string())
    }
    pub fn start() -> Result<(), String> {
        Err("Windows service start is only available on Windows".to_string())
    }
    pub fn stop() -> Result<(), String> {
        Err("Windows service stop is only available on Windows".to_string())
    }
    pub fn uninstall() -> Result<(), String> {
        Err("Windows service uninstall is only available on Windows".to_string())
    }
    pub fn status() -> ServiceControlStatus {
        ServiceControlStatus {
            installed: false,
            running: false,
            mode: "unsupported".to_string(),
            message: "Windows service is only available on Windows.".to_string(),
            pid: None,
            binary_path: None,
        }
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

fn push_notification(
    shared: &Arc<Shared>,
    app: Option<&tauri::AppHandle>,
    kind: &str,
    title: impl Into<String>,
    body: impl Into<String>,
    app_path: Option<String>,
    remote: Option<String>,
) -> NotificationRecord {
    let record = NotificationRecord {
        id: format!("{}-{}", now_ms(), kind),
        ts_ms: now_ms(),
        kind: kind.to_string(),
        title: title.into(),
        body: body.into(),
        app_path,
        remote,
    };
    {
        let mut notifications = shared.notifications.lock().unwrap();
        notifications.push(record.clone());
        if notifications.len() > 400 {
            let keep_from = notifications.len() - 400;
            *notifications = notifications.split_off(keep_from);
        }
    }
    let _ = shared.save();
    if let Some(app) = app {
        let _ = app.emit("notification-created", record.clone());
    }
    record
}

fn service_status(shared: &Shared) -> serde_json::Value {
    let backend_error = shared.backend_error.clone();
    let service = service_control::status();
    serde_json::json!({
        "installed": service.installed,
        "running": service.running,
        "mode": if backend_error.is_some() && !service.running { "offline".to_string() } else if service.running { service.mode.clone() } else { "app-only".to_string() },
        "defaultDenyService": if service.running { "running" } else if service.installed { "installed" } else { "not-installed" },
        "message": backend_error.unwrap_or(service.message),
        "pid": service.pid,
        "binaryPath": service.binary_path,
    })
}

fn quarantine_snapshot(shared: &Shared) -> Vec<AppQuarantine> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let app_blocks = shared.app_blocks.lock().unwrap();
    let rules = shared.program_rules.lock().unwrap();

    for (key, rule) in rules.iter() {
        if !rule.is_blocking() {
            continue;
        }
        let active = app_blocks.contains_key(&runtime_block_key(key, rule));
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

fn state_snapshot(state: &Arc<Shared>) -> serde_json::Value {
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
        .iter()
        .map(|rule| {
            let (rule_id, rule) = rule;
            serde_json::json!({
                "id": rule_id,
                "appPath": rule.app_path,
                "appName": rule.app_name,
                "appId": rule.app_id,
                "appPackageSid": rule.app_package_sid,
                "decision": rule.decision,
                "protocol": rule.protocol,
                "direction": rule.direction,
                "target": rule.target,
                "expiresAtMs": rule.expires_at_ms,
                "profileId": rule.profile_id,
                "createdAtMs": rule.created_at_ms,
                "updatedAtMs": rule.updated_at_ms,
            })
        })
        .collect();
    let session_rules: Vec<serde_json::Value> = state
        .session_program_rules
        .lock()
        .unwrap()
        .iter()
        .map(|rule| {
            let (rule_id, rule) = rule;
            serde_json::json!({
                "id": rule_id,
                "appPath": rule.app_path,
                "appName": rule.app_name,
                "appId": rule.app_id,
                "appPackageSid": rule.app_package_sid,
                "decision": rule.decision,
                "protocol": rule.protocol,
                "direction": rule.direction,
                "target": rule.target,
                "expiresAtMs": rule.expires_at_ms,
                "profileId": rule.profile_id,
                "createdAtMs": rule.created_at_ms,
                "updatedAtMs": rule.updated_at_ms,
                "temporary": true,
            })
        })
        .collect();
    serde_json::json!({
        "backend": state.fw.backend(),
        "backendError": state.backend_error.clone(),
        "toggles": { "ddos": cfg.ddos.enabled, "scan": cfg.scan.enabled },
        "config": cfg,
        "appSettings": state.app_settings.lock().unwrap().clone(),
        "profiles": state.profiles.lock().unwrap().clone(),
        "activeProfileId": state.app_settings.lock().unwrap().active_profile_id.clone(),
        "programRules": rules,
        "sessionProgramRules": session_rules,
        "appQuarantines": quarantine_snapshot(state),
        "pendingPrograms": pending,
        "notificationHistory": state.notifications.lock().unwrap().clone(),
        "serviceStatus": service_status(state),
    })
}

#[tauri::command]
fn get_state(state: State<Arc<Shared>>) -> serde_json::Value {
    state_snapshot(state.inner())
}

#[tauri::command]
fn get_firewall_state(state: State<Arc<Shared>>) -> serde_json::Value {
    state_snapshot(state.inner())
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
    duration_minutes: Option<u64>,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let decision = normalize_decision(&decision)?;
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
    if decision == "quarantine" || decision == "block" {
        let handle = if !pending.app_package_sid.is_empty() {
            state.fw.block_package(&pending.app_package_sid, scope)?
        } else {
            state.fw.block_app(&pending.app_id, scope)?
        };
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

    let now = now_ms();
    let expires_at_ms = duration_minutes.map(|minutes| {
        now.saturating_add(if minutes == 0 {
            30_000
        } else {
            minutes.saturating_mul(60_000)
        })
    });
    let rule = ProgramRule {
        app_path: pending.prompt.app_path,
        app_name: pending.prompt.app_name,
        app_id: pending.app_id,
        app_package_sid: pending.app_package_sid,
        decision: decision.clone(),
        protocol: normalize_protocol(&protocol),
        direction: pending.prompt.direction,
        target: None,
        expires_at_ms,
        profile_id: GLOBAL_PROFILE_ID.to_string(),
        created_at_ms: now,
        updated_at_ms: now,
    };
    let key = rule_storage_key(&rule);
    let app_key = request_id;
    if remember {
        {
            let mut session_rules = state.session_program_rules.lock().unwrap();
            remove_rules_with_identity(
                &mut session_rules,
                &app_key,
                &rule.app_id,
                &rule.app_package_sid,
            );
        }
        {
            let mut rules = state.program_rules.lock().unwrap();
            remove_rules_with_identity(&mut rules, &app_key, &rule.app_id, &rule.app_package_sid);
            rules.insert(key, rule);
        }
        state.save()?;
    } else {
        let mut session_rules = state.session_program_rules.lock().unwrap();
        remove_rules_with_identity(
            &mut session_rules,
            &app_key,
            &rule.app_id,
            &rule.app_package_sid,
        );
        session_rules.insert(key, rule);
    }
    push_notification(
        state.inner(),
        Some(&app),
        "program-decision",
        format!("{} {}", decision, app_name(&app_key)),
        if let Some(minutes) = duration_minutes {
            if minutes == 0 {
                "Temporary one-shot decision (~30 seconds)".to_string()
            } else {
                format!("Timed decision for {minutes} minutes")
            }
        } else if remember {
            "Remembered as a global app rule".to_string()
        } else {
            "Session-only rule".to_string()
        },
        Some(app_key),
        None,
    );
    Ok(())
}

#[tauri::command]
fn remove_program_rule(app_path: String, state: State<Arc<Shared>>) -> Result<(), String> {
    let key = app_key(&app_path);
    remove_rules_for_app(&mut state.program_rules.lock().unwrap(), &key);
    remove_rules_for_app(&mut state.session_program_rules.lock().unwrap(), &key);
    remove_runtime_blocks_for_app(&state, &key);
    state.save()
}

#[tauri::command]
fn set_program_rule_decision(
    app_path: String,
    decision: String,
    protocol: String,
    state: State<Arc<Shared>>,
) -> Result<(), String> {
    let decision = normalize_decision(&decision)?;
    let _ = parse_protocol(&protocol)?;
    let key = app_key(&app_path);
    let known = state.known_apps.lock().unwrap().get(&key).cloned();
    let now = now_ms();
    let (rule_key, mut rule) = if let Some(known) = known {
        if let Some((rule_key, rule)) =
            find_program_rule(&state, &key, &known.app_id, &known.app_package_sid)
        {
            (rule_key, rule)
        } else {
            (
                key.clone(),
                ProgramRule {
                    app_path: known.app_path,
                    app_name: known.app_name,
                    app_id: known.app_id,
                    app_package_sid: known.app_package_sid,
                    decision: "allow".to_string(),
                    protocol: "all".to_string(),
                    direction: "outbound".to_string(),
                    target: None,
                    expires_at_ms: None,
                    profile_id: GLOBAL_PROFILE_ID.to_string(),
                    created_at_ms: now,
                    updated_at_ms: now,
                },
            )
        }
    } else if let Some(rule) = state.program_rules.lock().unwrap().get(&key).cloned() {
        (key.clone(), rule)
    } else {
        return Err("program was not observed in this session yet".to_string());
    };

    if decision == "allow" {
        remove_runtime_blocks_for_app(&state, &key);
    } else {
        let mut block_rule = rule.clone();
        block_rule.protocol = protocol.clone();
        block_rule.target = None;
        install_block_for_rule(&state, &key, &block_rule)?;
    }

    rule.decision = decision;
    rule.protocol = normalize_protocol(&protocol);
    rule.direction = normalize_direction(&rule.direction);
    rule.profile_id = GLOBAL_PROFILE_ID.to_string();
    rule.updated_at_ms = now;
    let storage_key = rule_storage_key(&rule);
    {
        let mut session_rules = state.session_program_rules.lock().unwrap();
        remove_rules_with_identity(
            &mut session_rules,
            &rule_key,
            &rule.app_id,
            &rule.app_package_sid,
        );
    }
    {
        let mut rules = state.program_rules.lock().unwrap();
        remove_rules_with_identity(&mut rules, &rule_key, &rule.app_id, &rule.app_package_sid);
        rules.insert(storage_key, rule);
    }
    state.save()
}

#[tauri::command]
fn block_remote_ip(
    ip: String,
    minutes: u64,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
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
    push_notification(
        state.inner(),
        Some(&app),
        "ip-blocked",
        "Remote IP blocked",
        format!("{addr} for {} minutes", minutes.max(1)),
        None,
        Some(addr.to_string()),
    );
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

#[tauri::command]
fn set_active_profile(
    profile_id: String,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let exists = state
        .profiles
        .lock()
        .unwrap()
        .iter()
        .any(|profile| profile.id == profile_id);
    if !exists {
        return Err("unknown profile id".to_string());
    }
    {
        let mut settings = state.app_settings.lock().unwrap();
        settings.active_profile_id = profile_id.clone();
    }
    state.save()?;
    push_notification(
        state.inner(),
        Some(&app),
        "profile-changed",
        "Firewall profile changed",
        format!("Active profile is now {profile_id}"),
        None,
        None,
    );
    Ok(())
}

#[tauri::command]
fn upsert_rule(
    rule: ProgramRule,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let active_profile_id = state.app_settings.lock().unwrap().active_profile_id.clone();
    let mut rule = normalize_rule(rule, &active_profile_id, now_ms());
    if rule.app_id.is_empty() && !rule.app_path.trim().is_empty() {
        if let Some(known) = state
            .known_apps
            .lock()
            .unwrap()
            .get(&app_key(&rule.app_path))
            .cloned()
        {
            rule.app_id = known.app_id;
            rule.app_package_sid = known.app_package_sid;
        } else if let Some(app_id) = wfp::app_id_from_path(&rule.app_path) {
            rule.app_id = app_id;
        }
    }
    let rule_id = rule_storage_key(&rule);
    let app_block_key = app_key(&rule.app_path);

    if rule.is_blocking() && (!rule.app_id.is_empty() || !rule.app_package_sid.is_empty()) {
        install_block_for_rule(&state, &rule_id, &rule)?;
    } else if rule.decision == "allow" {
        remove_runtime_blocks_for_app(&state, &app_block_key);
    }

    state
        .program_rules
        .lock()
        .unwrap()
        .insert(rule_id.clone(), rule.clone());
    state.save()?;
    push_notification(
        state.inner(),
        Some(&app),
        "rule-upserted",
        "Firewall rule saved",
        format!(
            "{} · {} · {}",
            rule.app_name, rule.decision, rule.profile_id
        ),
        Some(rule.app_path),
        rule.target.as_ref().map(|target| target.value.clone()),
    );
    Ok(rule_id)
}

#[tauri::command]
fn remove_rule(
    rule_id: String,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let removed = state
        .program_rules
        .lock()
        .unwrap()
        .remove(&rule_id)
        .or_else(|| state.session_program_rules.lock().unwrap().remove(&rule_id));
    if let Some(rule) = removed {
        let key = app_key(&rule.app_path);
        remove_runtime_blocks_for_app(&state, &key);
        state.save()?;
        push_notification(
            state.inner(),
            Some(&app),
            "rule-removed",
            "Firewall rule removed",
            rule.app_name,
            Some(rule.app_path),
            rule.target.as_ref().map(|target| target.value.clone()),
        );
    }
    Ok(())
}

#[tauri::command]
fn set_timed_decision(
    app_path: String,
    decision: String,
    protocol: String,
    minutes: u64,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let key = app_key(&app_path);
    let known = state
        .known_apps
        .lock()
        .unwrap()
        .get(&key)
        .cloned()
        .ok_or_else(|| "program was not observed in this session yet".to_string())?;
    let now = now_ms();
    let rule = ProgramRule {
        app_path: known.app_path,
        app_name: known.app_name,
        app_id: known.app_id,
        app_package_sid: known.app_package_sid,
        decision: normalize_decision(&decision)?,
        protocol: normalize_protocol(&protocol),
        direction: "outbound".to_string(),
        target: None,
        expires_at_ms: Some(now.saturating_add(minutes.max(1).saturating_mul(60_000))),
        profile_id: GLOBAL_PROFILE_ID.to_string(),
        created_at_ms: now,
        updated_at_ms: now,
    };
    let rule_id = rule_storage_key(&rule);
    if rule.is_blocking() {
        install_block_for_rule(&state, &rule_id, &rule)?;
    }
    state
        .session_program_rules
        .lock()
        .unwrap()
        .insert(rule_id.clone(), rule.clone());
    push_notification(
        state.inner(),
        Some(&app),
        "timed-rule",
        "Timed firewall decision",
        format!("{} for {} minutes", rule.decision, minutes.max(1)),
        Some(rule.app_path),
        None,
    );
    Ok(rule_id)
}

fn persistent_state_from_shared(shared: &Shared) -> PersistentState {
    PersistentState {
        schema_version: 2,
        settings: shared.app_settings.lock().unwrap().clone(),
        rules: shared.program_rules.lock().unwrap().clone(),
        profiles: shared.profiles.lock().unwrap().clone(),
        notifications: shared.notifications.lock().unwrap().clone(),
    }
}

#[tauri::command]
fn export_state(state: State<Arc<Shared>>) -> Result<String, String> {
    serde_json::to_string_pretty(&persistent_state_from_shared(state.inner()))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn import_state(
    json: String,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let imported: PersistentState =
        serde_json::from_str(&json).map_err(|error| format!("invalid state JSON: {error}"))?;
    let imported = settings::normalize_state(imported);
    {
        *state.app_settings.lock().unwrap() = imported.settings;
        *state.program_rules.lock().unwrap() = imported.rules;
        *state.profiles.lock().unwrap() = imported.profiles;
        *state.notifications.lock().unwrap() = imported.notifications;
        state.session_program_rules.lock().unwrap().clear();
        state.pending_programs.lock().unwrap().clear();
    }
    state.save()?;
    push_notification(
        state.inner(),
        Some(&app),
        "state-imported",
        "Firewall state imported",
        "Rules, profiles, settings and history were loaded from JSON",
        None,
        None,
    );
    Ok(())
}

#[cfg(windows)]
fn kill_process_checked(pid: u32, expected_path: Option<&str>) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
        .map_err(|error| format!("OpenProcess failed: {error}"))?
    };
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    let path_result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    if let Some(expected_path) = expected_path.filter(|path| !path.trim().is_empty()) {
        path_result.map_err(|error| format!("process path check failed: {error}"))?;
        let actual_path = String::from_utf16_lossy(&buf[..len as usize]);
        if app_key(&actual_path) != app_key(expected_path) {
            let _ = unsafe { CloseHandle(handle) };
            return Err("pid no longer belongs to the expected executable".to_string());
        }
    }
    unsafe {
        TerminateProcess(handle, 1).map_err(|error| format!("TerminateProcess failed: {error}"))?
    };
    let _ = unsafe { CloseHandle(handle) };
    Ok(())
}

#[cfg(not(windows))]
fn kill_process_checked(_pid: u32, _expected_path: Option<&str>) -> Result<(), String> {
    Err("kill_process is only available on Windows".to_string())
}

#[tauri::command]
fn kill_process(
    pid: u32,
    app_path: Option<String>,
    state: State<Arc<Shared>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    kill_process_checked(pid, app_path.as_deref())?;
    push_notification(
        state.inner(),
        Some(&app),
        "process-killed",
        "Process killed",
        format!("PID {pid} was terminated after path verification"),
        app_path,
        None,
    );
    Ok(())
}

#[tauri::command]
fn resolve_endpoint(ip: String) -> serde_json::Value {
    let parsed = ip.parse::<IpAddr>().ok();
    serde_json::json!({
        "ip": ip,
        "host": serde_json::Value::Null,
        "source": "offline-first",
        "isPrivate": parsed.is_some_and(|ip| match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
        }),
        "note": "Reverse DNS cache mapping is staged; unknown endpoints remain visible as IPs.",
    })
}

#[tauri::command]
fn get_service_status(state: State<Arc<Shared>>) -> serde_json::Value {
    service_status(&state)
}

#[tauri::command]
fn install_service(state: State<Arc<Shared>>, app: tauri::AppHandle) -> Result<(), String> {
    state.save()?;
    service_control::install(&state.persistence_path)?;
    push_notification(
        state.inner(),
        Some(&app),
        "service-installed",
        "Default-deny service installed",
        "m0untain-service is configured for automatic startup.",
        None,
        None,
    );
    let _ = app.emit("service-status", service_status(&state));
    Ok(())
}

#[tauri::command]
fn start_service(state: State<Arc<Shared>>, app: tauri::AppHandle) -> Result<(), String> {
    state.save()?;
    service_control::start()?;
    push_notification(
        state.inner(),
        Some(&app),
        "service-started",
        "Default-deny service started",
        "Boot-level firewall enforcement is starting.",
        None,
        None,
    );
    let _ = app.emit("service-status", service_status(&state));
    Ok(())
}

#[tauri::command]
fn stop_service(state: State<Arc<Shared>>, app: tauri::AppHandle) -> Result<(), String> {
    service_control::stop()?;
    push_notification(
        state.inner(),
        Some(&app),
        "service-stopped",
        "Default-deny service stopped",
        "m0untain fell back to app-only protection.",
        None,
        None,
    );
    let _ = app.emit("service-status", service_status(&state));
    Ok(())
}

#[tauri::command]
fn uninstall_service(state: State<Arc<Shared>>, app: tauri::AppHandle) -> Result<(), String> {
    service_control::uninstall()?;
    push_notification(
        state.inner(),
        Some(&app),
        "service-uninstalled",
        "Default-deny service uninstalled",
        "Boot-level enforcement was removed.",
        None,
        None,
    );
    let _ = app.emit("service-status", service_status(&state));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(decision: &str, profile_id: &str, target: Option<RuleTarget>) -> ProgramRule {
        ProgramRule {
            app_path: "C:\\Tools\\demo.exe".to_string(),
            app_name: "demo.exe".to_string(),
            app_id: vec![1, 2, 3],
            app_package_sid: Vec::new(),
            decision: decision.to_string(),
            protocol: "tcp".to_string(),
            direction: "outbound".to_string(),
            target,
            expires_at_ms: None,
            profile_id: profile_id.to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn profile_target_rule_wins_over_global_app_rule() {
        let mut rules = HashMap::new();
        rules.insert("global".to_string(), rule("allow", GLOBAL_PROFILE_ID, None));
        rules.insert(
            "target".to_string(),
            rule(
                "block",
                "home",
                Some(RuleTarget {
                    kind: "ip".to_string(),
                    value: "8.8.8.8".to_string(),
                    port: Some(443),
                }),
            ),
        );

        let matched = find_rule_in(
            &rules,
            &app_key("C:\\Tools\\demo.exe"),
            &[1, 2, 3],
            &[],
            "tcp",
            "outbound",
            Some("8.8.8.8".parse().unwrap()),
            443,
            "home",
            10,
            false,
        )
        .unwrap();

        assert_eq!(matched.1.decision, "block");
    }

    #[test]
    fn expired_timed_rule_is_ignored() {
        let mut timed = rule("allow", "home", None);
        timed.expires_at_ms = Some(99);

        assert!(rule_score(&timed, "home", false, 100).is_none());
        assert!(rule_score(&timed, "home", false, 98).is_some());
    }

    #[test]
    fn legacy_app_rule_remains_effective_after_profile_switch() {
        let legacy = rule("allow", "work", None);

        assert_eq!(rule_score(&legacy, "gaming", false, 10).unwrap().0, 6);
    }

    #[test]
    fn packaged_app_rule_matches_package_sid() {
        let mut packaged = rule("block", GLOBAL_PROFILE_ID, None);
        packaged.app_path = "package:S-1-15-2-1234".to_string();
        packaged.app_id.clear();
        packaged.app_package_sid = vec![1, 9, 8, 4];

        assert!(app_matches(
            &packaged,
            &app_key("package:S-1-15-2-1234"),
            &[],
            &[1, 9, 8, 4]
        ));
        assert!(!app_matches(
            &packaged,
            &app_key("package:S-1-15-2-other"),
            &[],
            &[4, 8, 9, 1]
        ));
    }

    #[test]
    fn calculates_offline_risk_labels() {
        let labels = risk_labels_for(
            Some("C:\\Users\\micro\\Downloads\\weird.exe"),
            4444,
            false,
            true,
        );

        assert!(labels.contains(&"first-seen-app".to_string()));
        assert!(labels.contains(&"suspicious-path".to_string()));
        assert!(labels.contains(&"unusual-port".to_string()));
        assert!(labels.contains(&"blocked-or-quarantined-history".to_string()));
    }

    #[test]
    fn cidr_target_matching_supports_ipv4() {
        assert!(ip_in_cidr(
            "192.168.1.42".parse().unwrap(),
            "192.168.1.0/24"
        ));
        assert!(!ip_in_cidr(
            "192.168.2.42".parse().unwrap(),
            "192.168.1.0/24"
        ));
    }
}

// ---- background workers ---------------------------------------------------

fn prune_expired_rules(shared: &Arc<Shared>, app: &tauri::AppHandle, now: u64) {
    let mut expired = Vec::new();
    {
        let mut rules = shared.program_rules.lock().unwrap();
        let keys: Vec<String> = rules
            .iter()
            .filter(|(_, rule)| {
                rule.expires_at_ms
                    .is_some_and(|expires_at| now >= expires_at)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(rule) = rules.remove(&key) {
                expired.push((key, rule, false));
            }
        }
    }
    {
        let mut rules = shared.session_program_rules.lock().unwrap();
        let keys: Vec<String> = rules
            .iter()
            .filter(|(_, rule)| {
                rule.expires_at_ms
                    .is_some_and(|expires_at| now >= expires_at)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(rule) = rules.remove(&key) {
                expired.push((key, rule, true));
            }
        }
    }
    if expired.is_empty() {
        return;
    }
    for (rule_key, rule, _) in &expired {
        let block_key = runtime_block_key(rule_key, rule);
        if let Some(block) = shared.app_blocks.lock().unwrap().remove(&block_key) {
            let _ = shared.fw.unblock(block.handle);
        }
        let _ = app.emit("rule-expired", rule.clone());
        push_notification(
            shared,
            Some(app),
            "rule-expired",
            "Timed firewall rule expired",
            format!("{} · {}", rule.app_name, rule.decision),
            Some(rule.app_path.clone()),
            rule.target.as_ref().map(|target| target.value.clone()),
        );
    }
    let _ = shared.save();
}

fn inspect_program(shared: &Arc<Shared>, app: &tauri::AppHandle, raw: &RawConn) {
    if raw.inbound {
        return;
    }
    let Some(path) = raw_app_path(raw) else {
        return;
    };
    let app_id = raw.app_id.as_deref().unwrap_or(&[]);
    let app_package_sid = raw.app_package_sid.as_deref().unwrap_or(&[]);
    if app_id.is_empty() && app_package_sid.is_empty() {
        return;
    }
    let key = app_key(&path);
    let display_name = raw_app_name(raw, &path);

    let protocol = protocol_str(raw);
    let direction = if raw.inbound { "inbound" } else { "outbound" };
    if let Some((rule_key, rule)) = find_program_rule_for(
        shared,
        &key,
        app_id,
        app_package_sid,
        protocol,
        direction,
        Some(raw.remote_ip),
        raw.remote_port,
        now_ms(),
    ) {
        let block_key = runtime_block_key(&rule_key, &rule);
        if rule.is_blocking() && !shared.app_blocks.lock().unwrap().contains_key(&block_key) {
            let _ = install_block_for_rule(shared, &rule_key, &rule);
        }
        return;
    }
    let settings = shared.app_settings.lock().unwrap().clone();
    let active_profile_default_deny = shared
        .profiles
        .lock()
        .unwrap()
        .iter()
        .find(|profile| profile.id == settings.active_profile_id)
        .is_some_and(|profile| profile.default_deny);
    let should_prompt =
        settings.ask_new_apps || settings.default_deny_enabled || active_profile_default_deny;
    if !should_prompt
        || has_pending_program(shared, &key, app_id, app_package_sid)
        || shared.app_blocks.lock().unwrap().contains_key(&key)
    {
        return;
    }

    // User-mode WFP subscriptions observe classification after it happens. We
    // immediately quarantine future attempts, then ask the user for a rule.
    let temporary_handle = if !app_package_sid.is_empty() {
        shared
            .fw
            .block_package(app_package_sid, AppProtocol::All)
            .ok()
    } else {
        shared.fw.block_app(app_id, AppProtocol::All).ok()
    };
    let prompt = ProgramPrompt {
        id: key.clone(),
        app_path: path.clone(),
        app_name: display_name.clone(),
        direction: "outbound".to_string(),
        protocol: protocol.to_string(),
        remote_ip: raw.remote_ip.to_string(),
        remote_port: raw.remote_port,
        local_port: raw.local_port,
        pid: raw.pid,
        first_connection_may_have_passed: true,
    };
    shared.pending_programs.lock().unwrap().insert(
        key,
        PendingProgram {
            prompt: prompt.clone(),
            app_id: app_id.to_vec(),
            app_package_sid: app_package_sid.to_vec(),
            temporary_handle,
        },
    );
    push_notification(
        shared,
        Some(app),
        "prompt-shown",
        "New outbound app",
        format!("{} wants to connect to {}", display_name, raw.remote_ip),
        Some(path),
        Some(raw.remote_ip.to_string()),
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
        let risk_labels = risk_labels_for_raw(&shared, &raw);
        let seen = connection_seen(&raw, &verdict, risk_labels);
        let _ = app.emit("traffic-sample", seen.clone());
        let _ = app.emit("connection-seen", seen);
    }
}

fn ticker(shared: Arc<Shared>, app: tauri::AppHandle) {
    loop {
        thread::sleep(Duration::from_millis(1000));
        let now = now_ms();
        prune_expired_rules(&shared, &app, now);

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
            let risk_labels = risk_labels_for(
                conn.app_path.as_deref(),
                conn.remote_port,
                conn.app_path.as_deref().is_some_and(|path| {
                    let key = app_key(path);
                    state_has_rule_for_app(&shared, &key)
                }),
                conn.app_path.as_deref().is_some_and(|path| {
                    let key = app_key(path);
                    state_has_block_history_for_app(&shared, &key)
                }),
            );
            emitted.push(snapshot_seen(&conn, now, risk_labels));
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
            let (fw, backend_error): (Box<dyn Firewall>, Option<String>) = match wfp::start(tx) {
                Ok(fw) => (Box::new(fw), None),
                Err(error) => {
                    eprintln!("firewall backend failed to start: {error}");
                    (Box::new(DisabledFirewall::new(error.clone())), Some(error))
                }
            };

            let shared = Arc::new(Shared {
                engine: Mutex::new(Engine::new(cfg)),
                metrics: Mutex::new(Metrics::new(1000, 180)),
                talkers: Mutex::new(Talkers::new(60_000)),
                fw,
                backend_error,
                enforced: Mutex::new(HashMap::new()),
                app_settings: Mutex::new(persistent.settings),
                program_rules: Mutex::new(persistent.rules),
                session_program_rules: Mutex::new(HashMap::new()),
                profiles: Mutex::new(persistent.profiles),
                notifications: Mutex::new(persistent.notifications),
                pending_programs: Mutex::new(HashMap::new()),
                app_blocks: Mutex::new(HashMap::new()),
                known_apps: Mutex::new(HashMap::new()),
                persistence_path,
            });

            // Restore remembered quarantine rules before consuming new events.
            for (key, rule) in shared.program_rules.lock().unwrap().clone() {
                if rule.is_blocking() {
                    let _ = install_block_for_rule(&shared, &key, &rule);
                }
            }

            app.manage(shared.clone());
            install_tray(app)?;
            let _ = app.emit("service-status", service_status(&shared));

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
            get_firewall_state,
            set_protection,
            set_config,
            set_app_settings,
            decide_program,
            remove_program_rule,
            set_program_rule_decision,
            block_remote_ip,
            whitelist_add,
            unblock_ip,
            set_active_profile,
            upsert_rule,
            remove_rule,
            set_timed_decision,
            export_state,
            import_state,
            kill_process,
            resolve_endpoint,
            get_service_status,
            install_service,
            start_service,
            stop_service,
            uninstall_service
        ])
        .run(tauri::generate_context!())
        .expect("error while running m0untain");
}

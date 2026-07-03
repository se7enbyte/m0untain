# m0untain

**m0untain** is an experimental Windows host firewall and network control cockpit built with **Rust**, **Tauri**, and the **Windows Filtering Platform (WFP)**.

It watches live network activity, asks before newly observed applications are allowed to talk to the internet, lets you quarantine apps for the current session or permanently, and presents the machine's traffic in a dark, signal-driven UI inspired by simplewall-style control and GlassWire-style visibility.

_TR: m0untain; Rust/Tauri ile yazılmış, Windows WFP üstünde çalışan deneysel bir firewall ve ağ kontrol panelidir._

> Security note: this is a work-in-progress personal firewall project. It can install WFP rules and block/quarantine applications, but it has not been independently audited. Run it as administrator on Windows and treat it as an evolving security tool, not yet as a hardened enterprise firewall.

_TR: Güvenlik aracı olduğu için dürüst not: proje aktif geliştirme aşamasında; gerçek sistemlerde dikkatli test edilmelidir._

## Screenshots

### Connections and Application Control

![Connections and Application Control](docs/screenshots/connections-control.png)

The **Connections** view groups observed traffic by application/process, shows remote endpoints, blocked decisions, live flow counts, and a side panel for the selected process.

_TR: Bu ekran, internete çıkan uygulamaları/processleri ve bağlı oldukları hedefleri tek yerden yönetmek için tasarlandı._

### Protection Modules

![Protection Modules](docs/screenshots/protection-modules.png)

Protection modules expose live toggles for flood protection, scan/recon detection, WFP enforcement, and unknown-application quarantine behavior.

_TR: Koruma modülleri canlı açılıp kapanabilir; bilinmeyen uygulamalar karar verilene kadar karantinada tutulabilir._

### Live Traffic Signal

![Live Traffic Signal](docs/screenshots/live-traffic-signal.png)

The dashboard keeps a compact live signal chart for immediate traffic feedback.

_TR: Canlı trafik sinyali, ağ hareketini hızlıca hissettiren küçük bir metrik alanıdır._

## What it does

- Observes active TCP/UDP connections on Windows and maps them back to process IDs and executable paths.
- Prompts the user at least once for newly observed internet-facing applications when "ask new apps" mode is enabled.
- Supports **Allow** and **Quarantine** decisions with a selectable protocol scope: TCP, UDP, or both.
- Stores remembered decisions persistently and keeps non-remembered decisions alive for the current m0untain session.
- Installs WFP application block filters for quarantined apps.
- Shows a simplewall-like application inventory: pending, allowed, quarantined/blocked, and observed-but-unruled apps.
- Shows a GlassWire-like connections page with application trees, endpoints, protocols, directions, and hot remote targets.
- Includes IDS-style detection for inbound per-IP flood/DDoS pressure and port-scan/recon patterns.
- Can stay alive in the tray when the window is closed.
- Can be configured to launch at Windows startup.

_TR: Özetle; uygulama bazlı izin/karantina, canlı bağlantı takibi, WFP engelleme ve IDS metriklerini tek arayüzde toplar._

## Project layout

```text
core/          Detection engine, config, verdicts, metrics, tests
src-tauri/    Tauri desktop shell, WFP backend, settings, tray, snapshots
ui/           Single-file dark dashboard and firewall control UI
docs/         README screenshots and documentation assets
```

_TR: Ağ ve güvenlik mantığı Rust tarafında, arayüz ise Tauri içinde çalışan web UI tarafında tutuluyor._

## Requirements

- Windows 10/11
- Rust with the MSVC toolchain
- Visual Studio C++ Build Tools
- Microsoft Edge WebView2 Runtime
- Tauri CLI v2

```powershell
cargo install tauri-cli --version "^2"
```

_TR: WFP kuralları için uygulamayı Windows'ta yönetici olarak çalıştırmak gerekir._

## Run

From the project root:

```powershell
cargo test --workspace
cargo tauri dev
```

For a release build:

```powershell
cargo build -p m0untain --release
cargo tauri build
```

The release binary is produced under:

```text
target/release/m0untain.exe
```

The installer bundle is produced under Tauri's bundle output directory when `cargo tauri build` is used.

_TR: Geliştirme sırasında `cargo tauri dev`, hızlı test için `cargo test --workspace`, dağıtım için `cargo tauri build` kullanılır._

## Usage flow

1. Start m0untain as administrator.
2. Enable protection modules and "ask new apps" mode.
3. When an application attempts to connect, choose:
   - **Allow**: let it connect.
   - **Quarantine**: block the application with WFP rules.
4. Pick the decision scope: TCP, UDP, or all traffic.
5. Leave "remember" enabled for persistent rules, or disable it for a session-only decision.
6. Use the **Connections** page to inspect observed apps, endpoints, blocked traffic, and live targets.

_TR: Amaç, yabancı veya beklenmeyen bir uygulama internete çıkmaya çalıştığında veri sızdırmadan önce kullanıcıdan karar almaktır._

## Current status

- Rust workspace builds successfully.
- Core detection tests pass.
- Windows WFP integration compiles and installs app quarantine filters.
- Active connection snapshots are collected through Windows IP Helper APIs.
- UI includes dashboard cards, focus animations, connection trees, quarantine controls, app decision prompts, tray behavior, and startup settings.

_TR: Proje çalışır durumda; güvenlik davranışları ve UI akışı hâlâ geliştirilmeye açık._

## Improvement Ideas

These are the next ideas worth adding as the firewall grows:

- Real executable icons in the application list instead of generated initials.
- Rule profiles such as Home, Public Wi-Fi, Gaming, Work, and Lockdown.
- Timed allow rules, for example "allow this app for 10 minutes".
- Per-target rules by domain, IP, port, protocol, and direction.
- DNS/domain visibility so remote IPs can be understood as human-readable names.
- Risk labels for unsigned apps, unknown publishers, unusual ports, and suspicious destinations.
- Notification history for every prompt, allow, quarantine, and block event.
- Per-application traffic graphs and bandwidth totals.
- One-click "kill process" beside quarantine for emergency containment.
- Import/export for rules and settings.
- A stronger default-deny mode backed by an always-on Windows service.
- Optional reputation checks for domains, IPs, and executable signatures.
- Search and filtering for large app inventories, similar to simplewall.

_TR: Bunlar projeyi daha gerçek bir “tam kontrol firewall” hissine taşıyacak sonraki adımlar._

## Development notes

- Dynamic WFP sessions are preferred so temporary filters are cleaned up when the app exits.
- Persistent app rules are stored in the app settings layer.
- Session-only app rules remain active while m0untain is open.
- The first observed connection may already have reached Windows before a user decision is made; stronger pre-connection default-deny behavior should be implemented as a dedicated service/filter strategy.

_TR: En güçlü güvenlik için sonraki büyük adım, uygulama açılmadan da çalışan servis tabanlı default-deny mimarisi olacaktır._

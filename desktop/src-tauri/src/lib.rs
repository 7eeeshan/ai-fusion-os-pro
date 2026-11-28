//! AI Fusion OS Pro desktop shell.
//!
//! The shell owns no business logic. It supervises the Python backend (bundled embedded Python, started with
//! `python -I -m fusion_os desktop`), shows the chat interface (with Mission Control one click away) the backend serves on 127.0.0.1, and lives
//! in the system tray so agents keep working when the window is closed.
//!
//! - One instance: a second launch focuses the existing window. The backend has its own lock too, and an already
//!   running backend (for example after the shell crashed) is reused instead of started twice.
//! - Recovery: if the backend exits unexpectedly it is restarted with back-off; after repeated crashes the shell
//!   stops retrying for a minute and says so.
//! - Sign-in: the backend writes a per-start launch secret to the user's private data folder; the shell opens the
//!   dashboard with it, so nobody pastes the admin token.
//! - Quit asks the backend to shut down cleanly (missions are checkpointed in SQLite) before exiting.
//! - AI Fusion Engine Pro, when it is bundled (the combined installer puts it in `engine\`), runs headless as the
//!   local model API on 127.0.0.1:8765. An engine that is already answering there is used instead. "Open AI Fusion
//!   Engine" in the tray stops the headless engine and opens its window, which then serves the API itself; when
//!   that window closes the headless engine comes back.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewWindow, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

const PREFERRED_PORT: &str = "8790";
const ENGINE_PORT: u16 = 8765;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Default)]
struct Engine {
    headless: Mutex<Option<Child>>,
    gui: Mutex<Option<Child>>,
    opening: AtomicBool,
}

#[derive(Default)]
struct Backend {
    child: Mutex<Option<Child>>,
    quitting: AtomicBool,
    restart: AtomicBool,
    dashboard: Mutex<Option<String>>,
}

#[derive(Clone)]
struct Info {
    port: u16,
    launch: String,
}

fn data_home() -> PathBuf {
    if let Ok(h) = std::env::var("FUSION_OS_HOME") {
        return PathBuf::from(h);
    }
    #[cfg(windows)]
    if let Ok(l) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(l).join("AIFusionOSPro");
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".fusion_os")
}

fn read_info() -> Option<Info> {
    let text = fs::read_to_string(data_home().join("security").join("desktop.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(Info { port: v.get("port")?.as_u64()? as u16, launch: v.get("launch")?.as_str()?.to_string() })
}

/// Minimal HTTP/1.1 request to the loopback backend (no extra HTTP client dependency).
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]);
    head.split_whitespace().nth(1)?.parse().ok()
}

fn healthy(info: &Info) -> bool {
    http(info.port, "GET", "/health", None) == Some(200)
}

fn shutdown_backend(info: &Info) {
    let body = serde_json::json!({ "launch": info.launch }).to_string();
    let _ = http(info.port, "POST", "/desktop/shutdown", Some(&body));
}

fn backend_command(app: &AppHandle) -> Result<Command, String> {
    let res = app.path().resource_dir().map_err(|e| e.to_string())?;
    let bundled = if cfg!(windows) {
        res.join("backend").join("python").join("python.exe")
    } else {
        res.join("backend").join("python").join("bin").join("python3")
    };
    // FUSION_OS_DEV_PYTHON lets a developer run the shell against a source checkout.
    let python = match std::env::var("FUSION_OS_DEV_PYTHON") {
        Ok(p) => PathBuf::from(p),
        Err(_) if bundled.exists() => bundled,
        Err(_) => return Err(format!("backend not found at {}", bundled.display())),
    };
    let mut cmd = Command::new(&python);
    cmd.args(["-I", "-m", "fusion_os", "desktop", "--port", PREFERRED_PORT]);
    let tor = res.join("tor").join("tor").join(if cfg!(windows) { "tor.exe" } else { "tor" });
    if tor.exists() {
        cmd.env("FUSION_OS_TOR_BIN", tor);
    }
    let logs = data_home().join("logs");
    let _ = fs::create_dir_all(&logs);
    let log = OpenOptions::new().create(true).append(true).open(logs.join("backend.log")).map_err(|e| e.to_string())?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log2));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    Ok(cmd)
}

// ---------- bundled AI Fusion Engine Pro ----------

fn engine_dir(app: &AppHandle) -> Option<PathBuf> {
    let dir = app.path().resource_dir().ok()?.join("engine");
    dir.join(if cfg!(windows) { "afe-cli.exe" } else { "afe-cli" }).exists().then_some(dir)
}

fn engine_up() -> bool {
    http(ENGINE_PORT, "GET", "/health", None) == Some(200)
}

/// Stops a process and everything it started (the engine runs model servers as child processes).
fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn alive(slot: &Mutex<Option<Child>>) -> bool {
    let mut g = slot.lock().unwrap();
    let running = matches!(g.as_mut().map(|c| c.try_wait()), Some(Ok(None)));
    if !running {
        *g = None;
    }
    running
}

fn headless_engine(dir: &PathBuf) -> Result<Child, String> {
    let exe = dir.join(if cfg!(windows) { "afe-cli.exe" } else { "afe-cli" });
    let logs = data_home().join("logs");
    let _ = fs::create_dir_all(&logs);
    let log = OpenOptions::new().create(true).append(true).open(logs.join("engine.log")).map_err(|e| e.to_string())?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.arg("api").current_dir(dir).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log2));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn().map_err(|e| e.to_string())
}

/// Keeps the engine's API available while the app runs, unless another engine already serves it.
fn supervise_engine(app: AppHandle) {
    let Some(dir) = engine_dir(&app) else { return };
    let quitting = || app.state::<Backend>().quitting.load(Ordering::SeqCst);
    // The backend copies engine data from an earlier install before it starts serving; wait for that first.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(300) && !quitting() {
        if read_info().map(|i| healthy(&i)).unwrap_or(false) {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    let mut fails: u32 = 0;
    while !quitting() {
        let eng = app.state::<Engine>();
        if eng.opening.load(Ordering::SeqCst) || alive(&eng.gui) || engine_up() {
            thread::sleep(Duration::from_secs(3));
            continue;
        }
        let started = Instant::now();
        match headless_engine(&dir) {
            Ok(c) => *eng.headless.lock().unwrap() = Some(c),
            Err(e) => {
                let _ = fs::write(data_home().join("logs").join("engine-start-error.txt"), e);
                thread::sleep(Duration::from_secs(30));
                continue;
            }
        }
        while alive(&eng.headless) && !quitting() {
            thread::sleep(Duration::from_secs(1));
        }
        if quitting() {
            break;
        }
        if eng.opening.load(Ordering::SeqCst) {
            continue; // stopped on purpose to open the window
        }
        fails = if started.elapsed() > Duration::from_secs(300) { 1 } else { fails + 1 };
        thread::sleep(Duration::from_secs(1 << fails.min(6)));
    }
}

fn open_engine_window(app: &AppHandle) {
    let Some(dir) = engine_dir(app) else { return };
    let eng = app.state::<Engine>();
    if alive(&eng.gui) || eng.opening.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(mut c) = eng.headless.lock().unwrap().take() {
        kill_tree(&mut c);
    }
    let t0 = Instant::now();
    while engine_up() && t0.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(250));
    }
    let exe = dir.join(if cfg!(windows) { "AIFusionEnginePro.exe" } else { "AIFusionEnginePro" });
    match Command::new(exe).current_dir(&dir).env("AFE_AUTOSTART_API", "1").spawn() {
        Ok(c) => *eng.gui.lock().unwrap() = Some(c),
        Err(e) => {
            let _ = fs::write(data_home().join("logs").join("engine-start-error.txt"), e.to_string());
        }
    }
    eng.opening.store(false, Ordering::SeqCst);
}

fn status(window: &Option<WebviewWindow>, msg: &str) {
    if let Some(w) = window {
        let on_splash = w.url().map(|u| u.scheme() == "tauri" || u.host_str() == Some("tauri.localhost")).unwrap_or(false);
        if on_splash {
            let _ = w.eval(&format!("window.setStatus && window.setStatus({})", serde_json::to_string(msg).unwrap()));
        }
    }
}

fn open_dashboard(app: &AppHandle, info: &Info) {
    let url = format!("http://127.0.0.1:{}/app#launch={}", info.port, info.launch);
    let state = app.state::<Backend>();
    let mut current = state.dashboard.lock().unwrap();
    if current.as_deref() == Some(url.as_str()) {
        return;
    }
    if let Some(w) = app.get_webview_window("main") {
        if let Ok(u) = url.parse() {
            let _ = w.navigate(u);
        }
    }
    *current = Some(url);
}

fn wait_ready(timeout: Duration, child_alive: impl Fn() -> bool) -> Option<Info> {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        if let Some(info) = read_info() {
            if healthy(&info) {
                return Some(info);
            }
        }
        if !child_alive() {
            return None;
        }
        thread::sleep(Duration::from_millis(300));
    }
    None
}

/// Keeps exactly one backend running for as long as the app runs.
fn supervise(app: AppHandle) {
    let window = app.get_webview_window("main");
    let mut crashes: Vec<Instant> = Vec::new();
    loop {
        let state = app.state::<Backend>();
        if state.quitting.load(Ordering::SeqCst) {
            break;
        }
        // Reuse a backend that is already running (started earlier, or left running by a crashed shell).
        if let Some(info) = read_info() {
            if healthy(&info) {
                open_dashboard(&app, &info);
                if state.restart.swap(false, Ordering::SeqCst) {
                    shutdown_backend(&info);
                    *state.dashboard.lock().unwrap() = None;
                    thread::sleep(Duration::from_secs(2));
                }
                thread::sleep(Duration::from_secs(3));
                continue;
            }
        }
        status(&window, "Starting the AI Fusion OS Pro backend…");
        let child = match backend_command(&app).and_then(|mut c| c.spawn().map_err(|e| e.to_string())) {
            Ok(c) => c,
            Err(e) => {
                status(&window, &format!("Could not start the backend: {e}. Retrying in 30 seconds."));
                thread::sleep(Duration::from_secs(30));
                continue;
            }
        };
        *state.child.lock().unwrap() = Some(child);
        let alive = || {
            let st = app.state::<Backend>();
            let mut g = st.child.lock().unwrap();
            matches!(g.as_mut().map(|c| c.try_wait()), Some(Ok(None)))
        };
        match wait_ready(Duration::from_secs(90), alive) {
            Some(info) => {
                status(&window, "Opening Mission Control…");
                open_dashboard(&app, &info);
            }
            None => status(&window, "The backend is taking long to start; see logs\\backend.log in your data folder."),
        }
        // Watch the child until it exits.
        loop {
            thread::sleep(Duration::from_millis(1000));
            if state.restart.swap(false, Ordering::SeqCst) {
                if let Some(info) = read_info() {
                    shutdown_backend(&info);
                }
            }
            let mut g = state.child.lock().unwrap();
            let done = match g.as_mut() {
                Some(c) => !matches!(c.try_wait(), Ok(None)),
                None => true,
            };
            if done {
                let code = g.as_mut().and_then(|c| c.try_wait().ok().flatten()).and_then(|s| s.code());
                *g = None;
                *state.dashboard.lock().unwrap() = None;
                if state.quitting.load(Ordering::SeqCst) {
                    return;
                }
                if code != Some(0) && code != Some(3) {
                    crashes.push(Instant::now());
                }
                break;
            }
        }
        crashes.retain(|t| t.elapsed() < Duration::from_secs(300));
        if crashes.len() >= 5 {
            if let Some(w) = &window {
                let _ = w.navigate("tauri://localhost".parse().unwrap());
            }
            thread::sleep(Duration::from_secs(1));
            status(&window, "The backend stopped 5 times in 5 minutes. Retrying in one minute; details are in logs\\backend.log.");
            thread::sleep(Duration::from_secs(60));
            crashes.clear();
        } else {
            thread::sleep(Duration::from_secs(1 << crashes.len().min(4)));
        }
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn quit(app: &AppHandle) {
    let state = app.state::<Backend>();
    state.quitting.store(true, Ordering::SeqCst);
    if let Some(info) = read_info() {
        shutdown_backend(&info);
    }
    // The engine window, if open, is the person's to close; only the headless engine stops with the app.
    if let Some(mut c) = app.state::<Engine>().headless.lock().unwrap().take() {
        kill_tree(&mut c);
    }
    let t0 = Instant::now();
    loop {
        let mut g = state.child.lock().unwrap();
        let Some(c) = g.as_mut() else { break };
        if !matches!(c.try_wait(), Ok(None)) {
            break;
        }
        if t0.elapsed() > Duration::from_secs(15) {
            let _ = c.kill();
            let _ = c.wait();
            break;
        }
        drop(g);
        thread::sleep(Duration::from_millis(200));
    }
    app.exit(0);
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open AI Fusion OS Pro", true, None::<&str>)?;
    let engine = MenuItem::with_id(app, "engine", "Open AI Fusion Engine", engine_dir(app).is_some(), None::<&str>)?;
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let autostart = CheckMenuItem::with_id(app, "autostart", "Start at Windows sign-in", true, autostart_on, None::<&str>)?;
    let restart = MenuItem::with_id(app, "restart", "Restart backend", true, None::<&str>)?;
    let logs = MenuItem::with_id(app, "logs", "Open data folder", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "Quit (stops agents)", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = if engine_dir(app).is_some() {
        Menu::with_items(app, &[&open, &engine, &sep, &autostart, &restart, &logs, &sep2, &quit_i])?
    } else {
        Menu::with_items(app, &[&open, &sep, &autostart, &restart, &logs, &sep2, &quit_i])?
    };
    let autostart_item = autostart.clone();
    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("AI Fusion OS Pro: agents keep running while this icon is here")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "engine" => {
                let app = app.clone();
                thread::spawn(move || open_engine_window(&app));
            }
            "autostart" => {
                let al = app.autolaunch();
                let on = al.is_enabled().unwrap_or(false);
                let _ = if on { al.disable() } else { al.enable() };
                let _ = autostart_item.set_checked(al.is_enabled().unwrap_or(false));
            }
            "restart" => app.state::<Backend>().restart.store(true, Ordering::SeqCst),
            "logs" => {
                let dir = data_home();
                #[cfg(windows)]
                let _ = Command::new("explorer").arg(&dir).spawn();
                #[cfg(not(windows))]
                let _ = Command::new("xdg-open").arg(&dir).spawn();
            }
            "quit" => {
                let app = app.clone();
                thread::spawn(move || quit(&app));
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| show_main(app)))
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--hidden"])))
        .manage(Backend::default())
        .manage(Engine::default())
        .setup(move |app| {
            build_tray(app.handle())?;
            if !hidden {
                show_main(app.handle());
            }
            let handle = app.handle().clone();
            thread::Builder::new().name("backend-supervisor".into()).spawn(move || supervise(handle))?;
            let handle = app.handle().clone();
            thread::Builder::new().name("engine-supervisor".into()).spawn(move || supervise_engine(handle))?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it; agents keep working. Quit from the tray stops everything.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running AI Fusion OS Pro");
}

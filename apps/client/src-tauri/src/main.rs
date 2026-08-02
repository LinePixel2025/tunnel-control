use serde::Serialize;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

#[derive(Serialize)]
struct LogLine {
    timestamp: String,
    level: String,
    source: String,
    message: String,
    #[serde(skip)]
    epoch_ms: i64,
}

#[derive(Serialize)]
struct AgentConfig {
    server_url: String,
    token_configured: bool,
    device_name: String,
    service_installed: bool,
    service_running: bool,
}

fn config_path() -> PathBuf {
    let installed = env::var("ProgramFiles")
        .ok()
        .map(|root| PathBuf::from(root).join("TunnelControl").join("agent.env"));
    if let Some(path) = installed {
        if path.exists() {
            return path;
        }
    }
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("agent.env")))
        .unwrap_or_else(|| PathBuf::from("agent.env"))
}

fn read_config_value(path: &Path, key: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('=').map(|v| v.trim().to_owned()))
}

fn gui_log_path() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(|root| PathBuf::from(root).join("TunnelControl").join("gui.log"))
        .unwrap_or_else(|| PathBuf::from("gui.log"))
}

fn agent_log_dir() -> Option<PathBuf> {
    env::var_os("PROGRAMDATA")
        .map(|root| PathBuf::from(root).join("TunnelControl").join("logs"))
}

/// Appends one GUI event to `%LOCALAPPDATA%\TunnelControl\gui.log`, rolling
/// the file to `gui.log.old` once it exceeds 1 MiB. Callers must never pass
/// secrets such as the device token.
fn append_gui_log_file(level: &str, message: &str) {
    let path = gui_log_path();
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0) > 1024 * 1024 {
        let old = path.with_extension("log.old");
        let _ = fs::remove_file(&old);
        let _ = fs::rename(&path, old);
    }
    let line = format!(
        "{} {} {}\n",
        chrono::Local::now().to_rfc3339(),
        level.to_uppercase(),
        message
    );
    let mut file = match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(_) => return,
    };
    let _ = file.write_all(line.as_bytes());
}

fn push_log(
    entries: &mut Vec<LogLine>,
    timestamp: &str,
    level: &str,
    source: &str,
    message: &str,
) {
    if message.is_empty() {
        return;
    }
    let epoch_ms = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|time| time.timestamp_millis())
        .unwrap_or(0);
    entries.push(LogLine {
        timestamp: timestamp.to_string(),
        level: level.to_uppercase(),
        source: source.to_string(),
        message: message.to_string(),
        epoch_ms,
    });
}

fn read_gui_log(path: &Path, entries: &mut Vec<LogLine>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(timestamp), Some(level)) = (parts.next(), parts.next()) else {
            continue;
        };
        let message = parts.collect::<Vec<_>>().join(" ");
        push_log(entries, timestamp, level, "GUI", &message);
    }
}

fn read_agent_logs(dir: &Path, entries: &mut Vec<LogLine>) {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|read_dir| {
            read_dir
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("agent.log"))
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default();
    // Newest file first (current day plus recent rotations).
    files.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    });
    files.reverse();
    for path in files.into_iter().take(3) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let (Some(timestamp), Some(level), Some(_target)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            let message = parts.collect::<Vec<_>>().join(" ");
            push_log(entries, timestamp, level, "agent", &message);
        }
    }
}

#[tauri::command]
fn append_gui_log(level: String, message: String) -> Result<(), String> {
    append_gui_log_file(&level, &message);
    Ok(())
}

/// Merges the most recent GUI and agent log lines, newest first.
#[tauri::command]
fn read_logs(lines: Option<usize>) -> Vec<LogLine> {
    let limit = lines.unwrap_or(200).clamp(1, 500);
    let mut entries: Vec<LogLine> = Vec::new();
    read_gui_log(&gui_log_path(), &mut entries);
    read_gui_log(&gui_log_path().with_extension("log.old"), &mut entries);
    if let Some(dir) = agent_log_dir() {
        read_agent_logs(&dir, &mut entries);
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.epoch_ms));
    entries.truncate(limit);
    entries
}

fn query_service() -> (bool, bool) {
    #[cfg(windows)]
    {
        let output = Command::new("sc").args(["query", "TunnelAgent"]).output();
        if let Ok(output) = output {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            return (true, text.contains("running"));
        }
    }
    (false, false)
}

#[tauri::command]
fn load_config() -> AgentConfig {
    let path = config_path();
    let server_url = read_config_value(&path, "TUNNEL_SERVER_URL").unwrap_or_default();
    let token = read_config_value(&path, "TUNNEL_TOKEN").unwrap_or_default();
    let (service_installed, service_running) = query_service();
    AgentConfig {
        server_url,
        token_configured: !token.is_empty(),
        device_name: env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows device".into()),
        service_installed,
        service_running,
    }
}

#[tauri::command(rename_all = "snake_case")]
fn save_config(server_url: String, token: String) -> Result<(), String> {
    let path = config_path();
    let token = if token.trim().is_empty() {
        read_config_value(&path, "TUNNEL_TOKEN").unwrap_or_default()
    } else {
        token.trim().to_owned()
    };
    let content = format!(
        "TUNNEL_SERVER_URL={}\nTUNNEL_TOKEN={}\n",
        server_url.trim(),
        token
    );
    if let Err(error) = fs::write(&path, content) {
        append_gui_log_file("ERROR", &format!("保存连接配置失败：{error}"));
        return Err(error.to_string());
    }
    append_gui_log_file("INFO", &format!("连接配置已保存：{}", server_url.trim()));
    Ok(())
}

#[tauri::command]
async fn control_service(action: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || control_service_blocking(&action))
        .await
        .map_err(|error| error.to_string())?
}

fn control_service_blocking(action: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        let (verb, label) = match action {
            "start" => ("start", "启动"),
            "stop" => ("stop", "停止"),
            _ => return Err("unsupported action".into()),
        };
        let output = Command::new("sc")
            .args([verb, "TunnelAgent"])
            .output()
            .map_err(|error| {
                append_gui_log_file("ERROR", &format!("{label}后台服务失败：{error}"));
                error.to_string()
            })?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if output.status.success() {
            append_gui_log_file("INFO", &format!("后台服务已{label}"));
            Ok(text)
        } else {
            append_gui_log_file("ERROR", &format!("{label}后台服务失败：{text}"));
            Err(text)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        Err("Windows only".into())
    }
}

#[tauri::command(rename_all = "snake_case")]
async fn install_service(server_url: String, token: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || install_service_blocking(server_url, token))
        .await
        .map_err(|error| error.to_string())?
}

fn install_service_blocking(server_url: String, token: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        append_gui_log_file("INFO", "开始安装/修复后台服务");
        let program_files = env::var("ProgramFiles").map_err(|error| {
            append_gui_log_file("ERROR", &format!("安装失败：无法定位 ProgramFiles：{error}"));
            error.to_string()
        })?;
        let install_dir = PathBuf::from(&program_files).join("TunnelControl");
        fs::create_dir_all(&install_dir).map_err(|error| {
            append_gui_log_file("ERROR", &format!("创建安装目录失败：{error}"));
            error.to_string()
        })?;

        let exe_dir = env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());
        let source = [exe_dir.join("tunnel-agent.exe"), exe_dir.join("Tunnel-Agent-Setup.exe")]
            .into_iter()
            .find(|path| path.exists())
            .ok_or_else(|| {
                append_gui_log_file("ERROR", "安装失败：未找到 tunnel-agent.exe");
                "tunnel-agent.exe not found next to the GUI".to_string()
            })?;
        let target = install_dir.join("tunnel-agent.exe");
        fs::copy(&source, &target).map_err(|error| {
            append_gui_log_file("ERROR", &format!("复制 agent 程序失败：{error}"));
            error.to_string()
        })?;

        let token = if token.trim().is_empty() {
            read_config_value(&install_dir.join("agent.env"), "TUNNEL_TOKEN").unwrap_or_default()
        } else {
            token.trim().to_owned()
        };
        let content = format!(
            "TUNNEL_SERVER_URL={}\nTUNNEL_TOKEN={}\n",
            server_url.trim(),
            token
        );
        fs::write(install_dir.join("agent.env"), content).map_err(|error| {
            append_gui_log_file("ERROR", &format!("写入 agent.env 失败：{error}"));
            error.to_string()
        })?;

        let _ = Command::new("sc").args(["stop", "TunnelAgent"]).status();
        let _ = Command::new("sc").args(["delete", "TunnelAgent"]).status();
        let binary = format!("\"{}\" --service", target.display());
        let created = Command::new("sc")
            .args([
                "create",
                "TunnelAgent",
                "binPath=",
                &binary,
                "start=",
                "auto",
                "DisplayName=",
                "Tunnel Control Agent",
            ])
            .status()
            .map_err(|error| error.to_string())?;
        if !created.success() {
            append_gui_log_file("ERROR", "创建 TunnelAgent 服务失败（请以管理员身份运行）");
            return Err("Failed to create TunnelAgent service. Run the GUI as Administrator.".into());
        }
        let _ = Command::new("sc")
            .args([
                "failure",
                "TunnelAgent",
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/10000/restart/30000",
            ])
            .status();
        let started = Command::new("sc")
            .args(["start", "TunnelAgent"])
            .status()
            .map_err(|error| error.to_string())?;
        if started.success() {
            append_gui_log_file("INFO", "TunnelAgent 服务已安装并启动");
            Ok("TunnelAgent installed and started.".into())
        } else {
            append_gui_log_file("ERROR", "服务已安装但启动失败，请查看 Windows 事件日志");
            Err("Service installed but failed to start. Check Windows Event Viewer.".into())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (server_url, token);
        Err("Windows only".into())
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            control_service,
            install_service,
            append_gui_log,
            read_logs
        ])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}

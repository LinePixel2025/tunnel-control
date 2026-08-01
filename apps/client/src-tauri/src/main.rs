use serde::Serialize;
use std::{env, fs, path::{Path, PathBuf}, process::Command};

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
    fs::write(&path, content).map_err(|error| error.to_string())
}

#[tauri::command]
fn control_service(action: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let verb = match action.as_str() {
            "start" => "start",
            "stop" => "stop",
            _ => return Err("unsupported action".into()),
        };
        let output = Command::new("sc")
            .args([verb, "TunnelAgent"])
            .output()
            .map_err(|error| error.to_string())?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if output.status.success() {
            Ok(text)
        } else {
            Err(text)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        Err("Windows only".into())
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![load_config, save_config, control_service])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}

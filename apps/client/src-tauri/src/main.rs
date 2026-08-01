use serde::Serialize;
#[derive(Serialize)] struct AgentStatus { service: &'static str, configured: bool }
#[tauri::command] fn agent_status() -> AgentStatus { AgentStatus { service: "managed by Windows Service", configured: false } }
#[tauri::command] fn save_connection(_server_url: String, _token: String) -> Result<(), String> { Err("The GUI delegates credential storage to the installed TunnelAgent service. Configure it with the installer or service API.".into()) }
fn main() { tauri::Builder::default().invoke_handler(tauri::generate_handler![agent_status, save_connection]).run(tauri::generate_context!()).expect("Tauri application error"); }

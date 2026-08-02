import { FormEvent, useEffect, useState } from "react";
import { Activity, Cable, ChevronRight, CircleCheck, Computer, ExternalLink, Gauge, Network, Power, RefreshCw, Save, ScrollText, Settings, ShieldCheck } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import "./status.css";

type AgentConfig = {
  server_url: string;
  token_configured: boolean;
  device_name: string;
  service_installed: boolean;
  service_running: boolean;
};
type TunnelInfo = { id: string; name: string; kind: "tcp" | "http" | "udp"; public_port: number; local_host: string; local_port: number; enabled: boolean };
type ConnectionInfo = { stream_id: string; tunnel_id: string; kind: "tcp" | "http" | "udp"; public_port: number; local_host: string; local_port: number; opened_at: number };
type AgentStatus = { connected: boolean; tunnels: TunnelInfo[]; connections: ConnectionInfo[] };
type LogLine = { timestamp: string; level: string; source: string; message: string };
const STATUS_URL = "http://127.0.0.1:17890/status";

const invoke = async <T,>(command: string, args?: Record<string, unknown>): Promise<T> => {
  const api = (window as unknown as { __TAURI__?: { core?: { invoke: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core;
  if (api?.invoke) return api.invoke(command, args) as Promise<T>;
  if (command === "load_config") return { server_url: "", token_configured: false, device_name: "本机开发模式", service_installed: false, service_running: false } as T;
  if (command === "save_config") return true as T;
  if (command === "read_logs") return [] as T;
  if (command === "append_gui_log") return true as T;
  return "ok" as T;
};

type Page = "overview" | "tunnels" | "connections" | "settings" | "logs";

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [config, setConfig] = useState<AgentConfig>({ server_url: "", token_configured: false, device_name: "Windows 设备", service_installed: false, service_running: false });
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);

  const refresh = async () => {
    try {
      setConfig(await invoke<AgentConfig>("load_config"));
      setMessage("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };
  const refreshStatus = async () => {
    try {
      const response = await fetch(STATUS_URL, { cache: "no-store" });
      setStatus(response.ok ? (await response.json() as AgentStatus) : null);
    } catch {
      setStatus(null);
    }
  };
  const loadLogs = async () => {
    try {
      setLogs(await invoke<LogLine[]>("read_logs", { lines: 200 }));
    } catch {
      /* keep the last entries on read failure */
    }
  };
  useEffect(() => {
    void refresh();
    void refreshStatus();
    void invoke("append_gui_log", { level: "info", message: "客户端界面已启动" });
    const timer = window.setInterval(() => void refreshStatus(), 3000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (page !== "logs") return;
    void loadLogs();
    const timer = window.setInterval(() => void loadLogs(), 5000);
    return () => window.clearInterval(timer);
  }, [page]);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await invoke("save_config", { server_url: String(form.get("serverUrl") ?? ""), token: String(form.get("token") ?? "") });
      setSaved(true);
      setMessage("连接配置已保存，服务重启后生效。");
      void invoke("append_gui_log", { level: "info", message: `连接配置已保存：${String(form.get("serverUrl") ?? "")}` });
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
      void invoke("append_gui_log", { level: "error", message: `保存连接配置失败：${error instanceof Error ? error.message : String(error)}` });
    }
  };

  const service = async (action: "start" | "stop") => {
    try {
      const result = await invoke<string>("control_service", { action });
      setMessage(result);
      void invoke("append_gui_log", { level: "info", message: action === "start" ? "后台服务已启动" : "后台服务已停止" });
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
      void invoke("append_gui_log", { level: "error", message: `${action === "start" ? "启动" : "停止"}后台服务失败：${error instanceof Error ? error.message : String(error)}` });
    }
  };

  const install = async () => {
    const server = (document.getElementById("serverUrl") as HTMLInputElement)?.value ?? "";
    const token = (document.getElementById("token") as HTMLInputElement)?.value ?? "";
    try {
      const result = await invoke<string>("install_service", { server_url: server, token });
      setMessage(result);
      setSaved(true);
      void invoke("append_gui_log", { level: "info", message: "已安装/修复后台服务" });
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
      void invoke("append_gui_log", { level: "error", message: `安装/修复后台服务失败：${error instanceof Error ? error.message : String(error)}` });
    }
  };
  const online = status?.connected === true;
  return <div className="client"><aside><div className="brand"><span className="brand-mark"><Cable size={19}/></span><div><b>Tunnel Agent</b><small>Windows 内网穿透</small></div></div><nav>{([["overview", "概览", Gauge], ["tunnels", "隧道", Network], ["connections", "连接", Activity], ["settings", "设置", Settings], ["logs", "日志", ScrollText]] as [Page, string, typeof Gauge][]).map(([id, label, Icon]) => <button key={id} className={page === id ? "current" : ""} onClick={() => setPage(id)}><Icon size={17}/>{label}</button>)}</nav><div className="agent-state"><i className={online ? "online" : ""}/><div><small>后台服务</small><b>{config.service_running ? "运行中" : "未运行"}</b></div></div></aside><main><header><div><p className="eyebrow">本机代理</p><h1>{config.device_name}</h1></div><span className={`badge ${online ? "ok" : ""}`}>{online ? "代理在线" : "需要配置"}</span></header>{message && <div className="notice">{message}</div>}{page === "overview" && <Overview config={config} online={online} goSettings={() => setPage("settings")}/>}{page === "tunnels" && <Tunnels status={status}/>}{page === "connections" && <Connections status={status}/>}{page === "settings" && <SettingsPage config={config} saved={saved} onSave={save} onService={service} onInstall={install} onRefresh={() => void refresh()}/>}{page === "logs" && <LogsPanel logs={logs} onRefresh={() => void loadLogs()}/>}</main></div>;
}

function Overview({ config, online, goSettings }: { config: AgentConfig; online: boolean; goSettings: () => void }) {
  const adminUrl = config.server_url.replace(/^ws:\/\//, "http://").replace(/\/control$/, "");
  return <>
    <section className="connection"><div className="signal"><span/><span/><span/></div><div><p className="eyebrow">控制通道</p><h2>{online ? "已连接服务器" : config.token_configured ? "配置已保存，等待服务启动" : "连接尚未配置"}</h2><p>{online ? "后台服务正在保持控制连接，并在网络恢复后自动重连。" : "填写服务器 WebSocket 地址和访问令牌后，后台服务将接管隧道。"}</p></div><button onClick={goSettings}>{online ? "查看设置" : "开始配置"}<ChevronRight size={16}/></button></section>
    <section className="grid"><article><p>服务端状态</p><strong>{config.service_running ? "运行中" : "停止"}</strong><small>Windows 服务</small></article><article><p>访问令牌</p><strong>{config.token_configured ? "已配置" : "未配置"}</strong><small>存储在 agent.env</small></article><article><p>本机名称</p><strong>{config.device_name.slice(0, 14)}</strong><small>注册到服务端</small></article></section>
    <section className="panel"><div className="panel-title"><div><h2>快速上手</h2><p>管理台由服务端管理员统一分配公网端口。</p></div><ShieldCheck size={18}/></div><div className="steps"><div><span>1</span><div><b>配置连接</b><p>填写服务端控制地址和访问令牌。</p></div></div><div><span>2</span><div><b>启动服务</b><p>后台服务注册设备并保持在线。</p></div></div><div><span>3</span><div><b>等待隧道</b><p>管理员在服务端为这台设备分配隧道。</p></div></div><a className="text-link" href={adminUrl || undefined} target="_blank" rel="noreferrer">打开管理面板<ExternalLink size={14}/></a></div></section>
  </>;
}
function Tunnels({ status }: { status: AgentStatus | null }) {
  const tunnels = status?.tunnels ?? [];
  const online = status?.connected === true;
  return <section className="panel"><div className="panel-title"><div><h2>管理员隧道</h2><p>公网端口由服务端管理，本机只读展示。</p></div><span className="readonly">只读</span></div>{tunnels.length ? <div className="item-list">{tunnels.map(tunnel => (
    <div className="item" key={tunnel.id}><div className="item-main"><b>{tunnel.name}</b><small>{tunnel.kind.toUpperCase()}</small></div><div className="item-meta"><code>:{tunnel.public_port}</code><span>→ {tunnel.local_host}:{tunnel.local_port}</span><i className={tunnel.enabled ? "live" : ""}>{tunnel.enabled ? "已启用" : "已停用"}</i></div></div>
  ))}</div> : <div className="empty"><Network size={22}/><h3>{online ? "暂无下发的隧道" : "设备尚未在线"}</h3><p>{online ? "请让管理员在管理面板中为这台在线设备创建 TCP、HTTP 或 UDP 隧道。" : "先在设置中完成连接配置并启动后台服务。"}</p></div>}</section>;
}
function Connections({ status }: { status: AgentStatus | null }) {
  const connections = status?.connections ?? [];
  const tunnelNames = new Map((status?.tunnels ?? []).map(tunnel => [tunnel.id, tunnel.name]));
  const online = status?.connected === true;
  return <section className="panel"><div className="panel-title"><div><h2>实时连接</h2><p>通过本机代理转发的公网访问。</p></div><Activity size={18}/></div>{connections.length ? <div className="item-list">{connections.map(connection => (
    <div className="item" key={connection.stream_id}><div className="item-main"><b>{tunnelNames.get(connection.tunnel_id) ?? "隧道"}</b><small>{connection.kind.toUpperCase()}</small></div><div className="item-meta"><code>:{connection.public_port}</code><span>→ {connection.local_host}:{connection.local_port}</span><time>{new Date(connection.opened_at * 1000).toLocaleTimeString()}</time></div></div>
  ))}</div> : <div className="empty"><Activity size={22}/><h3>{online ? "当前没有活动连接" : "服务未连接"}</h3><p>{online ? "新的公网访问会出现在这里，包括协议、端口和本地目标。" : "启动后台服务并连接服务器后即可接收公网隧道连接。"}</p></div>}</section>;
}
function LogsPanel({ logs, onRefresh }: { logs: LogLine[]; onRefresh: () => void }) {
  return <section className="panel"><div className="panel-title"><div><h2>本地日志</h2><p>本机客户端与后台服务发生的事件，仅保存在本机。</p></div><button type="button" className="quiet" onClick={onRefresh}><RefreshCw size={15}/>刷新</button></div>{logs.length ? <div className="item-list">{logs.map((log, index) => (
    <div className="item" key={`${log.timestamp}-${index}`}><div className="item-main"><span className={`log-level ${log.level === "WARN" ? "warn" : log.level === "ERROR" ? "error" : ""}`}>{log.level}</span><span className="log-source">{log.source}</span><span className="log-message">{log.message}</span></div><time>{new Date(log.timestamp).toLocaleString()}</time></div>
  ))}</div> : <div className="empty"><ScrollText size={22}/><h3>暂无日志</h3><p>启动后台服务或执行客户端操作后，事件会记录在这里。</p></div>}</section>;
}
function SettingsPage({ config, saved, onSave, onService, onInstall, onRefresh }: { config: AgentConfig; saved: boolean; onSave: (event: FormEvent<HTMLFormElement>) => void; onService: (action: "start" | "stop") => void; onInstall: () => void; onRefresh: () => void }) {
  return <section className="settings"><div><p className="eyebrow">连接配置</p><h2>服务端与访问令牌</h2><p>令牌只保存在本机配置中，服务重启后由后台进程读取。</p></div><form onSubmit={onSave}><label>服务端控制地址<input id="serverUrl" name="serverUrl" required defaultValue={config.server_url || "ws://123.207.8.77:18080/control"} placeholder="ws://公网IP:端口/control" spellCheck={false}/></label><label>设备访问令牌<input id="token" name="token" type="password" placeholder={config.token_configured ? "已配置，留空保持不变" : "粘贴管理员分配的令牌"}/></label><div className="service"><span><CircleCheck size={18}/></span><div><b>后台 Windows 服务</b><p>{config.service_installed ? "服务已安装，可手动启动或停止。" : "当前环境中未检测到 TunnelAgent 服务。"}</p></div></div><div className="actions"><button type="button" className="save" onClick={onInstall}><CircleCheck size={16}/>安装/修复服务</button><button type="button" className="quiet" onClick={onRefresh}><RefreshCw size={15}/>刷新状态</button>{config.service_installed && <button type="button" className="quiet" onClick={() => void onService(config.service_running ? "stop" : "start")}><Power size={15}/>{config.service_running ? "停止服务" : "启动服务"}</button>}<button className="save" type="submit"><Save size={16}/>{saved ? "已保存" : "保存配置"}</button></div></form></section>;
}
createRoot(document.getElementById("root")!).render(<App/>);

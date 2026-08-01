import { FormEvent, useEffect, useState } from "react";
import { Activity, Cable, ChevronRight, CircleCheck, Computer, ExternalLink, Gauge, Network, Power, RefreshCw, Save, Settings, ShieldCheck } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type AgentConfig = {
  server_url: string;
  token_configured: boolean;
  device_name: string;
  service_installed: boolean;
  service_running: boolean;
};

const invoke = async <T,>(command: string, args?: Record<string, unknown>): Promise<T> => {
  const api = (window as unknown as { __TAURI__?: { core?: { invoke: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core;
  if (api?.invoke) return api.invoke(command, args) as Promise<T>;
  if (command === "load_config") return { server_url: "", token_configured: false, device_name: "本机开发模式", service_installed: false, service_running: false } as T;
  if (command === "save_config") return true as T;
  return "ok" as T;
};

type Page = "overview" | "tunnels" | "connections" | "settings";

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [config, setConfig] = useState<AgentConfig>({ server_url: "", token_configured: false, device_name: "Windows 设备", service_installed: false, service_running: false });
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState("");

  const refresh = async () => {
    try {
      setConfig(await invoke<AgentConfig>("load_config"));
      setMessage("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };
  useEffect(() => { void refresh(); }, []);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await invoke("save_config", { server_url: String(form.get("serverUrl") ?? ""), token: String(form.get("token") ?? "") });
      setSaved(true);
      setMessage("连接配置已保存，服务重启后生效。");
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };

  const service = async (action: "start" | "stop") => {
    try {
      const result = await invoke<string>("control_service", { action });
      setMessage(result);
      void refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };

  const online = config.service_running && config.token_configured && config.server_url.length > 0;
  return <div className="client"><aside><div className="brand"><span className="brand-mark"><Cable size={19}/></span><div><b>Tunnel Agent</b><small>Windows 内网穿透</small></div></div><nav>{([["overview", "概览", Gauge], ["tunnels", "隧道", Network], ["connections", "连接", Activity], ["settings", "设置", Settings]] as [Page, string, typeof Gauge][]).map(([id, label, Icon]) => <button key={id} className={page === id ? "current" : ""} onClick={() => setPage(id)}><Icon size={17}/>{label}</button>)}</nav><div className="agent-state"><i className={online ? "online" : ""}/><div><small>后台服务</small><b>{config.service_running ? "运行中" : "未运行"}</b></div></div></aside><main><header><div><p className="eyebrow">本机代理</p><h1>{config.device_name}</h1></div><span className={`badge ${online ? "ok" : ""}`}>{online ? "代理在线" : "需要配置"}</span></header>{message && <div className="notice">{message}</div>}{page === "overview" && <Overview config={config} online={online} goSettings={() => setPage("settings")}/>}{page === "tunnels" && <Tunnels online={online}/>}{page === "connections" && <Connections online={online}/>}{page === "settings" && <SettingsPage config={config} saved={saved} onSave={save} onService={service} onRefresh={() => void refresh()}/>}</main></div>;
}

function Overview({ config, online, goSettings }: { config: AgentConfig; online: boolean; goSettings: () => void }) {
  const adminUrl = config.server_url.replace(/^ws:\/\//, "http://").replace(/\/control$/, "");
  return <>
    <section className="connection"><div className="signal"><span/><span/><span/></div><div><p className="eyebrow">控制通道</p><h2>{online ? "已连接服务器" : config.token_configured ? "配置已保存，等待服务启动" : "连接尚未配置"}</h2><p>{online ? "后台服务正在保持控制连接，并在网络恢复后自动重连。" : "填写服务器 WebSocket 地址和访问令牌后，后台服务将接管隧道。"}</p></div><button onClick={goSettings}>{online ? "查看设置" : "开始配置"}<ChevronRight size={16}/></button></section>
    <section className="grid"><article><p>服务端状态</p><strong>{config.service_running ? "运行中" : "停止"}</strong><small>Windows 服务</small></article><article><p>访问令牌</p><strong>{config.token_configured ? "已配置" : "未配置"}</strong><small>存储在 agent.env</small></article><article><p>本机名称</p><strong>{config.device_name.slice(0, 14)}</strong><small>注册到服务端</small></article></section>
    <section className="panel"><div className="panel-title"><div><h2>快速上手</h2><p>管理台由服务端管理员统一分配公网端口。</p></div><ShieldCheck size={18}/></div><div className="steps"><div><span>1</span><div><b>配置连接</b><p>填写服务端控制地址和访问令牌。</p></div></div><div><span>2</span><div><b>启动服务</b><p>后台服务注册设备并保持在线。</p></div></div><div><span>3</span><div><b>等待隧道</b><p>管理员在服务端为这台设备分配隧道。</p></div></div><a className="text-link" href={adminUrl || undefined} target="_blank" rel="noreferrer">打开管理面板<ExternalLink size={14}/></a></div></section>
  </>;
}
function Tunnels({ online }: { online: boolean }) {
  return <section className="panel"><div className="panel-title"><div><h2>管理员隧道</h2><p>公网端口由服务端管理，本机只读展示。</p></div><span className="readonly">只读</span></div>{online ? <div className="empty"><Network size={22}/><h3>暂无下发的隧道</h3><p>请让管理员在管理面板中为这台在线设备创建 TCP 或 HTTP 隧道。</p></div> : <div className="empty"><Network size={22}/><h3>设备尚未在线</h3><p>先在设置中完成连接配置并启动后台服务。</p></div>}</section>;
}
function Connections({ online }: { online: boolean }) {
  return <section className="panel"><div className="panel-title"><div><h2>实时连接</h2><p>通过本机代理转发的公网访问。</p></div><Activity size={18}/></div><div className="empty"><Activity size={22}/><h3>{online ? "当前没有活动连接" : "服务未运行"}</h3><p>{online ? "新的公网访问会出现在这里，包括端口、客户端和传输方向。" : "启动后台服务后即可接收公网隧道连接。"}</p></div></section>;
}
function SettingsPage({ config, saved, onSave, onService, onRefresh }: { config: AgentConfig; saved: boolean; onSave: (event: FormEvent<HTMLFormElement>) => void; onService: (action: "start" | "stop") => void; onRefresh: () => void }) {
  return <section className="settings"><div><p className="eyebrow">连接配置</p><h2>服务端与访问令牌</h2><p>令牌只保存在本机配置中，服务重启后由后台进程读取。</p></div><form onSubmit={onSave}><label>服务端控制地址<input name="serverUrl" required defaultValue={config.server_url || "ws://123.207.8.77:18080/control"} placeholder="ws://公网IP:端口/control" spellCheck={false}/></label><label>设备访问令牌<input name="token" type="password" placeholder={config.token_configured ? "已配置，留空保持不变" : "粘贴管理员分配的令牌"}/></label><div className="service"><span><CircleCheck size={18}/></span><div><b>后台 Windows 服务</b><p>{config.service_installed ? "服务已安装，可手动启动或停止。" : "当前环境中未检测到 TunnelAgent 服务。"}</p></div></div><div className="actions"><button type="button" className="quiet" onClick={onRefresh}><RefreshCw size={15}/>刷新状态</button>{config.service_installed && <button type="button" className="quiet" onClick={() => void onService(config.service_running ? "stop" : "start")}><Power size={15}/>{config.service_running ? "停止服务" : "启动服务"}</button>}<button className="save" type="submit"><Save size={16}/>{saved ? "已保存" : "保存配置"}</button></div></form></section>;
}
createRoot(document.getElementById("root")!).render(<App/>);

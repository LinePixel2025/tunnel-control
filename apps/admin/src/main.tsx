import { FormEvent, useEffect, useState } from "react";
import { Activity, Cable, Check, CirclePlus, Computer, Copy, FlaskConical, KeyRound, LogIn, Pencil, Power, RefreshCw, ScrollText, Settings, ShieldCheck, Trash2, UserPlus, X } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import "./keys.css";

const API = import.meta.env.VITE_API_URL ?? "/api/v1";
type Summary = { devices: number; online_devices: number; tunnels: number; active_connections: number };
type Device = { id: string; name: string; status: "online" | "offline"; latency_ms: number; last_seen_at: string | null };
type Tunnel = { id: string; name: string; kind: "tcp" | "http" | "udp"; public_port: number; local_host: string; local_port: number; enabled: boolean; max_connections: number; device_id: string; status: string; connections: number };
type ProbeResult = { ok: boolean; listener: boolean; agent_online: boolean; local: boolean | null; message: string | null };
type AccessKey = { id: string; label: string; device_id: string | null; device_name: string | null; created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; status: "active" | "expired" | "revoked" };
type AgentDefaults = { server_url: string; data_channels: number; heartbeat_secs: number; pong_timeout_secs: number; reconnect_min_secs: number; reconnect_max_secs: number; log_level: string };
type SettingsData = { bandwidth_limit_mbps: number; agent_defaults: AgentDefaults };
type DeviceOverrides = { server_url: string | null; data_channels: number | null; heartbeat_secs: number | null; pong_timeout_secs: number | null; reconnect_min_secs: number | null; reconnect_max_secs: number | null; log_level: string | null };
type DeviceSettings = { device_name: string; settings: AgentDefaults & { device_name: string }; overrides: DeviceOverrides };
type Enrollment = { id: string; device_name: string; status: string; created_at: string; expires_at: string };
type LogEntry = { id: string; actor_id: string | null; actor_email: string | null; action: string; subject: string; created_at: string };
type View = "overview" | "tunnels" | "devices" | "enrollments" | "keys" | "settings" | "logs";

const viewTitle: Record<View, string> = { overview: "隧道运营", tunnels: "公网隧道", devices: "Windows 设备", enrollments: "设备注册", keys: "接入密钥", settings: "系统设置", logs: "操作日志" };
const keyStatusLabel: Record<AccessKey["status"], string> = { active: "有效", expired: "已过期", revoked: "已撤销" };
const actionLabels: Record<string, string> = {
  "auth.login": "登录成功",
  "auth.login_failed": "登录失败",
  "tunnel.created": "创建隧道",
  "tunnel.toggled": "启停隧道",
  "tunnel.updated": "修改隧道",
  "tunnel.deleted": "删除隧道",
  create_access_key: "创建密钥",
  update_access_key: "修改密钥",
  delete_access_key: "删除密钥",
  revoke_access_key: "撤销密钥",
  "settings.bandwidth_updated": "修改带宽设置",
  "settings.agent_defaults_updated": "修改代理默认设置",
  "enrollment.approved": "批准设备注册",
  "enrollment.denied": "拒绝设备注册",
  "device.settings_updated": "修改设备设置",
  "device.token_rotated": "轮换设备令牌",
  "device.deleted": "删除设备",
};
const formatDate = (value: string | null) => (value ? new Date(value).toLocaleString() : "—");

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("tunnel-admin-token") ?? "");
  const [summary, setSummary] = useState<Summary>();
  const [devices, setDevices] = useState<Device[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [keys, setKeys] = useState<AccessKey[]>([]);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [error, setError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [editingTunnel, setEditingTunnel] = useState<Tunnel | null>(null);
  const [editingKey, setEditingKey] = useState<AccessKey | null>(null);
  const [createdKey, setCreatedKey] = useState<{ id: string; token: string } | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [settings, setSettings] = useState<SettingsData>({ bandwidth_limit_mbps: 0, agent_defaults: { server_url: "", data_channels: 2, heartbeat_secs: 10, pong_timeout_secs: 25, reconnect_min_secs: 1, reconnect_max_secs: 10, log_level: "info" } });
  const [deviceSettings, setDeviceSettings] = useState<DeviceSettings | null>(null);
  const [editingSettingsDevice, setEditingSettingsDevice] = useState<Device | null>(null);
  const [enrollmentMessage, setEnrollmentMessage] = useState("");
  const [activeView, setActiveView] = useState<View>("overview");

  const request = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await fetch(`${API}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, ...init?.headers } });
    if (response.status === 401) {
      localStorage.removeItem("tunnel-admin-token");
      setToken("");
      throw new Error("登录已过期，请重新登录");
    }
    if (!response.ok) throw new Error(await response.text() || "请求失败");
    return response.json() as Promise<T>;
  };
  const refresh = async () => {
    try {
      const [nextSummary, nextDevices, nextTunnels, nextKeys, nextEnrollments, nextLogs] = await Promise.all([request<Summary>("/summary"), request<Device[]>("/devices"), request<Tunnel[]>("/tunnels"), request<AccessKey[]>("/keys"), request<Enrollment[]>("/enrollments"), request<LogEntry[]>("/logs")]);
      setSummary(nextSummary); setDevices(nextDevices); setTunnels(nextTunnels); setKeys(nextKeys); setEnrollments(nextEnrollments); setLogs(nextLogs); setError("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法连接管理服务"); }
  };
  const loadSettings = async () => {
    try {
      setSettings(await request<SettingsData>("/settings"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "无法加载设置");
    }
  };
  const saveSettings = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const enabled = form.get("enabled") === "on";
    const mbps = Number(form.get("mbps") ?? 0);
    const defaults: AgentDefaults = {
      server_url: String(form.get("server_url") ?? ""),
      data_channels: Number(form.get("data_channels") ?? 2),
      heartbeat_secs: Number(form.get("heartbeat_secs") ?? 10),
      pong_timeout_secs: Number(form.get("pong_timeout_secs") ?? 25),
      reconnect_min_secs: Number(form.get("reconnect_min_secs") ?? 1),
      reconnect_max_secs: Number(form.get("reconnect_max_secs") ?? 10),
      log_level: String(form.get("log_level") ?? "info"),
    };
    try {
      setSettings(await request<SettingsData>("/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bandwidth_limit_mbps: enabled ? mbps : 0, agent_defaults: defaults }),
      }));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "保存失败");
    }
  };
  const loadDeviceSettings = async (device: Device) => {
    try {
      setEditingSettingsDevice(device);
      setDeviceSettings(await request<DeviceSettings>(`/devices/${device.id}/settings`));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "无法加载设备设置");
    }
  };
  const saveDeviceSettings = async (body: { device_name?: string; overrides: DeviceOverrides }) => {
    if (!editingSettingsDevice) return false;
    try {
      setDeviceSettings(await request<DeviceSettings>(`/devices/${editingSettingsDevice.id}/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }));
      refresh();
      return true;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "保存设备设置失败");
      return false;
    }
  };
  const rotateToken = async () => {
    if (!editingSettingsDevice || !window.confirm(`确定为设备「${editingSettingsDevice.name}」轮换访问令牌吗？旧令牌会立即失效。`)) return;
    try {
      await request<{ rotated: boolean }>(`/devices/${editingSettingsDevice.id}/rotate-token`, { method: "POST" });
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "轮换令牌失败");
    }
  };
  const deleteDevice = async (device: Device) => {
    if (!window.confirm(`确定删除设备「${device.name}」吗？该设备的所有隧道、接入令牌和设备设置都会被删除，且不可恢复；设备需重新注册才能接入。`)) return;
    try {
      await request<{ deleted: boolean }>(`/devices/${device.id}`, { method: "DELETE" });
      setError("");
      refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "删除设备失败");
    }
  };
  const approveEnrollment = async (enrollment: Enrollment, code: string) => {
    try {
      await request<{ approved: boolean }>(`/enrollments/${enrollment.id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      setEnrollmentMessage(`已批准设备「${enrollment.device_name}」的注册。`);
      refresh();
    } catch (reason) {
      setEnrollmentMessage(`批准失败：${reason instanceof Error ? reason.message : "未知错误"}`);
    }
  };
  const denyEnrollment = async (enrollment: Enrollment) => {
    if (!window.confirm(`确定拒绝设备「${enrollment.device_name}」的注册吗？`)) return;
    try {
      await request<{ denied: boolean }>(`/enrollments/${enrollment.id}/deny`, { method: "POST" });
      setEnrollmentMessage(`已拒绝设备「${enrollment.device_name}」的注册。`);
      refresh();
    } catch (reason) {
      setEnrollmentMessage(`拒绝失败：${reason instanceof Error ? reason.message : "未知错误"}`);
    }
  };
  useEffect(() => { if (!token) return; refresh(); loadSettings(); const timer = window.setInterval(refresh, 7000); return () => window.clearInterval(timer); }, [token]);
  if (!token) return <Login onAuthenticated={value => { localStorage.setItem("tunnel-admin-token", value); setToken(value); }} />;
  const createTunnel = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    try {
      await request<Tunnel>("/tunnels", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: form.get("name"), kind: form.get("kind"), public_port: Number(form.get("public_port")), local_host: form.get("local_host"), local_port: Number(form.get("local_port")), device_id: form.get("device_id"), max_connections: Number(form.get("max_connections")) }) });
      setShowForm(false); refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法创建隧道"); }
  };
  const updateTunnel = async (event: FormEvent<HTMLFormElement>) => {
    if (!editingTunnel) return;
    event.preventDefault(); const form = new FormData(event.currentTarget);
    try {
      await request<Tunnel>(`/tunnels/${editingTunnel.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: form.get("name"), kind: form.get("kind"), public_port: Number(form.get("public_port")), local_host: form.get("local_host"), local_port: Number(form.get("local_port")), device_id: form.get("device_id"), max_connections: Number(form.get("max_connections")), enabled: editingTunnel.enabled }) });
      setEditingTunnel(null); refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法更新隧道"); }
  };
  const deleteTunnel = async (tunnel: Tunnel) => {
    if (!window.confirm(`确定删除隧道「${tunnel.name}」（公网端口 :${tunnel.public_port}）吗？删除后公网入口立即关闭且不可恢复。`)) return;
    try { await request<{ deleted: boolean }>(`/tunnels/${tunnel.id}`, { method: "DELETE" }); refresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "操作失败"); }
  };
  const toggle = async (id: string) => { try { await request<Tunnel>(`/tunnels/${id}/toggle`, { method: "POST" }); refresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "操作失败"); } };
  const probeTunnel = async (id: string) => {
    try {
      setTestingId(id);
      setProbeResult(null);
      const result = await request<ProbeResult>(`/tunnels/${id}/probe`, { method: "POST" });
      setProbeResult(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "操作失败");
    } finally {
      setTestingId(null);
    }
  };
  const createKey = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    const deviceId = String(form.get("device_id") ?? "");
    const days = String(form.get("expires_in_days") ?? "");
    try {
      const key = await request<{ id: string; token: string }>("/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: String(form.get("label") ?? ""),
          ...(deviceId ? { device_id: deviceId } : {}),
          ...(days ? { expires_in_days: Number(days) } : {}),
        }),
      });
      setShowKeyForm(false); setCreatedKey(key); refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法创建密钥"); }
  };
  const updateKey = async (event: FormEvent<HTMLFormElement>) => {
    if (!editingKey) return;
    event.preventDefault(); const form = new FormData(event.currentTarget);
    const deviceId = String(form.get("device_id") ?? "");
    const expiry = String(form.get("expires_in_days") ?? "keep");
    const body: Record<string, unknown> = { label: String(form.get("label") ?? ""), device_id: deviceId || null };
    if (expiry === "keep") { /* keep the current expiry setting */ }
    else if (expiry === "") body.expires_in_days = 0;
    else body.expires_in_days = Number(expiry);
    try {
      await request<AccessKey>(`/keys/${editingKey.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      setEditingKey(null); refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法更新密钥"); }
  };
  const revokeKey = async (key: AccessKey) => {
    if (!window.confirm(`确定撤销接入密钥「${key.label}」吗？撤销后立即失效且不可恢复。`)) return;
    try { await request<{ revoked: boolean }>(`/keys/${key.id}/revoke`, { method: "POST" }); refresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "操作失败"); }
  };
  const deleteKey = async (key: AccessKey) => {
    if (!window.confirm(`确定删除接入密钥「${key.label}」吗？删除后该令牌立即失效且不可恢复。`)) return;
    try { await request<{ deleted: boolean }>(`/keys/${key.id}`, { method: "DELETE" }); refresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "操作失败"); }
  };
  return <div className="app-shell"><aside><div className="brand"><span className="brand-mark"><Cable size={20}/></span><span>Tunnel<br/><b>Control</b></span></div><nav><button type="button" className={activeView === "overview" ? "nav-active" : ""} aria-current={activeView === "overview" ? "page" : undefined} onClick={() => setActiveView("overview")}><Activity size={17}/>运营概览</button><button type="button" className={activeView === "tunnels" ? "nav-active" : ""} aria-current={activeView === "tunnels" ? "page" : undefined} onClick={() => setActiveView("tunnels")}><Cable size={17}/>公网隧道</button><button type="button" className={activeView === "devices" ? "nav-active" : ""} aria-current={activeView === "devices" ? "page" : undefined} onClick={() => setActiveView("devices")}><Computer size={17}/>Windows 设备</button><button type="button" className={activeView === "enrollments" ? "nav-active" : ""} aria-current={activeView === "enrollments" ? "page" : undefined} onClick={() => setActiveView("enrollments")}><UserPlus size={17}/>设备注册</button><button type="button" className={activeView === "keys" ? "nav-active" : ""} aria-current={activeView === "keys" ? "page" : undefined} onClick={() => setActiveView("keys")}><KeyRound size={17}/>接入密钥</button><button type="button" className={activeView === "settings" ? "nav-active" : ""} aria-current={activeView === "settings" ? "page" : undefined} onClick={() => setActiveView("settings")}><Settings size={17}/>系统设置</button><button type="button" className={activeView === "logs" ? "nav-active" : ""} aria-current={activeView === "logs" ? "page" : undefined} onClick={() => setActiveView("logs")}><ScrollText size={17}/>操作日志</button></nav><div className="secure"><ShieldCheck size={16}/><span>管理控制面<br/><b>管理员会话已验证</b></span></div></aside><main><header><div><p className="eyebrow">默认工作区</p><h1>{viewTitle[activeView]}</h1></div><div className="header-actions"><span className="online-dot"/>服务运行中<button className="icon-button" title="刷新数据" onClick={refresh}><RefreshCw size={16}/></button><button className="text-button" onClick={() => { localStorage.removeItem("tunnel-admin-token"); setToken(""); }}>退出</button></div></header>{error && <div className="notice"><b>连接提示</b>{error}</div>}{activeView !== "settings" && activeView !== "enrollments" && activeView !== "logs" && <section className="metrics"><Metric label="在线设备" value={`${summary?.online_devices ?? 0} / ${summary?.devices ?? 0}`} icon={<Computer size={21}/>}/><Metric label="启用隧道" value={`${tunnels.filter(t => t.enabled).length}`} icon={<Cable size={21}/>}/><Metric label="活动连接" value={`${summary?.active_connections ?? 0}`} icon={<Activity size={21}/>}/></section>}{activeView !== "devices" && activeView !== "enrollments" && activeView !== "keys" && activeView !== "settings" && activeView !== "logs" && <TunnelsPanel tunnels={tunnels} devices={devices} onToggle={toggle} onEdit={setEditingTunnel} onDelete={deleteTunnel} onCreate={() => setShowForm(true)} onProbe={probeTunnel} testingId={testingId} probeResult={probeResult}/>}{activeView !== "tunnels" && activeView !== "enrollments" && activeView !== "keys" && activeView !== "settings" && activeView !== "logs" && <DevicesPanel devices={devices} goKeys={() => setActiveView("keys")} onSettings={loadDeviceSettings} onDelete={deleteDevice}/>}{activeView === "devices" && <DevicesPanel devices={devices} goKeys={() => setActiveView("keys")} onSettings={loadDeviceSettings} onDelete={deleteDevice}/>}{activeView === "enrollments" && <EnrollmentsPanel enrollments={enrollments} message={enrollmentMessage} onApprove={approveEnrollment} onDeny={denyEnrollment}/>}{activeView === "keys" && <KeysPanel keys={keys} onCreate={() => setShowKeyForm(true)} onEdit={setEditingKey} onDelete={deleteKey} onRevoke={revokeKey}/>}{activeView === "settings" && <SettingsPanel settings={settings} onSave={saveSettings}/>}{activeView === "logs" && <LogsPanel logs={logs}/>}</main>{(showForm || editingTunnel) && <TunnelForm devices={devices} tunnel={editingTunnel ?? undefined} onClose={() => { setShowForm(false); setEditingTunnel(null); }} onSubmit={editingTunnel ? updateTunnel : createTunnel}/>}{(showKeyForm || editingKey) && <KeyForm devices={devices} accessKey={editingKey ?? undefined} onClose={() => { setShowKeyForm(false); setEditingKey(null); }} onSubmit={editingKey ? updateKey : createKey}/>}{createdKey && <KeyCreatedModal token={createdKey.token} onClose={() => setCreatedKey(null)}/>}{editingSettingsDevice && deviceSettings && <DeviceSettingsModal device={editingSettingsDevice} data={deviceSettings} onClose={() => { setEditingSettingsDevice(null); setDeviceSettings(null); }} onSave={saveDeviceSettings} onRotate={rotateToken}/>}</div>;
}
function Login({ onAuthenticated }: { onAuthenticated: (token: string) => void }) { const [error, setError] = useState(""); const submit = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const values = new FormData(event.currentTarget); const response = await fetch(`${API}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: values.get("email"), password: values.get("password") }) }); if (!response.ok) { setError("邮箱或密码不正确，或管理服务暂不可用。"); return; } onAuthenticated((await response.json()).access_token); }; return <div className="login-page"><form className="login" onSubmit={submit}><div className="brand login-brand"><span className="brand-mark"><Cable size={20}/></span><span>Tunnel <b>Control</b></span></div><h1>管理员登录</h1><p>使用部署时创建的管理账号进入控制台。</p>{error && <div className="notice">{error}</div>}<label>邮箱<input name="email" type="email" required autoComplete="username" placeholder="admin@example.com"/></label><label>密码<input name="password" type="password" required autoComplete="current-password"/></label><button className="primary login-submit"><LogIn size={16}/>登录</button></form></div>; }
function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) { return <div className="metric"><div><p>{label}</p><strong>{value}</strong></div>{icon}</div>; }
function Empty({ onCreate }: { onCreate: () => void }) { return <div className="empty"><span className="empty-icon"><Cable size={22}/></span><h3>还没有公网入口</h3><p>选择已连接的 Windows 设备，为本地服务分配一个对外端口。</p><button className="primary" onClick={onCreate}><CirclePlus size={16}/>新建隧道</button></div>; }
function TunnelsPanel({ tunnels, devices, onToggle, onEdit, onDelete, onCreate, onProbe, testingId, probeResult }: { tunnels: Tunnel[]; devices: Device[]; onToggle: (id: string) => void; onEdit: (tunnel: Tunnel) => void; onDelete: (tunnel: Tunnel) => void; onCreate: () => void; onProbe: (id: string) => void; testingId: string | null; probeResult: ProbeResult | null }) {
  return <section className="panel"><div className="panel-heading"><div><h2>公网隧道</h2><p>由管理员分配端口，并转发到指定 Windows 设备的本地服务。</p></div><button className="primary" onClick={onCreate}><CirclePlus size={16}/>新建隧道</button></div>{probeResult && <div className={`probe ${probeResult.ok ? "ok" : "fail"}`}><b>{probeResult.ok ? "连接正常" : "连接失败"}</b><span>{probeResult.message ?? ""}</span></div>}{tunnels.length ? <div className="table"><div className="row label"><span>名称</span><span>公网入口</span><span>本地目标</span><span>设备</span><span>状态</span><span/></div>{tunnels.map(tunnel => <div className="row" key={tunnel.id}><b>{tunnel.name}<small>{tunnel.kind.toUpperCase()}</small></b><code>:{tunnel.public_port}</code><code>{tunnel.local_host}:{tunnel.local_port}</code><span>{devices.find(device => device.id === tunnel.device_id)?.name ?? "未知设备"}</span><span className={`status ${tunnel.enabled ? "ready" : "off"}`}>{tunnel.enabled ? tunnel.status : "已停用"}</span><div className="row-actions"><button className="icon-button" title="测试连接" disabled={testingId === tunnel.id} onClick={() => onProbe(tunnel.id)}>{testingId === tunnel.id ? <RefreshCw size={16} className="spin"/> : <FlaskConical size={16}/>}</button><button className="icon-button" title={tunnel.enabled ? "停用隧道" : "启用隧道"} onClick={() => onToggle(tunnel.id)}><Power size={16}/></button><button className="icon-button" title="编辑隧道" onClick={() => onEdit(tunnel)}><Pencil size={16}/></button><button className="icon-button danger" title="删除隧道" onClick={() => onDelete(tunnel)}><Trash2 size={16}/></button></div></div>)}</div> : <Empty onCreate={onCreate}/>}</section>;
}
function DevicesPanel({ devices, goKeys, onSettings, onDelete }: { devices: Device[]; goKeys: () => void; onSettings: (device: Device) => void; onDelete: (device: Device) => void }) {
  return <section className="panel devices-panel"><div className="panel-heading"><div><h2>设备状态</h2><p>设备需使用管理面板创建的接入密钥连接；点击设置可控制该设备的全部运行参数。</p></div></div>{devices.length ? devices.map(device => <div className="device" key={device.id}><span className={`device-dot ${device.status}`}/><div><b>{device.name}</b><p>{device.id.slice(0, 8)} · {device.latency_ms} ms</p></div><span className={`status ${device.status === "online" ? "ready" : "off"}`}>{device.status === "online" ? "在线" : "离线"}</span><button className="text-button" onClick={() => onSettings(device)}><Settings size={15}/>设置</button><button className="text-button danger-text" title="删除设备" onClick={() => onDelete(device)}><Trash2 size={15}/>删除</button></div>) : <div className="device-empty">尚无设备。请先在「设备注册」页批准代理的注册请求，或在「接入密钥」页创建密钥。<button className="text-button" onClick={goKeys}>去创建密钥</button></div>}</section>;
}
function KeysPanel({ keys, onCreate, onEdit, onRevoke, onDelete }: { keys: AccessKey[]; onCreate: () => void; onEdit: (key: AccessKey) => void; onRevoke: (key: AccessKey) => void; onDelete: (key: AccessKey) => void }) {
  return <section className="panel"><div className="panel-heading"><div><h2>接入密钥</h2><p>密钥用于客户端连接控制通道；未绑定设备的密钥在首次连接时自动注册设备。</p></div><button className="primary" onClick={onCreate}><CirclePlus size={16}/>新建密钥</button></div>{keys.length ? <div className="table keys-table"><div className="row label"><span>名称</span><span>设备</span><span>状态</span><span>创建时间</span><span>过期时间</span><span>最后使用</span><span/></div>{keys.map(key => <div className="row" key={key.id}><b>{key.label}</b><span>{key.device_name ?? "未绑定"}</span><span className={`status ${key.status === "active" ? "ready" : "off"}`}>{keyStatusLabel[key.status]}</span><span>{formatDate(key.created_at)}</span><span>{key.expires_at ? formatDate(key.expires_at) : "不过期"}</span><span>{formatDate(key.last_used_at)}</span><div className="row-actions"><button className="icon-button" title="撤销密钥" disabled={key.status !== "active"} onClick={() => onRevoke(key)}><Power size={16}/></button><button className="icon-button" title="编辑密钥" onClick={() => onEdit(key)}><Pencil size={16}/></button><button className="icon-button danger" title="删除密钥" onClick={() => onDelete(key)}><Trash2 size={16}/></button></div></div>)}</div> : <div className="device-empty">尚未创建接入密钥。创建后把令牌填入 Windows 客户端即可连接。</div>}</section>;
}
function KeyForm({ devices, accessKey, onClose, onSubmit }: { devices: Device[]; accessKey?: AccessKey; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  return <div className="modal-backdrop"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><div><p className="eyebrow">管理员操作</p><h2>{accessKey ? "编辑接入密钥" : "新建接入密钥"}</h2></div><button type="button" className="text-button" onClick={onClose}>关闭</button></div><label>名称<input required name="label" maxLength={100} defaultValue={accessKey?.label} placeholder="例如：研发笔记本"/></label><label>绑定设备<select name="device_id" defaultValue={accessKey?.device_id ?? ""}><option value="">未绑定（首次连接时自动注册设备）</option>{devices.map(device => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label><label>有效期<select name="expires_in_days" defaultValue={accessKey ? "keep" : ""}>{accessKey && <option value="keep">保持当前设置</option>}<option value="">不过期</option><option value="7">7 天</option><option value="30">30 天</option><option value="90">90 天</option><option value="365">365 天</option></select></label><div className="modal-actions"><button type="button" className="text-button" onClick={onClose}>取消</button><button className="primary" type="submit">{accessKey ? "保存修改" : "创建密钥"}</button></div></form></div>;
}
function KeyCreatedModal({ token, onClose }: { token: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(token); setCopied(true); } catch { /* clipboard unavailable */ } };
  return <div className="modal-backdrop"><div className="modal" role="dialog" aria-modal="true"><div className="modal-head"><div><p className="eyebrow">密钥已创建</p><h2>请立即保存</h2></div><button type="button" className="text-button" onClick={onClose}>关闭</button></div><p className="key-hint">令牌只显示这一次，关闭后将无法再次查看，请先复制并妥善保存。</p><div className="key-token"><code>{token}</code><button type="button" className="text-button" onClick={copy}>{copied ? <Check size={15}/> : <Copy size={15}/>}{copied ? "已复制" : "复制"}</button></div><div className="modal-actions"><button className="primary" type="button" onClick={onClose}>我已完成保存</button></div></div></div>;
}
function EnrollmentsPanel({ enrollments, message, onApprove, onDeny }: { enrollments: Enrollment[]; message: string; onApprove: (enrollment: Enrollment, code: string) => void; onDeny: (enrollment: Enrollment) => void }) {
  return <section className="panel"><div className="panel-heading"><div><h2>设备注册</h2><p>代理首次运行会在本机显示一次性注册码；管理员输入注册码批准后，服务器生成令牌并直接下发给该设备。</p></div></div>{message && <div className="notice">{message}</div>}{enrollments.length ? <div className="table"><div className="row label"><span>设备名称</span><span>请求时间</span><span>过期时间</span><span>注册码</span><span/></div>{enrollments.map(enrollment => <EnrollmentRow key={enrollment.id} enrollment={enrollment} onApprove={onApprove} onDeny={onDeny}/>)}</div> : <div className="device-empty">暂无待审批的注册请求。在 Windows 设备上运行 tunnel-agent.exe 后，注册码会出现在这里。</div>}</section>;
}
function EnrollmentRow({ enrollment, onApprove, onDeny }: { enrollment: Enrollment; onApprove: (enrollment: Enrollment, code: string) => void; onDeny: (enrollment: Enrollment) => void }) {
  const [code, setCode] = useState("");
  return <div className="row" key={enrollment.id}><span>{enrollment.device_name}</span><span>{formatDate(enrollment.created_at)}</span><span>{formatDate(enrollment.expires_at)}</span><span><input className="enroll-code" placeholder="8位注册码" maxLength={8} spellCheck={false} value={code} onChange={event => setCode(event.target.value.toUpperCase())}/></span><div className="row-actions"><button className="icon-button" title="批准注册（输入注册码）" disabled={code.length !== 8} onClick={() => onApprove(enrollment, code)}><Check size={16}/></button><button className="icon-button danger" title="拒绝注册" onClick={() => onDeny(enrollment)}><X size={16}/></button></div></div>;
}
type OverrideField = { key: keyof DeviceOverrides; label: string; kind: "text" | "number" | "select"; min?: number; max?: number };
const overrideFields: OverrideField[] = [
  { key: "server_url", label: "服务器地址", kind: "text" },
  { key: "data_channels", label: "数据通道数", kind: "number", min: 1, max: 8 },
  { key: "heartbeat_secs", label: "心跳间隔（秒）", kind: "number", min: 3, max: 60 },
  { key: "pong_timeout_secs", label: "Pong 超时（秒）", kind: "number", min: 5, max: 300 },
  { key: "reconnect_min_secs", label: "重连最短间隔（秒）", kind: "number", min: 1, max: 60 },
  { key: "reconnect_max_secs", label: "重连最长间隔（秒）", kind: "number", min: 1, max: 300 },
  { key: "log_level", label: "日志级别", kind: "select" },
];
function DeviceSettingsModal({ device, data, onClose, onSave, onRotate }: { device: Device; data: DeviceSettings; onClose: () => void; onSave: (body: { device_name?: string; overrides: DeviceOverrides }) => Promise<boolean>; onRotate: () => void }) {
  const [name, setName] = useState(data.device_name);
  const [values, setValues] = useState<Record<string, { inherit: boolean; value: string }>>(() => {
    const map: Record<string, { inherit: boolean; value: string }> = {};
    for (const field of overrideFields) {
      const current = data.overrides[field.key];
      map[field.key] = { inherit: current === null, value: current === null ? "" : String(current) };
    }
    return map;
  });
  const [saving, setSaving] = useState(false);
  const setField = (key: string, patch: Partial<{ inherit: boolean; value: string }>) => setValues(prev => ({ ...prev, [key]: { ...prev[key], ...patch } }));
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    const overrides: DeviceOverrides = { server_url: null, data_channels: null, heartbeat_secs: null, pong_timeout_secs: null, reconnect_min_secs: null, reconnect_max_secs: null, log_level: null };
    for (const field of overrideFields) {
      const entry = values[field.key];
      if (!entry.inherit) {
        (overrides as Record<string, unknown>)[field.key] = field.kind === "number" ? Number(entry.value) : entry.value;
      }
    }
    const ok = await onSave({ device_name: name.trim() || undefined, overrides });
    setSaving(false);
    if (ok) onClose();
  };
  return <div className="modal-backdrop"><form className="modal modal-wide" onSubmit={submit}><div className="modal-head"><div><p className="eyebrow">管理员操作</p><h2>设备设置 · {device.name}</h2></div><button type="button" className="text-button" onClick={onClose}>关闭</button></div><p className="key-hint">未勾选"继承全局默认"的字段会覆盖全局设置；修改会立即推送给在线代理。</p><label>设备名称<input value={name} maxLength={100} onChange={event => setName(event.target.value)}/></label>{overrideFields.map(field => { const entry = values[field.key]; return <div className="override-row" key={field.key}><label className="check"><input type="checkbox" checked={entry.inherit} onChange={event => setField(field.key, { inherit: event.target.checked })}/><span>继承全局默认</span></label>{field.kind === "select" ? <select disabled={entry.inherit} value={entry.value} onChange={event => setField(field.key, { value: event.target.value })}><option value="error">error</option><option value="warn">warn</option><option value="info">info</option><option value="debug">debug</option><option value="trace">trace</option></select> : <input disabled={entry.inherit} type={field.kind === "number" ? "number" : "text"} min={field.min} max={field.max} placeholder={String(data.settings[field.key as keyof AgentSettingsLike])} value={entry.value} onChange={event => setField(field.key, { value: event.target.value })} spellCheck={false}/>}<small>生效值：{String(data.settings[field.key as keyof AgentSettingsLike])}</small></div>; })}<div className="modal-actions"><button type="button" className="text-button danger-text" onClick={onRotate}><Power size={15}/>轮换令牌</button><button type="button" className="text-button" onClick={onClose}>取消</button><button className="primary" type="submit" disabled={saving}><Check size={16}/>{saving ? "保存中" : "保存设置"}</button></div></form></div>;
}
type AgentSettingsLike = { device_name: string } & AgentDefaults;
function SettingsPanel({ settings, onSave }: { settings: SettingsData; onSave: (event: FormEvent<HTMLFormElement>) => void }) {
  return <section className="panel"><div className="panel-heading"><div><h2>带宽限速</h2><p>设置服务器总带宽上限（Mbps）。接近上限时所有隧道公平降速，连接保持不断开。</p></div></div><form className="settings-form" onSubmit={onSave}><div className="settings-group"><label className="check"><input name="enabled" type="checkbox" defaultChecked={settings.bandwidth_limit_mbps > 0}/><span>启用带宽限速</span></label><label className="mbps">带宽上限<input name="mbps" type="number" min="1" max="10000" defaultValue={settings.bandwidth_limit_mbps || 3}/><small>Mbps</small></label></div><div className="panel-heading"><div><h2>代理默认设置</h2><p>所有设备继承这些默认值；单个设备可在「Windows 设备」页单独覆盖。修改会立即推送给在线代理，重连类设置（服务器地址、数据通道数）由代理自动重连生效。</p></div></div><div className="settings-group"><label>服务器地址<input name="server_url" spellCheck={false} placeholder="ws://公网IP:端口/control（留空表示不修改）" defaultValue={settings.agent_defaults.server_url}/></label><label>数据通道数<input name="data_channels" type="number" min="1" max="8" defaultValue={settings.agent_defaults.data_channels}/></label></div><div className="settings-group"><label>心跳间隔（秒）<input name="heartbeat_secs" type="number" min="3" max="60" defaultValue={settings.agent_defaults.heartbeat_secs}/></label><label>Pong 超时（秒）<input name="pong_timeout_secs" type="number" min="5" max="300" defaultValue={settings.agent_defaults.pong_timeout_secs}/></label></div><div className="settings-group"><label>重连最短间隔（秒）<input name="reconnect_min_secs" type="number" min="1" max="60" defaultValue={settings.agent_defaults.reconnect_min_secs}/></label><label>重连最长间隔（秒）<input name="reconnect_max_secs" type="number" min="1" max="300" defaultValue={settings.agent_defaults.reconnect_max_secs}/></label></div><div className="settings-group"><label>日志级别<select name="log_level" defaultValue={settings.agent_defaults.log_level}><option value="error">error</option><option value="warn">warn</option><option value="info">info</option><option value="debug">debug</option><option value="trace">trace</option></select></label></div><div className="modal-actions"><button className="primary" type="submit"><Check size={16}/>保存设置</button></div></form></section>;
}
function LogsPanel({ logs }: { logs: LogEntry[] }) {
  return <section className="panel"><div className="panel-heading"><div><h2>操作日志</h2><p>管理端发生的事件记录，仅管理员可见。</p></div></div>{logs.length ? <div className="table logs-table"><div className="row label"><span>时间</span><span>操作者</span><span>事件</span><span>对象</span></div>{logs.map(log => (
    <div className="row" key={log.id}><span>{formatDate(log.created_at)}</span><span>{log.actor_email ?? "—"}</span><span className={`log-action ${log.action === "auth.login_failed" ? "fail" : ""}`}>{actionLabels[log.action] ?? log.action}</span><span className="log-subject">{log.subject}</span></div>
  ))}</div> : <div className="device-empty">暂无操作日志。登录、隧道、密钥和带宽设置操作会记录在这里。</div>}</section>;
}
function TunnelForm({ devices, tunnel, onClose, onSubmit }: { devices: Device[]; tunnel?: Tunnel; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  const targetDevices = tunnel ? devices : devices.filter(device => device.status === "online");
  return <div className="modal-backdrop"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><div><p className="eyebrow">管理员操作</p><h2>{tunnel ? "编辑隧道" : "新建隧道"}</h2></div><button type="button" className="text-button" onClick={onClose}>关闭</button></div><label>名称<input required name="name" maxLength={100} defaultValue={tunnel?.name} placeholder="例如：研发远程桌面"/></label><div className="two"><label>类型<select name="kind" defaultValue={tunnel?.kind ?? "tcp"}><option value="tcp">TCP</option><option value="http">HTTP</option><option value="udp">UDP</option></select></label><label>公网端口<input name="public_port" required type="number" min="1" max="65535" defaultValue={tunnel?.public_port} placeholder="10001"/></label></div><label>目标设备<select required name="device_id" defaultValue={tunnel?.device_id ?? ""}><option value="">选择设备</option>{targetDevices.map(device => <option key={device.id} value={device.id}>{device.name}{device.status === "offline" ? "（离线）" : ""}</option>)}</select></label><div className="two"><label>本地地址<input name="local_host" required defaultValue={tunnel?.local_host ?? "127.0.0.1"}/></label><label>本地端口<input name="local_port" required type="number" min="1" max="65535" defaultValue={tunnel?.local_port} placeholder="3389"/></label></div><label>最大并发<input name="max_connections" type="number" min="1" max="1000" defaultValue={tunnel?.max_connections ?? 100}/></label><div className="modal-actions"><button type="button" className="text-button" onClick={onClose}>取消</button><button className="primary" type="submit">{tunnel ? "保存修改" : "创建隧道"}</button></div></form></div>;
}
createRoot(document.getElementById("root")!).render(<App/>);

import { FormEvent, useEffect, useState } from "react";
import { Activity, Cable, Check, CirclePlus, Computer, Copy, FlaskConical, KeyRound, LogIn, Pencil, Power, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import "./keys.css";

const API = import.meta.env.VITE_API_URL ?? "/api/v1";
type Summary = { devices: number; online_devices: number; tunnels: number; active_connections: number };
type Device = { id: string; name: string; status: "online" | "offline"; latency_ms: number; last_seen_at: string | null };
type Tunnel = { id: string; name: string; kind: "tcp" | "http" | "udp"; public_port: number; local_host: string; local_port: number; enabled: boolean; max_connections: number; device_id: string; status: string; connections: number };
type ProbeResult = { ok: boolean; listener: boolean; agent_online: boolean; local: boolean | null; message: string | null };
type AccessKey = { id: string; label: string; device_id: string | null; device_name: string | null; created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; status: "active" | "expired" | "revoked" };
type View = "overview" | "tunnels" | "devices" | "keys";

const viewTitle: Record<View, string> = { overview: "隧道运营", tunnels: "公网隧道", devices: "Windows 设备", keys: "接入密钥" };
const keyStatusLabel: Record<AccessKey["status"], string> = { active: "有效", expired: "已过期", revoked: "已撤销" };
const formatDate = (value: string | null) => (value ? new Date(value).toLocaleString() : "—");

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("tunnel-admin-token") ?? "");
  const [summary, setSummary] = useState<Summary>();
  const [devices, setDevices] = useState<Device[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [keys, setKeys] = useState<AccessKey[]>([]);
  const [error, setError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [editingTunnel, setEditingTunnel] = useState<Tunnel | null>(null);
  const [editingKey, setEditingKey] = useState<AccessKey | null>(null);
  const [createdKey, setCreatedKey] = useState<{ id: string; token: string } | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
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
      const [nextSummary, nextDevices, nextTunnels, nextKeys] = await Promise.all([request<Summary>("/summary"), request<Device[]>("/devices"), request<Tunnel[]>("/tunnels"), request<AccessKey[]>("/keys")]);
      setSummary(nextSummary); setDevices(nextDevices); setTunnels(nextTunnels); setKeys(nextKeys); setError("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "无法连接管理服务"); }
  };
  useEffect(() => { if (!token) return; refresh(); const timer = window.setInterval(refresh, 7000); return () => window.clearInterval(timer); }, [token]);
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
  return <div className="app-shell"><aside><div className="brand"><span className="brand-mark"><Cable size={20}/></span><span>Tunnel<br/><b>Control</b></span></div><nav><button type="button" className={activeView === "overview" ? "nav-active" : ""} aria-current={activeView === "overview" ? "page" : undefined} onClick={() => setActiveView("overview")}><Activity size={17}/>运营概览</button><button type="button" className={activeView === "tunnels" ? "nav-active" : ""} aria-current={activeView === "tunnels" ? "page" : undefined} onClick={() => setActiveView("tunnels")}><Cable size={17}/>公网隧道</button><button type="button" className={activeView === "devices" ? "nav-active" : ""} aria-current={activeView === "devices" ? "page" : undefined} onClick={() => setActiveView("devices")}><Computer size={17}/>Windows 设备</button><button type="button" className={activeView === "keys" ? "nav-active" : ""} aria-current={activeView === "keys" ? "page" : undefined} onClick={() => setActiveView("keys")}><KeyRound size={17}/>接入密钥</button></nav><div className="secure"><ShieldCheck size={16}/><span>管理控制面<br/><b>管理员会话已验证</b></span></div></aside><main><header><div><p className="eyebrow">默认工作区</p><h1>{viewTitle[activeView]}</h1></div><div className="header-actions"><span className="online-dot"/>服务运行中<button className="icon-button" title="刷新数据" onClick={refresh}><RefreshCw size={16}/></button><button className="text-button" onClick={() => { localStorage.removeItem("tunnel-admin-token"); setToken(""); }}>退出</button></div></header>{error && <div className="notice"><b>连接提示</b>{error}</div>}<section className="metrics"><Metric label="在线设备" value={`${summary?.online_devices ?? 0} / ${summary?.devices ?? 0}`} icon={<Computer size={21}/>}/><Metric label="启用隧道" value={`${tunnels.filter(t => t.enabled).length}`} icon={<Cable size={21}/>}/><Metric label="活动连接" value={`${summary?.active_connections ?? 0}`} icon={<Activity size={21}/>}/></section>{activeView !== "devices" && activeView !== "keys" && <TunnelsPanel tunnels={tunnels} devices={devices} onToggle={toggle} onEdit={setEditingTunnel} onDelete={deleteTunnel} onCreate={() => setShowForm(true)} onProbe={probeTunnel} testingId={testingId} probeResult={probeResult}/>}{activeView !== "tunnels" && activeView !== "keys" && <DevicesPanel devices={devices} goKeys={() => setActiveView("keys")}/>}{activeView === "keys" && <KeysPanel keys={keys} onCreate={() => setShowKeyForm(true)} onEdit={setEditingKey} onDelete={deleteKey} onRevoke={revokeKey}/>}</main>{(showForm || editingTunnel) && <TunnelForm devices={devices} tunnel={editingTunnel ?? undefined} onClose={() => { setShowForm(false); setEditingTunnel(null); }} onSubmit={editingTunnel ? updateTunnel : createTunnel}/>}{(showKeyForm || editingKey) && <KeyForm devices={devices} accessKey={editingKey ?? undefined} onClose={() => { setShowKeyForm(false); setEditingKey(null); }} onSubmit={editingKey ? updateKey : createKey}/>}{createdKey && <KeyCreatedModal token={createdKey.token} onClose={() => setCreatedKey(null)}/>}</div>;
}
function Login({ onAuthenticated }: { onAuthenticated: (token: string) => void }) { const [error, setError] = useState(""); const submit = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const values = new FormData(event.currentTarget); const response = await fetch(`${API}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: values.get("email"), password: values.get("password") }) }); if (!response.ok) { setError("邮箱或密码不正确，或管理服务暂不可用。"); return; } onAuthenticated((await response.json()).access_token); }; return <div className="login-page"><form className="login" onSubmit={submit}><div className="brand login-brand"><span className="brand-mark"><Cable size={20}/></span><span>Tunnel <b>Control</b></span></div><h1>管理员登录</h1><p>使用部署时创建的管理账号进入控制台。</p>{error && <div className="notice">{error}</div>}<label>邮箱<input name="email" type="email" required autoComplete="username" placeholder="admin@example.com"/></label><label>密码<input name="password" type="password" required autoComplete="current-password"/></label><button className="primary login-submit"><LogIn size={16}/>登录</button></form></div>; }
function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) { return <div className="metric"><div><p>{label}</p><strong>{value}</strong></div>{icon}</div>; }
function Empty({ onCreate }: { onCreate: () => void }) { return <div className="empty"><span className="empty-icon"><Cable size={22}/></span><h3>还没有公网入口</h3><p>选择已连接的 Windows 设备，为本地服务分配一个对外端口。</p><button className="primary" onClick={onCreate}><CirclePlus size={16}/>新建隧道</button></div>; }
function TunnelsPanel({ tunnels, devices, onToggle, onEdit, onDelete, onCreate, onProbe, testingId, probeResult }: { tunnels: Tunnel[]; devices: Device[]; onToggle: (id: string) => void; onEdit: (tunnel: Tunnel) => void; onDelete: (tunnel: Tunnel) => void; onCreate: () => void; onProbe: (id: string) => void; testingId: string | null; probeResult: ProbeResult | null }) {
  return <section className="panel"><div className="panel-heading"><div><h2>公网隧道</h2><p>由管理员分配端口，并转发到指定 Windows 设备的本地服务。</p></div><button className="primary" onClick={onCreate}><CirclePlus size={16}/>新建隧道</button></div>{probeResult && <div className={`probe ${probeResult.ok ? "ok" : "fail"}`}><b>{probeResult.ok ? "连接正常" : "连接失败"}</b><span>{probeResult.message ?? ""}</span></div>}{tunnels.length ? <div className="table"><div className="row label"><span>名称</span><span>公网入口</span><span>本地目标</span><span>设备</span><span>状态</span><span/></div>{tunnels.map(tunnel => <div className="row" key={tunnel.id}><b>{tunnel.name}<small>{tunnel.kind.toUpperCase()}</small></b><code>:{tunnel.public_port}</code><code>{tunnel.local_host}:{tunnel.local_port}</code><span>{devices.find(device => device.id === tunnel.device_id)?.name ?? "未知设备"}</span><span className={`status ${tunnel.enabled ? "ready" : "off"}`}>{tunnel.enabled ? tunnel.status : "已停用"}</span><div className="row-actions"><button className="icon-button" title="测试连接" disabled={testingId === tunnel.id} onClick={() => onProbe(tunnel.id)}>{testingId === tunnel.id ? <RefreshCw size={16} className="spin"/> : <FlaskConical size={16}/>}</button><button className="icon-button" title={tunnel.enabled ? "停用隧道" : "启用隧道"} onClick={() => onToggle(tunnel.id)}><Power size={16}/></button><button className="icon-button" title="编辑隧道" onClick={() => onEdit(tunnel)}><Pencil size={16}/></button><button className="icon-button danger" title="删除隧道" onClick={() => onDelete(tunnel)}><Trash2 size={16}/></button></div></div>)}</div> : <Empty onCreate={onCreate}/>}</section>;
}
function DevicesPanel({ devices, goKeys }: { devices: Device[]; goKeys: () => void }) {
  return <section className="panel devices-panel"><div className="panel-heading"><div><h2>设备状态</h2><p>设备需使用管理面板创建的接入密钥连接。</p></div></div>{devices.length ? devices.map(device => <div className="device" key={device.id}><span className={`device-dot ${device.status}`}/><div><b>{device.name}</b><p>{device.id.slice(0, 8)} · {device.latency_ms} ms</p></div><span className={`status ${device.status === "online" ? "ready" : "off"}`}>{device.status === "online" ? "在线" : "离线"}</span></div>) : <div className="device-empty">尚无设备。请先在「接入密钥」页创建密钥，再填入 Windows 客户端。<button className="text-button" onClick={goKeys}>去创建密钥</button></div>}</section>;
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
function TunnelForm({ devices, tunnel, onClose, onSubmit }: { devices: Device[]; tunnel?: Tunnel; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  const targetDevices = tunnel ? devices : devices.filter(device => device.status === "online");
  return <div className="modal-backdrop"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><div><p className="eyebrow">管理员操作</p><h2>{tunnel ? "编辑隧道" : "新建隧道"}</h2></div><button type="button" className="text-button" onClick={onClose}>关闭</button></div><label>名称<input required name="name" maxLength={100} defaultValue={tunnel?.name} placeholder="例如：研发远程桌面"/></label><div className="two"><label>类型<select name="kind" defaultValue={tunnel?.kind ?? "tcp"}><option value="tcp">TCP</option><option value="http">HTTP</option><option value="udp">UDP</option></select></label><label>公网端口<input name="public_port" required type="number" min="1" max="65535" defaultValue={tunnel?.public_port} placeholder="10001"/></label></div><label>目标设备<select required name="device_id" defaultValue={tunnel?.device_id ?? ""}><option value="">选择设备</option>{targetDevices.map(device => <option key={device.id} value={device.id}>{device.name}{device.status === "offline" ? "（离线）" : ""}</option>)}</select></label><div className="two"><label>本地地址<input name="local_host" required defaultValue={tunnel?.local_host ?? "127.0.0.1"}/></label><label>本地端口<input name="local_port" required type="number" min="1" max="65535" defaultValue={tunnel?.local_port} placeholder="3389"/></label></div><label>最大并发<input name="max_connections" type="number" min="1" max="1000" defaultValue={tunnel?.max_connections ?? 100}/></label><div className="modal-actions"><button type="button" className="text-button" onClick={onClose}>取消</button><button className="primary" type="submit">{tunnel ? "保存修改" : "创建隧道"}</button></div></form></div>;
}
createRoot(document.getElementById("root")!).render(<App/>);

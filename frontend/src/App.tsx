import { useState, useEffect, Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { 
  Activity, 
  AlertTriangle, 
  Shield, 
  ShieldAlert,
  Settings, 
  Layers, 
  Server, 
  FileText, 
  RefreshCw, 
  Radio,
  Sliders
} from 'lucide-react';
import Dashboard from './components/Dashboard';
import HostInventory from './components/HostInventory';
import AuditHistory from './components/AuditHistory';
import DiagnosticsView from './components/Diagnostics';
import EnterpriseCenter from './components/EnterpriseCenter';
import { useWebSocket } from './hooks/useWebSocket';
import { safeFormatDateTime } from './utils/format';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || 'idps_demo_key';
const WS_URL = `ws://${API_HOST}:8000/ws?api_key=${encodeURIComponent(API_KEY)}`;

class GlobalErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('IDPS UI exception:', error, errorInfo);
  }
  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.href = '/';
  };
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen p-6 bg-background text-foreground text-center">
          <div className="card max-w-md w-full p-6 text-left space-y-4 shadow-sm">
            <div className="flex items-center gap-3 text-destructive">
              <ShieldAlert className="w-6 h-6" />
              <h2 className="text-base font-semibold">An interface error occurred</h2>
            </div>
            <p className="text-sm text-muted-foreground">
              The monitoring sensor and daemon are still running normally in the background.
            </p>
            {this.state.error && (
              <pre className="text-xs font-mono p-3 rounded bg-muted text-muted-foreground overflow-x-auto max-h-32 border border-border">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReset}
              className="px-4 py-2 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 transition-opacity"
            >
              Reload Interface
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function SidebarNav({ status, reconnect }: { status: string; reconnect: () => void }) {
  const navItems = [
    { to: '/', label: 'Overview', icon: Activity },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
    { to: '/live-traffic', label: 'Live Traffic', icon: Radio },
    { to: '/blocked', label: 'Blocked IPs', icon: ShieldAlert },
    { to: '/inventory', label: 'Hosts', icon: Server },
    { to: '/audit', label: 'Audit Log', icon: FileText },
    { to: '/diagnostics', label: 'Diagnostics', icon: Sliders },
    { to: '/enterprise', label: 'Threat Intel', icon: Layers },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  const isConnected = status === 'connected';

  return (
    <aside className="w-56 bg-card border-r border-border flex flex-col shrink-0 select-none">
      {/* Brand */}
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center font-bold text-sm">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <span className="font-semibold text-sm tracking-tight block leading-tight">IDPS Guard</span>
            <span className="text-[11px] text-muted-foreground block leading-tight">Network Defense</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-secondary text-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Sensor Connection Footer */}
      <div className="p-3 border-t border-border text-xs flex items-center justify-between text-muted-foreground">
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${
              isConnected ? 'bg-success' : 'bg-destructive animate-pulse'
            }`}
          />
          <span className="text-[11px] font-medium text-foreground">
            {isConnected ? 'Sensor Active' : 'Connecting...'}
          </span>
        </div>
        {!isConnected && (
          <button
            onClick={reconnect}
            title="Reconnect"
            className="p-1 hover:text-foreground text-muted-foreground rounded transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </aside>
  );
}

function LiveTrafficView({ data }: { data: any }) {
  const [filterIP, setFilterIP] = useState('');
  const [protoFilter, setProtoFilter] = useState('ALL');

  if (!data) {
    return (
      <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
        Connecting to traffic stream...
      </div>
    );
  }

  const trafficLog = Array.isArray(data.traffic_log) ? data.traffic_log : [];

  const filteredTraffic = trafficLog.filter((log: any) => {
    const matchesIP = !filterIP || (log?.src_ip && log.src_ip.includes(filterIP));
    const matchesProto = protoFilter === 'ALL' || (log?.proto && log.proto.toUpperCase() === protoFilter);
    return matchesIP && matchesProto;
  });

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Live Network Traffic</h1>
        <p className="text-xs text-muted-foreground mt-0.5">Real-time inspected packet stream across active network adapters.</p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center">
        <div className="relative flex-1">
          <input
            value={filterIP}
            onChange={(e) => setFilterIP(e.target.value)}
            placeholder="Filter by source or destination IP..."
            className="w-full text-xs bg-card border border-border rounded-md px-3 py-1.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div className="flex items-center gap-1 bg-secondary/60 p-0.5 rounded-md text-xs border border-border/40">
          {['ALL', 'TCP', 'UDP', 'HTTP', 'HTTPS'].map((p) => (
            <button
              key={p}
              onClick={() => setProtoFilter(p)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                protoFilter === p ? 'bg-card text-foreground shadow-xs font-semibold' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Traffic Table */}
      <div className="card overflow-hidden">
        <div className="px-4 py-2.5 border-b border-border bg-muted/30 flex items-center justify-between text-xs text-muted-foreground font-medium">
          <span>Captured Traffic Events ({filteredTraffic.length})</span>
          <span>Buffer: Last 100 packets</span>
        </div>
        <div className="divide-y divide-border/60 max-h-[600px] overflow-y-auto">
          {filteredTraffic.length > 0 ? (
            filteredTraffic.map((log: any, idx: number) => {
              const proto = (log.proto || 'TCP').toUpperCase();
              let badgeColor = 'bg-secondary text-secondary-foreground';
              if (proto === 'HTTPS') badgeColor = 'bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300';
              if (proto === 'HTTP') badgeColor = 'bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300';
              if (proto === 'DNS') badgeColor = 'bg-purple-50 text-purple-700 dark:bg-purple-950/40 dark:text-purple-300';

              return (
                <div key={`${log.src_ip}-${log.timestamp || idx}`} className="px-4 py-2 flex items-center justify-between text-xs hover:bg-muted/20 transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="font-mono text-[11px] text-muted-foreground w-16 shrink-0">
                      {log.time || log.timestamp || 'Live'}
                    </span>
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${badgeColor} shrink-0`}>
                      {proto}
                    </span>
                    <div className="font-mono truncate">
                      <span className="text-foreground">{log.src_ip || '0.0.0.0'}</span>
                      <span className="text-muted-foreground mx-1.5">→</span>
                      <span className="text-muted-foreground">{log.domain || log.dest_ip || 'local'}</span>
                    </div>
                  </div>
                  {log.length && (
                    <span className="font-mono text-[11px] text-muted-foreground shrink-0 pl-2">
                      {log.length} B
                    </span>
                  )}
                </div>
              );
            })
          ) : (
            <div className="py-12 text-center text-xs text-muted-foreground">
              No traffic matching filter criteria.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AlertsView({ data }: { data: any }) {
  const [history, setHistory] = useState<any[]>([]);
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  useEffect(() => {
    fetch(`${API_BASE}/api/alerts?limit=500`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((d) => setHistory(Array.isArray(d) ? d : []))
      .catch(console.error);
  }, []);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
        Loading threat detections...
      </div>
    );
  }

  const liveAlerts = Array.isArray(data.alerts) ? data.alerts : [];
  const mergedMap = new Map();
  history.forEach((a) => {
    if (a?.id) mergedMap.set(a.id, a);
  });
  liveAlerts.forEach((a: any) => {
    if (a?.id) mergedMap.set(a.id, a);
  });

  const alerts = Array.from(mergedMap.values()).sort(
    (a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0)
  );

  const blocked = Array.isArray(data.blocked) ? data.blocked : [];
  const blockedIPs = blocked.map((b: any) => (typeof b === 'string' ? b : b?.ip || '')).filter(Boolean);

  const handleBlock = async (ip: string) => {
    try {
      await fetch(`${API_BASE}/api/block/${ip}`, {
        method: 'POST',
        headers: { 'X-API-Key': API_KEY },
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleDismiss = async (id: string) => {
    try {
      await fetch(`${API_BASE}/api/alerts/${id}`, {
        method: 'DELETE',
        headers: { 'X-API-Key': API_KEY },
      });
      setHistory((prev) => prev.filter((a) => a.id !== id));
    } catch (e) {
      console.error(e);
    }
  };

  const filteredAlerts = alerts.filter((a: any) => {
    if (!a) return false;
    if (filterSeverity === 'ALL') return true;
    return (a.severity || '').toUpperCase() === filterSeverity;
  });

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Security Alerts</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time threat detection and automated prevention events.
          </p>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-1 bg-secondary/60 p-0.5 rounded-md text-xs border border-border/40">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filterSeverity === s
                  ? 'bg-card text-foreground shadow-xs font-semibold'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="card divide-y divide-border/60">
        {filteredAlerts.length === 0 ? (
          <div className="py-16 text-center text-xs text-muted-foreground">
            No alerts found. Monitored traffic is safe.
          </div>
        ) : (
          filteredAlerts.map((alert: any) => {
            const isBlocked = blockedIPs.includes(alert.source_ip);
            const sev = (alert.severity || 'Medium').toUpperCase();
            let sevColor = 'text-blue-600 bg-blue-50 dark:bg-blue-950/40 dark:text-blue-300';
            if (sev === 'CRITICAL') sevColor = 'text-red-700 bg-red-50 dark:bg-red-950/40 dark:text-red-300';
            if (sev === 'HIGH') sevColor = 'text-amber-700 bg-amber-50 dark:bg-amber-950/40 dark:text-amber-300';

            return (
              <div key={alert.id || `${alert.source_ip}-${alert.timestamp}`} className="p-4 hover:bg-muted/15 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-sm uppercase tracking-wide ${sevColor}`}>
                        {sev}
                      </span>
                      <span className="text-sm font-medium text-foreground">{alert.type || 'Anomalous Threat'}</span>
                      {alert.action === 'BLOCK_CONFIRMED' && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 font-medium">
                          Blocked
                        </span>
                      )}
                      {alert.confidence > 0 && (
                        <span className="text-[11px] font-mono text-muted-foreground">
                          {Math.round(alert.confidence * 100)}% conf
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-muted-foreground leading-relaxed">{alert.reason || 'Pattern anomaly detected'}</p>

                    {alert.evidence && (
                      <div className="mt-1 text-[11px] font-mono bg-muted/50 text-muted-foreground px-2 py-1 rounded border border-border/40 inline-block">
                        <span className="font-semibold text-foreground">Evidence: </span>{alert.evidence}
                      </div>
                    )}

                    <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted-foreground">
                      <span>Source: <strong className="text-foreground">{alert.source_ip || '0.0.0.0'}</strong></span>
                      <span>Target: <strong className="text-foreground">{alert.dest_ip || 'Local'}</strong></span>
                      <span>{safeFormatDateTime(alert.timestamp)}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-start">
                    <button
                      onClick={() => handleDismiss(alert.id)}
                      className="px-2.5 py-1 rounded text-xs border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Dismiss
                    </button>
                    <button
                      onClick={() => handleBlock(alert.source_ip)}
                      disabled={isBlocked}
                      className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                        isBlocked
                          ? 'bg-muted text-muted-foreground cursor-not-allowed'
                          : 'bg-destructive text-destructive-foreground hover:opacity-90'
                      }`}
                    >
                      {isBlocked ? 'Blocked' : 'Block IP'}
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function BlockedIPsView({ data }: { data: any }) {
  if (!data) return <div className="text-xs text-muted-foreground">Loading blocked IP list...</div>;
  const blocked = Array.isArray(data.blocked) ? data.blocked : [];

  const handleUnblock = async (ip: string) => {
    try {
      await fetch(`${API_BASE}/api/unblock/${ip}`, {
        method: 'POST',
        headers: { 'X-API-Key': API_KEY },
      });
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Firewall Blocklist</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Actively enforced IP filter rules inside the host OS kernel.
        </p>
      </div>

      <div className="card overflow-hidden">
        <div className="px-4 py-2.5 border-b border-border bg-muted/30 flex items-center justify-between text-xs text-muted-foreground font-medium">
          <span>Active Kernel Blocks ({blocked.length})</span>
          <span>iptables / netsh backend</span>
        </div>

        {blocked.length === 0 ? (
          <div className="py-16 text-center text-xs text-muted-foreground">
            No IP addresses are currently blocked.
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {blocked.map((block: any) => {
              const ip = typeof block === 'string' ? block : block?.ip || '0.0.0.0';
              const reason = typeof block === 'object' && block?.reason ? block.reason : 'Automated IPS Mitigation';
              const platform = typeof block === 'object' && block?.platform ? block.platform : 'linux';

              return (
                <div key={ip} className="px-4 py-3 flex items-center justify-between gap-4 text-xs hover:bg-muted/15 transition-colors">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-sm text-foreground">{ip}</span>
                      <span className="text-[10px] font-mono uppercase bg-secondary px-1.5 py-0.2 rounded text-muted-foreground">
                        {platform}
                      </span>
                    </div>
                    <div className="text-muted-foreground text-[11px]">{reason}</div>
                  </div>

                  <button
                    onClick={() => handleUnblock(ip)}
                    className="px-2.5 py-1 rounded text-xs border border-border hover:bg-muted font-medium text-foreground transition-colors"
                  >
                    Unblock
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function SettingsView() {
  const [settings, setSettings] = useState({
    IDPS_DEPLOYMENT_MODE: 'HOST',
    IDPS_SECURITY_MODE: 'IDS',
    WAN_INTERFACE: 'enx2a7345453743',
    LAN_INTERFACE: 'wlp1s0',
    INTERFACE: 'wlp1s0',
    ML_ENABLED: true,
  });
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [togglingML, setTogglingML] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetch(`${API_BASE}/api/settings`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((data) => {
        if (!data) return;
        setSettings({
          IDPS_DEPLOYMENT_MODE: data.IDPS_DEPLOYMENT_MODE || 'HOST',
          IDPS_SECURITY_MODE: data.IDPS_SECURITY_MODE || 'IDS',
          WAN_INTERFACE: data.WAN_INTERFACE || 'enx2a7345453743',
          LAN_INTERFACE: data.LAN_INTERFACE || 'wlp1s0',
          INTERFACE: data.INTERFACE || 'wlp1s0',
          ML_ENABLED: data.ML_ENABLED !== false,
        });
      })
      .catch(console.error);

    fetch(`${API_BASE}/api/interfaces`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((data) => setInterfaces(Array.isArray(data) ? data : []))
      .catch(console.error);
  }, []);

  const handleToggleML = async () => {
    setTogglingML(true);
    try {
      const res = await fetch(`${API_BASE}/api/ml/toggle`, {
        method: 'POST',
        headers: { 'X-API-Key': API_KEY },
      });
      const data = await res.json();
      setSettings((prev) => ({ ...prev, ML_ENABLED: data.ml_enabled }));
      setMessage(data.message || `ML model is now ${data.ml_enabled ? 'enabled' : 'disabled'}.`);
      setTimeout(() => setMessage(''), 3000);
    } catch {
      setMessage('Failed to toggle ML engine.');
      setTimeout(() => setMessage(''), 3000);
    } finally {
      setTogglingML(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage('Applying changes...');
    try {
      const res = await fetch(`${API_BASE}/api/settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY,
        },
        body: JSON.stringify(settings),
      });
      const data = await res.json();
      setMessage(data.message || 'Configuration applied.');
      setTimeout(() => setMessage(''), 3000);
    } catch {
      setMessage('Failed to apply configuration.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">System Settings</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Sensor parameters, detection engines, and interface bindings.
        </p>
      </div>

      {/* ML Engine Card */}
      <div className="card p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold">Anomaly & Machine Learning Engine</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Isolation Forest flow classifier analyzing duration, packet count, and inter-arrival timing.
            </p>
          </div>
          <button
            type="button"
            onClick={handleToggleML}
            disabled={togglingML}
            className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
              settings.ML_ENABLED
                ? 'bg-primary text-primary-foreground border-primary'
                : 'bg-secondary text-secondary-foreground border-border hover:bg-muted'
            }`}
          >
            {settings.ML_ENABLED ? 'Engine Active' : 'Engine Disabled'}
          </button>
        </div>
      </div>

      {/* Deployment & Interface Settings */}
      <div className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold border-b border-border pb-2">Network Deployment</h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-foreground">Deployment Mode</label>
            <select
              value={settings.IDPS_DEPLOYMENT_MODE}
              onChange={(e) => setSettings({ ...settings, IDPS_DEPLOYMENT_MODE: e.target.value })}
              className="w-full text-xs bg-background border border-border rounded-md px-3 py-2 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="HOST">Host Mode (Local Endpoint)</option>
              <option value="GATEWAY">Gateway Mode (Inline Hotspot/Router)</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-foreground">Operation Policy</label>
            <select
              value={settings.IDPS_SECURITY_MODE}
              onChange={(e) => setSettings({ ...settings, IDPS_SECURITY_MODE: e.target.value })}
              className="w-full text-xs bg-background border border-border rounded-md px-3 py-2 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="IDS">IDS (Detection & Logging Only)</option>
              <option value="IPS">IPS (Automated Prevention & Blocking)</option>
            </select>
          </div>

          {settings.IDPS_DEPLOYMENT_MODE === 'HOST' ? (
            <div className="space-y-1.5 col-span-full">
              <label className="text-xs font-medium text-foreground">Inspection Interface</label>
              <select
                value={settings.INTERFACE}
                onChange={(e) => setSettings({ ...settings, INTERFACE: e.target.value })}
                className="w-full text-xs bg-background border border-border rounded-md px-3 py-2 font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {Array.from(new Set([...interfaces, settings.INTERFACE])).map((iface) => (
                  <option key={iface} value={iface}>
                    {iface}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">WAN Interface (Internet)</label>
                <select
                  value={settings.WAN_INTERFACE}
                  onChange={(e) => setSettings({ ...settings, WAN_INTERFACE: e.target.value })}
                  className="w-full text-xs bg-background border border-border rounded-md px-3 py-2 font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  {Array.from(new Set([...interfaces, settings.WAN_INTERFACE])).map((iface) => (
                    <option key={iface} value={iface}>
                      {iface}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">LAN Interface (Internal)</label>
                <select
                  value={settings.LAN_INTERFACE}
                  onChange={(e) => setSettings({ ...settings, LAN_INTERFACE: e.target.value })}
                  className="w-full text-xs bg-background border border-border rounded-md px-3 py-2 font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  {Array.from(new Set([...interfaces, settings.LAN_INTERFACE])).map((iface) => (
                    <option key={iface} value={iface}>
                      {iface}
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}
        </div>

        <div className="pt-3 border-t border-border flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{message}</span>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 bg-primary text-primary-foreground text-xs font-medium rounded-md hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {saving ? 'Saving...' : 'Apply Changes'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { data, status, reconnect } = useWebSocket(WS_URL);

  return (
    <GlobalErrorBoundary>
      <Router>
        <div className="flex h-screen bg-background text-foreground overflow-hidden">
          {/* Sidebar */}
          <SidebarNav status={status} reconnect={reconnect} />

          {/* Main Area */}
          <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
            {/* Disconnect Alert Banner */}
            {status !== 'connected' && (
              <div className="bg-amber-50 dark:bg-amber-950/40 border-b border-amber-200 dark:border-amber-900/50 px-4 py-2 flex items-center justify-between text-xs text-amber-800 dark:text-amber-200">
                <span>
                  Sensor stream is <strong>{status}</strong>. Attempting background reconnect...
                </span>
                <button
                  onClick={reconnect}
                  className="px-2 py-0.5 rounded bg-amber-200/50 dark:bg-amber-800/40 font-medium hover:bg-amber-200"
                >
                  Reconnect
                </button>
              </div>
            )}

            <main className="flex-1 overflow-y-auto p-6">
              <Routes>
                <Route path="/" element={<Dashboard data={data} status={status} />} />
                <Route path="/alerts" element={<AlertsView data={data} />} />
                <Route path="/live-traffic" element={<LiveTrafficView data={data} />} />
                <Route path="/blocked" element={<BlockedIPsView data={data} />} />
                <Route path="/inventory" element={<HostInventory data={data} />} />
                <Route path="/audit" element={<AuditHistory data={data} />} />
                <Route path="/diagnostics" element={<DiagnosticsView />} />
                <Route path="/enterprise" element={<EnterpriseCenter />} />
                <Route path="/settings" element={<SettingsView />} />
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </GlobalErrorBoundary>
  );
}

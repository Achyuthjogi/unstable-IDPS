import { useState, useEffect, Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, ShieldOff, Settings, Network, AlertOctagon, Ban } from 'lucide-react';
import Dashboard from './components/Dashboard';
import ThreeDBackground from './components/ThreeDBackground';
import { useWebSocket } from './hooks/useWebSocket';
import { format } from 'date-fns';

const API_HOST = window.location.hostname;
const API_BASE = `https://${API_HOST}:8000`;
const WS_URL = `wss://${API_HOST}:8000/ws`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

// Error boundary to catch 3D/WebGL crashes
class SafeBackground extends Component<{children: ReactNode}, {hasError: boolean}> {
  constructor(props: {children: ReactNode}) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.warn('3D Background failed to load:', error, info);
  }
  render() {
    if (this.state.hasError) {
      return <div className="fixed inset-0 z-0 bg-background" />;
    }
    return this.props.children;
  }
}

function App() {
  const [activeTab, setActiveTab] = useState(window.location.pathname.replace('/', '') || 'overview');
  const { data, status } = useWebSocket(WS_URL, API_KEY ? [API_KEY] : undefined);

  return (
    <Router>
      <div className="flex h-screen bg-transparent overflow-hidden text-foreground selection:bg-primary selection:text-primary-foreground relative z-10">
        <SafeBackground><ThreeDBackground /></SafeBackground>
        {/* Sidebar */}
        <aside className="w-64 kinetic-card z-10 flex flex-col rounded-r-2xl my-4 ml-4">
          <div className="p-6 flex items-center gap-3">
            <div className="p-2 kinetic-card rounded-lg">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <h1 className="text-xl font-bold tracking-tight">IDPS</h1>
          </div>
          
          <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
            <NavItem icon={<Activity />} label="Overview" path="/" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
            <NavItem icon={<AlertTriangle />} label="Alerts" path="/alerts" active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')} />
            <NavItem icon={<ShieldOff />} label="Blocked IPs" path="/blocked" active={activeTab === 'blocked'} onClick={() => setActiveTab('blocked')} />

            <NavItem icon={<Settings />} label="Settings" path="/settings" active={activeTab === 'settings'} onClick={() => setActiveTab('settings')} />
          </nav>
          
          <div className="p-4 border-t border-border text-xs text-muted-foreground flex justify-between items-center">
            <span>v1.0.0</span>
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${status === 'connected' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></span>
              {status === 'connected' ? 'System Active' : 'Disconnected'}
            </span>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto relative z-10">
          <div className="relative p-8 h-full">
            <Routes>
              <Route path="/" element={<Dashboard data={data} status={status} />} />
              <Route path="/alerts" element={<AlertsView data={data} />} />
              <Route path="/blocked" element={<BlockedIPsView data={data} />} />

              <Route path="/settings" element={<SettingsView />} />
            </Routes>
          </div>
        </main>
      </div>
    </Router>
  );
}

function AlertsView({ data }: { data: any }) {
  if (!data) return <div className="text-muted-foreground">Waiting for data...</div>;
  const { alerts, blocked } = data;
  const blockedIPs = blocked ? blocked.map((b: any) => typeof b === 'string' ? b : b.ip) : [];

  const handleBlock = async (ip: string) => {
    try {
      await fetch(`${API_BASE}/api/block/${ip}`, { 
        method: 'POST',
        headers: { 'X-API-Key': API_KEY }
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleDismiss = async (id: string) => {
    try {
      await fetch(`${API_BASE}/api/alerts/${id}`, { 
        method: 'DELETE',
        headers: { 'X-API-Key': API_KEY }
      });
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <h2 className="text-3xl font-bold">Active Alerts</h2>
      </div>
      <div className="kinetic-card rounded-2xl p-6">
        {alerts.filter((a: any) => !blockedIPs.includes(a.source_ip)).length === 0 ? (
          <div className="text-center text-muted-foreground py-12">No active alerts. The network is secure.</div>
        ) : (
          <div className="space-y-4">
            {alerts.filter((a: any) => !blockedIPs.includes(a.source_ip)).slice().reverse().map((alert: any) => (
              <div key={alert.id} className="p-4 rounded-xl kinetic-card flex gap-4">
                <div className="mt-1 text-amber-500">
                  <AlertOctagon className="w-5 h-5" />
                </div>
                <div className="flex-1">
                  <h4 className="font-semibold">{alert.type} - {alert.severity} Severity</h4>
                  <p className="text-sm text-muted-foreground mt-1">{alert.reason}</p>
                  <div className="text-xs font-mono mt-2 bg-background/50 inline-block p-1 rounded flex gap-2 items-center">
                    <span className="text-muted-foreground">SRC:</span> 
                    <span className={blockedIPs.includes(alert.source_ip) ? 'text-red-400 line-through' : ''}>{alert.source_ip}</span>
                    <span className="text-muted-foreground ml-2">DST:</span> {alert.dest_ip}
                  </div>
                  <div className="text-xs text-muted-foreground mt-2 flex justify-between items-center w-full">
                    <span>{format(new Date(alert.timestamp * 1000), 'MMM dd, yyyy HH:mm:ss')}</span>
                    <div className="flex gap-2">
                      <button 
                        onClick={() => handleDismiss(alert.id)}
                        className="kinetic-card hover:bg-white/5 text-muted-foreground px-3 py-1.5 rounded-lg text-xs transition-all font-medium"
                      >
                        Dismiss
                      </button>
                      <button 
                        onClick={() => handleBlock(alert.source_ip)}
                        disabled={blockedIPs.includes(alert.source_ip)}
                        className={`kinetic-card px-3 py-1.5 rounded-lg text-xs transition-all flex items-center gap-1 font-medium ${
                          blockedIPs.includes(alert.source_ip) 
                            ? 'opacity-50 cursor-not-allowed bg-red-500/5 text-red-500' 
                            : 'hover:bg-red-500/10 text-red-500'
                        }`}
                      >
                        <Ban className="w-3 h-3" />
                        Block {alert.source_ip}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function BlockedIPsView({ data }: { data: any }) {
  if (!data) return <div className="text-muted-foreground">Waiting for data...</div>;
  const { blocked } = data;

  const handleUnblock = async (ip: string) => {
    try {
      await fetch(`${API_BASE}/api/unblock/${ip}`, { 
        method: 'POST',
        headers: { 'X-API-Key': API_KEY }
      });
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <ShieldOff className="w-8 h-8 text-red-500" />
        <h2 className="text-3xl font-bold">Blocked IPs List</h2>
      </div>
      <div className="kinetic-card rounded-2xl p-6">
        {blocked.length === 0 ? (
          <div className="text-center text-muted-foreground py-12">No IPs are currently blocked.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {blocked.map((block: any) => {
              const ip = typeof block === 'string' ? block : block.ip;
              return (
              <div key={ip} className="p-4 rounded-xl kinetic-card flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Ban className="w-5 h-5 text-red-500" />
                  <span className="font-mono">{ip}</span>
                </div>
                <button 
                  onClick={() => handleUnblock(ip)}
                  className="kinetic-card hover:bg-green-500/10 text-green-500 px-3 py-1.5 rounded-lg text-xs transition-all font-medium"
                >
                  Unblock
                </button>
              </div>
            )})}
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
    INTERFACE: 'wlp1s0'
  });
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  // Fetch current settings on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/settings`, { headers: { 'X-API-Key': API_KEY } })
      .then(res => res.json())
      .then(data => {
        setSettings({
          IDPS_DEPLOYMENT_MODE: data.IDPS_DEPLOYMENT_MODE || 'HOST',
          IDPS_SECURITY_MODE: data.IDPS_SECURITY_MODE || 'IDS',
          WAN_INTERFACE: data.WAN_INTERFACE || 'enx2a7345453743',
          LAN_INTERFACE: data.LAN_INTERFACE || 'wlp1s0',
          INTERFACE: data.INTERFACE || 'wlp1s0'
        });
      })
      .catch(console.error);

    fetch(`${API_BASE}/api/interfaces`, { headers: { 'X-API-Key': API_KEY } })
      .then(res => res.json())
      .then(data => setInterfaces(data))
      .catch(console.error);
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setMessage('Applying changes to core system...');
    try {
      const res = await fetch(`${API_BASE}/api/settings`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY 
        },
        body: JSON.stringify(settings)
      });
      const data = await res.json();
      setMessage(data.message || 'Configuration applied successfully.');
      setTimeout(() => setMessage(''), 3000);
    } catch {
      setMessage('Failed to apply configuration. Check connection.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <Settings className="w-8 h-8 text-blue-500" />
        <h2 className="text-3xl font-bold">System Settings</h2>
      </div>
      <div className="kinetic-card rounded-2xl p-6 space-y-6">
        <div>
          <h3 className="text-xl font-bold mb-4 text-primary flex items-center gap-2">
            <Network className="w-5 h-5" /> 
            Deployment Configuration
          </h3>
          <p className="text-sm text-muted-foreground mb-6">
            Configure how the IDPS inspects traffic. In GATEWAY mode, it acts as an inline IPS to protect connected devices.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
             <div className="p-5 rounded-xl kinetic-card flex flex-col gap-2">
               <label className="text-sm text-muted-foreground font-medium">Deployment Mode</label>
               <select 
                 value={settings.IDPS_DEPLOYMENT_MODE} 
                 onChange={e => setSettings({...settings, IDPS_DEPLOYMENT_MODE: e.target.value})}
                 className="w-full bg-background border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors"
               >
                 <option value="HOST">HOST (Protect Local Machine)</option>
                 <option value="GATEWAY">GATEWAY (Inline Router / Hotspot)</option>
               </select>
               <p className="text-xs text-muted-foreground mt-1">Defines network positioning.</p>
             </div>
             
             <div className="p-5 rounded-xl kinetic-card flex flex-col gap-2">
               <label className="text-sm text-muted-foreground font-medium">Security Mode</label>
               <select 
                 value={settings.IDPS_SECURITY_MODE} 
                 onChange={e => setSettings({...settings, IDPS_SECURITY_MODE: e.target.value})}
                 className="w-full bg-background border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors"
               >
                 <option value="IDS">IDS (Monitor & Alert Only)</option>
                 <option value="IPS">IPS (Active Blocking / Prevention)</option>
               </select>
               <p className="text-xs text-muted-foreground mt-1">In IPS mode, attackers are automatically blocked.</p>
             </div>
             
             {settings.IDPS_DEPLOYMENT_MODE === 'HOST' && (
               <div className="p-5 rounded-xl kinetic-card flex flex-col gap-2 border-l-2 border-l-blue-500">
                 <label className="text-sm text-muted-foreground font-medium">Monitoring Interface</label>
                 <select 
                   value={settings.INTERFACE} 
                   onChange={e => setSettings({...settings, INTERFACE: e.target.value})}
                   className="w-full bg-background border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors"
                 >
                   {Array.from(new Set([...interfaces, settings.INTERFACE])).map(iface => (
                     <option key={iface} value={iface}>{iface}</option>
                   ))}
                 </select>
                 <p className="text-xs text-muted-foreground">The network interface the IDPS will monitor.</p>
               </div>
             )}
             
             {settings.IDPS_DEPLOYMENT_MODE === 'GATEWAY' && (
               <>
                 <div className="p-5 rounded-xl kinetic-card flex flex-col gap-2 border-l-2 border-l-amber-500">
                   <label className="text-sm text-muted-foreground font-medium">WAN Interface (Internet)</label>
                   <select 
                     value={settings.WAN_INTERFACE} 
                     onChange={e => setSettings({...settings, WAN_INTERFACE: e.target.value})}
                     className="w-full bg-background border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors"
                   >
                     {Array.from(new Set([...interfaces, settings.WAN_INTERFACE])).map(iface => (
                       <option key={iface} value={iface}>{iface}</option>
                     ))}
                   </select>
                   <p className="text-xs text-muted-foreground">The interface connected to the internet (e.g., USB Tethering).</p>
                 </div>
                 <div className="p-5 rounded-xl kinetic-card flex flex-col gap-2 border-l-2 border-l-green-500">
                   <label className="text-sm text-muted-foreground font-medium">LAN Interface (Internal)</label>
                   <select 
                     value={settings.LAN_INTERFACE} 
                     onChange={e => setSettings({...settings, LAN_INTERFACE: e.target.value})}
                     className="w-full bg-background border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors"
                   >
                     {Array.from(new Set([...interfaces, settings.LAN_INTERFACE])).map(iface => (
                       <option key={iface} value={iface}>{iface}</option>
                     ))}
                   </select>
                   <p className="text-xs text-muted-foreground">The interface broadcasting your hotspot to clients.</p>
                 </div>
               </>
             )}
          </div>
          
          <div className="mt-8 pt-6 border-t border-border/10 flex items-center justify-between">
            <div className="text-sm font-medium text-amber-500">
              {message}
            </div>
            <button 
              onClick={handleSave}
              disabled={saving}
              className="bg-primary/20 hover:bg-primary/30 text-primary border border-primary/50 px-6 py-2.5 rounded-xl font-medium transition-all shadow-[0_0_15px_rgba(var(--primary),0.3)] hover:shadow-[0_0_25px_rgba(var(--primary),0.5)] disabled:opacity-50"
            >
              {saving ? 'Applying...' : 'Apply Network Configuration'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function NavItem({ icon, label, path, active, onClick }: { icon: React.ReactNode, label: string, path: string, active: boolean, onClick: () => void }) {
  return (
    <Link 
      to={path} 
      onClick={onClick}
      className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
        active 
          ? 'kinetic-card border-primary/30 text-primary font-medium text-glow' 
          : 'hover:bg-white/5 text-muted-foreground hover:text-foreground'
      }`}
    >
      <div className={`${active ? 'text-primary' : 'text-muted-foreground'}`}>
        {icon}
      </div>
      {label}
    </Link>
  );
}

export default App;

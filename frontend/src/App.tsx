import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, ShieldOff, Settings, Network, AlertOctagon, Ban } from 'lucide-react';
import Dashboard from './components/Dashboard';
import ThreeDBackground from './components/ThreeDBackground';
import { useWebSocket } from './hooks/useWebSocket';
import { format } from 'date-fns';

function App() {
  const [activeTab, setActiveTab] = useState(window.location.pathname.replace('/', '') || 'overview');
  const { data, status } = useWebSocket('ws://localhost:8000/ws');

  return (
    <Router>
      <div className="flex h-screen bg-transparent overflow-hidden text-foreground selection:bg-primary selection:text-primary-foreground relative z-10">
        <ThreeDBackground />
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
  const { alerts } = data;

  const handleBlock = async (ip: string) => {
    try {
      await fetch(`http://localhost:8000/api/block/${ip}`, { method: 'POST' });
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
        {alerts.length === 0 ? (
          <div className="text-center text-muted-foreground py-12">No active alerts. The network is secure.</div>
        ) : (
          <div className="space-y-4">
            {alerts.slice().reverse().map((alert: any) => (
              <div key={alert.id} className="p-4 rounded-xl kinetic-card flex gap-4">
                <div className="mt-1 text-amber-500">
                  <AlertOctagon className="w-5 h-5" />
                </div>
                <div className="flex-1">
                  <h4 className="font-semibold">{alert.type} - {alert.severity} Severity</h4>
                  <p className="text-sm text-muted-foreground mt-1">{alert.reason}</p>
                  <div className="text-xs font-mono mt-2 bg-background/50 inline-block p-1 rounded">
                    {alert.source_ip} &rarr; {alert.dest_ip}
                  </div>
                  <div className="text-xs text-muted-foreground mt-2 flex justify-between items-center w-full">
                    <span>{format(new Date(alert.timestamp * 1000), 'MMM dd, yyyy HH:mm:ss')}</span>
                    <button 
                      onClick={() => handleBlock(alert.source_ip)}
                      className="kinetic-card hover:bg-red-500/10 text-red-500 px-3 py-1.5 rounded-lg text-xs transition-all flex items-center gap-1 font-medium"
                    >
                      <Ban className="w-3 h-3" />
                      Block {alert.source_ip}
                    </button>
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
      await fetch(`http://localhost:8000/api/unblock/${ip}`, { method: 'POST' });
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
            {blocked.map((ip: string) => (
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
            ))}
          </div>
        )}
      </div>
    </div>
  );
}



function SettingsView() {
  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <Settings className="w-8 h-8 text-blue-500" />
        <h2 className="text-3xl font-bold">System Settings</h2>
      </div>
      <div className="kinetic-card rounded-2xl p-6 space-y-6">
        <div>
          <h3 className="text-lg font-semibold mb-2">Detection Thresholds</h3>
          <p className="text-sm text-muted-foreground mb-4">Note: These settings are currently read-only in this demo. Update backend/app/config.py to apply permanently.</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
             <div className="p-5 rounded-xl kinetic-card">
               <label className="text-sm text-muted-foreground block mb-2 font-medium">SYN Flood Threshold (pkts/sec)</label>
               <input type="number" disabled value={100} className="w-full bg-transparent border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors" />
             </div>
             <div className="p-5 rounded-xl kinetic-card">
               <label className="text-sm text-muted-foreground block mb-2 font-medium">Port Scan Threshold (ports/sec)</label>
               <input type="number" disabled value={20} className="w-full bg-transparent border border-border/20 rounded-lg p-3 text-foreground font-mono outline-none focus:border-primary/50 transition-colors" />
             </div>
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

import { useState, useEffect } from 'react';
import { Network, Server, Router as RouterIcon, ShieldCheck, AlertCircle } from 'lucide-react';

export default function DiagnosticsView() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('http://localhost:8000/api/system/network-check')
      .then(res => res.json())
      .then(data => {
        setData(data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setError('Failed to load diagnostics.');
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="text-muted-foreground animate-pulse">Loading diagnostics...</div>;
  if (error) return <div className="text-red-500">{error}</div>;
  if (!data) return null;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <Network className="w-8 h-8 text-blue-500" />
        <h2 className="text-3xl font-bold">Network Diagnostics</h2>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="kinetic-card rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-6 h-6 text-primary" />
            <h3 className="text-xl font-semibold">Deployment Configuration</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">Deployment Mode</span>
              <span className="font-mono text-primary font-bold">{data.deployment_mode}</span>
            </div>
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">Security Mode</span>
              <span className="font-mono">{data.security_mode}</span>
            </div>
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">Firewall Mode</span>
              <span className="font-mono">{data.firewall_mode}</span>
            </div>
          </div>
        </div>

        <div className="kinetic-card rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <RouterIcon className="w-6 h-6 text-emerald-500" />
            <h3 className="text-xl font-semibold">Interfaces</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">WAN ({data.wan_interface})</span>
              <span className="font-mono">{data.wan_address || 'Disconnected'}</span>
            </div>
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">LAN ({data.lan_interface})</span>
              <span className="font-mono">{data.lan_address || 'Disconnected'}</span>
            </div>
            <div className="flex justify-between border-b border-border/20 pb-2">
              <span className="text-muted-foreground">IP Forwarding</span>
              <span className={`font-mono ${data.ip_forwarding_enabled ? 'text-emerald-500' : 'text-red-500'}`}>
                {data.ip_forwarding_enabled ? 'ENABLED' : 'DISABLED'}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className={`kinetic-card rounded-2xl p-6 ${data.gateway_ready ? 'border-l-4 border-emerald-500' : 'border-l-4 border-amber-500'}`}>
        <div className="flex items-center gap-2 mb-2">
          {data.gateway_ready ? <ShieldCheck className="w-6 h-6 text-emerald-500" /> : <AlertCircle className="w-6 h-6 text-amber-500" />}
          <h3 className="text-xl font-semibold">Gateway Readiness</h3>
        </div>
        <p className="text-muted-foreground">{data.gateway_reason}</p>
      </div>
    </div>
  );
}

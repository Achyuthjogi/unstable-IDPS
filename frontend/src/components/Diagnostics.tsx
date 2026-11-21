import { useState, useEffect } from 'react';
import { Server, Router as RouterIcon, ShieldCheck, AlertCircle } from 'lucide-react';

export default function DiagnosticsView() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const API_HOST = window.location.hostname;
    const API_BASE = `http://${API_HOST}:8000`;
    const API_KEY = import.meta.env.VITE_API_KEY || '';
    fetch(`${API_BASE}/api/system/network-check`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`Diagnostics request failed with status ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        setData(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError('Failed to load network diagnostics.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div className="text-xs text-muted-foreground">Running network diagnostics...</div>;
  }
  if (error) {
    return <div className="text-xs text-destructive">{error}</div>;
  }
  if (!data) return null;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Network Diagnostics</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Interface bindings, packet forwarding configuration, and gateway routing readiness.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Deployment Config */}
        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-border pb-2.5">
            <Server className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Deployment Status</h2>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Mode</span>
              <span className="font-mono font-medium text-foreground">{data.deployment_mode}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Security Mode</span>
              <span className="font-mono font-medium text-foreground">{data.security_mode}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Firewall Filter</span>
              <span className="font-mono font-medium text-foreground">{data.firewall_mode}</span>
            </div>
          </div>
        </div>

        {/* Interfaces */}
        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-border pb-2.5">
            <RouterIcon className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Interface State</h2>
          </div>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-muted-foreground font-sans">WAN ({data.wan_interface})</span>
              <span className="text-foreground">{data.wan_address || 'Disconnected'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground font-sans">LAN ({data.lan_interface})</span>
              <span className="text-foreground">{data.lan_address || 'Disconnected'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground font-sans">IP Forwarding</span>
              <span
                className={
                  data.ip_forwarding_enabled === null
                    ? 'text-muted-foreground'
                    : data.ip_forwarding_enabled
                    ? 'text-success font-semibold'
                    : 'text-destructive font-semibold'
                }
              >
                {data.ip_forwarding_enabled === null
                  ? 'UNAVAILABLE'
                  : data.ip_forwarding_enabled
                  ? 'ENABLED'
                  : 'DISABLED'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Gateway Status Banner */}
      <div
        className={`card p-4 flex items-start gap-3 border-l-4 ${
          data.gateway_ready ? 'border-l-success' : 'border-l-warning'
        }`}
      >
        {data.gateway_ready ? (
          <ShieldCheck className="w-5 h-5 text-success shrink-0 mt-0.5" />
        ) : (
          <AlertCircle className="w-5 h-5 text-warning shrink-0 mt-0.5" />
        )}
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-foreground">
            {data.gateway_ready ? 'Gateway Ready' : 'Gateway Notice'}
          </h3>
          <p className="text-xs text-muted-foreground leading-relaxed">{data.gateway_reason}</p>
        </div>
      </div>
    </div>
  );
}

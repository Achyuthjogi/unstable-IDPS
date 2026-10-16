import { Server, Shield, Cpu, HardDrive, Clock, CheckCircle2, AlertTriangle, Network, Laptop, RefreshCw } from 'lucide-react';

interface HostInventoryProps {
  data: any;
}

export default function HostInventory({ data }: HostInventoryProps) {
  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
        <div className="w-10 h-10 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
        <p className="text-sm">Loading host sensor telemetry...</p>
      </div>
    );
  }

  const platform = data.platform || {
    os: 'linux',
    arch: 'amd64',
    hostname: 'unknown',
    is_elevated: false,
    capture_driver: 'AF_PACKET',
    firewall_backend: 'iptables',
    has_inline_engine: true,
    capabilities: ['af_packet', 'iptables_block', 'conntrack'],
  };

  const telemetry = data.telemetry || {
    cpu_percent: data.system?.cpu || 0,
    memory_percent: data.system?.memory || 0,
    memory_used_bytes: 0,
    memory_total_bytes: 0,
    uptime_seconds: 0,
    goroutine_count: 0,
  };

  const devices = data.devices || [];

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    return `${(mb / 1024).toFixed(2)} GB`;
  };

  const formatUptime = (seconds: number) => {
    if (!seconds || seconds === 0) return 'Just started';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  };

  const isWindows = platform.os.toLowerCase() === 'windows';

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <Server className="w-8 h-8 text-primary" />
          <div>
            <h2 className="text-3xl font-bold tracking-tight">Host & Sensor Inventory</h2>
            <p className="text-sm text-muted-foreground">Cross-platform sensor capabilities, system health, and monitored network inventory</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold kinetic-card border-primary/30 text-primary">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            Sensor Telemetry Live
          </span>
        </div>
      </div>

      {/* Sensor Host Identity Card */}
      <div className="kinetic-card rounded-2xl p-6 border border-border/40">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-border/20">
          <div className="flex items-start gap-4">
            <div className={`p-4 rounded-2xl kinetic-card text-2xl ${isWindows ? 'text-sky-400' : 'text-amber-400'}`}>
              {isWindows ? '🪟' : '🐧'}
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h3 className="text-xl font-bold font-mono">{platform.hostname || 'Security-Sensor'}</h3>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                  isWindows 
                    ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' 
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                }`}>
                  {platform.os} / {platform.arch}
                </span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1 ${
                  platform.is_elevated 
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' 
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                }`}>
                  <Shield className="w-3 h-3" />
                  {platform.is_elevated ? (isWindows ? 'Admin Privileged' : 'Root Privileged') : 'Unprivileged'}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Active sensor operating in {data.system?.gateway_ip ? 'GATEWAY (Inline IPS)' : 'HOST (Local Security)'} mode.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="px-3.5 py-2 rounded-xl kinetic-card text-left">
              <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Capture Driver</span>
              <span className="font-mono text-xs font-bold text-primary">{platform.capture_driver || 'AF_PACKET'}</span>
            </div>
            <div className="px-3.5 py-2 rounded-xl kinetic-card text-left">
              <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Firewall Enforcement</span>
              <span className="font-mono text-xs font-bold text-primary">{platform.firewall_backend || 'iptables'}</span>
            </div>
            <div className="px-3.5 py-2 rounded-xl kinetic-card text-left">
              <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Inline IPS Engine</span>
              <span className={`font-mono text-xs font-bold ${platform.has_inline_engine ? 'text-emerald-400' : 'text-amber-400'}`}>
                {platform.has_inline_engine ? 'Supported' : 'Passive Only'}
              </span>
            </div>
          </div>
        </div>

        {/* Sensor Capabilities */}
        <div className="pt-4">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block mb-2">
            Active Platform Capabilities
          </span>
          <div className="flex flex-wrap gap-2">
            {platform.capabilities && platform.capabilities.length > 0 ? (
              platform.capabilities.map((cap: string) => (
                <span
                  key={cap}
                  className="px-2.5 py-1 rounded-lg text-xs font-mono font-medium kinetic-card text-foreground/80 border border-border/30 flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  {cap}
                </span>
              ))
            ) : (
              <span className="text-xs text-muted-foreground italic">Standard capture capabilities active</span>
            )}
          </div>
        </div>
      </div>

      {/* Live Hardware Telemetry Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* CPU */}
        <div className="kinetic-card rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-primary" /> CPU Utilization
            </span>
            <span className="font-mono text-xs font-bold text-primary">
              {(telemetry.cpu_percent || 0).toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-border/30 rounded-full h-2 overflow-hidden mb-2">
            <div
              className="bg-primary h-2 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, Math.max(0, telemetry.cpu_percent || 0))}%` }}
            />
          </div>
          <span className="text-[11px] text-muted-foreground">Dynamic load across engine workers</span>
        </div>

        {/* Memory */}
        <div className="kinetic-card rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
              <HardDrive className="w-4 h-4 text-emerald-400" /> Sensor Memory
            </span>
            <span className="font-mono text-xs font-bold text-emerald-400">
              {(telemetry.memory_percent || 0).toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-border/30 rounded-full h-2 overflow-hidden mb-2">
            <div
              className="bg-emerald-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, Math.max(0, telemetry.memory_percent || 0))}%` }}
            />
          </div>
          <span className="text-[11px] text-muted-foreground font-mono">
            {formatBytes(telemetry.memory_used_bytes)} / {formatBytes(telemetry.memory_total_bytes)}
          </span>
        </div>

        {/* Sensor Uptime */}
        <div className="kinetic-card rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-amber-400" /> Sensor Uptime
            </span>
            <span className="font-mono text-xs font-bold text-amber-400">
              Active
            </span>
          </div>
          <div className="text-2xl font-bold tracking-tight text-foreground font-mono mb-1">
            {formatUptime(telemetry.uptime_seconds)}
          </div>
          <span className="text-[11px] text-muted-foreground">Continuous zero-loss monitoring</span>
        </div>

        {/* Concurrency / Goroutines */}
        <div className="kinetic-card rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
              <RefreshCw className="w-4 h-4 text-purple-400" /> Engine Concurrency
            </span>
            <span className="font-mono text-xs font-bold text-purple-400">
              Go Runtime
            </span>
          </div>
          <div className="text-2xl font-bold tracking-tight text-foreground font-mono mb-1">
            {telemetry.goroutine_count || 12} <span className="text-xs font-normal text-muted-foreground">threads</span>
          </div>
          <span className="text-[11px] text-muted-foreground">Worker pool & packet dispatchers</span>
        </div>
      </div>

      {/* Monitored Host & Network Device Inventory */}
      <div className="kinetic-card rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Laptop className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold">Monitored Network Endpoints</h3>
          </div>
          <span className="text-xs font-mono text-muted-foreground">
            {devices.length} endpoints discovered
          </span>
        </div>

        {devices.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground text-sm">
            No connected network devices recorded yet. Packets traversing monitored interfaces will be automatically cataloged.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border/30 text-muted-foreground uppercase tracking-wider">
                  <th className="py-3 px-4 font-semibold">IP Address</th>
                  <th className="py-3 px-4 font-semibold">MAC Address</th>
                  <th className="py-3 px-4 font-semibold">Identified Vendor / Name</th>
                  <th className="py-3 px-4 font-semibold">First Seen</th>
                  <th className="py-3 px-4 font-semibold">Last Activity</th>
                  <th className="py-3 px-4 font-semibold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20 font-mono">
                {devices.map((device: any, idx: number) => (
                  <tr key={device.ip || idx} className="hover:bg-white/5 transition-colors">
                    <td className="py-3 px-4 font-bold text-primary">{device.ip}</td>
                    <td className="py-3 px-4 text-muted-foreground">{device.mac || 'N/A'}</td>
                    <td className="py-3 px-4 text-foreground">{device.vendor || device.name || 'Network Host'}</td>
                    <td className="py-3 px-4 text-muted-foreground">{device.first_seen || 'N/A'}</td>
                    <td className="py-3 px-4 text-muted-foreground">{device.last_seen || 'Active'}</td>
                    <td className="py-3 px-4 text-right">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        Monitored
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}


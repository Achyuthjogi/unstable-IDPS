import { Server, Shield, Cpu, HardDrive, Clock, CheckCircle2, Laptop } from 'lucide-react';
import { safeFormatDateTime, safeToFixed, safeLocaleString } from '../utils/format';

interface HostInventoryProps {
  data: any;
}

export default function HostInventory({ data }: HostInventoryProps) {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
        Loading host telemetry...
      </div>
    );
  }

  const platform = data.platform || {
    os: 'linux',
    arch: 'amd64',
    hostname: 'Security-Sensor',
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

  const devices = Array.isArray(data.devices) ? data.devices : [];

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes <= 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    return `${(mb / 1024).toFixed(2)} GB`;
  };

  const formatUptime = (seconds: number) => {
    if (!seconds || seconds <= 0) return 'Just started';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Host & Sensor Inventory</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Host environment details, capture drivers, and cataloged network endpoints.
        </p>
      </div>

      {/* Host Summary Card */}
      <div className="card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-md bg-secondary text-foreground flex items-center justify-center font-bold text-sm">
              <Server className="w-5 h-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm">{platform.hostname || 'Security-Sensor'}</span>
                <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-secondary text-muted-foreground uppercase">
                  {platform.os} / {platform.arch}
                </span>
                <span className="text-[11px] px-1.5 py-0.5 rounded bg-secondary text-muted-foreground flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  {platform.is_elevated ? 'Privileged' : 'Standard'}
                </span>
              </div>
              <span className="text-xs text-muted-foreground mt-0.5 block">
                Operating in {data.system?.gateway_ip ? 'Gateway Mode' : 'Host Mode'}.
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <div className="px-3 py-1 rounded bg-secondary/50 border border-border/50">
              <span className="text-muted-foreground block text-[10px]">Driver</span>
              <span className="text-foreground font-semibold">{platform.capture_driver || 'AF_PACKET'}</span>
            </div>
            <div className="px-3 py-1 rounded bg-secondary/50 border border-border/50">
              <span className="text-muted-foreground block text-[10px]">Firewall</span>
              <span className="text-foreground font-semibold">{platform.firewall_backend || 'iptables'}</span>
            </div>
            <div className="px-3 py-1 rounded bg-secondary/50 border border-border/50">
              <span className="text-muted-foreground block text-[10px]">Inline Engine</span>
              <span className={platform.has_inline_engine ? 'text-success font-semibold' : 'text-muted-foreground'}>
                {platform.has_inline_engine ? 'Active' : 'Passive'}
              </span>
            </div>
          </div>
        </div>

        {/* Platform Capabilities */}
        <div>
          <span className="text-xs font-medium text-muted-foreground block mb-2">Driver Capabilities</span>
          <div className="flex flex-wrap gap-1.5">
            {platform.capabilities && platform.capabilities.length > 0 ? (
              platform.capabilities.map((cap: string) => (
                <span
                  key={cap}
                  className="px-2 py-0.5 rounded bg-secondary text-foreground text-xs font-mono flex items-center gap-1 border border-border/50"
                >
                  <CheckCircle2 className="w-3 h-3 text-success" />
                  {cap}
                </span>
              ))
            ) : (
              <span className="text-xs text-muted-foreground">Standard packet capture enabled.</span>
            )}
          </div>
        </div>
      </div>

      {/* Hardware Telemetry Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* CPU */}
        <div className="card p-4 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground flex items-center gap-1.5 font-medium">
              <Cpu className="w-3.5 h-3.5 text-primary" /> CPU Usage
            </span>
            <span className="font-mono font-semibold text-foreground">
              {safeToFixed(telemetry.cpu_percent || data.system?.cpu, 1)}%
            </span>
          </div>
          <div className="w-full bg-secondary rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-primary h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(0, Number(telemetry.cpu_percent) || 0))}%` }}
            />
          </div>
          <span className="text-[11px] text-muted-foreground block">Daemon processing load</span>
        </div>

        {/* Memory */}
        <div className="card p-4 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground flex items-center gap-1.5 font-medium">
              <HardDrive className="w-3.5 h-3.5 text-success" /> Memory
            </span>
            <span className="font-mono font-semibold text-foreground">
              {safeToFixed(telemetry.memory_percent || data.system?.memory, 1)}%
            </span>
          </div>
          <div className="w-full bg-secondary rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-success h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(0, Number(telemetry.memory_percent) || 0))}%` }}
            />
          </div>
          <span className="text-[11px] text-muted-foreground font-mono block">
            {formatBytes(telemetry.memory_used_bytes)} / {formatBytes(telemetry.memory_total_bytes)}
          </span>
        </div>

        {/* Uptime */}
        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground flex items-center gap-1.5 font-medium">
            <Clock className="w-3.5 h-3.5 text-warning" /> Sensor Uptime
          </span>
          <div className="text-lg font-bold font-mono tracking-tight text-foreground pt-1">
            {formatUptime(telemetry.uptime_seconds)}
          </div>
          <span className="text-[11px] text-muted-foreground block">Continuous packet tracking</span>
        </div>

        {/* Goroutines */}
        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground flex items-center gap-1.5 font-medium">
            <Server className="w-3.5 h-3.5 text-primary" /> Active Goroutines
          </span>
          <div className="text-lg font-bold font-mono tracking-tight text-foreground pt-1">
            {safeLocaleString(telemetry.goroutine_count || 12)}
          </div>
          <span className="text-[11px] text-muted-foreground block">Worker pool threads</span>
        </div>
      </div>

      {/* Discovered Hosts Table */}
      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-muted/30 flex items-center justify-between text-xs font-medium">
          <div className="flex items-center gap-2">
            <Laptop className="w-4 h-4 text-primary" />
            <span className="text-foreground">Network Endpoints ({devices.length})</span>
          </div>
          <span className="text-muted-foreground">Automatic ARP & Flow discovery</span>
        </div>

        {devices.length === 0 ? (
          <div className="py-16 text-center text-xs text-muted-foreground">
            No connected network devices cataloged yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border text-muted-foreground bg-muted/15 font-medium">
                  <th className="py-2.5 px-4">IP Address</th>
                  <th className="py-2.5 px-4">MAC Address</th>
                  <th className="py-2.5 px-4">Vendor / Name</th>
                  <th className="py-2.5 px-4">First Seen</th>
                  <th className="py-2.5 px-4">Last Activity</th>
                  <th className="py-2.5 px-4 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 font-mono">
                {devices.map((device: any, idx: number) => (
                  <tr key={device.ip || idx} className="hover:bg-muted/15 transition-colors">
                    <td className="py-2.5 px-4 font-semibold text-foreground">{device.ip}</td>
                    <td className="py-2.5 px-4 text-muted-foreground">{device.mac || 'N/A'}</td>
                    <td className="py-2.5 px-4 font-sans text-foreground">
                      {device.vendor || device.name || 'Network Host'}
                    </td>
                    <td className="py-2.5 px-4 text-muted-foreground">
                      {safeFormatDateTime(device.first_seen, 'Initial')}
                    </td>
                    <td className="py-2.5 px-4 text-muted-foreground">
                      {safeFormatDateTime(device.last_seen, 'Now')}
                    </td>
                    <td className="py-2.5 px-4 text-right font-sans">
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[10px] font-medium bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                        Active
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

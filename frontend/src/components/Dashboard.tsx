import { useState, useMemo, useCallback, memo, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { 
  Activity, 
  X, 
  Monitor, 
  Cpu, 
  CheckCircle2, 
  ExternalLink 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { safeFormatTime, safeToFixed, safeLocaleString } from '../utils/format';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

const KpiCard = memo(function KpiCard({
  title,
  value,
  subtitle,
  onClick,
}: {
  title: string;
  value: string;
  subtitle: string;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={`card p-4 flex flex-col justify-between ${
        onClick ? 'cursor-pointer hover:border-primary/50' : ''
      }`}
    >
      <span className="text-xs text-muted-foreground font-medium">{title}</span>
      <div className="my-2">
        <span className="text-2xl font-bold tracking-tight text-foreground">{value}</span>
      </div>
      <span className="text-[11px] text-muted-foreground">{subtitle}</span>
    </div>
  );
});

const TrafficChart = memo(function TrafficChart({
  data,
}: {
  data: { time: string; packets: number; cumulative?: number }[];
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="packetsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--color-primary)" stopOpacity={0.2} />
            <stop offset="95%" stopColor="var(--color-primary)" stopOpacity={0.0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
        <XAxis
          dataKey="time"
          stroke="var(--color-muted-foreground)"
          fontSize={10}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          stroke="var(--color-muted-foreground)"
          fontSize={10}
          tickLine={false}
          axisLine={false}
          tickFormatter={(val) => (val >= 1000 ? `${(val / 1000).toFixed(1)}k` : val)}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'var(--color-card)',
            borderColor: 'var(--color-border)',
            borderRadius: '6px',
            fontSize: '11px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
          }}
          itemStyle={{ color: 'var(--color-foreground)' }}
          formatter={(val: any) => [`${safeLocaleString(val)} pkts/s`, 'Rate']}
        />
        <Area
          type="monotone"
          dataKey="packets"
          stroke="var(--color-primary)"
          strokeWidth={1.5}
          fill="url(#packetsGradient)"
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
});

const ProtocolChart = memo(function ProtocolChart({
  protocolCounts,
}: {
  protocolCounts: Record<string, number>;
}) {
  const chartData = useMemo(() => {
    if (!protocolCounts || typeof protocolCounts !== 'object') return [];
    return Object.entries(protocolCounts).map(([name, value]) => ({
      name,
      value: Number(value) || 0,
    }));
  }, [protocolCounts]);

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
        <XAxis
          dataKey="name"
          stroke="var(--color-muted-foreground)"
          fontSize={10}
          tickLine={false}
          axisLine={false}
        />
        <YAxis stroke="var(--color-muted-foreground)" fontSize={10} tickLine={false} axisLine={false} />
        <Tooltip
          cursor={{ fill: 'var(--color-secondary)' }}
          contentStyle={{
            backgroundColor: 'var(--color-card)',
            borderColor: 'var(--color-border)',
            borderRadius: '6px',
            fontSize: '11px',
          }}
          formatter={(val: any) => [safeLocaleString(val), 'Packets']}
        />
        <Bar dataKey="value" fill="var(--color-primary)" radius={[3, 3, 0, 0]}>
          {chartData.map((_, index) => (
            <Cell key={`cell-${index}`} fill="var(--color-primary)" opacity={0.8 + (index % 3) * 0.1} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
});

export default function Dashboard({ data, status }: { data: any; status: string }) {
  const [packetHistory, setPacketHistory] = useState<{ time: string; packets: number; cumulative?: number }[]>(() => {
    const now = Date.now();
    return Array.from({ length: 14 }, (_, i) => ({
      time: safeFormatTime(new Date(now - (13 - i) * 2000)),
      packets: 0,
    }));
  });
  const [showDevicesModal, setShowDevicesModal] = useState(false);

  const mergedIPs = useMemo(() => {
    if (!data) return [];
    const ipMap = new Map<string, { ip: string; count: number; mac: string; status: string }>();

    if (data.network?.top_src_ips && Array.isArray(data.network.top_src_ips)) {
      data.network.top_src_ips.forEach((item: any) => {
        if (!item?.ip) return;
        ipMap.set(item.ip, {
          ip: item.ip,
          count: Number(item.count) || 0,
          mac: 'Unknown',
          status: 'Active',
        });
      });
    }

    if (data.devices && Array.isArray(data.devices)) {
      data.devices.forEach((device: any) => {
        if (!device?.ip) return;
        if (ipMap.has(device.ip)) {
          ipMap.set(device.ip, { ...ipMap.get(device.ip)!, mac: device.mac || 'Unknown' });
        } else {
          ipMap.set(device.ip, {
            ip: device.ip,
            count: 0,
            mac: device.mac || 'Unknown',
            status: 'Idle',
          });
        }
      });
    }

    return Array.from(ipMap.values()).sort((a, b) => b.count - a.count);
  }, [data?.network?.top_src_ips, data?.devices]);

  const blockedIPs = useMemo(() => {
    if (!data?.blocked || !Array.isArray(data.blocked)) return [];
    return data.blocked.map((b: any) => (typeof b === 'string' ? b : b?.ip || '')).filter(Boolean);
  }, [data?.blocked]);

  const activeAlerts = useMemo(() => {
    if (!data?.alerts || !Array.isArray(data.alerts)) return [];
    return data.alerts.filter((a: any) => a && !blockedIPs.includes(a.source_ip));
  }, [data?.alerts, blockedIPs]);

  const reversedAlerts = useMemo(() => [...activeAlerts].reverse(), [activeAlerts]);

  const livePacketRate = packetHistory[packetHistory.length - 1]?.packets ?? 0;

  const openDevices = useCallback(() => setShowDevicesModal(true), []);
  const closeDevices = useCallback(() => setShowDevicesModal(false), []);

  const lastPacketCountRef = useRef<number | null>(null);
  const lastTimeRef = useRef<number>(Date.now());

  useEffect(() => {
    if (!data) return;

    const currentTotal = Number(data.metrics?.packets_captured ?? data.network?.packet_count ?? 0);
    const now = Date.now();

    if (lastPacketCountRef.current === null) {
      lastPacketCountRef.current = currentTotal;
      lastTimeRef.current = now;
      return;
    }

    const elapsedSeconds = Math.max(0.5, (now - lastTimeRef.current) / 1000);
    const deltaPackets = Math.max(0, currentTotal - lastPacketCountRef.current);
    const packetRate = Math.round(deltaPackets / elapsedSeconds);

    lastPacketCountRef.current = currentTotal;
    lastTimeRef.current = now;

    setPacketHistory((prev) => {
      const nextPoint = { time: safeFormatTime(new Date(now)), packets: packetRate, cumulative: currentTotal };
      const updated = [...prev, nextPoint];
      return updated.length > 20 ? updated.slice(updated.length - 20) : updated;
    });
  }, [data?.network?.packet_count, data?.metrics?.packets_captured, data]);

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-72 text-muted-foreground text-xs">
        <Activity className="w-5 h-5 animate-spin mb-2 text-primary" />
        <span>Initializing telemetry connection...</span>
      </div>
    );
  }

  const system = data.system || {};
  const network = data.network || {};
  const alerts = Array.isArray(data.alerts) ? data.alerts : [];
  const devices = Array.isArray(data.devices) ? data.devices : [];
  const blocked = Array.isArray(data.blocked) ? data.blocked : [];
  const metrics = data.metrics || {};
  const telemetry = data.telemetry || {
    cpu_percent: system.cpu || 0,
    uptime_seconds: 0,
  };

  const formatUptime = (seconds: number) => {
    if (!seconds || seconds <= 0) return 'Just started';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Top Header & Telemetry Status Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">System Overview</h1>
          <p className="text-xs text-muted-foreground mt-0.5">Live sensor metrics and intrusion inspection statistics.</p>
        </div>

        {/* Minimalist System Status Pill */}
        <div className="flex items-center gap-3 text-xs text-muted-foreground bg-card border border-border px-3 py-1.5 rounded-md self-start sm:self-auto font-mono">
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${status === 'connected' ? 'bg-success' : 'bg-destructive'}`} />
            <span className="text-foreground font-sans text-xs">{status === 'connected' ? 'Online' : 'Offline'}</span>
          </div>
          <span className="text-border">|</span>
          <div className="flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-muted-foreground" />
            <span>{safeToFixed(telemetry.cpu_percent || system.cpu, 1)}%</span>
          </div>
          <span className="text-border">|</span>
          <span>{system.gateway_ip || 'Local Host'}</span>
          <span className="text-border">|</span>
          <span>Up {formatUptime(telemetry.uptime_seconds)}</span>
          <span className="text-border">|</span>
          <span className={`text-[10px] px-1.5 py-0.2 rounded font-sans font-medium ${system.ml_enabled !== false ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}>
            ML: {system.ml_enabled !== false ? 'Active' : 'Off'}
          </span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard
          title="Monitored Hosts"
          value={safeLocaleString(devices.length)}
          subtitle="Click to view discovered devices"
          onClick={openDevices}
        />
        <KpiCard
          title="Active Alerts"
          value={safeLocaleString(network.alerts_count ?? alerts.length)}
          subtitle={alerts.length > 0 ? 'Threat detections' : 'No threats detected'}
        />
        <KpiCard
          title="Enforced Blocks"
          value={safeLocaleString(network.blocked_ips_count ?? blocked.length)}
          subtitle="Active kernel firewall rules"
        />
        <KpiCard
          title="Current Throughput"
          value={`${safeLocaleString(livePacketRate)}/s`}
          subtitle="Inspected packets per second"
        />
      </div>

      {/* Metric Counters Strip */}
      <div className="card p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs">
        <div>
          <span className="text-muted-foreground block text-[11px]">Total Packets</span>
          <span className="text-base font-semibold font-mono text-foreground">
            {safeLocaleString(metrics.packets_captured ?? network.packet_count ?? 0)}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Deep Inspected</span>
          <span className="text-base font-semibold font-mono text-foreground">
            {safeLocaleString(metrics.packets_inspected ?? network.packet_count ?? 0)}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Active Flows</span>
          <span className="text-base font-semibold font-mono text-foreground">
            {safeLocaleString(metrics.active_flows ?? system.active_connections ?? 0)}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Confirmed Blocks</span>
          <span className="text-base font-semibold font-mono text-success">
            {safeLocaleString(metrics.blocks_confirmed ?? network.blocked_ips_count ?? 0)}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Requested Blocks</span>
          <span className="text-base font-semibold font-mono text-warning">
            {safeLocaleString(metrics.blocks_requested ?? 0)}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground block text-[11px]">Packets Dropped</span>
          <span className="text-base font-semibold font-mono text-muted-foreground">
            {safeLocaleString(metrics.packets_dropped ?? 0)}
          </span>
        </div>
      </div>

      {/* Traffic Rate Chart */}
      <div className="card p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold">Inspection Throughput</h2>
            <p className="text-xs text-muted-foreground">Rolling packet ingestion rate over time.</p>
          </div>
          <Link
            to="/live-traffic"
            className="text-xs text-primary hover:underline inline-flex items-center gap-1 font-medium"
          >
            Live monitor <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
        <div className="h-44 w-full pt-2">
          <TrafficChart data={packetHistory} />
        </div>
      </div>

      {/* Middle Grid: Top Sources & Protocol Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Active Source IPs */}
        <div className="card p-4 flex flex-col lg:col-span-2">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <h2 className="text-sm font-semibold">Active Endpoints ({mergedIPs.length})</h2>
            <span className="text-xs text-muted-foreground">Sorted by packet volume</span>
          </div>
          <div className="divide-y divide-border/60 max-h-64 overflow-y-auto mt-2">
            {mergedIPs.slice(0, 15).map((ip: any) => (
              <div key={ip.ip} className="py-2 flex items-center justify-between text-xs">
                <div className="space-y-0.5">
                  <span className="font-mono font-medium text-foreground">{ip.ip}</span>
                  <div className="text-[11px] text-muted-foreground font-mono">
                    {ip.mac !== 'Unknown' ? `MAC: ${ip.mac}` : ip.status}
                  </div>
                </div>
                <span className="font-mono text-xs text-muted-foreground">
                  {safeLocaleString(ip.count)} pkts
                </span>
              </div>
            ))}
            {mergedIPs.length === 0 && (
              <div className="py-8 text-center text-xs text-muted-foreground">
                No active traffic detected yet.
              </div>
            )}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="card p-4 flex flex-col">
          <div className="pb-3 border-b border-border">
            <h2 className="text-sm font-semibold">Protocols</h2>
          </div>
          <div className="h-64 w-full pt-2">
            <ProtocolChart protocolCounts={network.protocol_counts || {}} />
          </div>
        </div>
      </div>

      {/* Bottom Grid: Recent Detections & Blocked IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Detections */}
        <div className="card p-4 lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <h2 className="text-sm font-semibold">Recent Alerts ({reversedAlerts.length})</h2>
            <Link to="/alerts" className="text-xs text-primary hover:underline">
              View all
            </Link>
          </div>
          <div className="divide-y divide-border/60 max-h-72 overflow-y-auto mt-1">
            {reversedAlerts.slice(0, 8).map((alert: any) => {
              const sev = (alert.severity || 'Medium').toUpperCase();
              let dotColor = 'bg-blue-500';
              if (sev === 'CRITICAL') dotColor = 'bg-destructive';
              if (sev === 'HIGH') dotColor = 'bg-warning';

              return (
                <div key={alert.id || `${alert.source_ip}-${alert.timestamp}`} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span className={`w-2 h-2 rounded-full mt-1 shrink-0 ${dotColor}`} />
                    <div className="space-y-0.5 truncate">
                      <div className="font-medium text-foreground truncate">{alert.type || 'Alert'}</div>
                      <div className="font-mono text-[11px] text-muted-foreground truncate">
                        {alert.source_ip || '0.0.0.0'} → {alert.dest_ip || 'Local'}
                      </div>
                    </div>
                  </div>
                  <span className="font-mono text-[11px] text-muted-foreground shrink-0">
                    {safeFormatTime(alert.timestamp)}
                  </span>
                </div>
              );
            })}
            {reversedAlerts.length === 0 && (
              <div className="py-12 text-center text-xs text-muted-foreground flex flex-col items-center gap-1">
                <CheckCircle2 className="w-5 h-5 text-success mb-1" />
                <span>No active threats detected.</span>
              </div>
            )}
          </div>
        </div>

        {/* Blocked IP Quick List */}
        <div className="card p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <h2 className="text-sm font-semibold">Firewall Blocks ({blockedIPs.length})</h2>
            <Link to="/blocked" className="text-xs text-primary hover:underline">
              Manage
            </Link>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5 overflow-y-auto max-h-64">
            {blockedIPs.map((ip: string) => (
              <span
                key={ip}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-secondary text-foreground font-mono text-xs border border-border"
              >
                {ip}
                <button
                  onClick={() =>
                    fetch(`${API_BASE}/api/unblock/${ip}`, {
                      method: 'POST',
                      headers: { 'X-API-Key': API_KEY },
                    })
                  }
                  className="text-muted-foreground hover:text-foreground ml-0.5"
                  title="Unblock"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            {blockedIPs.length === 0 && (
              <div className="py-8 text-center text-xs text-muted-foreground w-full">
                No addresses currently blocked.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Discovered Devices Modal */}
      {showDevicesModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-xs"
          onClick={closeDevices}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="card w-full max-w-xl p-5 shadow-lg border border-border space-y-4"
          >
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Monitor className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-semibold">Discovered Devices ({devices.length})</h3>
              </div>
              <button
                onClick={closeDevices}
                className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-muted"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="max-h-80 overflow-y-auto divide-y divide-border/60">
              {devices.map((device: any, i: number) => (
                <div key={i} className="py-2.5 flex items-center justify-between text-xs">
                  <div className="space-y-0.5">
                    <span className="font-semibold text-foreground">{device.name || 'Unknown Host'}</span>
                    <div className="font-mono text-muted-foreground text-[11px]">
                      {device.ip} • MAC: {device.mac || 'N/A'}
                    </div>
                  </div>
                  <span className="text-[11px] text-muted-foreground font-mono">
                    {safeFormatTime(device.last_seen)}
                  </span>
                </div>
              ))}
              {devices.length === 0 && (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  No active devices recorded on network.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

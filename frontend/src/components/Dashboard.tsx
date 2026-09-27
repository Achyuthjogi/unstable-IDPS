import { useState, useMemo, useEffect, useCallback, memo, useRef } from 'react';
import { Activity, AlertOctagon, ShieldAlert, Cpu, Network, ArrowUpRight, Ban, X, Monitor, Maximize, Search, Filter, BrainCircuit } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { format } from 'date-fns';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

/**
 * Memoized KPI card — only re-renders when its specific props change,
 * not when the parent Dashboard re-renders from a WS tick.
 */
const KpiCard = memo(function KpiCard({ title, value, icon, trend, alert = false, onClick }: {
  title: string; value: string; icon: React.ReactNode; trend: string; alert?: boolean; onClick?: () => void;
}) {
  return (
    <div
      className={`kinetic-card rounded-2xl p-6 transition-colors duration-300 ${alert ? 'border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.2)]' : ''} ${onClick ? 'cursor-pointer hover:border-primary/50' : ''}`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-4 w-full">
        <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
        <div className="p-2 kinetic-card rounded-xl">{icon}</div>
      </div>
      <div className="flex items-baseline gap-2">
        <h2 className="text-3xl font-bold tracking-tight text-primary text-glow">{value}</h2>
      </div>
      <p className="text-xs text-muted-foreground mt-2">{trend}</p>
    </div>
  );
});

/**
 * Memoized chart wrapper — Recharts is expensive to re-render.
 * Only re-renders when packetHistory length changes (new data point added).
 */
const TrafficChart = memo(function TrafficChart({ data, gradientId = "colorPackets", strokeWidth = 3 }: {
  data: { time: string; packets: number }[];
  gradientId?: string;
  strokeWidth?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.8} />
            <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.2} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
        <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(val) => `${val >= 1000 ? (val / 1000).toFixed(1) + 'k' : val}`} />
        <Tooltip
          contentStyle={{ backgroundColor: 'var(--color-background)', borderColor: 'transparent', borderRadius: '1rem', boxShadow: '8px 8px 16px #1c1f22, -8px -8px 16px #363b42' }}
          itemStyle={{ color: 'var(--color-foreground)' }}
        />
        <Area type="monotone" dataKey="packets" stroke="hsl(var(--primary))" strokeWidth={strokeWidth} fillOpacity={1} fill={`url(#${gradientId})`} />
      </AreaChart>
    </ResponsiveContainer>
  );
}, (prev, next) => prev.data.length === next.data.length && prev.data[prev.data.length - 1]?.packets === next.data[next.data.length - 1]?.packets);

/**
 * Memoized protocol bar chart
 */
const ProtocolChart = memo(function ProtocolChart({ protocolCounts }: { protocolCounts: Record<string, number> }) {
  const chartData = useMemo(
    () => Object.entries(protocolCounts).map(([name, value]) => ({ name, value })),
    [protocolCounts]
  );

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
        <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
        <Tooltip
          cursor={{ fill: 'rgba(0,0,0,0.1)' }}
          contentStyle={{ backgroundColor: 'var(--color-background)', borderColor: 'transparent', borderRadius: '1rem', boxShadow: '8px 8px 16px #1c1f22, -8px -8px 16px #363b42' }}
        />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {chartData.map((_, index) => (
            <Cell key={`cell-${index}`} fill={`hsl(var(--primary))`} opacity={0.8 + (index % 3) * 0.1} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
});

export default function Dashboard({ data, status }: { data: any; status: string }) {
  // Keep local history of packet rates for the chart
  const [packetHistory, setPacketHistory] = useState<{ time: string; packets: number }[]>([]);
  const [showDevicesModal, setShowDevicesModal] = useState(false);
  const [showTrafficModal, setShowTrafficModal] = useState(false);
  const [showLiveTrafficModal, setShowLiveTrafficModal] = useState(false);
  const [filterIP, setFilterIP] = useState<string>('');

  // Track previous packet count to avoid adding duplicate history entries
  const prevPacketCount = useRef<number | null>(null);

  useEffect(() => {
    if (data?.network?.packet_count !== undefined) {
      const newCount = data.network.packet_count;
      // Only add a new history point if the count actually changed
      if (prevPacketCount.current !== newCount) {
        prevPacketCount.current = newCount;
        setPacketHistory(prev => {
          const newHist = [...prev, { time: new Date().toLocaleTimeString(), packets: newCount }];
          if (newHist.length > 20) return newHist.slice(newHist.length - 20);
          return newHist;
        });
      }
    }
  }, [data?.network?.packet_count]);

  const mergedIPs = useMemo(() => {
    if (!data) return [];
    const ipMap = new Map();
    if (data.network?.top_src_ips) {
      data.network.top_src_ips.forEach((item: any) => {
        ipMap.set(item.ip, { ip: item.ip, count: item.count, mac: 'Unknown', status: 'Active Traffic' });
      });
    }
    if (data.devices) {
      data.devices.forEach((device: any) => {
        if (ipMap.has(device.ip)) {
          ipMap.set(device.ip, { ...ipMap.get(device.ip), mac: device.mac });
        } else {
          ipMap.set(device.ip, { ip: device.ip, count: 0, mac: device.mac, status: 'Connected (Idle)' });
        }
      });
    }
    return Array.from(ipMap.values()).sort((a, b) => b.count - a.count);
  }, [data?.network?.top_src_ips, data?.devices]);

  const blockedIPs = useMemo(() => {
    if (!data?.blocked) return [];
    return data.blocked.map((b: any) => typeof b === 'string' ? b : b.ip);
  }, [data?.blocked]);

  // Stable reference for filtered alerts (avoids re-computing on every render)
  const activeAlerts = useMemo(() => {
    if (!data?.alerts) return [];
    return data.alerts.filter((a: any) => !blockedIPs.includes(a.source_ip));
  }, [data?.alerts, blockedIPs]);

  const reversedAlerts = useMemo(() => [...activeAlerts].reverse(), [activeAlerts]);

  // Stable callbacks for modals
  const openDevices = useCallback(() => setShowDevicesModal(true), []);
  const closeDevices = useCallback(() => setShowDevicesModal(false), []);
  const openTraffic = useCallback(() => setShowTrafficModal(true), []);
  const closeTraffic = useCallback(() => setShowTrafficModal(false), []);
  const openLiveTraffic = useCallback(() => setShowLiveTrafficModal(true), []);
  const closeLiveTraffic = useCallback(() => { setShowLiveTrafficModal(false); setFilterIP(''); }, []);

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
        <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
        <p className="animate-pulse">Initializing Detection Engine...</p>
      </div>
    );
  }

  const { system, network, alerts, devices, blocked, traffic_log } = data;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Security Overview</h2>
          <p className="text-muted-foreground">Real-time threat monitoring and mitigation</p>
        </div>
        <div className="flex items-center gap-4 kinetic-card px-4 py-2 rounded-xl">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${status === 'connected' ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-sm font-medium">{status === 'connected' ? 'Engine Online' : 'Connecting...'}</span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-2 text-sm">
            <Cpu className="w-4 h-4 text-muted-foreground" />
            <span className="font-mono">{system.cpu.toFixed(1)}%</span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-2 text-sm" title="Gateway IP Address">
            <Network className="w-4 h-4 text-muted-foreground" />
            <span className="font-mono">{system.gateway_ip || 'Unknown IP'}</span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div
            className="flex items-center gap-2 text-sm"
            title={system.ml_enabled !== false ? 'AI/DNN Model Active: Inbound flows analyzed for zero-day anomalies' : 'AI/DNN Model Disabled: ML inference bypassed'}
          >
            <BrainCircuit className={`w-4 h-4 ${system.ml_enabled !== false ? 'text-purple-400' : 'text-muted-foreground'}`} />
            <span className={`px-2 py-0.5 text-xs font-semibold rounded-full border ${
              system.ml_enabled !== false
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                : 'bg-muted/40 text-muted-foreground border-border/30'
            }`}>
              ML: {system.ml_enabled !== false ? 'Active' : 'Disabled'}
            </span>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Devices"
          value={devices.length.toString()}
          icon={<Network className="text-emerald-500" />}
          trend="Click to view details"
          onClick={openDevices}
        />
        <KpiCard
          title="Active Alerts"
          value={network.alerts_count.toString()}
          icon={<AlertOctagon className="text-amber-500" />}
          trend={alerts.length > 0 ? "Requires attention" : "All clear"}
          alert={alerts.length > 0}
        />
        <KpiCard
          title="Blocked Threats"
          value={network.blocked_ips_count.toString()}
          icon={<ShieldAlert className="text-red-500" />}
          trend="Automatically mitigated"
        />
        <div className="kinetic-card rounded-2xl p-4 flex flex-col h-[130px] overflow-hidden relative">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-1">
              <Activity className="w-4 h-4 text-blue-500" />
              Live Traffic
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-xs text-primary font-mono">{network.packet_count.toLocaleString()} pkts</span>
              <button
                onClick={openLiveTraffic}
                className="p-1 hover:bg-white/10 rounded-md transition-colors text-muted-foreground hover:text-foreground"
                title="Full Screen Live Traffic"
              >
                <Maximize className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
            {traffic_log && traffic_log.length > 0 ? (
              [...traffic_log].slice(0, 10).map((log: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-xs">
                  <span className="text-muted-foreground font-mono truncate max-w-[80px]" title={log.src_ip}>{log.src_ip}</span>
                  <span className="truncate flex-1 mx-2 text-right text-foreground font-mono" title={log.domain}>{log.domain}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${log.proto === 'HTTPS' ? 'bg-green-500/10 text-green-500' : log.proto === 'HTTP' ? 'bg-orange-500/10 text-orange-500' : 'bg-blue-500/10 text-blue-500'}`}>{log.proto}</span>
                </div>
              ))
            ) : (
              <div className="h-full flex items-center justify-center text-muted-foreground text-xs italic">Awaiting traffic...</div>
            )}
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-4 bg-gradient-to-t from-[var(--color-background)] to-transparent pointer-events-none" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <div className="lg:col-span-2 kinetic-card rounded-2xl p-6 relative">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary" /> Traffic Analysis
            </h3>
            <button
              onClick={openTraffic}
              className="p-1.5 hover:bg-white/10 rounded-lg transition-colors text-muted-foreground hover:text-foreground"
              title="Full Screen Analysis"
            >
              <Maximize className="w-4 h-4" />
            </button>
          </div>
          <div className="h-[300px] w-full">
            <TrafficChart data={packetHistory} />
          </div>
        </div>

        {/* All Source IPs */}
        <div className="kinetic-card rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <ArrowUpRight className="w-5 h-5 text-rose-500" /> All Source IPs
            </h3>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 space-y-3 max-h-[300px] custom-scrollbar">
            {mergedIPs.map((ip: any, i: number) => (
              <div key={ip.ip || i} className="flex items-center gap-4 p-3 rounded-xl kinetic-card">
                <div className="px-3 py-1.5 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-bold text-primary min-w-[80px]">
                  {ip.count.toLocaleString()} pkts
                </div>
                <div className="flex flex-col flex-1">
                  <span className="font-mono text-sm font-medium">{ip.ip}</span>
                  <span className="text-xs text-muted-foreground font-mono">{ip.mac !== 'Unknown' ? `MAC: ${ip.mac}` : ip.status}</span>
                </div>
              </div>
            ))}
            {mergedIPs.length === 0 && (
              <div className="text-center text-muted-foreground py-8 text-sm">No traffic or devices detected yet</div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Alerts — REMOVED framer-motion AnimatePresence that was re-animating every WS tick */}
        <div className="kinetic-card rounded-2xl p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-amber-500" /> Recent Detections
          </h3>
          <div className="space-y-3 h-[400px] overflow-y-auto pr-2">
            {reversedAlerts.map((alert: any) => (
              <div
                key={alert.id}
                className="p-4 rounded-xl kinetic-card flex gap-4 bg-background"
              >
                <div className={`mt-1 flex-shrink-0 ${alert.severity === 'Critical' ? 'text-red-500' :
                  alert.severity === 'High' ? 'text-orange-500' :
                    alert.severity === 'Medium' ? 'text-amber-500' :
                      'text-blue-500'
                }`}>
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="font-semibold text-sm truncate">{alert.type}</h4>
                    <span className="text-xs text-muted-foreground">{format(new Date(alert.timestamp * 1000), 'HH:mm:ss')}</span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-2">{alert.reason}</p>
                  <div className="flex gap-2 text-xs font-mono kinetic-card p-2 rounded-lg inline-flex mt-2">
                    <span className="text-muted-foreground">SRC:</span>
                    <span className={blockedIPs.includes(alert.source_ip) ? 'text-red-400 line-through' : ''}>{alert.source_ip}</span>
                    <span className="text-muted-foreground ml-2">DST:</span> {alert.dest_ip}
                  </div>
                </div>
              </div>
            ))}
            {alerts.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                <ShieldAlert className="w-12 h-12 mb-4 opacity-20" />
                <p>No threats detected</p>
              </div>
            )}
          </div>
        </div>

        {/* Threat Timeline & Blocked IPs */}
        <div className="space-y-6 flex flex-col">
          <div className="kinetic-card rounded-2xl p-6 flex-1">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Ban className="w-5 h-5 text-red-500" /> Blocked IPs
            </h3>
            <div className="flex flex-wrap gap-2">
              {blockedIPs.map((ip: string) => (
                <div key={ip} className="px-3 py-1.5 kinetic-card text-red-500 rounded-lg font-mono text-sm flex items-center gap-2">
                  {ip}
                  <button onClick={() => fetch(`${API_BASE}/api/unblock/${ip}`, {
                    method: 'POST',
                    headers: { 'X-API-Key': API_KEY }
                  })} className="hover:text-red-400 transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
                  </button>
                </div>
              ))}
              {blocked.length === 0 && (
                <div className="text-muted-foreground text-sm w-full text-center py-4">No IPs currently blocked</div>
              )}
            </div>
          </div>

          <div className="kinetic-card rounded-2xl p-6 flex-1">
            <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
            <div className="h-[200px]">
              <ProtocolChart protocolCounts={network.protocol_counts || {}} />
            </div>
          </div>
        </div>
      </div>

      {/* Active Devices Modal */}
      {showDevicesModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" onClick={closeDevices}>
          <div
            onClick={(e) => e.stopPropagation()}
            className="kinetic-card rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl border border-white/10 animate-in fade-in zoom-in-95 duration-200"
          >
            <div className="flex items-center justify-between p-4 border-b border-border bg-black/20">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Monitor className="w-5 h-5 text-emerald-500" /> Active Devices on Network
              </h3>
              <button onClick={closeDevices} className="p-1 hover:bg-white/10 rounded-lg transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 max-h-[60vh] overflow-y-auto">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {devices.map((device: any, i: number) => (
                  <div key={i} className="kinetic-card p-4 rounded-xl flex flex-col gap-2 bg-black/10">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-primary">{device.name || 'Unknown Device'}</span>
                      <span className="text-xs bg-emerald-500/10 text-emerald-500 px-2 py-1 rounded-full">Active</span>
                    </div>
                    <div className="flex flex-col text-sm font-mono text-muted-foreground mt-2 space-y-1">
                      <div className="flex justify-between"><span>IP:</span> <span className="text-foreground">{device.ip}</span></div>
                      <div className="flex justify-between"><span>MAC:</span> <span className="text-foreground">{device.mac}</span></div>
                      <div className="flex justify-between text-xs mt-2 text-muted-foreground/50">
                        <span>Seen:</span> <span>{format(new Date(device.last_seen * 1000), 'HH:mm:ss')}</span>
                      </div>
                    </div>
                  </div>
                ))}
                {devices.length === 0 && (
                  <div className="col-span-full text-center py-8 text-muted-foreground">No active devices detected</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Traffic Analysis Full Screen Modal */}
      {showTrafficModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md" onClick={closeTraffic}>
          <div
            onClick={(e) => e.stopPropagation()}
            className="kinetic-card rounded-2xl w-full h-[90vh] max-w-[95vw] overflow-hidden shadow-2xl border border-white/10 flex flex-col animate-in fade-in zoom-in-95 duration-200"
          >
            <div className="flex items-center justify-between p-4 border-b border-border bg-black/20 shrink-0">
              <h3 className="text-xl font-semibold flex items-center gap-2">
                <Activity className="w-6 h-6 text-primary" /> Full Screen Traffic Analysis
              </h3>
              <button onClick={closeTraffic} className="p-2 hover:bg-white/10 rounded-lg transition-colors bg-white/5">
                <X className="w-6 h-6" />
              </button>
            </div>
            <div className="flex-1 p-6 overflow-hidden flex flex-col lg:flex-row gap-6">
              <div className="flex-1 flex flex-col">
                <h4 className="text-sm font-medium text-muted-foreground mb-4">Live Packet Rate</h4>
                <div className="flex-1 min-h-[300px]">
                  <TrafficChart data={packetHistory} gradientId="colorPacketsModal" strokeWidth={4} />
                </div>
              </div>
              <div className="w-full lg:w-[400px] flex flex-col kinetic-card rounded-xl bg-black/20 p-4">
                <h4 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
                  <ArrowUpRight className="w-4 h-4 text-rose-500" /> Active Clients
                </h4>
                <div className="flex-1 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
                  {mergedIPs.map((ip: any, i: number) => (
                    <div key={ip.ip || i} className="flex items-center gap-3 p-3 rounded-lg bg-black/40 border border-white/5 hover:border-primary/30 transition-colors">
                      <div className="px-2 py-1 rounded bg-primary/10 flex items-center justify-center text-[10px] font-bold text-primary min-w-[60px]">
                        {ip.count.toLocaleString()} pkt
                      </div>
                      <div className="flex flex-col flex-1 min-w-0">
                        <span className="font-mono text-sm font-medium truncate">{ip.ip}</span>
                        <span className="text-[10px] text-muted-foreground font-mono truncate">{ip.mac !== 'Unknown' ? `MAC: ${ip.mac}` : ip.status}</span>
                      </div>
                    </div>
                  ))}
                  {mergedIPs.length === 0 && (
                    <div className="text-center text-muted-foreground py-8 text-sm">No active clients detected</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Live Traffic Full Screen Modal */}
      {showLiveTrafficModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md" onClick={closeLiveTraffic}>
          <div
            onClick={(e) => e.stopPropagation()}
            className="kinetic-card rounded-2xl w-full h-[90vh] max-w-6xl overflow-hidden shadow-2xl border border-white/10 flex flex-col animate-in fade-in zoom-in-95 duration-200"
          >
            <div className="flex items-center justify-between p-4 border-b border-border bg-black/20 shrink-0">
              <h3 className="text-xl font-semibold flex items-center gap-2">
                <Activity className="w-6 h-6 text-blue-500" /> Live Traffic Monitor
              </h3>
              <div className="flex items-center gap-3">
                {filterIP && (
                  <div className="flex items-center gap-2 bg-primary/10 border border-primary/30 text-primary px-3 py-1.5 rounded-lg text-sm font-mono">
                    <Filter className="w-3.5 h-3.5" />
                    Monitoring: {filterIP}
                    <button onClick={() => setFilterIP('')} className="hover:text-red-400 transition-colors ml-1">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
                <button onClick={closeLiveTraffic} className="p-2 hover:bg-white/10 rounded-lg transition-colors bg-white/5">
                  <X className="w-6 h-6" />
                </button>
              </div>
            </div>
            <div className="flex-1 flex overflow-hidden">
              {/* IP Selector Sidebar */}
              <div className="w-64 border-r border-white/5 bg-black/20 flex flex-col shrink-0">
                <div className="p-3 border-b border-white/5">
                  <div className="relative">
                    <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="text"
                      value={filterIP}
                      onChange={(e) => setFilterIP(e.target.value)}
                      placeholder="Filter by IP..."
                      className="w-full bg-black/30 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-sm font-mono text-foreground outline-none focus:border-primary/50 transition-colors placeholder:text-muted-foreground/50"
                    />
                  </div>
                </div>
                <div className="p-2 flex-1 overflow-y-auto custom-scrollbar space-y-1">
                  <button
                    onClick={() => setFilterIP('')}
                    className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-all flex items-center gap-2 ${
                      !filterIP ? 'bg-primary/15 text-primary border border-primary/30' : 'hover:bg-white/5 text-muted-foreground'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" />
                    All Traffic
                  </button>
                  {mergedIPs.map((ip: any, i: number) => (
                    <button
                      key={ip.ip || i}
                      onClick={() => setFilterIP(ip.ip)}
                      className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-all font-mono flex items-center justify-between ${
                        filterIP === ip.ip ? 'bg-primary/15 text-primary border border-primary/30' : 'hover:bg-white/5 text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      <span className="truncate">{ip.ip}</span>
                      <span className="text-[10px] bg-white/5 px-1.5 py-0.5 rounded ml-2 shrink-0">{ip.count}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Traffic Log */}
              <div className="flex-1 p-6 overflow-hidden flex flex-col bg-black/10">
                <div className="flex items-center justify-between text-sm font-medium text-muted-foreground border-b border-white/5 pb-2 mb-4 px-2">
                  <div className="w-[15%]">Time</div>
                  <div className="w-[20%]">Source IP</div>
                  <div className="w-[45%]">Domain / Destination</div>
                  <div className="w-[20%] text-right">Protocol</div>
                </div>
                <div className="flex-1 overflow-y-auto pr-2 space-y-1.5 custom-scrollbar">
                  {traffic_log && traffic_log.length > 0 ? (
                    (() => {
                      const filtered = [...traffic_log].filter((log: any) =>
                        !filterIP || log.src_ip === filterIP || log.src_ip?.includes(filterIP)
                      );
                      return filtered.length > 0 ? filtered.map((log: any, i: number) => (
                        <div key={i} className={`flex items-center text-sm p-3 rounded-lg border transition-colors ${
                          filterIP && log.src_ip === filterIP
                            ? 'bg-primary/5 border-primary/20 hover:bg-primary/10'
                            : 'bg-black/20 hover:bg-black/40 border-transparent hover:border-white/5'
                        }`}>
                          <span className="w-[15%] text-muted-foreground font-mono text-xs truncate pr-2">
                            {log.timestamp ? format(new Date(log.timestamp * 1000), 'HH:mm:ss') : '--'}
                          </span>
                          <span
                            className="w-[20%] font-mono truncate pr-4 cursor-pointer hover:text-primary transition-colors"
                            title={`Click to filter: ${log.src_ip}`}
                            onClick={() => setFilterIP(log.src_ip)}
                          >
                            {log.src_ip}
                          </span>
                          <span className="w-[45%] text-foreground font-mono truncate pr-4" title={log.domain}>{log.domain}</span>
                          <div className="w-[20%] flex justify-end">
                            <span className={`px-2 py-1 rounded-md text-xs font-bold ${log.proto === 'HTTPS' ? 'bg-green-500/10 text-green-500' : log.proto === 'HTTP' ? 'bg-orange-500/10 text-orange-500' : 'bg-blue-500/10 text-blue-500'}`}>
                              {log.proto}
                            </span>
                          </div>
                        </div>
                      )) : (
                        <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-2">
                          <Filter className="w-8 h-8 opacity-30" />
                          <span className="italic">No traffic from {filterIP}</span>
                          <button onClick={() => setFilterIP('')} className="text-primary text-sm hover:underline">Clear filter</button>
                        </div>
                      );
                    })()
                  ) : (
                    <div className="h-full flex items-center justify-center text-muted-foreground italic">Awaiting traffic...</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

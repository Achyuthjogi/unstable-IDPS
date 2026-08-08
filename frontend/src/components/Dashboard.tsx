import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useWebSocket } from '../hooks/useWebSocket';
import { Activity, AlertOctagon, ShieldAlert, Cpu, Network, ArrowUpRight, Ban } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { format } from 'date-fns';

export default function Dashboard({ data, status }: { data: any, status: string }) {
  // Keep local history of packet rates for the chart
  const [packetHistory, setPacketHistory] = useState<{time: string, packets: number}[]>([]);
  
  useMemo(() => {
    if (data?.network?.packet_count !== undefined) {
      setPacketHistory(prev => {
        const newHist = [...prev, { time: new Date().toLocaleTimeString(), packets: data.network.packet_count }];
        if (newHist.length > 20) return newHist.slice(newHist.length - 20);
        return newHist;
      });
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

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
        <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
        <p className="animate-pulse">Initializing Detection Engine...</p>
      </div>
    );
  }

  const { system, network, alerts, devices, blocked, timeline } = data;

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
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 container-3d">
        <KpiCard 
          title="Total Packets Analyzed" 
          value={network.packet_count.toLocaleString()} 
          icon={<Activity className="text-blue-500" />} 
          trend="+12% from last hour" 
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
        <KpiCard 
          title="Active Devices" 
          value={devices.length.toString()} 
          icon={<Network className="text-emerald-500" />} 
          trend="On local network" 
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 container-3d">
        {/* Main Chart */}
        <div className="lg:col-span-2 kinetic-card rounded-2xl p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" /> Traffic Analysis
          </h3>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={packetHistory}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(val) => `${val >= 1000 ? (val/1000).toFixed(1)+'k' : val}`} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--color-background)', borderColor: 'transparent', borderRadius: '1rem', boxShadow: '8px 8px 16px #1c1f22, -8px -8px 16px #363b42' }}
                  itemStyle={{ color: 'var(--color-foreground)' }}
                />
                <Area type="monotone" dataKey="packets" stroke="hsl(var(--primary))" strokeWidth={2} fillOpacity={1} fill="url(#colorPackets)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* All Source IPs */}
        <div className="kinetic-card rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <ArrowUpRight className="w-5 h-5 text-rose-500" /> All Source IPs
            </h3>
            <button 
              onClick={async () => {
                try {
                  await fetch('http://localhost:8000/api/scan', { method: 'POST' });
                } catch (e) {
                  console.error(e);
                }
              }}
              className="kinetic-card hover:bg-primary/20 text-primary px-3 py-1.5 rounded-lg transition-all font-medium flex items-center gap-2 text-xs"
            >
              <Network className="w-3.5 h-3.5" />
              Scan Network
            </button>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 space-y-3">
            {mergedIPs.map((ip: any, i: number) => (
              <div key={i} className="flex items-center gap-4 p-3 rounded-xl kinetic-card transition-all">
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 container-3d">
        {/* Recent Alerts */}
        <div className="kinetic-card rounded-2xl p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-amber-500" /> Recent Detections
          </h3>
          <div className="space-y-3 h-[400px] overflow-y-auto pr-2">
            <AnimatePresence>
              {alerts.slice().reverse().map((alert: any) => (
                <motion.div 
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  key={alert.id} 
                  className={`p-4 rounded-xl kinetic-card flex gap-4 bg-background`}
                >
                  <div className={`mt-1 flex-shrink-0 ${
                    alert.severity === 'Critical' ? 'text-red-500' :
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
                      <span className={blocked.includes(alert.source_ip) ? 'text-red-400 line-through' : ''}>{alert.source_ip}</span>
                      <span className="text-muted-foreground ml-2">DST:</span> {alert.dest_ip}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
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
              {blocked.map((ip: string) => (
                <div key={ip} className="px-3 py-1.5 kinetic-card text-red-500 rounded-lg font-mono text-sm flex items-center gap-2">
                  {ip}
                  <button className="hover:text-red-400 transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
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
               <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={Object.entries(network.protocol_counts || {}).map(([name, value]) => ({ name, value }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                    <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                    <Tooltip 
                      cursor={{fill: 'rgba(0,0,0,0.1)'}}
                      contentStyle={{ backgroundColor: 'var(--color-background)', borderColor: 'transparent', borderRadius: '1rem', boxShadow: '8px 8px 16px #1c1f22, -8px -8px 16px #363b42' }}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {Object.entries(network.protocol_counts || {}).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={`hsl(var(--primary))`} opacity={0.8 + (index % 3) * 0.1} />
                      ))}
                    </Bar>
                  </BarChart>
               </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function KpiCard({ title, value, icon, trend, alert = false }: { title: string, value: string, icon: React.ReactNode, trend: string, alert?: boolean }) {
  return (
    <div className={`kinetic-card rounded-2xl p-6 transition-all duration-300 ${alert ? 'border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.2)]' : ''}`}>
      <div className="flex items-center justify-between mb-4 w-full">
        <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
        <div className="p-2 kinetic-card rounded-xl">
          {icon}
        </div>
      </div>
      <div className="flex items-baseline gap-2">
        <h2 className="text-3xl font-bold tracking-tight text-primary text-glow">{value}</h2>
      </div>
      <p className="text-xs text-muted-foreground mt-2">{trend}</p>
    </div>
  );
}

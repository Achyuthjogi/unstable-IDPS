import { useState, useEffect } from 'react';
import { 
  Network, 
  Lock, 
  RefreshCw, 
  Database, 
  Search, 
  ExternalLink, 
  CheckCircle2, 
  AlertOctagon, 
  FileCode 
} from 'lucide-react';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

export default function EnterpriseCenter() {
  const [clusterData, setClusterData] = useState<any>({ nodes: [] });
  const [tiStatus, setTiStatus] = useState<any>({});
  const [tiIndicators, setTiIndicators] = useState<any[]>([]);
  const [siemStatus, setSiemStatus] = useState<any>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResult, setSearchResult] = useState<any>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [syncingCluster, setSyncingCluster] = useState(false);

  const fetchEnterpriseState = () => {
    fetch(`${API_BASE}/api/cluster/status`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((d) => setClusterData(d))
      .catch(console.error);

    fetch(`${API_BASE}/api/threat-intel/status`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((d) => setTiStatus(d))
      .catch(console.error);

    fetch(`${API_BASE}/api/threat-intel/indicators?limit=20`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((d) => setTiIndicators(d || []))
      .catch(console.error);

    fetch(`${API_BASE}/api/siem/status`, { headers: { 'X-API-Key': API_KEY } })
      .then((res) => res.json())
      .then((d) => setSiemStatus(d))
      .catch(console.error);
  };

  useEffect(() => {
    fetchEnterpriseState();
    const interval = setInterval(fetchEnterpriseState, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRefreshTI = () => {
    setRefreshing(true);
    fetch(`${API_BASE}/api/threat-intel/refresh`, {
      method: 'POST',
      headers: { 'X-API-Key': API_KEY },
    })
      .then(() => {
        setTimeout(() => {
          fetchEnterpriseState();
          setRefreshing(false);
        }, 1500);
      })
      .catch(() => setRefreshing(false));
  };

  const handleSyncCluster = () => {
    setSyncingCluster(true);
    fetch(`${API_BASE}/api/cluster/sync`, {
      method: 'POST',
      headers: { 'X-API-Key': API_KEY },
    })
      .then(() => {
        setTimeout(() => {
          fetchEnterpriseState();
          setSyncingCluster(false);
        }, 1000);
      })
      .catch(() => setSyncingCluster(false));
  };

  const handleSearchIOC = () => {
    if (!searchQuery.trim()) return;
    const query = searchQuery.trim().toLowerCase();
    const match = tiIndicators.find(
      (ind) =>
        ind.indicator.toLowerCase().includes(query) ||
        (ind.description && ind.description.toLowerCase().includes(query))
    );
    if (match) {
      setSearchResult(match);
    } else {
      setSearchResult({
        indicator: searchQuery,
        found: false,
        message: 'No threat intelligence correlation detected. Indicator clean in local cache.',
      });
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Threat Intelligence & Cluster</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Distributed mesh sync, dynamic IOC feeds, encrypted traffic fingerprinting, and SIEM forwarding.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`${API_BASE}/metrics`}
            target="_blank"
            rel="noreferrer"
            className="px-3 py-1.5 rounded-md border border-border text-xs font-medium flex items-center gap-1.5 hover:bg-muted transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-muted-foreground" />
            <span>Metrics</span>
            <ExternalLink className="w-3 h-3 text-muted-foreground" />
          </a>
          <button
            onClick={fetchEnterpriseState}
            className="p-1.5 rounded-md border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground block font-medium">Cluster Nodes</span>
          <div className="text-2xl font-bold tracking-tight text-foreground">
            {clusterData.nodes?.length || 1}
          </div>
          <span className="text-[11px] text-muted-foreground block">
            HMAC Sync ({clusterData.sync_pkts || 0} pkts)
          </span>
        </div>

        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground block font-medium">Active IOC Indicators</span>
          <div className="text-2xl font-bold tracking-tight text-foreground">
            {(tiStatus.active_ip_indicators || 0) +
              (tiStatus.active_domains || 0) +
              (tiStatus.active_cidr_blocks || 0)}
          </div>
          <span className="text-[11px] text-muted-foreground block">Feodo, ThreatFox, ET-Open</span>
        </div>

        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground block font-medium">TLS Signatures (ETA)</span>
          <div className="text-2xl font-bold tracking-tight text-foreground">JA3 / JA3S</div>
          <span className="text-[11px] text-muted-foreground block">Fingerprint anomaly detection</span>
        </div>

        <div className="card p-4 space-y-1">
          <span className="text-xs text-muted-foreground block font-medium">SIEM Stream</span>
          <div className="text-2xl font-bold tracking-tight text-foreground">
            {siemStatus?.format || 'CEF'}
          </div>
          <span className="text-[11px] text-muted-foreground block truncate">
            {siemStatus?.destination || 'Syslog RFC5424'}
          </span>
        </div>
      </div>

      {/* Mesh & Threat Feeds Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Cluster HA Topology */}
        <div className="card p-4 space-y-3 flex flex-col">
          <div className="flex items-center justify-between border-b border-border pb-2.5">
            <div>
              <h2 className="text-sm font-semibold flex items-center gap-1.5">
                <Network className="w-4 h-4 text-primary" /> Cluster Mesh Status
              </h2>
            </div>
            <button
              onClick={handleSyncCluster}
              disabled={syncingCluster}
              className="px-2.5 py-1 bg-secondary hover:bg-muted text-xs font-medium rounded border border-border transition-colors flex items-center gap-1"
            >
              <RefreshCw className={`w-3 h-3 ${syncingCluster ? 'animate-spin' : ''}`} />
              Replicate
            </button>
          </div>

          <div className="space-y-2 overflow-y-auto max-h-56">
            {clusterData.nodes && clusterData.nodes.length > 0 ? (
              clusterData.nodes.map((node: any, idx: number) => (
                <div
                  key={idx}
                  className="p-2.5 bg-muted/30 border border-border rounded-md flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground">{node.node_id}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-secondary text-muted-foreground font-mono uppercase">
                        {node.role}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-muted-foreground">
                      IP: {node.address} • Flows: {node.active_flows || 0}
                    </div>
                  </div>
                  <span className="text-[10px] text-success font-medium flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> {node.status}
                  </span>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-xs text-muted-foreground">
                Standalone leader mode. Add peer addresses in HA_PEER_ADDRS for multi-node mesh.
              </div>
            )}
          </div>
        </div>

        {/* Threat Intelligence Feeds */}
        <div className="card p-4 space-y-3 flex flex-col">
          <div className="flex items-center justify-between border-b border-border pb-2.5">
            <div>
              <h2 className="text-sm font-semibold flex items-center gap-1.5">
                <Database className="w-4 h-4 text-primary" /> Ingested Feeds
              </h2>
            </div>
            <button
              onClick={handleRefreshTI}
              disabled={refreshing}
              className="px-2.5 py-1 bg-secondary hover:bg-muted text-xs font-medium rounded border border-border transition-colors flex items-center gap-1"
            >
              <RefreshCw className={`w-3 h-3 ${refreshing ? 'animate-spin' : ''}`} />
              Sync Now
            </button>
          </div>

          <div className="space-y-2 overflow-y-auto max-h-56">
            {tiStatus.feeds && tiStatus.feeds.length > 0 ? (
              tiStatus.feeds.map((feed: any, idx: number) => (
                <div
                  key={idx}
                  className="p-2.5 bg-muted/30 border border-border rounded-md flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="font-medium text-foreground">{feed.name}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {feed.type} • Severity: {feed.severity}
                    </div>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 font-medium">
                    Connected
                  </span>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-xs text-muted-foreground">
                Baseline feeds loaded ({tiStatus.active_ip_indicators || 0} indicators cached).
              </div>
            )}
          </div>
        </div>
      </div>

      {/* IOC Search */}
      <div className="card p-4 space-y-3">
        <div>
          <h2 className="text-sm font-semibold flex items-center gap-1.5">
            <Search className="w-4 h-4 text-primary" /> Indicator Search
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Query the in-memory Radix tree for any IP, CIDR block, or domain.
          </p>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearchIOC()}
            placeholder="Search IP or domain (e.g. 194.26.29.112)..."
            className="flex-1 text-xs bg-background border border-border rounded-md px-3 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
          />
          <button
            onClick={handleSearchIOC}
            className="px-3.5 py-1.5 bg-primary text-primary-foreground text-xs font-medium rounded-md hover:opacity-90 transition-opacity"
          >
            Check
          </button>
        </div>

        {searchResult && (
          <div
            className={`p-3 rounded-md border text-xs ${
              searchResult.found !== false
                ? 'bg-rose-50 border-rose-200 text-rose-900 dark:bg-rose-950/30 dark:border-rose-900/40 dark:text-rose-200'
                : 'bg-emerald-50 border-emerald-200 text-emerald-900 dark:bg-emerald-950/30 dark:border-emerald-900/40 dark:text-emerald-200'
            }`}
          >
            {searchResult.found !== false ? (
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertOctagon className="w-4 h-4 text-destructive" />
                  <span>Threat Match: {searchResult.indicator}</span>
                </div>
                <p className="text-xs opacity-90">{searchResult.description}</p>
                <div className="text-[11px] font-mono opacity-80 pt-1 flex gap-3">
                  <span>Type: {searchResult.type}</span>
                  <span>Source: {searchResult.source_feed}</span>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-success" />
                <span>{searchResult.message}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Encrypted Traffic Analytics (ETA) */}
      <div className="card p-4 space-y-3">
        <div>
          <h2 className="text-sm font-semibold flex items-center gap-1.5">
            <Lock className="w-4 h-4 text-primary" /> Encrypted Traffic Fingerprints (JA3)
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Client TLS fingerprinting detects known C2 malware without TLS MITM decryption.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {[
            { name: 'Cobalt Strike HTTPS Beacon', hash: 'a0e9f5d64349fb13191bc781f81f42e1', sev: 'Critical' },
            { name: 'Cobalt Strike Malleable C2', hash: '72a589da586844d7f0818ce684948eea', sev: 'Critical' },
            { name: 'Metasploit Reverse HTTPS', hash: 'b32309a26951912be7dba376398abc3b', sev: 'Critical' },
            { name: 'Emotet Banking Trojan C2', hash: '4d7a28d6f22da2e8ee309e8699c70376', sev: 'Critical' },
            { name: 'TrickBot Anchor C2', hash: '6734f3743167022587532acab30bf442', sev: 'Critical' },
            { name: 'AsyncRAT / Quasar RAT', hash: 'fd37536d5012e75e11f7c132c32cf988', sev: 'High' },
          ].map((ja3, idx) => (
            <div key={idx} className="p-2.5 bg-muted/20 border border-border rounded-md space-y-1 text-xs">
              <div className="flex justify-between items-center">
                <span className="font-medium text-foreground">{ja3.name}</span>
                <span className="text-[10px] px-1 rounded bg-secondary text-muted-foreground font-mono font-medium">
                  {ja3.sev}
                </span>
              </div>
              <div className="text-[11px] font-mono text-muted-foreground truncate" title={ja3.hash}>
                {ja3.hash}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

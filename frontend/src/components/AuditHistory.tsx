import { useState, useMemo, useEffect } from 'react';
import { FileText, ShieldAlert, CheckCircle, XCircle, Search, Filter, RefreshCw, Terminal, ArrowUpRight } from 'lucide-react';
import { format } from 'date-fns';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  ip: string;
  details: string;
  status: string;
  platform: string;
}

export default function AuditHistory({ data }: { data: any }) {
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'SUCCESS' | 'FAILED'>('ALL');
  const [loading, setLoading] = useState(false);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/audit?limit=200`, {
        headers: { 'X-API-Key': API_KEY }
      });
      if (res.ok) {
        const json = await res.json();
        setAuditLogs(json || []);
      }
    } catch (e) {
      console.error('Failed to load audit logs:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  // Sync with live WebSocket audit logs if newer
  const mergedLogs = useMemo(() => {
    const map = new Map<string, AuditEntry>();
    auditLogs.forEach(entry => map.set(entry.id, entry));
    if (data?.audit_logs) {
      data.audit_logs.forEach((entry: AuditEntry) => map.set(entry.id, entry));
    }
    return Array.from(map.values()).sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return tb - ta;
    });
  }, [auditLogs, data?.audit_logs]);

  const filteredLogs = useMemo(() => {
    return mergedLogs.filter(entry => {
      const matchesStatus = statusFilter === 'ALL' || entry.status === statusFilter;
      const term = searchTerm.toLowerCase();
      const matchesSearch = !term ||
        entry.action.toLowerCase().includes(term) ||
        entry.actor.toLowerCase().includes(term) ||
        entry.ip.toLowerCase().includes(term) ||
        entry.details.toLowerCase().includes(term) ||
        (entry.platform && entry.platform.toLowerCase().includes(term));
      return matchesStatus && matchesSearch;
    });
  }, [mergedLogs, searchTerm, statusFilter]);

  const formatTimestamp = (ts: string) => {
    try {
      return format(new Date(ts), 'MMM dd, yyyy HH:mm:ss');
    } catch {
      return ts;
    }
  };

  const getActionColor = (action: string) => {
    if (action.includes('BLOCK')) return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (action.includes('UNBLOCK')) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (action.includes('ALLOWLIST')) return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
    if (action.includes('CONFIG') || action.includes('SETTINGS')) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-primary bg-primary/10 border-primary/30';
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3">
          <FileText className="w-8 h-8 text-primary" />
          <div>
            <h2 className="text-3xl font-bold tracking-tight">Audit Trail & Investigation</h2>
            <p className="text-sm text-muted-foreground">Immutable audit logs for security policy enforcement, firewall modifications, and administrative actions</p>
          </div>
        </div>
        <button
          onClick={fetchAuditLogs}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl kinetic-card hover:bg-white/5 text-sm font-medium transition-all"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh Audit Trail
        </button>
      </div>

      {/* Control / Filter Bar */}
      <div className="kinetic-card rounded-2xl p-4 flex flex-col sm:flex-row items-center gap-4">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search audit events by action, actor, IP, or details..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-background border border-border/30 rounded-xl pl-10 pr-4 py-2 text-sm text-foreground outline-none focus:border-primary/50 transition-colors font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <div className="flex rounded-xl kinetic-card p-1 text-xs font-semibold">
            {(['ALL', 'SUCCESS', 'FAILED'] as const).map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1 rounded-lg transition-all ${
                  statusFilter === status
                    ? 'bg-primary text-primary-foreground shadow'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="kinetic-card rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold">Security Audit Events</h3>
          </div>
          <span className="text-xs font-mono text-muted-foreground">
            {filteredLogs.length} events logged
          </span>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground text-sm">
            {loading ? 'Fetching audit records from persistent store...' : 'No audit entries match the current search filters.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border/30 text-muted-foreground uppercase tracking-wider">
                  <th className="py-3 px-4 font-semibold">Timestamp</th>
                  <th className="py-3 px-4 font-semibold">Action</th>
                  <th className="py-3 px-4 font-semibold">Actor</th>
                  <th className="py-3 px-4 font-semibold">Target / IP</th>
                  <th className="py-3 px-4 font-semibold">Platform</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold">Enforcement Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20 font-mono">
                {filteredLogs.map(entry => (
                  <tr key={entry.id} className="hover:bg-white/5 transition-colors">
                    <td className="py-3 px-4 text-muted-foreground whitespace-nowrap">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border uppercase ${getActionColor(entry.action)}`}>
                        {entry.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-foreground font-semibold">
                      {entry.actor}
                    </td>
                    <td className="py-3 px-4 text-primary font-bold">
                      {entry.ip || '-'}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase kinetic-card text-muted-foreground">
                        {entry.platform || 'linux'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {entry.status === 'SUCCESS' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                          <CheckCircle className="w-3.5 h-3.5" />
                          SUCCESS
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-rose-400 font-bold">
                          <XCircle className="w-3.5 h-3.5" />
                          FAILED
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-muted-foreground max-w-xs truncate" title={entry.details}>
                      {entry.details}
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


import { useState, useMemo, useEffect } from 'react';
import { CheckCircle2, XCircle, Search, RefreshCw } from 'lucide-react';
import { safeFormatDateTime } from '../utils/format';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

interface AuditEntry {
  id: string;
  timestamp: string | number;
  action: string;
  actor: string;
  ip?: string;
  target?: string;
  details: string;
  status: string;
  platform?: string;
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
        headers: { 'X-API-Key': API_KEY },
      });
      if (res.ok) {
        const json = await res.json();
        setAuditLogs(Array.isArray(json) ? json : []);
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

  const mergedLogs = useMemo(() => {
    const map = new Map<string, AuditEntry>();
    auditLogs.forEach((entry) => {
      if (entry?.id) map.set(entry.id, entry);
    });
    if (data?.audit_logs && Array.isArray(data.audit_logs)) {
      data.audit_logs.forEach((entry: AuditEntry) => {
        if (entry?.id) map.set(entry.id, entry);
      });
    }
    return Array.from(map.values()).sort((a, b) => {
      const ta = new Date(a.timestamp).getTime() || 0;
      const tb = new Date(b.timestamp).getTime() || 0;
      return tb - ta;
    });
  }, [auditLogs, data?.audit_logs]);

  const filteredLogs = useMemo(() => {
    return mergedLogs.filter((entry) => {
      if (!entry) return false;
      const matchesStatus = statusFilter === 'ALL' || (entry.status || '').toUpperCase() === statusFilter;
      const term = searchTerm.trim().toLowerCase();
      if (!term) return matchesStatus;

      const safeStr = (v: any) => (v ? String(v).toLowerCase() : '');
      const ip = entry.ip || entry.target || '';

      const matchesSearch =
        safeStr(entry.action).includes(term) ||
        safeStr(entry.actor).includes(term) ||
        safeStr(ip).includes(term) ||
        safeStr(entry.details).includes(term) ||
        safeStr(entry.platform).includes(term);

      return matchesStatus && matchesSearch;
    });
  }, [mergedLogs, searchTerm, statusFilter]);

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Audit Trail</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Log of administrative actions, block enforcements, and security policy modifications.
          </p>
        </div>
        <button
          onClick={fetchAuditLogs}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border text-xs font-medium hover:bg-muted transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="card p-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by action, actor, IP address, or details..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full text-xs bg-background border border-border rounded-md pl-8 pr-3 py-1.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
          />
        </div>

        <div className="flex items-center gap-1 bg-secondary/60 p-0.5 rounded-md text-xs border border-border/40 shrink-0">
          {(['ALL', 'SUCCESS', 'FAILED'] as const).map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                statusFilter === status
                  ? 'bg-card text-foreground shadow-xs font-semibold'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="card overflow-hidden">
        <div className="px-4 py-2.5 border-b border-border bg-muted/30 flex items-center justify-between text-xs text-muted-foreground font-medium">
          <span>Logged Audit Records ({filteredLogs.length})</span>
          <span>Append-only journal</span>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="py-16 text-center text-xs text-muted-foreground">
            {loading ? 'Fetching audit records...' : 'No audit entries found matching filter.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border text-muted-foreground bg-muted/15 font-medium">
                  <th className="py-2.5 px-4">Time</th>
                  <th className="py-2.5 px-4">Action</th>
                  <th className="py-2.5 px-4">Actor</th>
                  <th className="py-2.5 px-4">Target IP</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 font-mono">
                {filteredLogs.map((entry, idx) => {
                  const targetIP = entry.ip || entry.target || '—';
                  const isSuccess = (entry.status || '').toUpperCase() === 'SUCCESS';

                  return (
                    <tr key={entry.id || idx} className="hover:bg-muted/15 transition-colors">
                      <td className="py-2.5 px-4 text-muted-foreground whitespace-nowrap">
                        {safeFormatDateTime(entry.timestamp)}
                      </td>
                      <td className="py-2.5 px-4 font-semibold text-foreground font-sans">
                        {entry.action || 'EVENT'}
                      </td>
                      <td className="py-2.5 px-4 text-muted-foreground">
                        {entry.actor || 'system'}
                      </td>
                      <td className="py-2.5 px-4 text-foreground">
                        {targetIP}
                      </td>
                      <td className="py-2.5 px-4 font-sans">
                        {isSuccess ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-success font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Success
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] text-destructive font-medium">
                            <XCircle className="w-3.5 h-3.5" /> Failed
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-muted-foreground font-sans max-w-sm truncate" title={entry.details}>
                        {entry.details || '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Shield, Activity, Save, Server, Target, Zap, AlertTriangle, Key, Search, FileCode2, Terminal, Code2 } from 'lucide-react';

const API_HOST = window.location.hostname;
const API_BASE = `http://${API_HOST}:8000`;
const API_KEY = import.meta.env.VITE_API_KEY || '';

interface Thresholds {
  SuspiciousRateThreshold: number;
  PortScanThreshold: number;
  ICMPFloodThreshold: number;
  UDPFloodThreshold: number;
  SYNFloodThreshold: number;
  SSHBruteForceThreshold: number;
}

export default function AttackDetectionView() {
  const [thresholds, setThresholds] = useState<Thresholds | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });

  useEffect(() => {
    fetch(`${API_BASE}/api/rules/thresholds`, {
      headers: { 'X-API-Key': API_KEY }
    })
      .then(res => res.json())
      .then(data => setThresholds(data))
      .catch(err => console.error("Failed to load thresholds", err));
  }, []);

  const handleSave = async () => {
    if (!thresholds) return;
    setIsSaving(true);
    setMessage({ text: '', type: '' });
    
    try {
      const res = await fetch(`${API_BASE}/api/rules/thresholds`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(thresholds)
      });
      
      if (res.ok) {
        setMessage({ text: 'Thresholds successfully updated.', type: 'success' });
      } else {
        setMessage({ text: 'Failed to update thresholds.', type: 'error' });
      }
    } catch (err) {
      setMessage({ text: 'Error connecting to backend.', type: 'error' });
    }
    
    setIsSaving(false);
    setTimeout(() => setMessage({ text: '', type: '' }), 3000);
  };

  const updateThreshold = (key: keyof Thresholds, value: string) => {
    const num = parseInt(value, 10);
    if (!isNaN(num)) {
      setThresholds(prev => prev ? { ...prev, [key]: num } : null);
    }
  };

  if (!thresholds) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
        <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
        <p className="animate-pulse">Loading Threat Intelligence Data...</p>
      </div>
    );
  }

  const attackTypes = [
    {
      id: "SYNFloodThreshold",
      title: "SYN Flood (TCP)",
      icon: <Activity className="text-blue-500 w-5 h-5" />,
      desc: "Detects rapid, incomplete TCP connections aimed at exhausting server resources.",
      metric: "packets / 3s"
    },
    {
      id: "UDPFloodThreshold",
      title: "UDP Flood",
      icon: <Zap className="text-purple-500 w-5 h-5" />,
      desc: "Detects an overwhelming number of UDP packets sent to random ports.",
      metric: "packets / 3s"
    },
    {
      id: "ICMPFloodThreshold",
      title: "ICMP Flood / Ping of Death",
      icon: <Server className="text-green-500 w-5 h-5" />,
      desc: "Detects massive ping requests designed to overwhelm network bandwidth.",
      metric: "packets / 3s"
    },
    {
      id: "PortScanThreshold",
      title: "Port Scanning",
      icon: <Search className="text-amber-500 w-5 h-5" />,
      desc: "Detects reconnaissance activity where an attacker probes multiple ports.",
      metric: "ports / 5s"
    },
    {
      id: "SSHBruteForceThreshold",
      title: "SSH Brute Force",
      icon: <Key className="text-red-500 w-5 h-5" />,
      desc: "Detects repeated, rapid SSH (Port 22) connection attempts.",
      metric: "attempts / 10s"
    },
    {
      id: "SuspiciousRateThreshold",
      title: "Generic DoS (Denial of Service)",
      icon: <AlertTriangle className="text-orange-500 w-5 h-5" />,
      desc: "Detects unusually high packet rates from a single source IP.",
      metric: "packets / sec"
    }
  ];

  const signatureAttacks = [
    { title: "SQL Injection", icon: <Code2 className="text-cyan-500 w-5 h-5" />, desc: "Detects malicious SQL queries (e.g. UNION SELECT, OR 1=1) in HTTP payloads." },
    { title: "Cross-Site Scripting (XSS)", icon: <Terminal className="text-pink-500 w-5 h-5" />, desc: "Detects malicious script injections and XSS vectors in web traffic." },
    { title: "Command Injection", icon: <Terminal className="text-purple-500 w-5 h-5" />, desc: "Detects unauthorized OS command executions (e.g. cat /etc/passwd)." },
    { title: "Buffer Overflow / NOP Sled", icon: <Target className="text-red-500 w-5 h-5" />, desc: "Detects memory corruption attempts and shellcode executions." },
    { title: "Malware & C2 Traffic", icon: <Zap className="text-rose-500 w-5 h-5" />, desc: "Detects reverse shells (like Meterpreter) communicating with attackers." },
    { title: "Cleartext / SSL Stripping", icon: <Shield className="text-yellow-500 w-5 h-5" />, desc: "Detects unencrypted passwords sent over cleartext connections." },
    { title: "FTP/Telnet Brute-Force", icon: <Key className="text-orange-500 w-5 h-5" />, desc: "Detects repeated authentication failures over unencrypted protocols." },
    { title: "Protocol Anomalies", icon: <Activity className="text-blue-500 w-5 h-5" />, desc: "Detects malformed HTTP methods and protocol specification violations." },
    { title: "Directory Traversal", icon: <FileCode2 className="text-yellow-500 w-5 h-5" />, desc: "Detects attempts to access unauthorized files using ../ patterns." },
    { title: "MAC Flooding", icon: <Target className="text-indigo-500 w-5 h-5" />, desc: "Detects CAM table exhaustion attacks (automatically blocks at 100 MACs/s)." },
  ];

  return (
    <div className="h-full flex flex-col gap-6 p-2 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-black tracking-tight text-glow flex items-center gap-3">
            <Shield className="w-10 h-10 text-primary" />
            Attack Detection Engine
          </h1>
          <p className="text-muted-foreground mt-2 text-lg">
            Comprehensive list of detectable threats and heuristic threshold tuning.
          </p>
        </div>
        <button 
          onClick={handleSave}
          disabled={isSaving}
          className="flex items-center gap-2 bg-primary/20 hover:bg-primary/40 text-primary font-bold py-3 px-6 rounded-xl transition-all shadow-[0_0_15px_rgba(var(--primary),0.3)] hover:shadow-[0_0_25px_rgba(var(--primary),0.5)] border border-primary/30"
        >
          {isSaving ? <div className="w-5 h-5 border-2 border-primary/30 border-t-primary rounded-full animate-spin" /> : <Save className="w-5 h-5" />}
          {isSaving ? 'Saving...' : 'Apply Thresholds'}
        </button>
      </header>

      {message.text && (
        <div className={`p-4 rounded-xl border ${message.type === 'success' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
          {message.text}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 overflow-y-auto pb-10 pr-2 custom-scrollbar">
        
        {/* Heuristic Attacks */}
        <section className="flex flex-col gap-4">
          <h2 className="text-2xl font-bold border-b border-border/50 pb-2 flex items-center gap-2">
            <Activity className="w-6 h-6 text-primary" />
            Heuristic Detection (Tunable)
          </h2>
          <div className="grid gap-4">
            {attackTypes.map(attack => (
              <div key={attack.id} className="kinetic-card p-5 rounded-xl border border-border/20 hover:border-primary/30 transition-all flex flex-col gap-4">
                <div className="flex justify-between items-start">
                  <div className="flex gap-3">
                    <div className="p-2 bg-white/5 rounded-lg border border-white/10 h-fit">
                      {attack.icon}
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{attack.title}</h3>
                      <p className="text-sm text-muted-foreground mt-1">{attack.desc}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/30 p-4 rounded-lg border border-white/5 flex items-center gap-4">
                  <label className="text-sm font-medium whitespace-nowrap min-w-[120px]">Trigger Threshold:</label>
                  <input 
                    type="range" 
                    min="1" 
                    max={attack.id === 'SuspiciousRateThreshold' ? 20000 : 1000} 
                    value={thresholds[attack.id as keyof Thresholds]} 
                    onChange={(e) => updateThreshold(attack.id as keyof Thresholds, e.target.value)}
                    className="flex-1 accent-primary"
                  />
                  <div className="flex items-center gap-2 bg-background border border-border/50 px-3 py-1.5 rounded-lg w-40 justify-end">
                    <input 
                      type="number"
                      value={thresholds[attack.id as keyof Thresholds]}
                      onChange={(e) => updateThreshold(attack.id as keyof Thresholds, e.target.value)}
                      className="bg-transparent w-16 text-right font-mono outline-none text-primary font-bold"
                    />
                    <span className="text-xs text-muted-foreground w-16">{attack.metric}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Signature Attacks */}
        <section className="flex flex-col gap-4">
          <h2 className="text-2xl font-bold border-b border-border/50 pb-2 flex items-center gap-2">
            <Code2 className="w-6 h-6 text-cyan-500" />
            Signature-Based Detection
          </h2>
          <div className="grid gap-4">
            <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 text-sm text-primary mb-2 flex flex-col gap-2">
              <p>These attacks are detected dynamically using the Snort Rule Engine via deep packet inspection.</p>
              <p className="font-bold border-t border-primary/20 pt-2">
                💡 Want to detect 50,000+ attacks? Just drop standard Snort community .rules files into your `backend/rules/` folder!
              </p>
            </div>
            
            {signatureAttacks.map((attack, i) => (
              <div key={i} className="kinetic-card p-5 rounded-xl border border-border/20 flex gap-4 items-center">
                <div className="p-3 bg-white/5 rounded-xl border border-white/10">
                  {attack.icon}
                </div>
                <div>
                  <h3 className="font-bold text-lg">{attack.title}</h3>
                  <p className="text-sm text-muted-foreground">{attack.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import useSWR from 'swr';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, ShieldAlert, Cpu, ActivitySquare } from 'lucide-react';
import { AreaChart, Area, ResponsiveContainer, XAxis, Tooltip, YAxis } from 'recharts';
import './index.css';

// Usamos el path relativo provisto por NGINX si estamos en docker, o localhost si en dev
const PROM_URL = import.meta.env.VITE_PROM_URL || '/api/v1/query';
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:9091';

const fetcher = async (query) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);
  try {
    const res = await fetch(`${PROM_URL}?query=${encodeURIComponent(query)}`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!res.ok) throw new Error('Network response was not ok');
    return res.json();
  } catch (error) {
    throw error;
  }
};

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'k';
  return num.toString();
}

export default function App() {
  const [history, setHistory] = useState([]);
  const [isOffline, setIsOffline] = useState(false);

  // Queries
  const { data: epsData, error: epsError } = useSWR('rate(pentagensec_ebpf_packets_total[1s])', fetcher, { refreshInterval: 1000 });
  const { data: hitsData } = useSWR('sum(rate(pentagensec_ebpf_regex_hits_total[1s]))', fetcher, { refreshInterval: 1000 });
  const { data: dropsData } = useSWR('rate(pentagensec_ebpf_consensus_drops_total[1s])', fetcher, { refreshInterval: 1000 });
  const { data: tailCallFails } = useSWR('pentagensec_ebpf_tail_call_fails', fetcher, { refreshInterval: 1000 });
  const { data: blocksData } = useSWR('sum(rate(pentagensec_soar_actions_total{type="block"}[1m]))', fetcher, { refreshInterval: 1000 });
  const { data: tarpitData } = useSWR('sum(rate(pentagensec_soar_actions_total{type="tarpit"}[1m]))', fetcher, { refreshInterval: 1000 });
  const { data: mlScoreData } = useSWR('histogram_quantile(0.99, rate(pentagensec_ml_score_bucket[1m]))', fetcher, { refreshInterval: 1000 });

  const [autoBlock, setAutoBlock] = useState(false);
  const [blockedIps, setBlockedIps] = useState([]);
  const [explainData, setExplainData] = useState(null);

  const fetchExplain = async (ip) => {
    try {
      const res = await fetch(`${API_URL}/api/v1/ml/explain/${ip}`);
      if (res.ok) {
        setExplainData(await res.json());
      }
    } catch(e) {}
  };

  useEffect(() => {
    const fetchActions = async () => {
      try {
        const res = await fetch(`${API_URL}/api/v1/soar/actions`);
        if (res.ok) setBlockedIps(await res.json());
      } catch(e){}
    };
    fetchActions();
    const intv = setInterval(fetchActions, 2000);
    return () => clearInterval(intv);
  }, []);

  const toggleAutoBlock = async () => {
    const nextState = !autoBlock;
    setAutoBlock(nextState);
    await fetch(`${API_URL}/api/v1/soar/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auto_block: nextState })
    });
  };

  const unblockIp = async (ip) => {
    await fetch(`${API_URL}/api/v1/soar/actions/${ip}`, { method: 'DELETE' });
    setBlockedIps(prev => prev.filter(x => x.ip_src !== ip));
  };

  useEffect(() => {
    if (epsError) {
      setIsOffline(true);
    } else if (epsData) {
      setIsOffline(false);
      const eps = parseFloat(epsData?.data?.result[0]?.value[1] || 0);
      const hits = parseFloat(hitsData?.data?.result[0]?.value[1] || 0);
      const drops = parseFloat(dropsData?.data?.result[0]?.value[1] || 0);
      const time = new Date().toLocaleTimeString();

      setHistory(prev => {
        const next = [...prev, { time, eps, hits, drops }];
        if (next.length > 20) next.shift();
        return next;
      });
    }
  }, [epsData, hitsData, dropsData, epsError]);

  const currentEps = history.length > 0 ? history[history.length - 1].eps : 0;
  const currentHits = history.length > 0 ? history[history.length - 1].hits : 0;
  const currentDrops = history.length > 0 ? history[history.length - 1].drops : 0;
  const failsCount = parseFloat(tailCallFails?.data?.result[0]?.value[1] || 0);
  const blocksPerSec = parseFloat(blocksData?.data?.result[0]?.value[1] || 0);
  const tarpitsPerSec = parseFloat(tarpitData?.data?.result[0]?.value[1] || 0);
  const mlScore = parseFloat(mlScoreData?.data?.result[0]?.value[1] || 0);

  // SOAR Animation (red ray)
  const [showBlockRay, setShowBlockRay] = useState(false);
  const [tarpitVibrate, setTarpitVibrate] = useState(false);
  useEffect(() => {
    if (blocksPerSec > 0 || tarpitsPerSec > 0) {
      setShowBlockRay(true);
      setTimeout(() => setShowBlockRay(false), 500);
      if (tarpitsPerSec > 0) {
          setTarpitVibrate(true);
          setTimeout(() => setTarpitVibrate(false), 30000); // Vibrate for 30s
      }
    }
  }, [blocksPerSec, tarpitsPerSec]);

  // Hit Stream Particles
  const [particles, setParticles] = useState([]);
  useEffect(() => {
    if (currentHits > 0) {
      const newParticles = Array.from({ length: Math.min(currentHits, 10) }).map((_, i) => ({
        id: Date.now() + i,
        x: Math.random() * 100,
      }));
      setParticles(p => [...p, ...newParticles].slice(-30));
    }
  }, [currentHits]);

  return (
    <div className="dashboard">
      <header className="header">
        <h1>Pentagen<span className="accent">Sec</span></h1>
        
        <div className="soar-toggle">
          <label>
            <input type="checkbox" checked={autoBlock} onChange={toggleAutoBlock} />
            Auto-Remediation (SOAR)
          </label>
        </div>

        <motion.div 
          className={`status-badge ${isOffline ? 'offline' : ''}`}
          animate={tarpitVibrate ? { x: [-10, 10, -10, 10, 0], backgroundColor: 'rgba(239,68,68,0.8)' } : (showBlockRay ? { x: [-5, 5, -5, 5, 0], backgroundColor: 'rgba(239,68,68,0.5)' } : {})}
          transition={{ duration: tarpitVibrate ? 0.1 : 0.3, repeat: tarpitVibrate ? Infinity : 0 }}
        >
          <div className={`status-dot ${isOffline ? 'offline' : ''}`}></div>
          {isOffline ? 'SYSTEM OFFLINE' : 'ADAPTIVE CORE ONLINE'}
          {tarpitVibrate && <span style={{marginLeft: '10px', fontSize: '0.8em'}}>🔥 TARPIT ACTIVE</span>}
        </motion.div>
      </header>

      <AnimatePresence>
        {failsCount > 0 && (
          <motion.div 
            className="critical-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <h1>SLA BREACH</h1>
            <p>Tail Call Fails Detected: {failsCount}</p>
            <p>eBPF Verifier Complexity Exceeded</p>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="grid">
        <motion.div className="glass-panel" layout>
          <h3><Activity size={18} /> Network Throughput (EPS)</h3>
          <motion.p 
            className={`value-display ${currentEps > 8000000 ? 'danger' : ''}`}
            key={currentEps}
            initial={{ scale: 1.1 }}
            animate={{ scale: 1 }}
          >
            {formatNumber(currentEps)}
          </motion.p>
        </motion.div>

        <motion.div className="glass-panel" layout style={{ position: 'relative' }}>
          <h3><ShieldAlert size={18} /> Malicious Hits</h3>
          <p className="value-display">{formatNumber(currentHits)}</p>
          <div className="particle-container">
            <AnimatePresence>
              {particles.map(p => (
                <motion.div
                  key={p.id}
                  className="particle malicious"
                  initial={{ top: '100%', left: `${p.x}%`, opacity: 1 }}
                  animate={{ top: '-10%', opacity: 0 }}
                  transition={{ duration: 1, ease: 'easeOut' }}
                  onAnimationComplete={() => setParticles(arr => arr.filter(item => item.id !== p.id))}
                />
              ))}
              {showBlockRay && (
                <motion.div
                  className="block-ray"
                  initial={{ width: 0, opacity: 1 }}
                  animate={{ width: '100%', opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  style={{ position: 'absolute', top: '50%', left: '100%', height: '2px', background: 'red', zIndex: 100 }}
                />
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        <motion.div className="glass-panel" layout>
          <h3><Cpu size={18} /> Consensus Drops</h3>
          <p className="value-display">{formatNumber(currentDrops)}</p>
        </motion.div>

        <motion.div className="glass-panel soar-panel" layout>
          <h3>Blocks/s (SOAR)</h3>
          <p className="value-display accent">{formatNumber(blocksPerSec)}</p>
        </motion.div>
        
        <motion.div className="glass-panel soar-panel" layout>
          <h3>Attackers Tarred</h3>
          <p className="value-display danger">{formatNumber(tarpitsPerSec)}</p>
        </motion.div>

        <motion.div className="glass-panel soar-panel" layout>
          <h3>ML Anomaly Score</h3>
          <p className={`value-display ${mlScore > 38 ? 'danger' : 'accent'}`}>{mlScore.toFixed(1)}</p>
          {mlScore > 38 && <span style={{color: 'red', fontSize: '0.8rem'}}>SHADOW MODE</span>}
        </motion.div>
      </main>

      <section className="glass-panel" style={{ flex: 1, minHeight: '300px' }}>
        <h3><ActivitySquare size={18} /> EPS Telemetry Stream</h3>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={history}>
            <defs>
              <linearGradient id="colorEps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorHits" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <XAxis dataKey="time" hide />
            <YAxis hide />
            <Tooltip contentStyle={{ backgroundColor: 'rgba(15,15,20,0.9)', border: '1px solid rgba(255,255,255,0.1)' }} />
            <Area type="monotone" dataKey="eps" stroke="#3B82F6" fillOpacity={1} fill="url(#colorEps)" isAnimationActive={false} />
            <Area type="monotone" dataKey="hits" stroke="#EF4444" fillOpacity={1} fill="url(#colorHits)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </section>

      <section className="glass-panel blocked-ips">
        <h3>Active Blocks & Tarpits (SOAR)</h3>
        <table>
          <thead>
            <tr><th>IP Source</th><th>Action</th><th></th></tr>
          </thead>
          <tbody>
            {blockedIps.map(entry => (
              <tr key={entry.ip_src}>
                <td style={{cursor: 'pointer', textDecoration: 'underline'}} onClick={() => fetchExplain(entry.ip_src)}>{entry.ip_src}</td>
                <td className={entry.action === 'TARPIT' ? 'danger' : 'accent'}>{entry.action}</td>
                <td><button onClick={() => unblockIp(entry.ip_src)}>Unblock</button></td>
              </tr>
            ))}
            {blockedIps.length === 0 && (
              <tr><td colSpan="3" style={{textAlign:'center', opacity:0.5}}>No IPs blocked/tarred</td></tr>
            )}
          </tbody>
        </table>
      </section>

      <AnimatePresence>
        {explainData && (
          <motion.div 
            className="modal-overlay"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={() => setExplainData(null)}
          >
            <motion.div className="glass-panel modal-content" onClick={e => e.stopPropagation()}>
              <h3><Activity size={18} /> ML Explanation for {explainData.ip}</h3>
              <p>Score: <span className="danger">{explainData.score}</span> (Threshold: {explainData.threshold})</p>
              <ul>
                {explainData.top_features.map(f => (
                  <li key={f.name}><strong>{f.name}</strong>: {f.value} - <em>{f.description}</em></li>
                ))}
              </ul>
              <button onClick={() => setExplainData(null)} style={{marginTop: '15px'}}>Close</button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

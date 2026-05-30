import React, { useState, useEffect } from 'react';

// Simulación de la respuesta del backend FastAPI (Polling)
const fetchMetrics = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      // Simulamos la fluctuación del score. 
      // La mayoría de las veces será normal (10-25), a veces habrá picos (35-48)
      const isAnomaly = Math.random() > 0.85;
      const baseScore = isAnomaly ? 38 + Math.random() * 10 : 10 + Math.random() * 15;
      resolve({ ml_score_p99: baseScore.toFixed(1) });
    }, 150); // Delay simulado de red
  });
};

export default function MLAnomalyGauge() {
  const [score, setScore] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Carga inicial
    fetchMetrics().then(data => {
      setScore(parseFloat(data.ml_score_p99));
      setIsLoading(false);
    });
    
    // Polling cada 1 segundo como solicitaste
    const interval = setInterval(async () => {
      const data = await fetchMetrics();
      setScore(parseFloat(data.ml_score_p99));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // Lógica de colores (Grafana Style: Verde 0-30, Ámbar 30-42, Rojo 42-100)
  let statusColor = 'text-emerald-400';
  let strokeColor = '#34d399'; // emerald-400
  let bgColorClass = 'bg-emerald-400/10 border-emerald-400/20';
  let statusText = 'NORMAL';
  let glowColor = 'drop-shadow-[0_0_8px_rgba(52,211,153,0.3)]';

  if (score >= 42) {
    statusColor = 'text-rose-500';
    strokeColor = '#f43f5e'; // rose-500
    bgColorClass = 'bg-rose-500/10 border-rose-500/30 animate-pulse';
    statusText = 'CRÍTICO';
    glowColor = 'drop-shadow-[0_0_15px_rgba(244,63,94,0.6)]';
  } else if (score >= 30) {
    statusColor = 'text-amber-400';
    strokeColor = '#fbbf24'; // amber-400
    bgColorClass = 'bg-amber-400/10 border-amber-400/20';
    statusText = 'ALERTA';
    glowColor = 'drop-shadow-[0_0_12px_rgba(251,191,36,0.4)]';
  }

  // Matemáticas para el semicírculo SVG
  const radius = 80;
  const circumference = Math.PI * radius; // Pi * R para un semicírculo
  const percent = Math.min(Math.max(score, 0), 100);
  const strokeDashoffset = circumference - (percent / 100) * circumference;

  return (
    <div className="flex flex-col items-center p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl max-w-xs w-full font-sans relative overflow-hidden group hover:border-slate-700 transition-colors duration-300">
      
      {/* Glow de fondo para darle toque premium de SOC */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-1/2 bg-gradient-to-b from-slate-800/50 to-transparent pointer-events-none" />

      {/* Cabecera del Widget */}
      <div className="flex justify-between items-center w-full mb-8 relative z-10">
        <h2 className="text-slate-300 font-medium text-xs tracking-[0.2em] uppercase">ML Anomaly Score</h2>
        <div className={`px-2.5 py-1 text-[10px] font-bold tracking-widest rounded border ${bgColorClass} ${statusColor} uppercase transition-colors duration-500`}>
          {statusText}
        </div>
      </div>

      {/* Visualización del Gauge (SVG nativo para mejor control y performance que Recharts) */}
      <div className="relative flex justify-center items-end mt-2" style={{ width: '200px', height: '100px' }}>
        
        {/* Track / Fondo del Gauge */}
        <svg className="absolute top-0 left-0" width="200" height="100" viewBox="0 0 200 100">
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke="#1e293b" // slate-800
            strokeWidth="16"
            strokeLinecap="round"
          />
        </svg>

        {/* Indicador de Valor / Arco dinámico */}
        <svg 
          className={`absolute top-0 left-0 ${glowColor} transition-all duration-700 ease-[cubic-bezier(0.4,0,0.2,1)]`} 
          width="200" 
          height="100" 
          viewBox="0 0 200 100"
        >
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke={strokeColor}
            strokeWidth="16"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={isLoading ? circumference : strokeDashoffset}
            className="transition-all duration-700 ease-[cubic-bezier(0.4,0,0.2,1)]"
          />
        </svg>

        {/* Lectura del Score en el centro */}
        <div className="absolute bottom-0 flex flex-col items-center transform translate-y-3">
          <span className={`text-5xl font-black tabular-nums tracking-tighter ${statusColor} transition-colors duration-700 drop-shadow-md`}>
            {score.toFixed(1)}
          </span>
        </div>
      </div>

      {/* Etiquetas Min/Max del Eje */}
      <div className="w-full flex justify-between px-6 mt-5 text-slate-600 text-[10px] font-bold tracking-wider relative z-10">
        <span>0.0</span>
        <span>100.0</span>
      </div>
      
    </div>
  );
}

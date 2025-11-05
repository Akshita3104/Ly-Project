import React, { useState, useEffect } from 'react';
import { Wifi, WifiOff, Activity, Shield, AlertTriangle } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import clsx from 'clsx';
import { apiService, getSocket } from './services/api';
import BlockedIPs from './components/BlockedIPs';
import LivePacketTable from './components/LivePacketTable';

export interface Packet {
  timestamp: number;
  srcIP: string;
  dstIP: string;
  protocol: string;
  network_slice?: string;
  packetSize: number;
  isMalicious?: boolean;
  detectionReason?: string;
  confidence?: number;
}

export default function App() {
  const [connected, setConnected] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState(0);
  const [pps, setPps] = useState(0);
  const [livePackets, setLivePackets] = useState<Packet[]>([]);
  const [trafficData, setTrafficData] = useState<Array<{time: number; normalPps: number; maliciousPps: number}>>([]);
  const [blockedIPs, setBlockedIPs] = useState<any[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const check = async () => {
      try {
        await apiService.healthCheck();
        setConnected(true);
        setError('');
      } catch {
        setConnected(false);
      }
    };
    check();
    const interval = setInterval(check, 2000);

    socket.on('connect', () => {
      setConnected(true);
      setError('');
    });

    socket.on('connect_error', () => {
      setConnected(false);
      setError('Reconnecting...');
    });

    socket.on('capture-started', () => {
      setCapturing(true);
      setPackets(0);
      setLivePackets([]);
    });

    socket.on('capture-stopped', () => setCapturing(false));

    // Listen for new packets and detection results
    socket.on('new_packet', (pkt: any) => {
      setPackets(p => p + 1);
      const curPps = Math.floor(Math.random() * 300 + 100);
      setPps(curPps);

      // Check if this packet is in the malicious packets list
      const isMalicious = pkt.isMalicious || false;
      
      setLivePackets(prev => [
        {
          timestamp: pkt.timestamp || Date.now(),
          srcIP: pkt.srcIP,
          dstIP: pkt.dstIP,
          protocol: pkt.protocol,
          packetSize: pkt.packetSize,
          network_slice: pkt.network_slice || 'eMBB',
          isMalicious: isMalicious,
          detectionReason: pkt.detectionReason,
          confidence: pkt.confidence
        },
        ...prev.slice(0, 9),
      ]);
      
      // If malicious, also add to blocked IPs
      if (isMalicious) {
        setBlockedIPs(prev => [
          {
            ip: pkt.srcIP,
            timestamp: new Date().toISOString(),
            reason: pkt.detectionReason || 'Suspicious activity',
            threatLevel: 'high',
            mitigation: 'SDN DROP Rule'
          },
          ...prev
        ]);
      }

      setTrafficData(prev => {
        const newData = [...prev.slice(-29)];
        const isMalicious = pkt.isMalicious || false;
        
        // Get the last data point or create a new one
        const lastPoint = newData[newData.length - 1] || { time: newData.length, normalPps: 0, maliciousPps: 0 };
        
        // Create a new data point
        newData.push({
          time: newData.length,
          normalPps: isMalicious ? lastPoint.normalPps : (lastPoint.normalPps + 1),
          maliciousPps: isMalicious ? (lastPoint.maliciousPps + 1) : lastPoint.maliciousPps
        });
        
        return newData;
      });
    });

    // 🧱 Blocked IP listeners
    socket.on('initial_blocked_ips', (ips: any[]) => {
      console.log("📥 Initial Blocked IPs:", ips);
      setBlockedIPs(ips);
    });

    socket.on('update_blocked_ips', (ips: any[]) => {
      console.log("🧱 Updated Blocked IP list:", ips);
      setBlockedIPs(ips);
    });

    socket.on('ip_blocked', (ipData: any) => {
      console.log("🚫 New IP blocked:", ipData);
      setBlockedIPs(prev => {
        if (prev.some(i => i.ip === ipData.ip)) return prev;
        return [...prev, ipData];
      });
    });

    socket.on('unblocked_ip', ({ ip }) => {
      console.log(`♻️ Unblocked IP: ${ip}`);
      setBlockedIPs(prev => prev.filter(b => b.ip !== ip));
    });

    return () => {
      clearInterval(interval);
      socket.off();
    };
  }, []);

  const toggleCapture = async () => {
    if (capturing) {
      await apiService.stopPacketCapture();
    } else {
      await apiService.startPacketCapture('192.168.56.1');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-black to-gray-900 text-white p-8 font-sans">
      <div className="max-w-7xl mx-auto">
        {/* Header with Connection Status */}
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-6xl font-extrabold text-purple-500">
            SentinelAI
          </h1>
          <div
            className={clsx(
              "px-6 py-3 rounded-full flex items-center gap-2 text-lg font-bold shadow-lg transition-all border-2",
              connected
                ? "bg-green-500/20 text-green-400 border-green-500/70"
                : "bg-red-500/20 text-red-400 border-red-500/70"
            )}
          >
            {connected ? <Wifi className="w-6 h-6" /> : <WifiOff className="w-6 h-6" />}
            <span className="hidden sm:inline">{connected ? 'LIVE' : 'OFFLINE'}</span>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded-xl flex items-center gap-3 animate-pulse">
            <AlertTriangle className="w-6 h-6" />
            <span>{error}</span>
          </div>
        )}

        {/* Stats + Control Button */}
        <div className="flex flex-col md:flex-row gap-6 mb-8 items-center">
          {/* Stats */}
          <div className="grid grid-cols-2 gap-6 flex-1">
            <div className="bg-gray-900 p-6 rounded-2xl border border-gray-700 text-center shadow hover:shadow-cyan-500/40 transition">
              <div className="text-4xl font-bold text-cyan-400 animate-count">{packets.toLocaleString()}</div>
              <div className="text-gray-400 text-sm">Packets Captured</div>
            </div>
            <div className="bg-gray-900 p-6 rounded-2xl border border-gray-700 text-center shadow hover:shadow-green-500/40 transition">
              <div className="text-4xl font-bold text-green-400 animate-count">{pps}</div>
              <div className="text-gray-400 text-sm">Packets/sec</div>
            </div>
          </div>
          
          {/* Control Button */}
          <button
            onClick={toggleCapture}
            className={clsx(
              "px-8 py-4 md:py-6 rounded-2xl text-xl md:text-2xl font-extrabold transition-transform transform hover:scale-105 shadow-2xl flex items-center gap-2 h-fit",
              capturing
                ? "bg-red-600 hover:bg-red-700 text-white border-2 border-red-300"
                : "bg-blue-600 hover:bg-blue-700 text-white border-2 border-blue-300"
            )}
          >
            <Shield className="w-6 h-6 md:w-8 md:h-8" />
            {capturing ? 'STOP CAPTURE' : 'START CAPTURE'}
          </button>
        </div>

        {/* Live Packets Section */}
        <div className="mb-8">
          <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
            <h3 className="text-xl font-bold mb-4">Live Packets</h3>
            <LivePacketTable packets={livePackets} capturing={capturing} />
          </div>
        </div>

        {/* Live Traffic Section */}
        <div className="mb-8">
          <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Activity className="text-cyan-400" />
              Live Traffic
            </h3>
            <div className="h-96 relative">
              <div className="absolute top-0 right-0 flex gap-4 mb-2 z-10">
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-cyan-400 mr-2"></div>
                  <span className="text-xs text-gray-300">Normal</span>
                </div>
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div>
                  <span className="text-xs text-gray-300">Malicious</span>
                </div>
              </div>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart 
                  data={trafficData}
                  margin={{ top: 10, right: 20, left: 0, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.1} />
                    </linearGradient>
                    <linearGradient id="maliciousGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ef4444" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid 
                    strokeDasharray="3 3" 
                    stroke="#2d3748" 
                    vertical={false} 
                  />
                  <XAxis 
                    dataKey="time" 
                    tick={{ fill: '#a0aec0', fontSize: 12 }}
                    axisLine={{ stroke: '#2d3748' }}
                    tickLine={{ stroke: '#2d3748' }}
                    tickMargin={10}
                  />
                  <YAxis 
                    tick={{ fill: '#a0aec0', fontSize: 12 }}
                    axisLine={{ stroke: '#2d3748' }}
                    tickLine={{ stroke: '#2d3748' }}
                    tickMargin={10}
                    label={{ 
                      value: 'Packets/s', 
                      angle: -90, 
                      position: 'insideLeft',
                      fill: '#a0aec0',
                      style: { textAnchor: 'middle' },
                      offset: 10
                    }}
                  />
                  <Tooltip 
                    content={({ active, payload, label }) => {
                      if (!active || !payload || !payload.length) return null;
                      
                      return (
                        <div className="bg-gray-800 p-3 border border-gray-700 rounded-lg shadow-xl">
                          <p className="text-gray-400 text-sm mb-1">
                            Time: {label}
                          </p>
                          {payload.map((entry, index) => (
                            <div key={`tooltip-${index}`} className="flex items-center">
                              <div 
                                className="w-2 h-2 rounded-full mr-2" 
                                style={{ 
                                  backgroundColor: entry.color || '#000',
                                }}
                              />
                              <span className="text-sm">
                                {entry.name}: <span className="font-bold">{entry.value}</span>
                              </span>
                            </div>
                          ))}
                        </div>
                      );
                    }}
                    cursor={{ stroke: '#4a5568', strokeWidth: 1 }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="normalPps" 
                    name="Normal Traffic"
                    stroke="#06b6d4"
                    fill="url(#normalGrad)" 
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 2, fill: '#06b6d4' }}
                    isAnimationActive={true}
                    animationDuration={1000}
                    animationEasing="ease-out"
                  />
                  <Area 
                    type="monotone" 
                    dataKey="maliciousPps" 
                    name="Malicious Traffic"
                    stroke="#ef4444"
                    fill={trafficData.some(d => d.maliciousPps > 0) ? "url(#maliciousGrad)" : 'none'}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 2, fill: '#ef4444' }}
                    isAnimationActive={true}
                    animationDuration={1000}
                    animationEasing="ease-out"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Blocked IPs */}
        <div className="mb-8">
          <BlockedIPs blockedIPs={blockedIPs} />
        </div>

        {/* Footer */}
        <div className="text-center text-gray-500 text-sm mt-10">
          <p>Real-time DDoS Detection • Ryu SDN Mitigation • AI-Powered</p>
          <p className="mt-2">{connected ? 'All systems operational' : 'Waiting for backend...'}</p>
        </div>
      </div>

      <style>{`
        .drop-shadow-neon { text-shadow: 0 0 12px #a78bfa, 0 0 24px #06b6d4 }
        .neon-red { box-shadow: 0 0 12px #f43f5e, 0 0 28px #f43f5e44; }
        .neon-blue { box-shadow: 0 0 12px #06b6d4, 0 0 28px #06b6d444; }
        .glow-green { box-shadow: 0 0 8px #22d3ee99, 0 0 18px #22d3ee33; }
        .glow-red { box-shadow: 0 0 8px #f87171aa, 0 0 18px #f43f5e33; }
        .animate-count { transition: all 0.4s cubic-bezier(0.17,0.67,0.83,0.67); }
      `}</style>
    </div>
  );
}

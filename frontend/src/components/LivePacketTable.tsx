import React from 'react';
import { Packet } from '../App';
import { AlertTriangle, Shield } from 'lucide-react';

// === PROTOCOL → COLOR MAPPING ===
const PROTOCOL_COLORS: Record<string, string> = {
  TCP:   'bg-emerald-600 text-white',
  UDP:   'bg-blue-600 text-white',
  ICMP:  'bg-yellow-600 text-white',
  IGMP:  'bg-orange-600 text-white',
  OSPF:  'bg-purple-600 text-white',
  ESP:   'bg-red-600 text-white',
  AH:    'bg-pink-600 text-white',
  IPv6:  'bg-indigo-600 text-white',
  // Fallback for unknown
  default: 'bg-gray-600 text-white'
};

const getProtocolColor = (protocol: string) => {
  return PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.default;
};

export default function LivePacketTable({
  packets,
  capturing
}: {
  packets: Packet[];
  capturing: boolean;
}) {
  if (packets.length === 0) {
    return (
      <div className="text-center text-gray-500 py-8 bg-gray-900/50 rounded-lg">
        {capturing ? (
          <div className="flex flex-col items-center justify-center space-y-2">
            <div className="animate-pulse">
              <div className="w-16 h-16 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
            <p>Capturing network traffic...</p>
          </div>
        ) : (
          'Start defense to see live packet capture'
        )}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto max-h-64">
      <table className="min-w-full text-sm font-mono border-collapse bg-gray-800 rounded-xl shadow">
        <thead>
          <tr className="bg-gradient-to-r from-cyan-600 to-purple-700 sticky top-0">
            <th className="px-4 py-2 text-left">Time</th>
            <th className="px-4 py-2 text-left">Source</th>
            <th className="px-4 py-2 text-left">Destination</th>
            <th className="px-4 py-2 text-left">Protocol</th>
            <th className="px-4 py-2 text-left">Slice</th>
            <th className="px-4 py-2 text-left">Size</th>
            <th className="px-4 py-2 text-left">Detection</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p, idx) => {
            const protoColor = getProtocolColor(p.protocol);

            return (
              <tr 
                key={idx} 
                className={`transition border-b ${
                  p.isMalicious 
                    ? p.packet_data?.simulated
                      ? 'bg-purple-900/20 hover:bg-purple-900/40 border-l-4 border-l-purple-500'
                      : 'bg-red-900/20 hover:bg-red-900/40 border-l-4 border-l-red-500'
                    : 'border-gray-700 hover:bg-cyan-900/20'
                }`}
              >
                <td className="px-4 py-2 text-gray-400 text-xs relative">
                  {p.isMalicious && p.packet_data?.simulated && (
                    <span className="absolute -left-1 top-1/2 transform -translate-y-1/2 w-1 h-1/2 bg-purple-500 rounded-r"></span>
                  )}
                  {new Date(p.timestamp).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: true
                  })}
                </td>
                <td className="px-4 py-2 font-mono">
                  <div className="flex items-center gap-1">
                    {p.isMalicious && p.packet_data?.simulated && (
                      <Shield className="w-3 h-3 text-purple-400" />
                    )}
                    {p.isMalicious && !p.packet_data?.simulated && (
                      <AlertTriangle className="w-3 h-3 text-red-400" />
                    )}
                    <span className={`${p.isMalicious ? (p.packet_data?.simulated ? 'text-purple-400' : 'text-red-400') : 'text-orange-400'} font-mono`}>
                      {p.srcIP}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-2 text-purple-300">{p.dstIP}</td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-1 rounded font-semibold text-xs ${protoColor}`}>
                    {p.protocol}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-1 rounded text-white text-xs ${
                    p.network_slice === 'eMBB' ? 'bg-purple-700/70' : 
                    p.network_slice === 'URLLC' ? 'bg-blue-600/70' : 'bg-green-600/70'
                  }`}>
                    {p.network_slice || 'eMBB'}
                  </span>
                </td>
                <td className="px-4 py-2 text-gray-200 font-mono">{p.packetSize}B</td>
                <td className="px-4 py-2">
                  {p.isMalicious ? (
                    <div className="flex items-center gap-1">
                      {p.packet_data?.simulated ? (
                        <span className="px-2 py-1 bg-purple-600/80 rounded text-white text-xs flex items-center gap-1">
                          <Shield className="w-3 h-3" />
                          Simulated
                          {p.confidence && (
                            <span className="ml-1 text-xs opacity-80">({(p.confidence * 100).toFixed(0)}%)</span>
                          )}
                        </span>
                      ) : (
                        <span className="px-2 py-1 bg-red-500/80 rounded text-white text-xs flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          Malicious
                          {p.confidence && (
                            <span className="ml-1 text-xs opacity-80">({(p.confidence * 100).toFixed(0)}%)</span>
                          )}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="px-2 py-1 bg-green-500/80 rounded text-white text-xs">
                      Normal
                      {p.confidence && (
                        <span className="ml-1 opacity-80">({((1 - (p.confidence || 0)) * 100).toFixed(0)}%)</span>
                      )}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
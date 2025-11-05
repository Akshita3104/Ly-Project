import { Packet } from '../App';

export default function LivePacketTable({
  packets,
  capturing
}: {
  packets: Packet[];
  capturing: boolean;
}) {
  if (packets.length === 0) {
    return (
      <p className="text-center text-gray-500 py-8">
        {capturing ? 'Capturing...' : 'Start defense to see packets'}
      </p>
    );
  }
  return (
    <div className="overflow-x-auto max-h-64">
      <table className="min-w-full text-sm font-mono border-collapse bg-gray-800 rounded-xl shadow">
        <thead>
          <tr className="bg-gradient-to-r from-cyan-600 to-purple-700 sticky top-0">
            <th className="px-4 py-2 text-left">Time</th>
            <th className="px-4 py-2 text-left">Source</th>
            <th className="px-4 py-2 text-left">→</th>
            <th className="px-4 py-2 text-left">Destination</th>
            <th className="px-4 py-2 text-left">Protocol</th>
            <th className="px-4 py-2 text-left">Slice</th>
            <th className="px-4 py-2 text-left">Size</th>
            <th className="px-4 py-2 text-left">Detection</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p, idx) => (
            <tr key={idx} className="hover:bg-cyan-900/40 transition border-b border-gray-700">
              <td className="px-4 py-2 text-gray-400 text-xs">
                {new Date(p.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: true})}
              </td>
              <td className="px-4 py-2 text-orange-400">{p.srcIP}</td>
              <td className="px-2 py-2 text-cyan-400">→</td>
              <td className="px-4 py-2 text-purple-300">{p.dstIP}</td>
              <td className="px-4 py-2">
                <span className="px-2 py-1 bg-blue-700/70 rounded text-white">{p.protocol}</span>
              </td>
              <td className="px-4 py-2">
                <span className="px-2 py-1 bg-purple-700/70 rounded text-white">{p.network_slice || 'eMBB'}</span>
              </td>
              <td className="px-4 py-2 text-gray-200">{p.packetSize}B</td>
              <td className="px-4 py-2">
                {p.isMalicious ? (
                  <span className="px-2 py-1 bg-red-500/80 rounded text-white text-xs">Malicious</span>
                ) : (
                  <span className="px-2 py-1 bg-green-500/80 rounded text-white text-xs">Normal</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

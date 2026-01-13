#!/usr/bin/env python3
"""
Capture Analysis Module
=======================
Uses pyshark to parse .pcap files and extract TCP metrics:
- TCP Window Size evolution
- RTT (Round Trip Time)
- Packet Inter-arrival Time (IAT)

Compares kernel signatures between legitimate and stealth streams.

Author: Senior Detection Engineer
"""

import pyshark
import sys
import argparse
import statistics
from collections import defaultdict
from typing import List, Dict, Tuple
import json


class TCPStreamAnalyzer:
    """Analyze TCP stream characteristics from pcap."""
    
    def __init__(self, pcap_file: str):
        """
        Initialize analyzer with pcap file.
        
        Args:
            pcap_file: Path to pcap file
        """
        self.pcap_file = pcap_file
        self.streams = defaultdict(list)
        
    def _extract_tcp_metrics(self, packet) -> Dict:
        """Extract TCP metrics from packet."""
        if not hasattr(packet, 'tcp'):
            return None
        
        metrics = {
            'timestamp': float(packet.sniff_timestamp),
            'stream': int(packet.tcp.stream) if hasattr(packet.tcp, 'stream') else None,
        }
        
        # Window size
        if hasattr(packet.tcp, 'window_size'):
            metrics['window_size'] = int(packet.tcp.window_size)
        elif hasattr(packet.tcp, 'window_size_value'):
            metrics['window_size'] = int(packet.tcp.window_size_value)
        else:
            metrics['window_size'] = None
        
        # Sequence and acknowledgment numbers
        if hasattr(packet.tcp, 'seq'):
            metrics['seq'] = int(packet.tcp.seq)
        if hasattr(packet.tcp, 'ack'):
            metrics['ack'] = int(packet.tcp.ack)
        
        # Length
        if hasattr(packet.tcp, 'len'):
            metrics['length'] = int(packet.tcp.len)
        else:
            metrics['length'] = 0
        
        # Flags
        if hasattr(packet.tcp, 'flags'):
            metrics['flags'] = packet.tcp.flags
        
        return metrics
    
    def parse_pcap(self, display_filter: str = None):
        """
        Parse pcap file and extract TCP metrics.
        
        Args:
            display_filter: Wireshark display filter (e.g., 'tcp.port == 8080')
        """
        print(f"[*] Parsing pcap file: {self.pcap_file}")
        
        try:
            cap = pyshark.FileCapture(
                self.pcap_file,
                display_filter=display_filter,
                keep_packets=False  # Don't keep all packets in memory
            )
            
            packet_count = 0
            for packet in cap:
                packet_count += 1
                metrics = self._extract_tcp_metrics(packet)
                
                if metrics and metrics['stream'] is not None:
                    stream_id = metrics['stream']
                    self.streams[stream_id].append(metrics)
                
                if packet_count % 1000 == 0:
                    print(f"[*] Processed {packet_count} packets...")
            
            cap.close()
            print(f"[+] Parsed {packet_count} packets")
            print(f"[+] Found {len(self.streams)} TCP streams")
            
        except Exception as e:
            print(f"[-] Error parsing pcap: {e}", file=sys.stderr)
            sys.exit(1)
    
    def calculate_rtt(self, stream_data: List[Dict]) -> List[float]:
        """
        Calculate RTT from packet timestamps and ACKs.
        This is a simplified RTT calculation.
        """
        rtt_values = []
        ack_times = {}  # Map ACK numbers to timestamps
        
        for packet in stream_data:
            if 'ack' in packet and packet['ack']:
                ack_times[packet['ack']] = packet['timestamp']
            
            if 'seq' in packet and packet['seq']:
                seq = packet['seq']
                # Look for corresponding ACK
                if seq in ack_times:
                    rtt = packet['timestamp'] - ack_times[seq]
                    if rtt > 0:
                        rtt_values.append(rtt * 1000)  # Convert to ms
        
        return rtt_values
    
    def calculate_iat(self, stream_data: List[Dict]) -> List[float]:
        """Calculate Inter-arrival Time between packets."""
        iat_values = []
        
        if len(stream_data) < 2:
            return iat_values
        
        for i in range(1, len(stream_data)):
            iat = (stream_data[i]['timestamp'] - stream_data[i-1]['timestamp']) * 1000  # ms
            if iat > 0:
                iat_values.append(iat)
        
        return iat_values
    
    def analyze_stream(self, stream_id: int) -> Dict:
        """
        Analyze a specific TCP stream.
        
        Args:
            stream_id: TCP stream ID
            
        Returns:
            Dictionary with analysis results
        """
        if stream_id not in self.streams:
            return None
        
        stream_data = self.streams[stream_id]
        if not stream_data:
            return None
        
        # Sort by timestamp
        stream_data.sort(key=lambda x: x['timestamp'])
        
        # Window size evolution
        window_sizes = [p['window_size'] for p in stream_data if p['window_size'] is not None]
        
        # RTT calculation
        rtt_values = self.calculate_rtt(stream_data)
        
        # Inter-arrival time
        iat_values = self.calculate_iat(stream_data)
        
        # Packet sizes
        packet_sizes = [p['length'] for p in stream_data if p.get('length', 0) > 0]
        
        analysis = {
            'stream_id': stream_id,
            'packet_count': len(stream_data),
            'duration': (stream_data[-1]['timestamp'] - stream_data[0]['timestamp']) * 1000,  # ms
            'total_bytes': sum(p.get('length', 0) for p in stream_data),
            'window_size': {
                'values': window_sizes,
                'min': min(window_sizes) if window_sizes else None,
                'max': max(window_sizes) if window_sizes else None,
                'mean': statistics.mean(window_sizes) if window_sizes else None,
                'stdev': statistics.stdev(window_sizes) if len(window_sizes) > 1 else None,
            },
            'rtt': {
                'values': rtt_values,
                'min': min(rtt_values) if rtt_values else None,
                'max': max(rtt_values) if rtt_values else None,
                'mean': statistics.mean(rtt_values) if rtt_values else None,
                'stdev': statistics.stdev(rtt_values) if len(rtt_values) > 1 else None,
            },
            'iat': {
                'values': iat_values,
                'min': min(iat_values) if iat_values else None,
                'max': max(iat_values) if iat_values else None,
                'mean': statistics.mean(iat_values) if iat_values else None,
                'stdev': statistics.stdev(iat_values) if len(iat_values) > 1 else None,
            },
            'packet_size': {
                'values': packet_sizes,
                'min': min(packet_sizes) if packet_sizes else None,
                'max': max(packet_sizes) if packet_sizes else None,
                'mean': statistics.mean(packet_sizes) if packet_sizes else None,
                'stdev': statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else None,
            }
        }
        
        return analysis
    
    def compare_streams(self, stream_ids: List[int]) -> Dict:
        """
        Compare multiple streams and generate summary.
        
        Args:
            stream_ids: List of stream IDs to compare
            
        Returns:
            Comparison summary
        """
        analyses = {}
        for stream_id in stream_ids:
            analysis = self.analyze_stream(stream_id)
            if analysis:
                analyses[stream_id] = analysis
        
        if len(analyses) < 2:
            return None
        
        comparison = {
            'streams': analyses,
            'summary': {}
        }
        
        # Compare key metrics
        for metric in ['window_size', 'rtt', 'iat', 'packet_size']:
            values = []
            for stream_id, analysis in analyses.items():
                if analysis[metric]['mean'] is not None:
                    values.append(analysis[metric]['mean'])
            
            if values:
                comparison['summary'][metric] = {
                    'mean_difference': max(values) - min(values),
                    'coefficient_of_variation': statistics.stdev(values) / statistics.mean(values) if len(values) > 1 else 0
                }
        
        return comparison


def print_analysis(analysis: Dict, label: str = ""):
    """Pretty print analysis results."""
    if not analysis:
        return
    
    print("\n" + "=" * 70)
    if label:
        print(f"Analysis: {label}")
    else:
        print(f"Stream Analysis: Stream {analysis['stream_id']}")
    print("=" * 70)
    
    print(f"\n[Basic Statistics]")
    print(f"  Packet Count: {analysis['packet_count']}")
    print(f"  Duration: {analysis['duration']:.2f} ms")
    print(f"  Total Bytes: {analysis['total_bytes']:,}")
    print(f"  Throughput: {(analysis['total_bytes'] / (analysis['duration'] / 1000)) / 1024:.2f} KB/s")
    
    print(f"\n[TCP Window Size]")
    ws = analysis['window_size']
    if ws['mean'] is not None:
        print(f"  Min: {ws['min']:,} bytes")
        print(f"  Max: {ws['max']:,} bytes")
        print(f"  Mean: {ws['mean']:.2f} bytes")
        if ws['stdev'] is not None:
            print(f"  Std Dev: {ws['stdev']:.2f} bytes")
    
    print(f"\n[Round Trip Time (RTT)]")
    rtt = analysis['rtt']
    if rtt['mean'] is not None:
        print(f"  Min: {rtt['min']:.2f} ms")
        print(f"  Max: {rtt['max']:.2f} ms")
        print(f"  Mean: {rtt['mean']:.2f} ms")
        if rtt['stdev'] is not None:
            print(f"  Std Dev: {rtt['stdev']:.2f} ms")
    
    print(f"\n[Inter-arrival Time (IAT)]")
    iat = analysis['iat']
    if iat['mean'] is not None:
        print(f"  Min: {iat['min']:.2f} ms")
        print(f"  Max: {iat['max']:.2f} ms")
        print(f"  Mean: {iat['mean']:.2f} ms")
        if iat['stdev'] is not None:
            print(f"  Std Dev: {iat['stdev']:.2f} ms")
    
    print(f"\n[Packet Size]")
    ps = analysis['packet_size']
    if ps['mean'] is not None:
        print(f"  Min: {ps['min']:,} bytes")
        print(f"  Max: {ps['max']:,} bytes")
        print(f"  Mean: {ps['mean']:.2f} bytes")
        if ps['stdev'] is not None:
            print(f"  Std Dev: {ps['stdev']:.2f} bytes")


def print_comparison(comparison: Dict):
    """Pretty print comparison results."""
    if not comparison:
        return
    
    print("\n" + "=" * 70)
    print("Kernel Signature Comparison")
    print("=" * 70)
    
    print("\n[Stream Summaries]")
    for stream_id, analysis in comparison['streams'].items():
        print(f"\n  Stream {stream_id}:")
        print(f"    Packets: {analysis['packet_count']}")
        print(f"    Duration: {analysis['duration']:.2f} ms")
        print(f"    Throughput: {(analysis['total_bytes'] / (analysis['duration'] / 1000)) / 1024:.2f} KB/s")
        if analysis['window_size']['mean']:
            print(f"    Avg Window Size: {analysis['window_size']['mean']:.2f} bytes")
        if analysis['rtt']['mean']:
            print(f"    Avg RTT: {analysis['rtt']['mean']:.2f} ms")
        if analysis['iat']['mean']:
            print(f"    Avg IAT: {analysis['iat']['mean']:.2f} ms")
        if analysis['packet_size']['mean']:
            print(f"    Avg Packet Size: {analysis['packet_size']['mean']:.2f} bytes")
    
    print("\n[Key Differences]")
    summary = comparison['summary']
    for metric, stats in summary.items():
        print(f"\n  {metric.upper().replace('_', ' ')}:")
        print(f"    Mean Difference: {stats['mean_difference']:.2f}")
        print(f"    Coefficient of Variation: {stats['coefficient_of_variation']:.4f}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze TCP streams from pcap and compare kernel signatures"
    )
    parser.add_argument('pcap', help='Path to pcap file')
    parser.add_argument(
        '--streams',
        type=int,
        nargs='+',
        help='Specific stream IDs to analyze (default: all streams)'
    )
    parser.add_argument(
        '--filter',
        help='Wireshark display filter (e.g., "tcp.port == 8080")'
    )
    parser.add_argument(
        '--compare',
        action='store_true',
        help='Compare multiple streams'
    )
    parser.add_argument(
        '--json',
        help='Output results to JSON file'
    )
    
    args = parser.parse_args()
    
    analyzer = TCPStreamAnalyzer(args.pcap)
    analyzer.parse_pcap(display_filter=args.filter)
    
    if not analyzer.streams:
        print("[-] No TCP streams found in pcap file")
        sys.exit(1)
    
    stream_ids = args.streams if args.streams else list(analyzer.streams.keys())
    
    if args.compare and len(stream_ids) >= 2:
        comparison = analyzer.compare_streams(stream_ids)
        if comparison:
            print_comparison(comparison)
            
            if args.json:
                with open(args.json, 'w') as f:
                    json.dump(comparison, f, indent=2)
                print(f"\n[+] Results saved to {args.json}")
    else:
        # Analyze individual streams
        for stream_id in stream_ids:
            analysis = analyzer.analyze_stream(stream_id)
            if analysis:
                label = f"Stream {stream_id}"
                print_analysis(analysis, label)
                
                if args.json:
                    json_file = args.json.replace('.json', f'_stream_{stream_id}.json')
                    with open(json_file, 'w') as f:
                        json.dump(analysis, f, indent=2)
                    print(f"[+] Results saved to {json_file}")


if __name__ == '__main__':
    main()

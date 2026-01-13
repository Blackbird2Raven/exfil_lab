#!/usr/bin/env python3
"""
Test Server for Dual-Stream Network Research Lab
=================================================
Simple TCP server to receive data from legit_stream.py and stealth_exfil.py
for testing and packet capture.

Author: Senior Detection Engineer
"""

import socket
import sys
import argparse
import threading
from datetime import datetime


class TestServer:
    """Simple TCP server for receiving test data."""
    
    def __init__(self, host: str, port: int):
        """
        Initialize test server.
        
        Args:
            host: Hostname or IP to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        
    def handle_client(self, client_sock: socket.socket, addr: tuple):
        """
        Handle client connection.
        
        Args:
            client_sock: Client socket
            addr: Client address tuple
        """
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        total_received = 0
        packet_count = 0
        start_time = datetime.now()
        
        try:
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                
                total_received += len(data)
                packet_count += 1
                
                # Progress indicator
                if packet_count % 100 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (total_received / elapsed) / 1024 if elapsed > 0 else 0
                    print(f"[*] Received: {total_received:,} bytes | "
                          f"Packets: {packet_count} | "
                          f"Rate: {rate:.2f} KB/s")
            
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"[+] Transfer completed from {addr[0]}:{addr[1]}")
            print(f"[*] Total bytes: {total_received:,}")
            print(f"[*] Total packets: {packet_count}")
            print(f"[*] Duration: {elapsed:.2f} seconds")
            print(f"[*] Average rate: {(total_received / elapsed) / 1024:.2f} KB/s")
            
        except Exception as e:
            print(f"[-] Error handling client: {e}", file=sys.stderr)
        finally:
            client_sock.close()
            print(f"[*] Connection to {addr[0]}:{addr[1]} closed")
    
    def start(self):
        """Start the server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            print("=" * 60)
            print("Test Server for Dual-Stream Network Research Lab")
            print("=" * 60)
            print(f"[*] Listening on {self.host}:{self.port}")
            print(f"[*] Ready to receive connections...")
            print("=" * 60)
            
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, addr),
                        daemon=True
                    )
                    client_thread.start()
                except OSError:
                    if self.running:
                        raise
                    
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        except Exception as e:
            print(f"[-] Server error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()
            print("[*] Server stopped")
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.sock:
            self.sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Test server for receiving data from legit_stream.py and stealth_exfil.py"
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0 - all interfaces)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    
    args = parser.parse_args()
    
    server = TestServer(args.host, args.port)
    server.start()


if __name__ == '__main__':
    main()

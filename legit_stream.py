#!/usr/bin/env python3
"""
Legit Stream Module
===================
Sends a large file using standard socket or HTTP methods, allowing the Linux
Kernel (Cubic/BBR) to manage window scaling naturally.

Author: Senior Detection Engineer
"""

import socket
import sys
import argparse
import time
from pathlib import Path


def send_file_socket(host: str, port: int, file_path: str, chunk_size: int = 8192):
    """
    Send file using standard TCP socket, letting kernel manage window scaling.
    
    Args:
        host: Target hostname or IP
        port: Target port
        file_path: Path to file to send
        chunk_size: Standard chunk size (kernel will optimize)
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    print(f"[*] Connecting to {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
        
        # Let kernel handle TCP options naturally
        # No manual TCP_NODELAY or TCP_CORK manipulation
        
        with open(file_path, 'rb') as f:
            total_sent = 0
            file_size = file_path.stat().st_size
            start_time = time.time()
            
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                sent = sock.send(chunk)
                total_sent += sent
                
                # Progress indicator
                if total_sent % (1024 * 1024) == 0:  # Every MB
                    progress = (total_sent / file_size) * 100
                    print(f"[*] Progress: {progress:.2f}% ({total_sent}/{file_size} bytes)")
            
            elapsed = time.time() - start_time
            print(f"[+] File sent successfully")
            print(f"[*] Total bytes: {total_sent}")
            print(f"[*] Time elapsed: {elapsed:.2f} seconds")
            print(f"[*] Average throughput: {(total_sent / elapsed) / 1024:.2f} KB/s")
            
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()
        print("[*] Connection closed")


def send_file_http(host: str, port: int, file_path: str, endpoint: str = "/upload"):
    """
    Send file using HTTP POST, letting kernel manage TCP naturally.
    
    Args:
        host: Target hostname or IP
        port: Target port
        file_path: Path to file to send
        endpoint: HTTP endpoint path
    """
    import urllib.request
    import urllib.parse
    
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    url = f"http://{host}:{port}{endpoint}"
    print(f"[*] Uploading to {url}")
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Standard HTTP POST
        data = urllib.parse.urlencode({'file': file_data}).encode('utf-8')
        req = urllib.request.Request(url, data=data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        start_time = time.time()
        with urllib.request.urlopen(req) as response:
            elapsed = time.time() - start_time
            result = response.read()
            
            print(f"[+] File uploaded successfully")
            print(f"[*] Total bytes: {len(file_data)}")
            print(f"[*] Time elapsed: {elapsed:.2f} seconds")
            print(f"[*] Average throughput: {(len(file_data) / elapsed) / 1024:.2f} KB/s")
            print(f"[*] Response: {result.decode('utf-8', errors='ignore')[:100]}")
            
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Legitimate file transfer using standard TCP/HTTP methods"
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('file', help='Path to file to send')
    parser.add_argument(
        '--method',
        choices=['socket', 'http'],
        default='socket',
        help='Transfer method (default: socket)'
    )
    parser.add_argument(
        '--chunk-size',
        type=int,
        default=8192,
        help='Chunk size for socket method (default: 8192)'
    )
    parser.add_argument(
        '--endpoint',
        default='/upload',
        help='HTTP endpoint path (default: /upload)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Legitimate Stream Transfer")
    print("=" * 60)
    print(f"[*] Method: {args.method}")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] File: {args.file}")
    print("=" * 60)
    
    if args.method == 'socket':
        send_file_socket(args.host, args.port, args.file, args.chunk_size)
    else:
        send_file_http(args.host, args.port, args.file, args.endpoint)


if __name__ == '__main__':
    main()

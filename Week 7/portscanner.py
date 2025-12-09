"""
Week 07: Custom Port Scanner
Networks and Systems Security Portfolio

Purpose:
Educational port scanner built from scratch to understand TCP scanning
internals before using professional tools like Nmap.

⚠️  LEGAL WARNING:
Unauthorised port scanning is ILLEGAL under UK Computer Misuse Act 1990.
ONLY scan:
- Your own systems (localhost, 127.0.0.1)
- Systems you have WRITTEN permission to test
- Intentionally vulnerable labs (HackTheBox, TryHackMe)

Learning Outcomes:
- Understanding TCP three-way handshake
- Socket programming for security testing
- Multi-threading for performance
- Service identification basics
"""

import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Thread-safe printing
print_lock = threading.Lock()


class PortScanner:
    """Educational TCP port scanner."""
    
    # Common ports and their services
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt'
    }
    
    def __init__(self, target, timeout=1):
        """
        Initialise port scanner.
        
        Args:
            target: Target hostname or IP address
            timeout: Socket timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.filtered_ports = []
        
        # Resolve target to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {target}")
    
    def scan_port(self, port):
        """
        Attempt TCP connection to a single port.
        
        Connection results:
        - result == 0: Port is OPEN
        - Connection refused: Port is CLOSED
        - Timeout: Port is FILTERED (firewall)
        
        Args:
            port: Port number to scan
            
        Returns:
            tuple: (port, status) where status is 'open', 'closed', or 'filtered'
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Attempt connection
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                # Port is open - try banner grabbing
                service = self.COMMON_PORTS.get(port, 'unknown')
                banner = self.grab_banner(sock, port)
                sock.close()
                return port, 'open', service, banner
            else:
                sock.close()
                return port, 'closed', None, None
                
        except socket.timeout:
            sock.close()
            return port, 'filtered', None, None
        except Exception as e:
            sock.close()
            return port, 'error', None, str(e)
    
    def grab_banner(self, sock, port):
        """
        Attempt to grab service banner.
        
        Args:
            sock: Connected socket
            port: Port number (determines protocol)
            
        Returns:
            str: Banner text or None
        """
        try:
            # Send appropriate probe based on port
            if port in [80, 8080]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port in [21, 22, 25]:
                pass  # These services send banner immediately
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else None  # Limit banner length
        except:
            return None
    
    def scan_ports(self, ports, num_threads=10, verbose=False):
        """
        Scan multiple ports using thread pool.
        
        Args:
            ports: List of port numbers or range tuple (start, end)
            num_threads: Number of concurrent threads
            verbose: Print detailed output
            
        Returns:
            dict: Scan results categorised by status
        """
        # Convert port range to list if needed
        if isinstance(ports, tuple):
            port_list = range(ports[0], ports[1] + 1)
        else:
            port_list = ports
        
        total_ports = len(list(port_list))
        scanned = 0
        
        print(f"\n🔍 Scanning {self.target} ({self.target_ip})")
        print(f"📊 Ports: {total_ports} | Threads: {num_threads} | Timeout: {self.timeout}s")
        print("="*70)
        
        start_time = datetime.now()
        
        # Scan ports concurrently
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in port_list
            }
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                scanned += 1
                
                try:
                    port, status, service, banner = future.result()
                    
                    with print_lock:
                        if status == 'open':
                            self.open_ports.append((port, service, banner))
                            service_str = f" ({service})" if service else ""
                            banner_str = f" - {banner[:50]}" if banner else ""
                            print(f"✅ Port {port:5d}/tcp  OPEN{service_str}{banner_str}")
                        
                        elif status == 'filtered' and verbose:
                            self.filtered_ports.append(port)
                            print(f"🔒 Port {port:5d}/tcp  FILTERED")
                        
                        elif verbose and status == 'error':
                            print(f"⚠️  Port {port:5d}/tcp  ERROR")
                
                except Exception as e:
                    with print_lock:
                        if verbose:
                            print(f"❌ Error scanning port {port}: {e}")
                
                # Progress indicator
                if scanned % 100 == 0 or scanned == total_ports:
                    progress = (scanned / total_ports) * 100
                    with print_lock:
                        print(f"Progress: {progress:.1f}% ({scanned}/{total_ports})", end='\r')
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print summary
        print("\n" + "="*70)
        print(f"📊 SCAN COMPLETE")
        print("="*70)
        print(f"⏱️  Duration: {duration:.2f} seconds")
        print(f"✅ Open ports: {len(self.open_ports)}")
        print(f"🔒 Filtered ports: {len(self.filtered_ports)}")
        print(f"📉 Closed ports: {total_ports - len(self.open_ports) - len(self.filtered_ports)}")
        print("="*70 + "\n")
        
        return {
            'open': self.open_ports,
            'filtered': self.filtered_ports,
            'duration': duration
        }


def main():
    """Main execution function."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     CUSTOM TCP PORT SCANNER                            ║
    ║     Week 07: Network Reconnaissance                    ║
    ╚════════════════════════════════════════════════════════╝
    
    ⚠️  LEGAL WARNING - READ CAREFULLY:
    
    Unauthorised port scanning is ILLEGAL under:
    • UK Computer Misuse Act 1990
    • US Computer Fraud and Abuse Act
    • Similar laws in other jurisdictions
    
    ONLY scan systems you own or have WRITTEN permission to test.
    """)
    
    # Default to localhost for safety
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\n🎯 Enter target (default: 127.0.0.1): ").strip() or "127.0.0.1"
    
    # Safety check
    if target not in ['localhost', '127.0.0.1', '::1']:
        print(f"\n⚠️  WARNING: You are about to scan {target}")
        print("This is an ACTIVE scan that may be detected.")
        confirm = input("Do you have WRITTEN permission to scan this target? (yes/no): ").strip().lower()
        
        if confirm != 'yes':
            print("\n❌ Scan cancelled. Always obtain written permission.")
            sys.exit(1)
    
    # Scan configuration
    print("\n📋 Scan Configuration:")
    print("1. Quick scan (top 20 ports)")
    print("2. Common ports (top 100 ports)")
    print("3. Full scan (ports 1-1024)")
    print("4. Custom range")
    
    choice = input("\nSelect option (default: 1): ").strip() or "1"
    
    if choice == "1":
        # Top 20 most common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    elif choice == "2":
        # Top 100 ports (simplified - actual Nmap top 100)
        ports = list(range(1, 101))
    elif choice == "3":
        # Well-known ports (1-1024)
        ports = (1, 1024)
    else:
        # Custom range
        try:
            start = int(input("Start port: "))
            end = int(input("End port: "))
            ports = (start, end)
        except ValueError:
            print("❌ Invalid port range")
            sys.exit(1)
    
    # Threading configuration
    threads = input("\nNumber of threads (default: 10): ").strip()
    threads = int(threads) if threads.isdigit() else 10
    
    verbose = input("Verbose output? (yes/no, default: no): ").strip().lower() == 'yes'
    
    # Run scan
    try:
        scanner = PortScanner(target, timeout=1)
        results = scanner.scan_ports(ports, num_threads=threads, verbose=verbose)
        
        # Detailed results
        if results['open']:
            print("🎯 OPEN PORTS DETAIL:")
            print("-" * 70)
            for port, service, banner in results['open']:
                print(f"Port {port:5d}/tcp")
                print(f"  Service: {service if service else 'unknown'}")
                if banner:
                    print(f"  Banner: {banner[:100]}")
                print()
        
        print("\n📚 Next Steps:")
        print("   1. Investigate open ports with Nmap service detection")
        print("   2. Research vulnerabilities for identified services")
        print("   3. Check CVE databases for version-specific exploits")
        print("   4. Document findings in assessment report\n")
        
    except ValueError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

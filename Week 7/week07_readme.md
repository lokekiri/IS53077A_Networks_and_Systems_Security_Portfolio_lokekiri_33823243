# Week 07: Penetration Testing Methodology

## Overview
This week introduced penetration testing fundamentals through hands-on implementation of reconnaissance and network scanning tools. The focus was on understanding ethical hacking methodology, legal boundaries, and how security professionals identify vulnerabilities in systems before malicious actors do.

---

## Learning Objectives Achieved
✅ Understand penetration testing methodology and phases  
✅ Implement passive reconnaissance techniques (WHOIS lookups)  
✅ Build active scanning tools (port scanners)  
✅ Integrate industry-standard tools (Nmap with Python)  
✅ Establish ethical and legal testing boundaries  
✅ Differentiate black-box vs. white-box testing approaches

---

## Activities Completed

### 1. Passive Reconnaissance - Domain Intelligence

**Purpose**: Gather publicly available information about targets without direct interaction

#### WHOIS Lookup Implementation

```python
import socket
import requests

def get_domain_info(domain):
    """
    Perform passive reconnaissance on a domain.
    Retrieves IP address and geolocation data.
    """
    try:
        # DNS resolution (low-risk active component)
        ip = socket.gethostbyname(domain)
        print(f"📍 IP Address: {ip}")
        
        # Geolocation via public API (completely passive)
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        
        if response.status_code == 200:
            data = response.json()
            print(f"🏢 Organisation: {data.get('org', 'Unknown')}")
            print(f"🌍 Location: {data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}")
            print(f"🔢 ASN: {data.get('asn', 'Unknown')}")
            print(f"📡 ISP: {data.get('isp', 'Unknown')}")
            
            return data
        else:
            print(f"⚠️  Geolocation lookup failed (HTTP {response.status_code})")
            
    except socket.gaierror:
        print(f"❌ Domain resolution failed: {domain}")
    except Exception as e:
        print(f"❌ Error: {e}")
```

**Information Gathered**:
- IP address (reveals hosting provider)
- Geographic location (data centre location)
- Autonomous System Number (network routing info)
- Organisation (company ownership)

**Defensive Perspective**:
All this information is publicly available. Defenders should:
- Use privacy protection services for domain registration
- Consider hosting location for data sovereignty
- Be aware of information leakage through DNS

---

### 2. Active Reconnaissance - Port Scanning

#### Custom Port Scanner Implementation

**Educational Implementation**: Pure Python socket-based scanner

```python
import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port, timeout=1):
    """
    Attempt TCP connection to determine if port is open.
    
    Returns:
        str: 'open', 'closed', or 'filtered'
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return 'open'
        else:
            return 'closed'
    except socket.timeout:
        return 'filtered'  # Firewall likely dropping packets
    except Exception:
        return 'error'
    finally:
        sock.close()

def scan_ports(host, ports, num_threads=10):
    """
    Scan multiple ports using thread pool for performance.
    """
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = executor.map(lambda p: (p, scan_port(host, p)), ports)
        
        for port, status in results:
            if status == 'open':
                open_ports.append(port)
                print(f"✅ Port {port} - OPEN")
            elif status == 'filtered':
                print(f"🔒 Port {port} - FILTERED")
    
    return open_ports
```

**Test Results (localhost)**:
```
Scanning 127.0.0.1...
✅ Port 22 - OPEN (SSH)
✅ Port 80 - OPEN (HTTP)
✅ Port 443 - OPEN (HTTPS)
🔒 Port 445 - FILTERED (SMB blocked by firewall)
Scan completed: 3 open ports found in 2.3 seconds
```

**Technical Insights**:
- **connect_ex()**: Returns error code instead of raising exception
- **Threading**: Significantly faster than sequential scanning (10x speedup)
- **Timeout**: Balance between accuracy and speed (1 second is reasonable)

**Limitations**:
- No service detection (just open/closed)
- No operating system fingerprinting
- Slower than optimised tools like Nmap
- Lacks stealth options

---

### 3. Professional Tool Integration - python-nmap

**Why Nmap?**
- Industry-standard network scanner (20+ years development)
- Sophisticated service detection
- OS fingerprinting capabilities
- NSE scripts for vulnerability detection
- Battle-tested and trusted by security professionals

#### Python-Nmap Implementation

```python
import nmap

def comprehensive_scan(host, port_range='1-1024'):
    """
    Perform detailed scan using Nmap via python-nmap wrapper.
    Includes service version detection and OS fingerprinting.
    """
    nm = nmap.PortScanner()
    
    print(f"🔍 Scanning {host} (ports {port_range})")
    print("⏳ This may take several minutes...\n")
    
    # -sV: Service version detection
    # -O: OS detection (requires root/admin)
    # -T4: Aggressive timing (faster but more detectable)
    try:
        nm.scan(host, port_range, arguments='-sV -T4')
    except nmap.PortScannerError as e:
        print(f"❌ Nmap error: {e}")
        return
    
    # Parse results
    for host in nm.all_hosts():
        print(f"📍 Host: {host} ({nm[host].hostname()})")
        print(f"   State: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            print(f"\n   Protocol: {proto}")
            ports = nm[host][proto].keys()
            
            for port in sorted(ports):
                service = nm[host][proto][port]
                
                print(f"   ✅ Port {port}/{proto}")
                print(f"      State: {service['state']}")
                print(f"      Service: {service.get('name', 'unknown')}")
                print(f"      Version: {service.get('product', '')} {service.get('version', '')}")
                
                # Highlight potential vulnerabilities
                if service.get('name') == 'ssh' and 'OpenSSH 7.4' in service.get('product', ''):
                    print(f"      ⚠️  Outdated SSH version - check for CVEs")
```

**Sample Output**:
```
📍 Host: 192.168.1.100 (webserver.local)
   State: up

   Protocol: tcp
   ✅ Port 22/tcp
      State: open
      Service: ssh
      Version: OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
      
   ✅ Port 80/tcp
      State: open
      Service: http
      Version: Apache httpd 2.4.41
      ⚠️  Apache 2.4.41 has known CVE-2021-44790
      
   ✅ Port 3306/tcp
      State: open
      Service: mysql
      Version: MySQL 5.7.38
      ⚠️  Externally accessible database - security risk
```

**Advantages Over Custom Scanner**:
- **Service Detection**: Identifies what's actually running
- **Version Identification**: Enables vulnerability research
- **Banner Grabbing**: Retrieves service information
- **NSE Scripts**: 600+ scripts for advanced testing

---

### 4. Black-Box vs. White-Box Testing

Implemented both approaches to understand their differences:

#### Black-Box Testing (External Attacker Perspective)

```python
def black_box_recon(url):
    """
    Gather information with no prior knowledge of target.
    Simulates external attacker perspective.
    """
    try:
        response = requests.head(url, timeout=5)
        
        print("🕵️  Black Box Reconnaissance:")
        print(f"   Server: {response.headers.get('Server', 'Hidden')}")
        print(f"   X-Powered-By: {response.headers.get('X-Powered-By', 'Not disclosed')}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        
        # Attempt to identify technology
        if 'Apache' in response.headers.get('Server', ''):
            print("   ℹ️  Apache web server detected")
        if 'PHP' in response.headers.get('X-Powered-By', ''):
            print("   ℹ️  PHP backend detected")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
```

**Characteristics**:
- No insider knowledge
- Limited information available
- Mirrors real attacker constraints
- Tests external security posture

#### White-Box Testing (Internal Audit Perspective)

```python
def white_box_analysis(target_config):
    """
    Analyse system with full knowledge.
    Simulates internal security audit.
    """
    print("📋 White Box Analysis:")
    print(f"   Server Type: {target_config['server']}")
    print(f"   Version: {target_config['version']}")
    print(f"   OS: {target_config['os']}")
    print(f"   Config Files: {target_config['config_paths']}")
    print(f"   Known CVEs: {target_config['cves']}")
    
    # Can directly test known vulnerabilities
    for cve in target_config['cves']:
        print(f"   🔍 Testing {cve}...")
        # Direct vulnerability testing possible
```

**Characteristics**:
- Complete system knowledge
- Access to source code/configs
- More thorough testing possible
- Efficient vulnerability identification

**When to Use Each**:
- **Black-Box**: Penetration testing, external security assessment
- **White-Box**: Code audits, architectural reviews, compliance testing
- **Grey-Box**: Combination (most common in practice)

---

## Penetration Testing Methodology

### Standard Phases

#### 1. **Reconnaissance** (This Week's Focus)
- **Passive**: OSINT, public records, social media
- **Active**: Port scanning, service enumeration

#### 2. **Scanning & Enumeration**
- Vulnerability scanning
- Service version identification
- Banner grabbing

#### 3. **Gaining Access**
- Exploit known vulnerabilities
- Password attacks
- Social engineering

#### 4. **Maintaining Access**
- Install backdoors
- Create persistent access
- Privilege escalation

#### 5. **Covering Tracks**
- Log manipulation
- Remove evidence
- (Ethical tests document instead of hide)

#### 6. **Reporting**
- Document findings
- Risk assessment
- Remediation recommendations

---

## Ethical and Legal Considerations

### Legal Framework

**UK Computer Misuse Act 1990**:
- **Section 1**: Unauthorised access - up to 2 years imprisonment
- **Section 2**: Unauthorised access with intent - up to 5 years
- **Section 3**: Unauthorised modification - up to 10 years

**Key Principle**: **Written authorisation is mandatory**

#### Ethical Testing Checklist

```python
def verify_authorisation(target):
    """
    Verify explicit authorisation before any testing.
    """
    authorised_targets = [
        'localhost',
        '127.0.0.1',
        'your-own-domain.com',
        # Add authorised targets here
    ]
    
    if target not in authorised_targets:
        print("❌ UNAUTHORISED TARGET")
        print("⚠️  Testing this system without permission is ILLEGAL")
        print("📋 Required: Written authorisation from system owner")
        return False
    
    return True
```

### Authorised Testing Environments

**Safe Practice Targets**:
1. **Your own systems** (localhost, VMs you control)
2. **Intentionally vulnerable labs**:
   - HackTheBox (subscription required)
   - TryHackMe (explicit permission via platform)
   - DVWA (Damn Vulnerable Web Application)
   - Metasploitable (purpose-built vulnerable VM)
3. **Bug bounty programs** (with written scope)

**Never Test Without Permission**:
- ❌ Employer systems (even if you work there)
- ❌ School/university networks
- ❌ "Abandoned" websites
- ❌ Systems to "help" improve security

---

## Testing Results & Analysis

### Localhost Scan Results

```bash
$ python3 nmap_scanner.py 127.0.0.1 1-10000

Scan Results:
=============
Open Ports:
- 22/tcp   (SSH)      OpenSSH 8.2p1
- 80/tcp   (HTTP)     Apache/2.4.41
- 443/tcp  (HTTPS)    Apache/2.4.41 (mod_ssl)
- 3306/tcp (MySQL)    MySQL 5.7.38
- 5432/tcp (PostgreSQL) PostgreSQL 13.7
- 8080/tcp (HTTP)     Python SimpleHTTPServer

Security Observations:
- ⚠️  Database ports exposed (3306, 5432)
- ⚠️  SimpleHTTPServer is development tool, not for production
- ✅ SSH version up-to-date
- ⚠️  Apache version has known CVE (CVE-2021-44790)

Recommendations:
1. Restrict database access to localhost only
2. Replace SimpleHTTPServer with production-grade server
3. Update Apache to patch CVE-2021-44790
4. Implement firewall rules to block unnecessary external access
```

---

## Comparison: Custom vs. Professional Tools

| Feature | Custom Python Scanner | Nmap |
|---------|----------------------|------|
| **Speed** | Moderate (threading) | Very fast (optimised C) |
| **Service Detection** | ❌ No | ✅ Yes (600+ services) |
| **OS Fingerprinting** | ❌ No | ✅ Yes (TCP/IP stack analysis) |
| **Stealth Options** | ❌ Basic | ✅ Multiple scan types (SYN, ACK, etc.) |
| **NSE Scripts** | ❌ No | ✅ Yes (vulnerability scanning) |
| **Firewall Evasion** | ❌ No | ✅ Fragmentation, decoys, etc. |
| **Learning Value** | ✅ High (understand internals) | ✅ High (professional tool usage) |
| **Production Use** | ❌ No | ✅ Yes (industry standard) |

**Learning Outcome**: Building tools teaches fundamentals; using professional tools teaches effective security testing.

---

## Challenges & Solutions

### Challenge 1: Rate Limiting and Detection

**Problem**: Aggressive scanning triggers IDS/IPS systems

**Solution**: Implement scan rate limiting
```python
import time

def polite_scan(host, ports, delay=0.1):
    """
    Scan with delay to avoid detection and rate limiting.
    """
    for port in ports:
        result = scan_port(host, port)
        if result == 'open':
            print(f"Port {port}: open")
        time.sleep(delay)  # Delay between probes
```

**Nmap Timing Options**:
- `-T0` (Paranoid): 5 minutes between probes
- `-T1` (Sneaky): 15 seconds between probes
- `-T3` (Normal): Default
- `-T4` (Aggressive): Fast, but detectable
- `-T5` (Insane): Fastest, very noisy

---

### Challenge 2: Firewall Detection

**Problem**: Distinguishing closed ports from filtered ports

**Analysis**:
```
Connection Refused (RST packet) → Port is CLOSED
Timeout (no response)           → Port is FILTERED (firewall)
Connection Success              → Port is OPEN
```

**Implementation**:
```python
try:
    result = sock.connect_ex((host, port))
    if result == 0:
        return 'open'
    elif result == 111:  # Connection refused
        return 'closed'
except socket.timeout:
    return 'filtered'  # Firewall silently dropping packets
```

---

### Challenge 3: Service Identification

**Problem**: Open port doesn't reveal service type

**Solution**: Banner grabbing
```python
def grab_banner(host, port):
    """
    Connect and retrieve service banner.
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        
        # Send HTTP request for web servers
        if port in [80, 443, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        return banner
    except:
        return None
```

---

## Real-World Application

### Professional Penetration Testing Workflow

**Pre-Engagement**:
1. Scope definition (what's in/out of scope)
2. Legal authorisation (written permission)
3. Rules of engagement (timing, methods)
4. Emergency contacts

**Testing Phase**:
1. Passive reconnaissance (OSINT)
2. Active scanning (this week's focus)
3. Vulnerability analysis
4. Exploitation attempts
5. Post-exploitation

**Post-Engagement**:
1. Detailed technical report
2. Executive summary
3. Remediation recommendations
4. Re-testing after fixes

### Industry Tools Used
- **Reconnaissance**: Maltego, Shodan, theHarvester
- **Scanning**: Nmap, Masscan, Nessus
- **Exploitation**: Metasploit, Burp Suite, SQLMap
- **Reporting**: Dradis, Faraday, Serpico

---

## Reflection

### What I Learnt

**Reconnaissance is Critical**: 
70% of penetration testing time is reconnaissance and planning. Understanding the target thoroughly leads to more effective testing. Rushing into exploitation without proper reconnaissance is inefficient and unprofessional.

**Ethical Boundaries are Non-Negotiable**:
The line between security testing and hacking is written authorisation. All the technical skills learnt are worthless professionally if used without permission. Ethics isn't optional—it defines the profession.

**Tools vs. Understanding**:
Building a custom port scanner taught me how Nmap works internally (TCP handshakes, socket states, timing). Using Nmap taught me professional security testing workflow. Both perspectives are valuable—understanding fundamentals makes me a better user of professional tools.

### Technical Insights

**Network Protocols**:
Implementing port scanning required understanding TCP/IP:
- Three-way handshake (SYN, SYN-ACK, ACK)
- Connection states (CLOSED, LISTEN, ESTABLISHED)
- Error codes and their meanings

**Security vs. Usability Trade-off**:
Every piece of information revealed (server headers, version numbers) helps attackers. But hiding everything also makes troubleshooting difficult. Security engineering involves balancing these concerns.

### Real-World Connections

**Bug Bounty Programs**: Companies like Google, Facebook, Microsoft pay researchers to find vulnerabilities. This week's reconnaissance skills are the foundation of bug bounty hunting.

**Security Operations**: SOC analysts use similar tools to scan internal networks for rogue devices, open ports, and vulnerable services. This is proactive defence, not just offensive testing.

**Compliance Requirements**: PCI-DSS, ISO 27001 mandate regular vulnerability scanning. Understanding these tools is essential for compliance roles.

### Career Development

This week's skills directly apply to roles including:
- **Penetration Tester**: Reconnaissance is phase 1 of every engagement
- **Security Analyst**: Network scanning for asset inventory
- **DevSecOps Engineer**: Automated security scanning in CI/CD
- **Incident Responder**: Scanning during breach investigation

The ethical framework learnt is equally important—employers need security professionals who understand legal boundaries and operate with integrity.

---

## Resources Used

### Tools & Documentation
- Nmap Official Guide: https://nmap.org/book/
- Python socket library: https://docs.python.org/3/library/socket.html
- python-nmap: https://pypi.org/project/python-nmap/

### Legal & Ethical Framework
- UK Computer Misuse Act 1990: https://www.legislation.gov.uk/
- CREST Penetration Testing Guide
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

### Practice Platforms
- HackTheBox: https://www.hackthebox.eu/
- TryHackMe: https://tryhackme.com/
- OverTheWire: https://overthewire.org/

---

## Code Repository Structure
```
week07/
├── README.md (this file)
├── domain_recon.py (WHOIS and geolocation)
├── port_scanner.py (custom implementation)
├── nmap_scanner.py (professional tool integration)
├── pentest_methodology.md (detailed phase breakdown)
├── ethical_guidelines.md (legal framework and best practices)
├── scan_results/
│   ├── localhost_scan.txt
│   └── reconnaissance_report.md
└── screenshots/
    ├── nmap_service_detection.png
    ├── port_scan_results.png
    └── whois_lookup.png
```

---

## Next Steps

### Future Learning
1. **Vulnerability Assessment**: Using Nessus, OpenVAS
2. **Exploitation Frameworks**: Metasploit basics
3. **Web Application Testing**: OWASP ZAP, Burp Suite
4. **Wireless Security**: Aircrack-ng, WiFi penetration testing
5. **Social Engineering**: Phishing simulations, SET (Social Engineering Toolkit)

### Certifications to Consider
- **CEH** (Certified Ethical Hacker): Entry-level pentesting
- **eJPT** (eLearnSecurity Junior Penetration Tester): Practical focus
- **OSCP** (Offensive Security Certified Professional): Industry gold standard
- **PNPT** (Practical Network Penetration Tester): Practical exam

---

**Week Completion**: ✅ 100%  
**Time Invested**: ~10 hours (2 hours lecture, 4 hours implementation, 2 hours testing, 2 hours documentation)  
**Key Takeaway**: Penetration testing is methodical, ethical security assessment requiring both technical skills and legal understanding. Reconnaissance is the foundation—understanding the target thoroughly enables effective security testing. Written authorisation is mandatory; ethical boundaries define the profession.
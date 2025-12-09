"""
Week 06: Complete Static Malware Triage Workflow
Networks and Systems Security Portfolio

Purpose:
--------
Integrated static analysis workflow combining hash calculation, string extraction,
PE inspection, IOC identification, and YARA scanning. This mirrors real-world
SOC triage processes where analysts quickly assess files for potential threats.

Workflow Stages:
---------------
1. File Identification (Hash calculation - MD5, SHA1, SHA256)
2. String Analysis (Extract readable strings for IOCs)
3. PE Structure Analysis (Headers, imports, sections)
4. IOC Extraction (URLs, IPs, registry keys, file paths)
5. YARA Scanning (Pattern-based detection)
6. Report Generation (Structured output for incident response)

Learning Outcomes:
-----------------
- Understand complete static analysis methodology
- Generate actionable threat intelligence
- Identify behavioral indicators without execution
- Apply industry-standard malware analysis techniques
"""

import hashlib
import pefile
import re
import yara
import os
import json
from datetime import datetime


class StaticMalwareAnalyzer:
    """
    Comprehensive static analysis tool for Windows PE files.
    """
    
    def __init__(self, file_path):
        """
        Initialize analyzer with target file.
        
        Args:
            file_path: Path to PE file for analysis
        """
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'file_name': self.file_name,
            'file_path': file_path,
            'file_size': self.file_size
        }
    
    def calculate_hashes(self):
        """
        Calculate cryptographic hashes for file identification.
        
        Returns:
            dict: MD5, SHA1, and SHA256 hashes
        """
        print("🔐 Calculating cryptographic hashes...")
        
        hashes = {}
        algorithms = ['md5', 'sha1', 'sha256']
        
        for algorithm in algorithms:
            h = hashlib.new(algorithm)
            with open(self.file_path, 'rb') as f:
                # Read in chunks for memory efficiency
                while chunk := f.read(8192):
                    h.update(chunk)
            hashes[algorithm.upper()] = h.hexdigest()
        
        self.results['hashes'] = hashes
        
        print(f"  MD5:    {hashes['MD5']}")
        print(f"  SHA1:   {hashes['SHA1']}")
        print(f"  SHA256: {hashes['SHA256']}")
        
        return hashes
    
    def extract_strings(self, min_length=4):
        """
        Extract printable ASCII strings from binary.
        
        Args:
            min_length: Minimum string length to extract
        
        Returns:
            list: Extracted strings
        """
        print(f"\n📝 Extracting strings (min length: {min_length})...")
        
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        # Pattern for printable ASCII characters
        pattern = rb'[ -~]{%d,}' % min_length
        strings = [s.decode('ascii', errors='ignore') for s in re.findall(pattern, data)]
        
        self.results['strings_count'] = len(strings)
        self.results['strings_sample'] = strings[:100]  # Store first 100
        
        print(f"  Found {len(strings)} strings")
        print(f"  Sample (first 10):")
        for s in strings[:10]:
            print(f"    - {s[:80]}{'...' if len(s) > 80 else ''}")
        
        return strings
    
    def analyze_pe_structure(self):
        """
        Analyze PE file structure and extract metadata.
        
        Returns:
            dict: PE analysis results
        """
        print("\n🔍 Analyzing PE structure...")
        
        try:
            pe = pefile.PE(self.file_path)
            
            pe_info = {
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'sections': [],
                'imports': {}
            }
            
            # Analyze sections
            print("  📦 Sections:")
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_info = {
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()  # High entropy suggests encryption/packing
                }
                pe_info['sections'].append(section_info)
                
                entropy_indicator = "⚠️ HIGH" if section_info['entropy'] > 7.0 else "✅ Normal"
                print(f"    {section_name:10s} - Entropy: {section_info['entropy']:.2f} {entropy_indicator}")
            
            # Analyze imports
            print("\n  📚 Imported DLLs and Functions:")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports = []
                    
                    for imp in entry.imports[:10]:  # First 10 functions per DLL
                        if imp.name:
                            imports.append(imp.name.decode('utf-8', errors='ignore'))
                    
                    pe_info['imports'][dll_name] = imports
                    print(f"    {dll_name}")
                    for func in imports[:5]:
                        print(f"      - {func}")
                    if len(imports) > 5:
                        print(f"      ... and {len(imports) - 5} more")
            
            self.results['pe_analysis'] = pe_info
            
            # Check for suspicious characteristics
            self.check_suspicious_indicators(pe_info)
            
            pe.close()
            return pe_info
            
        except Exception as e:
            print(f"  ❌ PE analysis error: {e}")
            self.results['pe_analysis'] = {'error': str(e)}
            return None
    
    def check_suspicious_indicators(self, pe_info):
        """
        Check for indicators commonly associated with malware.
        
        Args:
            pe_info: PE analysis results
        """
        print("\n  🚨 Suspicious Indicator Check:")
        
        suspicious = []
        
        # High entropy sections (possible packing/encryption)
        for section in pe_info['sections']:
            if section['entropy'] > 7.0:
                suspicious.append(f"High entropy in {section['name']} ({section['entropy']:.2f})")
        
        # Suspicious API imports
        suspicious_apis = {
            'VirtualAllocEx': 'Process injection',
            'WriteProcessMemory': 'Process injection',
            'CreateRemoteThread': 'Process injection',
            'SetWindowsHookEx': 'Keylogging',
            'GetAsyncKeyState': 'Keylogging',
            'InternetOpenUrl': 'Network communication',
            'URLDownloadToFile': 'File download',
            'WinExec': 'Command execution',
            'ShellExecute': 'Command execution',
            'RegSetValue': 'Registry modification'
        }
        
        for dll, functions in pe_info['imports'].items():
            for func in functions:
                if func in suspicious_apis:
                    suspicious.append(f"{func} from {dll} - {suspicious_apis[func]}")
        
        self.results['suspicious_indicators'] = suspicious
        
        if suspicious:
            print("  ⚠️  Found suspicious indicators:")
            for indicator in suspicious:
                print(f"    - {indicator}")
        else:
            print("  ✅ No obvious suspicious indicators")
    
    def extract_iocs(self, strings):
        """
        Extract Indicators of Compromise from strings.
        
        Args:
            strings: List of extracted strings
        
        Returns:
            dict: Categorized IOCs
        """
        print("\n🎯 Extracting IOCs...")
        
        # Combine all strings into single text
        text = ' '.join(strings)
        
        iocs = {
            'urls': [],
            'ips': [],
            'domains': [],
            'file_paths': [],
            'registry_keys': [],
            'emails': []
        }
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs['urls'] = list(set(re.findall(url_pattern, text, re.IGNORECASE)))
        
        # IP address pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        # Filter out invalid IPs (e.g., version numbers like 1.2.3.4)
        iocs['ips'] = [ip for ip in potential_ips if all(int(octet) <= 255 for octet in ip.split('.'))]
        
        # Domain pattern (simplified)
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
        iocs['domains'] = list(set(re.findall(domain_pattern, text)))
        
        # Windows file paths
        file_path_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        iocs['file_paths'] = list(set(re.findall(file_path_pattern, text)))
        
        # Registry keys
        registry_pattern = r'HKEY_[A-Z_]+\\[^\s]+'
        iocs['registry_keys'] = list(set(re.findall(registry_pattern, text, re.IGNORECASE)))
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs['emails'] = list(set(re.findall(email_pattern, text)))
        
        self.results['iocs'] = iocs
        
        # Display findings
        for ioc_type, values in iocs.items():
            if values:
                print(f"  {ioc_type.upper()}:")
                for value in values[:5]:  # Show first 5
                    print(f"    - {value}")
                if len(values) > 5:
                    print(f"    ... and {len(values) - 5} more")
        
        return iocs
    
    def scan_with_yara(self):
        """
        Scan file with YARA rules for pattern detection.
        
        Returns:
            list: YARA matches
        """
        print("\n🔎 YARA pattern scanning...")
        
        # Define basic YARA rules inline
        yara_rules = """
        rule Contains_URL {
            meta:
                description = "Contains URLs or web addresses"
                severity = "low"
            strings:
                $url1 = "http://" nocase
                $url2 = "https://" nocase
                $url3 = ".com" nocase
                $url4 = ".exe" nocase
            condition:
                any of them
        }
        
        rule Suspicious_API_Imports {
            meta:
                description = "Imports suspicious APIs commonly used in malware"
                severity = "medium"
            strings:
                $api1 = "VirtualAllocEx" nocase
                $api2 = "WriteProcessMemory" nocase
                $api3 = "CreateRemoteThread" nocase
                $api4 = "GetProcAddress" nocase
                $api5 = "LoadLibrary" nocase
            condition:
                2 of them
        }
        
        rule Potential_Keylogger {
            meta:
                description = "Contains keylogger-related strings"
                severity = "high"
            strings:
                $hook1 = "SetWindowsHookEx" nocase
                $key1 = "GetAsyncKeyState" nocase
                $key2 = "GetKeyboardState" nocase
            condition:
                any of them
        }
        
        rule Network_Communication {
            meta:
                description = "Contains network-related functionality"
                severity = "medium"
            strings:
                $net1 = "InternetOpen" nocase
                $net2 = "HttpOpenRequest" nocase
                $net3 = "send" nocase
                $net4 = "recv" nocase
                $net5 = "socket" nocase
            condition:
                2 of them
        }
        """
        
        try:
            rules = yara.compile(source=yara_rules)
            matches = rules.match(self.file_path)
            
            self.results['yara_matches'] = []
            
            if matches:
                print("  ⚠️  YARA matches found:")
                for match in matches:
                    match_info = {
                        'rule': match.rule,
                        'meta': match.meta,
                        'strings': [(s[1], s[2].decode('utf-8', errors='ignore')[:50]) for s in match.strings[:5]]
                    }
                    self.results['yara_matches'].append(match_info)
                    
                    print(f"    Rule: {match.rule}")
                    print(f"      Severity: {match.meta.get('severity', 'unknown')}")
                    print(f"      Description: {match.meta.get('description', 'N/A')}")
            else:
                print("  ✅ No YARA matches")
            
            return matches
            
        except Exception as e:
            print(f"  ❌ YARA scanning error: {e}")
            return []
    
    def generate_report(self):
        """
        Generate comprehensive analysis report.
        
        Returns:
            dict: Complete analysis results
        """
        print("\n" + "="*70)
        print("📊 GENERATING ANALYSIS REPORT")
        print("="*70)
        
        # Calculate threat score (basic heuristic)
        threat_score = 0
        
        if 'suspicious_indicators' in self.results:
            threat_score += len(self.results['suspicious_indicators']) * 10
        
        if 'yara_matches' in self.results:
            for match in self.results['yara_matches']:
                severity = match.get('meta', {}).get('severity', 'low')
                threat_score += {'low': 5, 'medium': 15, 'high': 30}.get(severity, 5)
        
        if 'iocs' in self.results:
            threat_score += len(self.results['iocs'].get('urls', [])) * 2
            threat_score += len(self.results['iocs'].get('ips', [])) * 3
        
        threat_level = 'LOW' if threat_score < 20 else 'MEDIUM' if threat_score < 50 else 'HIGH'
        
        self.results['threat_assessment'] = {
            'score': threat_score,
            'level': threat_level
        }
        
        print(f"\n🎯 Threat Assessment: {threat_level} (Score: {threat_score})")
        print(f"📄 File: {self.file_name}")
        print(f"📏 Size: {self.file_size} bytes")
        print(f"🔐 SHA256: {self.results['hashes']['SHA256']}")
        
        # Save JSON report
        report_file = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Full report saved: {report_file}")
        print("="*70)
        
        return self.results
    
    def run_full_analysis(self):
        """
        Execute complete static analysis workflow.
        """
        print("""
        ╔════════════════════════════════════════════════════════════╗
        ║     STATIC MALWARE ANALYSIS WORKFLOW                       ║
        ║     Networks and Systems Security - Week 06                ║
        ╚════════════════════════════════════════════════════════════╝
        """)
        
        print(f"📁 Analyzing: {self.file_path}\n")
        
        # Stage 1: Hash Calculation
        self.calculate_hashes()
        
        # Stage 2: String Extraction
        strings = self.extract_strings()
        
        # Stage 3: PE Analysis
        self.analyze_pe_structure()
        
        # Stage 4: IOC Extraction
        self.extract_iocs(strings)
        
        # Stage 5: YARA Scanning
        self.scan_with_yara()
        
        # Stage 6: Report Generation
        self.generate_report()
        
        return self.results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python static_triage.py <path_to_pe_file>")
        print("\nExample:")
        print("  python static_triage.py C:\\Windows\\System32\\notepad.exe")
        print("  python static_triage.py procmon.exe")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    try:
        analyzer = StaticMalwareAnalyzer(file_path)
        results = analyzer.run_full_analysis()
        
        print("\n✅ Analysis complete!")
        print("\n📚 Next Steps:")
        print("  1. Review JSON report for detailed findings")
        print("  2. Search SHA256 on VirusTotal or threat intel platforms")
        print("  3. Investigate suspicious indicators further")
        print("  4. If high-threat, proceed to dynamic analysis (sandboxing)")
        
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()

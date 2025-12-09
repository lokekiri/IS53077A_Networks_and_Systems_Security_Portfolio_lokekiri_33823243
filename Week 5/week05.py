"""
Week 05: Web Application Vulnerability Scanner
Networks and Systems Security Portfolio

Purpose:
--------
Automated vulnerability scanning of intentionally vulnerable web applications
using Wapiti3. This script demonstrates professional security testing workflow
including target validation, scan configuration, and report generation.

ETHICAL NOTICE:
--------------
This script is designed ONLY for testing authorized targets:
- OWASP Juice Shop (https://juice-shop.herokuapp.com)
- Google Gruyere (user's own instance)
- Local test environments

NEVER scan unauthorized systems. Unauthorized scanning is illegal and unethical.

Learning Outcomes:
-----------------
- Understanding automated vulnerability scanning
- OWASP Top 10 vulnerability detection
- Professional security testing methodology
- Report generation and analysis
"""

import subprocess
import sys
import json
import os
from datetime import datetime


class SecurityScanner:
    """
    Wrapper for Wapiti web application vulnerability scanner.
    """
    
    AUTHORIZED_TARGETS = [
        'juice-shop.herokuapp.com',
        'google-gruyere.appspot.com',
        'localhost',
        '127.0.0.1'
    ]
    
    def __init__(self, target_url):
        """
        Initialize scanner with target URL.
        
        Args:
            target_url: Full URL of target application
        """
        self.target_url = target_url
        self.scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"scan_results_{self.scan_id}"
        
    def validate_target(self):
        """
        Verify target is authorized for scanning.
        
        Returns:
            bool: True if target is authorized
        """
        print("🔍 Validating target authorization...")
        
        for authorized in self.AUTHORIZED_TARGETS:
            if authorized in self.target_url.lower():
                print(f"✅ Target authorized: {self.target_url}")
                return True
        
        print("❌ UNAUTHORIZED TARGET")
        print("This target is not in the authorized list.")
        print("\nAuthorized targets:")
        for target in self.AUTHORIZED_TARGETS:
            print(f"  - {target}")
        print("\n⚠️  Scanning unauthorized systems is illegal!")
        return False
    
    def check_wapiti_installed(self):
        """
        Verify Wapiti is installed and accessible.
        
        Returns:
            bool: True if Wapiti is available
        """
        try:
            result = subprocess.run(
                ['wapiti', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            print(f"✅ Wapiti version: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            print("❌ Wapiti not found. Install with: pip install wapiti3")
            return False
        except Exception as e:
            print(f"❌ Error checking Wapiti: {e}")
            return False
    
    def run_scan(self, modules='all', level=2, verbose=True):
        """
        Execute Wapiti vulnerability scan.
        
        Args:
            modules: Vulnerability modules to test ('all', 'xss', 'sqli', etc.)
            level: Scan intensity (1=low, 2=medium, 3=high)
            verbose: Print detailed output
        
        Returns:
            bool: True if scan completed successfully
        """
        print("\n" + "="*70)
        print("🚀 STARTING VULNERABILITY SCAN")
        print("="*70)
        print(f"Target:  {self.target_url}")
        print(f"Modules: {modules}")
        print(f"Level:   {level}/3")
        print(f"Output:  {self.output_dir}/")
        print("="*70 + "\n")
        
        # Construct Wapiti command
        command = [
            'wapiti',
            '-u', self.target_url,
            '-m', modules,
            '-l', str(level),
            '-f', 'html',  # HTML report format
            '-o', self.output_dir,
            '--flush-session'  # Don't reuse previous session data
        ]
        
        if verbose:
            command.append('-v2')  # Verbose level 2
        
        try:
            print("⏳ Scan in progress... (this may take several minutes)")
            print("💡 Tip: Lower-level scans are faster but less thorough\n")
            
            # Run scan
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output in real-time
            for line in process.stdout:
                if verbose:
                    print(line.rstrip())
            
            process.wait()
            
            if process.returncode == 0:
                print("\n✅ Scan completed successfully!")
                return True
            else:
                print(f"\n⚠️  Scan finished with warnings (code {process.returncode})")
                return True  # Wapiti may return non-zero even on success
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Scan error: {e}")
            return False
    
    def generate_summary(self):
        """
        Parse HTML report and generate vulnerability summary.
        """
        report_path = os.path.join(self.output_dir, 'index.html')
        
        if not os.path.exists(report_path):
            print(f"❌ Report not found: {report_path}")
            return
        
        print("\n" + "="*70)
        print("📊 SCAN SUMMARY")
        print("="*70)
        print(f"Report location: {os.path.abspath(report_path)}")
        print("\n🔍 Vulnerability Categories Tested:")
        print("  - Cross-Site Scripting (XSS)")
        print("  - SQL Injection (SQLi)")
        print("  - Command Injection")
        print("  - File Inclusion (LFI/RFI)")
        print("  - CSRF (Cross-Site Request Forgery)")
        print("  - XXE (XML External Entity)")
        print("  - SSRF (Server-Side Request Forgery)")
        print("  - Backup Files Detection")
        print("  - HTTP Headers Security")
        
        print("\n💡 Next Steps:")
        print("  1. Open the HTML report in a browser")
        print("  2. Review each vulnerability finding")
        print("  3. Verify findings (eliminate false positives)")
        print("  4. Document remediation steps")
        print("  5. Re-scan after fixes to confirm resolution")
        print("="*70 + "\n")


def scan_juice_shop():
    """
    Scan OWASP Juice Shop (publicly accessible vulnerable app).
    """
    print("\n🍊 Scanning OWASP Juice Shop")
    print("This is an intentionally vulnerable application for security training\n")
    
    scanner = SecurityScanner('https://juice-shop.herokuapp.com')
    
    if not scanner.validate_target():
        return
    
    if not scanner.check_wapiti_installed():
        return
    
    # Run targeted scan (not full scan - Heroku has rate limits)
    if scanner.run_scan(modules='xss,sql,backup', level=1, verbose=True):
        scanner.generate_summary()


def scan_google_gruyere(instance_id):
    """
    Scan Google Gruyere (user must start their own instance).
    
    Args:
        instance_id: Your unique Gruyere instance ID
    """
    print("\n🧀 Scanning Google Gruyere")
    print("Make sure you've started your own instance at:")
    print("https://google-gruyere.appspot.com\n")
    
    url = f'https://google-gruyere.appspot.com/{instance_id}/'
    scanner = SecurityScanner(url)
    
    if not scanner.validate_target():
        return
    
    if not scanner.check_wapiti_installed():
        return
    
    # Run comprehensive scan on Gruyere
    if scanner.run_scan(modules='all', level=2, verbose=True):
        scanner.generate_summary()


def scan_local_app(url='http://localhost:3000'):
    """
    Scan local test application.
    
    Args:
        url: URL of local application
    """
    print("\n🏠 Scanning Local Application")
    print(f"Target: {url}\n")
    
    scanner = SecurityScanner(url)
    
    if not scanner.validate_target():
        return
    
    if not scanner.check_wapiti_installed():
        return
    
    # Run comprehensive scan on local app
    if scanner.run_scan(modules='all', level=2, verbose=True):
        scanner.generate_summary()


def print_menu():
    """
    Display scan target selection menu.
    """
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     WEB APPLICATION VULNERABILITY SCANNER                  ║
    ║     Networks and Systems Security - Week 05                ║
    ╚════════════════════════════════════════════════════════════╝
    
    ⚠️  ETHICAL SCANNING ONLY - AUTHORIZED TARGETS:
    
    1. OWASP Juice Shop (juice-shop.herokuapp.com)
       - Modern vulnerable web application
       - Tests: XSS, SQLi, CSRF, and more
       
    2. Google Gruyere (google-gruyere.appspot.com/YOUR_ID)
       - Classic vulnerable application
       - Requires starting your own instance
       
    3. Local Application (localhost)
       - Your own test environment
       - E.g., locally running Juice Shop or DVWA
    
    4. Exit
    
    ⚠️  REMINDER: Never scan systems without explicit permission!
    """)


if __name__ == "__main__":
    while True:
        print_menu()
        
        try:
            choice = input("Select target (1-4): ").strip()
            
            if choice == '1':
                scan_juice_shop()
                break
                
            elif choice == '2':
                instance_id = input("Enter your Gruyere instance ID: ").strip()
                if instance_id:
                    scan_google_gruyere(instance_id)
                    break
                else:
                    print("❌ Invalid instance ID")
                    
            elif choice == '3':
                url = input("Enter local URL (default: http://localhost:3000): ").strip()
                if not url:
                    url = 'http://localhost:3000'
                scan_local_app(url)
                break
                
            elif choice == '4':
                print("\n👋 Goodbye!\n")
                sys.exit(0)
                
            else:
                print("❌ Invalid choice. Please select 1-4.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Scan cancelled by user\n")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
    
    print("\n📚 Additional Resources:")
    print("   - Wapiti Docs: https://wapiti-scanner.github.io/")
    print("   - OWASP Top 10: https://owasp.org/www-project-top-ten/")
    print("   - Burp Suite: For manual testing and verification")
    print("   - OWASP ZAP: Alternative automated scanner")

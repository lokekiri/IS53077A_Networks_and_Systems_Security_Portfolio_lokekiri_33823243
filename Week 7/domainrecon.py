"""
Week 07: Domain Reconnaissance Tool
Networks and Systems Security Portfolio

Purpose:
Perform passive reconnaissance on domain names to gather publicly
available information. This is the first phase of penetration testing
methodology.

⚠️  ETHICAL USE ONLY:
- Only scan domains you own or have written permission to test
- Passive reconnaissance gathers PUBLIC information only
- Still respect robots.txt and rate limits

Learning Outcomes:
- Understanding passive vs active reconnaissance
- DNS resolution and geolocation
- Open-source intelligence (OSINT) gathering
"""

import socket
import requests
import sys
from datetime import datetime
import json


class DomainRecon:
    """Passive reconnaissance tool for domain analysis."""
    
    def __init__(self, domain):
        """
        Initialise reconnaissance for a domain.
        
        Args:
            domain: Domain name to investigate (e.g., example.com)
        """
        self.domain = domain.lower().strip()
        self.results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'geolocation': {},
            'errors': []
        }
    
    def resolve_dns(self):
        """
        Perform DNS resolution to find IP address.
        This is a low-risk active component.
        
        Returns:
            str: IP address or None if resolution fails
        """
        print(f"🔍 Resolving DNS for {self.domain}...")
        
        try:
            ip_address = socket.gethostbyname(self.domain)
            print(f"   ✅ IP Address: {ip_address}")
            
            self.results['dns']['ipv4'] = ip_address
            return ip_address
            
        except socket.gaierror as e:
            print(f"   ❌ DNS resolution failed: {e}")
            self.results['errors'].append(f"DNS resolution failed: {e}")
            return None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            self.results['errors'].append(f"DNS error: {e}")
            return None
    
    def get_geolocation(self, ip_address):
        """
        Get geolocation information from IP address.
        Uses free public API (ipapi.co) - completely passive.
        
        Args:
            ip_address: IPv4 address to lookup
            
        Returns:
            dict: Geolocation information
        """
        print(f"\n🌍 Gathering geolocation data...")
        
        try:
            # Use free geolocation API
            response = requests.get(
                f"https://ipapi.co/{ip_address}/json/",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                geo_info = {
                    'ip': data.get('ip', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'latitude': data.get('latitude', 'Unknown'),
                    'longitude': data.get('longitude', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'asn': data.get('asn', 'Unknown'),
                    'organisation': data.get('org', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
                
                self.results['geolocation'] = geo_info
                
                # Display results
                print(f"   📍 Location: {geo_info['city']}, {geo_info['country']}")
                print(f"   🏢 Organisation: {geo_info['organisation']}")
                print(f"   📡 ISP: {geo_info['isp']}")
                print(f"   🔢 ASN: {geo_info['asn']}")
                print(f"   🕐 Timezone: {geo_info['timezone']}")
                
                return geo_info
                
            else:
                print(f"   ⚠️  Geolocation lookup failed (HTTP {response.status_code})")
                self.results['errors'].append(f"Geolocation failed: HTTP {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"   ❌ Request error: {e}")
            self.results['errors'].append(f"Geolocation request error: {e}")
            return None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            self.results['errors'].append(f"Geolocation error: {e}")
            return None
    
    def get_reverse_dns(self, ip_address):
        """
        Attempt reverse DNS lookup.
        
        Args:
            ip_address: IP address to reverse lookup
            
        Returns:
            str: Hostname or None
        """
        print(f"\n🔄 Attempting reverse DNS lookup...")
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            print(f"   ✅ Hostname: {hostname}")
            self.results['dns']['reverse'] = hostname
            return hostname
            
        except socket.herror:
            print(f"   ℹ️  No reverse DNS entry found")
            return None
        except Exception as e:
            print(f"   ⚠️  Reverse DNS error: {e}")
            return None
    
    def run_full_recon(self):
        """
        Execute complete passive reconnaissance workflow.
        
        Returns:
            dict: Complete reconnaissance results
        """
        print("\n" + "="*70)
        print(f"🕵️  PASSIVE RECONNAISSANCE: {self.domain}")
        print("="*70 + "\n")
        
        # Step 1: DNS Resolution
        ip_address = self.resolve_dns()
        
        if ip_address:
            # Step 2: Geolocation
            self.get_geolocation(ip_address)
            
            # Step 3: Reverse DNS
            self.get_reverse_dns(ip_address)
        else:
            print("\n⚠️  Cannot continue without IP address")
            return self.results
        
        # Summary
        print("\n" + "="*70)
        print("📊 RECONNAISSANCE SUMMARY")
        print("="*70)
        print(f"Domain: {self.domain}")
        print(f"IP: {self.results['dns'].get('ipv4', 'N/A')}")
        print(f"Location: {self.results['geolocation'].get('city', 'N/A')}, {self.results['geolocation'].get('country', 'N/A')}")
        print(f"Hosting: {self.results['geolocation'].get('organisation', 'N/A')}")
        
        if self.results['errors']:
            print(f"\n⚠️  Errors encountered: {len(self.results['errors'])}")
        
        print("="*70 + "\n")
        
        return self.results
    
    def save_results(self, filename=None):
        """
        Save reconnaissance results to JSON file.
        
        Args:
            filename: Output filename (default: domain_recon_TIMESTAMP.json)
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"recon_{self.domain}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"💾 Results saved to: {filename}")
        except Exception as e:
            print(f"❌ Failed to save results: {e}")


def main():
    """Main execution function."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     DOMAIN RECONNAISSANCE TOOL                         ║
    ║     Week 07: Passive Information Gathering             ║
    ╚════════════════════════════════════════════════════════╝
    
    ⚠️  ETHICAL USE ONLY:
    - Only scan domains you own or have permission to test
    - This tool gathers PUBLIC information only
    - Respect rate limits and legal boundaries
    """)
    
    # Get domain from command line or prompt
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("\n🎯 Enter domain to investigate (e.g., example.com): ").strip()
    
    if not domain:
        print("❌ No domain provided")
        sys.exit(1)
    
    # Confirm user understands ethical implications
    print(f"\n⚠️  You are about to gather information about: {domain}")
    confirm = input("Do you have permission to investigate this domain? (yes/no): ").strip().lower()
    
    if confirm != 'yes':
        print("\n❌ Operation cancelled. Always obtain permission before testing.")
        sys.exit(1)
    
    # Run reconnaissance
    try:
        recon = DomainRecon(domain)
        results = recon.run_full_recon()
        
        # Offer to save results
        save = input("\n💾 Save results to JSON file? (yes/no): ").strip().lower()
        if save == 'yes':
            recon.save_results()
        
        print("\n✅ Reconnaissance complete!")
        print("\n📚 Next Steps:")
        print("   1. Review gathered information")
        print("   2. Identify potential attack surface")
        print("   3. Proceed to active scanning (with permission)")
        print("   4. Document findings in assessment report\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Reconnaissance interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

import re
import requests
from urllib.parse import urlparse
import socket
import whois
from datetime import datetime, timedelta
import ssl
import OpenSSL

class PhishingURLChecker:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'suspended', 'locked', 'confirm', 'wallet', 'credential'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        self.risk_score = 0
        self.warnings = []
    
    def check_url_length(self, url):
        """Check if URL is suspiciously long"""
        if len(url) > 75:
            self.risk_score += 2
            self.warnings.append(f"⚠️ Unusually long URL ({len(url)} characters)")
            return False
        return True
    
    def check_ip_address(self, url):
        """Check if URL uses IP address instead of domain"""
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Check for IP address pattern
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, hostname):
            self.risk_score += 3
            self.warnings.append("🚨 URL uses IP address instead of domain name")
            return False
        return True
    
    def check_suspicious_symbols(self, url):
        """Check for suspicious characters like @, //"""
        if '@' in url:
            self.risk_score += 3
            self.warnings.append("🚨 URL contains '@' symbol (redirect trick)")
        
        if url.count('//') > 1:
            self.risk_score += 2
            self.warnings.append("⚠️ Multiple '//' found (possible redirect)")
    
    def check_subdomain_count(self, url):
        """Check number of subdomains"""
        parsed = urlparse(url)
        hostname = parsed.netloc
        dots = hostname.count('.')
        
        if dots > 3:
            self.risk_score += 2
            self.warnings.append(f"⚠️ Excessive subdomains ({dots} dots)")
    
    def check_suspicious_keywords(self, url):
        """Check for common phishing keywords"""
        url_lower = url.lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url_lower]
        
        if found_keywords:
            self.risk_score += len(found_keywords)
            self.warnings.append(f"⚠️ Suspicious keywords found: {', '.join(found_keywords)}")
    
    def check_tld(self, url):
        """Check for suspicious top-level domains"""
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        for tld in self.suspicious_tlds:
            if hostname.endswith(tld):
                self.risk_score += 2
                self.warnings.append(f"⚠️ Suspicious TLD: {tld}")
                break
    
    def check_https(self, url):
        """Check if URL uses HTTPS"""
        if not url.startswith('https://'):
            self.risk_score += 2
            self.warnings.append("⚠️ Not using HTTPS (insecure)")
            return False
        return True
    
    def check_domain_age(self, url):
        """Check domain registration age"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            domain_info = whois.whois(hostname)
            
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age = datetime.now() - creation_date
                
                if age < timedelta(days=30):
                    self.risk_score += 3
                    self.warnings.append(f"🚨 Very new domain (registered {age.days} days ago)")
                elif age < timedelta(days=180):
                    self.risk_score += 1
                    self.warnings.append(f"⚠️ Recently registered domain ({age.days} days ago)")
                else:
                    self.warnings.append(f"✅ Domain age: {age.days} days")
        except Exception as e:
            self.warnings.append(f"ℹ️ Could not verify domain age: {str(e)}")
    
    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        self.warnings.append("✅ Valid SSL certificate found")
                    else:
                        self.risk_score += 2
                        self.warnings.append("⚠️ SSL certificate issues detected")
        except Exception as e:
            self.risk_score += 2
            self.warnings.append(f"⚠️ SSL check failed: {str(e)}")
    
    def check_url_shortener(self, url):
        """Check if URL uses shortening service"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        parsed = urlparse(url)
        
        if any(short in parsed.netloc for short in shorteners):
            self.risk_score += 2
            self.warnings.append("⚠️ URL shortener detected (could hide destination)")
    
    def check_misspelling(self, url):
        """Check for common domain misspellings"""
        common_domains = {
            'google': ['g00gle', 'gogle', 'googel'],
            'facebook': ['faceb00k', 'facebok', 'faceboook'],
            'paypal': ['paypai', 'paypa1', 'paypall'],
            'amazon': ['arnazon', 'amazom', 'amaz0n'],
            'microsoft': ['micros0ft', 'microsft', 'microosft']
        }
        
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        for legitimate, misspellings in common_domains.items():
            for misspell in misspellings:
                if misspell in hostname and legitimate not in hostname:
                    self.risk_score += 4
                    self.warnings.append(f"🚨 Possible typosquatting: '{misspell}' (mimics '{legitimate}')")
    
    def analyze(self, url):
        """Run all checks on the URL"""
        self.risk_score = 0
        self.warnings = []
        
        print(f"\n{'='*60}")
        print(f"Analyzing URL: {url}")
        print(f"{'='*60}\n")
        
        # Run all checks
        self.check_url_length(url)
        self.check_ip_address(url)
        self.check_suspicious_symbols(url)
        self.check_subdomain_count(url)
        self.check_suspicious_keywords(url)
        self.check_tld(url)
        self.check_https(url)
        self.check_url_shortener(url)
        self.check_misspelling(url)
        self.check_domain_age(url)
        self.check_ssl_certificate(url)
        
        # Display results
        print("\n📋 Analysis Results:")
        print("-" * 60)
        for warning in self.warnings:
            print(warning)
        
        print(f"\n📊 Risk Score: {self.risk_score}")
        
        # Determine risk level
        if self.risk_score >= 10:
            risk_level = "🔴 HIGH RISK - Likely Phishing"
            recommendation = "❌ DO NOT VISIT THIS SITE"
        elif self.risk_score >= 5:
            risk_level = "🟡 MEDIUM RISK - Suspicious"
            recommendation = "⚠️ Proceed with extreme caution"
        else:
            risk_level = "🟢 LOW RISK"
            recommendation = "✅ Appears relatively safe (still be cautious)"
        
        print(f"\n🎯 Risk Level: {risk_level}")
        print(f"💡 Recommendation: {recommendation}")
        print(f"\n{'='*60}\n")
        
        return self.risk_score

def main():
    checker = PhishingURLChecker()
    
    print("🔒 Phishing URL Checker")
    print("=" * 60)
    
    while True:
        url = input("\nEnter URL to check (or 'quit' to exit): ").strip()
        
        if url.lower() == 'quit':
            print("Goodbye!")
            break
        
        if not url:
            print("Please enter a valid URL")
            continue
        
        # Add http:// if no scheme provided
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        checker.analyze(url)

if __name__ == "__main__":
    main()
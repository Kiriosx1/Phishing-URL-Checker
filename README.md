Phishing URL Checker
A Python-based security tool that analyzes URLs for phishing indicators and malicious patterns. Helps users identify potentially dangerous links before clicking them.
Features

🔍 Comprehensive URL Analysis - Examines multiple suspicious patterns
🚨 Risk Scoring System - Calculates threat level based on multiple factors
🔐 SSL Certificate Validation - Checks for valid HTTPS certificates
📅 Domain Age Verification - Identifies newly registered domains
🎯 Typosquatting Detection - Catches common domain misspellings
⚠️ Suspicious Pattern Recognition - Detects IP addresses, URL shorteners, and more
💬 Interactive CLI - Easy-to-use command-line interface
📊 Detailed Reports - Provides actionable security recommendations

Detection Capabilities
What It Checks

URL length (phishing URLs are often suspiciously long)
IP addresses instead of domain names
Suspicious symbols (@, multiple //)
Excessive subdomains
Common phishing keywords (login, verify, account, etc.)
Suspicious top-level domains (.tk, .ml, .ga, etc.)
HTTPS usage
Domain registration age
SSL certificate validity
URL shortening services
Typosquatting and domain misspellings

Risk Levels

🔴 HIGH RISK (Score ≥ 10) - Likely phishing, do not visit
🟡 MEDIUM RISK (Score 5-9) - Suspicious, proceed with caution
🟢 LOW RISK (Score < 5) - Appears relatively safe

Requirements

Python 3.6 or higher
Internet connection (for domain lookups and SSL checks)

Dependencies
requests>=2.28.0
python-whois>=0.8.0
pyOpenSSL>=23.0.0
Installation
1. Clone the Repository
bashgit clone https://github.com/yourusername/phishing-url-checker.git
cd phishing-url-checker
2. Install Dependencies
bashpip install -r requirements.txt
Or install manually:
bashpip install requests python-whois pyOpenSSL
3. Run the Script
bashpython phishing_checker.py
Usage
Interactive Mode
Simply run the script and enter URLs when prompted:
bash$ python phishing_checker.py

🔒 Phishing URL Checker
============================================================

Enter URL to check (or 'quit' to exit): http://g00gle-login.tk/verify
Example Output
============================================================
Analyzing URL: http://g00gle-login.tk/verify
============================================================

📋 Analysis Results:
------------------------------------------------------------
⚠️ Not using HTTPS (insecure)
⚠️ Suspicious keywords found: login, verify
⚠️ Suspicious TLD: .tk
🚨 Possible typosquatting: 'g00gle' (mimics 'google')
🚨 Very new domain (registered 5 days ago)
⚠️ SSL check failed: [SSL: CERTIFICATE_VERIFY_FAILED]

📊 Risk Score: 15

🎯 Risk Level: 🔴 HIGH RISK - Likely Phishing
💡 Recommendation: ❌ DO NOT VISIT THIS SITE

============================================================
As a Python Module
You can also import and use it in your own scripts:
pythonfrom phishing_checker import PhishingURLChecker

checker = PhishingURLChecker()
risk_score = checker.analyze("http://suspicious-site.com")

if risk_score >= 10:
    print("This URL is dangerous!")
Configuration
Customizing Detection
You can modify the detection parameters in the PhishingURLChecker class:
Suspicious Keywords - Edit the list in __init__:
pythonself.suspicious_keywords = [
    'login', 'signin', 'account', 'verify', 'secure'
    # Add your own keywords
]
Suspicious TLDs - Modify the TLD list:
pythonself.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
Risk Thresholds - Adjust in the analyze() method:
pythonif self.risk_score >= 10:  # High risk threshold
    risk_level = "HIGH RISK"
How It Works
Scoring System
Each detected suspicious pattern adds points to the risk score:
PatternPointsSeverityIP address in URL+3HighTyposquatting detected+4CriticalVery new domain (< 30 days)+3High@ symbol in URL+3HighNo HTTPS+2MediumURL shortener+2MediumSuspicious TLD+2MediumLong URL (> 75 chars)+2MediumSuspicious keywords+1 eachLow
Analysis Flow

Parse and validate URL structure
Check for obvious red flags (IP addresses, @, etc.)
Analyze domain characteristics (TLD, subdomains)
Verify domain age via WHOIS lookup
Check SSL certificate validity
Detect typosquatting patterns
Calculate total risk score
Generate report with recommendations

Requirements File
Create a requirements.txt file:
requests>=2.28.0
python-whois>=0.8.0
pyOpenSSL>=23.0.0
Limitations

WHOIS lookups may be rate-limited
Some legitimate sites may score medium risk
Cannot detect zero-day phishing campaigns
Requires internet connection for full analysis
SSL checks may timeout on slow connections
Domain age check depends on WHOIS availability

False Positives
Some legitimate sites may trigger warnings:

New startups (low domain age)
Sites with many subdomains
Legitimate sites on unusual TLDs
Password reset or login pages

Always use your judgment and verify through official channels.
Best Practices

Never trust shortened URLs from unknown sources
Verify sender identity before clicking links in emails
Check the actual domain - not just the displayed text
Use bookmarks for banking and financial sites
Enable 2FA on all important accounts
Report phishing to the appropriate authorities

Future Enhancements

 API integration for URL reputation services
 Machine learning-based detection
 Browser extension version
 Database of known phishing domains
 Email integration for bulk checking
 GUI interface
 Real-time blacklist checking
 Screenshot capture of suspicious sites
 Integration with Google Safe Browsing API
 PDF report generation

Contributing
Contributions are welcome! Here's how you can help:

Fork the repository
Create a feature branch (git checkout -b feature/awesome-feature)
Commit your changes (git commit -m 'Add awesome feature')
Push to the branch (git push origin feature/awesome-feature)
Open a Pull Request

Areas for Improvement

Additional phishing patterns
Better typosquatting detection
Improved scoring algorithm
More TLD patterns
Performance optimizations

Testing
Test with known safe URLs:
bashhttps://www.google.com
https://www.github.com
https://www.wikipedia.org
Test with suspicious patterns (DO NOT VISIT):
bashhttp://192.168.1.1/login
http://g00gle-verify.tk
http://paypa1-secure.xyz/update
Security Notice
⚠️ Important: This tool provides analysis only and should not be the sole factor in security decisions. Always:

Use common sense and caution
Verify links through official channels
Never enter credentials on suspicious sites
Report phishing to authorities
Keep your software updated

Legal Disclaimer
This tool is provided for educational and security research purposes only. Users are responsible for:

Ensuring lawful use of the tool
Not using it to facilitate phishing or fraud
Complying with applicable laws and regulations
Using results as guidance, not absolute truth

The authors are not liable for any misuse or damages resulting from the use of this tool.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Support
If you encounter issues:

Check existing GitHub issues
Open a new issue with details
Include the URL being tested (if safe to share)
Provide error messages and Python version

Resources

Anti-Phishing Working Group
PhishTank
Google Safe Browsing
WHOIS Lookup

Author
Kiriosx1

GitHub: @Kiriosx1
Email: kyros.businesss@gmail.com

Acknowledgments

Thanks to the cybersecurity community
Inspired by various phishing detection research
Built with standard Python libraries


⭐ If this tool helps you stay safe online, please star the repository!
🔒 Stay safe, stay vigilant!

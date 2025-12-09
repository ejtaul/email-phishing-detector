# 🛡️ Email Phishing Detection System

A Python-based cybersecurity tool that analyzes emails for phishing indicators by examining sender information, URLs, content patterns, and email headers.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![VS Code](https://img.shields.io/badge/VS%20Code-Tools-007ACC?logo=visual-studio-code)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)

## 📋 Project Overview

This system helps identify potential phishing attempts by analyzing multiple email components:

- **🔍 Sender Verification** - Detects email spoofing and mismatched sender information
- **🔗 URL Analysis** - Identifies suspicious links, IP addresses, and lookalike domains
- **📝 Content Scanning** - Flags urgent language, sensitive information requests, and phishing keywords
- **✉️ Header Authentication** - Checks SPF and DKIM authentication results

## 🎯 Why I Built This

Phishing is one of the most common cybersecurity threats, affecting individuals and organizations worldwide. I wanted to understand:
- How phishing attacks work at a technical level
- What patterns make emails suspicious
- How to build practical security tools using Python

This project demonstrates my ability to translate cybersecurity concepts into working code.

## ✨ Key Features

- **Multi-Layer Detection** - Comprehensive analysis covering 4 key areas
- **Risk Scoring System** - Calculates scores (0-100) with Low/Medium/High classifications
- **Color-Coded Reports** - Visual indicators make results easy to understand
- **Report Export** - Save analysis to text files for documentation
- **Interactive CLI** - Menu-driven interface for easy operation
- **Demo Mode** - Built-in phishing example for testing and learning

## 🚀 Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Git (for cloning)
- pip (Python package manager)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/email-phishing-detector.git
cd email-phishing-detector
```

2. **Create virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**

Windows:
```bash
venv\Scripts\activate
```

macOS/Linux:
```bash
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Run the analyzer**
```bash
python email_analyzer.py
```

## 📦 Dependencies

```
beautifulsoup4==4.12.3  # HTML parsing
requests==2.31.0        # HTTP requests
validators==0.22.0      # Email/URL validation
colorama==0.4.6         # Colored terminal output
```

## 💻 Usage

### Interactive Mode

Run the analyzer and follow the menu:
```bash
python email_analyzer.py
```

**Menu Options:**
1. **Analyze New Email** - Paste any email for analysis
2. **Run Demo** - See how the system detects a phishing example
3. **View Detection Criteria** - Learn what the system checks for
4. **Exit** - Close the program

### Analyzing an Email

When you select "Analyze New Email", provide:
- Sender's email address
- Sender's display name (optional)
- Email subject line
- Full email body (press Enter twice when done)
- Optional: Reply-To address, SPF/DKIM results

The system will generate a detailed report with risk assessment.

## 🔍 How It Works

### Detection Mechanisms

#### 1. Sender Verification
- Validates email format using regex patterns
- Compares sender display name with actual email domain
- Flags mismatches like "PayPal <scammer@evil.com>"

**Example:**
```python
# Suspicious: Name says PayPal but email is from different domain
Sender Name: "PayPal Security Team"
Sender Email: "security@paypa1-verify.com"  # Notice the '1' instead of 'l'
```

#### 2. URL Analysis
Examines all links for:
- **IP Addresses** - `http://192.168.1.1/login` (15 points)
- **Suspicious TLDs** - `.tk`, `.ml`, `.xyz` domains (10 points)
- **URL Shorteners** - `bit.ly`, `tinyurl.com` (5 points)
- **Excessive Subdomains** - `secure.login.verify.paypal.evil.com` (10 points)
- **Lookalike Domains** - `paypa1.com` vs `paypal.com` (20 points)

#### 3. Content Analysis
Scans email text for:
- **25+ phishing keywords** - "verify account", "urgent action", "suspended"
- **Urgency language** - Multiple uses of "now", "immediately", "hurry"
- **Sensitive data requests** - Asks for passwords, SSN, credit cards
- **Grammar issues** - Poor formatting, unusual spacing

#### 4. Header Authentication
- **SPF Check** - Verifies sender is authorized for the domain
- **DKIM Check** - Validates email hasn't been tampered with
- **Reply-To Mismatch** - Different reply address than sender

### Risk Scoring

| Risk Level | Score Range | Description | Action |
|------------|-------------|-------------|--------|
| 🟢 **LOW** | 0-30 | Minor or no issues | Proceed with caution |
| 🟡 **MEDIUM** | 30-60 | Some red flags present | Verify before acting |
| 🔴 **HIGH** | 60-100 | Multiple phishing indicators | DO NOT interact |

## 📊 Example Output

```
============================================================
EMAIL PHISHING ANALYSIS REPORT
============================================================

[1] Analyzing Sender Information...
  ⚠ Sender name mentions 'paypal' but email is from 'paypa1-verify.com'

[2] Analyzing URLs...
  Found 1 URL(s)
  ⚠ Suspicious domain extension: http://paypal-secure.tk/verify
  ⚠ Possible lookalike domain: http://paypal-secure.tk/verify

[3] Analyzing Email Content...
  ⚠ Suspicious keywords found: verify your account, account will be closed
  ⚠ Excessive urgency language (4 instances)
  ⚠ Requests sensitive information: password, credit card

[4] Analyzing Email Headers...
  ⚠ Reply-To address (support@suspicious-domain.ru) differs from sender
  ⚠ SPF authentication failed
  ⚠ DKIM authentication failed

============================================================
FINAL ASSESSMENT
============================================================

Risk Score: 85/100
Risk Level: HIGH

Recommendation: HIGH RISK! This email shows strong phishing indicators.
DO NOT click links or provide information.

Issues Found (8):
  1. Sender name mentions 'paypal' but email is from 'paypa1-verify.com'
  2. Suspicious domain extension: http://paypal-secure.tk/verify
  3. Possible lookalike domain: http://paypal-secure.tk/verify
  4. Suspicious keywords found: verify your account, account will be closed
  5. Excessive urgency language (4 instances)
  6. Requests sensitive information: password, credit card
  7. Reply-To address (support@suspicious-domain.ru) differs from sender
  8. SPF authentication failed
```

## 📁 Project Structure

```
email-phishing-detector/
├── phishing_detector.py       # Core detection engine with analysis logic
├── email_analyzer.py           # Interactive CLI interface
├── requirements.txt            # Python package dependencies
├── README.md                   # Project documentation
├── .gitignore                  # Git ignore rules
└── screenshots/                # Project screenshots
```

## 🎓 What I Learned

### Technical Skills
- **Python OOP** - Classes, methods, encapsulation
- **Regular Expressions** - Pattern matching for URLs and text analysis
- **String Manipulation** - Parsing and analyzing email components
- **CLI Development** - Building user-friendly terminal interfaces
- **Package Management** - Using pip and virtual environments

### Cybersecurity Concepts
- **Email Authentication** - SPF, DKIM, and how they prevent spoofing
- **Phishing Tactics** - Common techniques used by attackers
- **Domain Analysis** - Identifying lookalike and suspicious domains
- **Social Engineering** - Urgency, authority, and psychological manipulation
- **Risk Assessment** - Quantifying threats with scoring systems

### Development Practices
- **Version Control** - Git workflow and GitHub repository management
- **Documentation** - Writing clear READMEs and code comments
- **Code Organization** - Modular design with separate files for logic and interface
- **Testing** - Creating demo data to verify functionality

## 🔮 Future Enhancements

Ideas for expanding this project:

- [ ] **Machine Learning** - Train ML model on labeled phishing dataset
- [ ] **Database Integration** - Store analysis history in SQLite
- [ ] **Web Interface** - Flask/Django web app with drag-and-drop email upload
- [ ] **Email Client Integration** - Direct integration with Gmail/Outlook APIs
- [ ] **Real-Time URL Checking** - Query VirusTotal, Google Safe Browsing APIs
- [ ] **Multi-Language Support** - Detect phishing in non-English emails
- [ ] **PDF Reports** - Generate professional PDF analysis reports
- [ ] **Browser Extension** - Analyze emails directly in Gmail web interface

## ⚠️ Limitations

**Important Considerations:**
- Pattern-based detection may produce false positives/negatives
- Cannot analyze encrypted emails without decryption keys
- Relies on user input for header information (no automatic parsing)
- Does not replace human judgment or professional security tools
- New phishing techniques may not be detected

**This tool is educational** - use it alongside, not instead of, your email provider's built-in security.

## 🛠️ Troubleshooting

### Common Issues

**"Python is not recognized"**
- Ensure Python is installed and added to PATH
- Restart terminal after installation

**"No module named 'colorama'"**
- Activate virtual environment: `venv\Scripts\activate`
- Install requirements: `pip install -r requirements.txt`

**Colors not showing in terminal**
- Windows: Use Command Prompt or PowerShell, not Git Bash
- Update Windows Terminal for best color support

**Virtual environment not activating**
- Check you're in the project directory
- Use correct path: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (macOS/Linux)

## 📝 License

This project is open source and available under the MIT License.

## 👤 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your LinkedIn Profile](https://linkedin.com/in/yourprofile)

## 🙏 Acknowledgments

- Python Community for excellent libraries (colorama, validators, etc.)
- OWASP for phishing attack research and documentation
- Anti-Phishing Working Group for industry best practices

## 📚 Resources

- [OWASP Phishing Guide](https://owasp.org/www-community/attacks/Phishing)
- [Email Header Analysis Tool](https://mxtoolbox.com/EmailHeaders.aspx)
- [SPF, DKIM, and DMARC Explained](https://www.cloudflare.com/learning/email-security/)
- [Python Regular Expressions](https://docs.python.org/3/library/re.html)

## ⭐ Show Your Support

Give a ⭐️ if this project helped you learn about cybersecurity and Python!

---

**⚡ Built with Python • 🛡️ Focused on Security • 📚 Created for Learning**

*Disclaimer: This tool is for educational purposes. Always verify suspicious emails through official channels and report phishing attempts to your IT security team or email provider.*
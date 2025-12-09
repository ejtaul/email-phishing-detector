"""
Email Phishing Detection System
Analyzes email content and headers for phishing indicators
"""

import re
import validators
from urllib.parse import urlparse
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama for colored terminal output
init(autoreset=True)


class PhishingDetector:
    """Main class for detecting phishing attempts in emails"""
    
    def __init__(self):
        # Suspicious keywords that phishers commonly use
        self.suspicious_keywords = [
            'verify your account', 'confirm your identity', 'suspended account',
            'urgent action required', 'click here immediately', 'verify your information',
            'account will be closed', 'unusual activity', 'confirm your password',
            'update payment', 'claim your prize', 'you have won', 'act now',
            'limited time', 'expire', 'social security', 'tax refund'
        ]
        
        # Legitimate domains (you can expand this list)
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com'
        ]
        
        # Risk thresholds
        self.risk_levels = {
            'low': (0, 30),
            'medium': (30, 60),
            'high': (60, 100)
        }
    
    def extract_urls(self, text):
        """Extract all URLs from email text"""
        # Regular expression to find URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def check_sender_spoofing(self, sender_email, sender_name):
        """Check if sender email matches sender name (basic spoofing check)"""
        risk_score = 0
        issues = []
        
        # Check if email is valid format
        if not validators.email(sender_email):
            risk_score += 20
            issues.append("Invalid email format")
        
        # Check for display name spoofing (e.g., "PayPal <hacker@evil.com>")
        if sender_name:
            # Extract domain from email
            email_domain = sender_email.split('@')[-1].lower()
            
            # Check if name mentions a company but email doesn't match
            for legit_domain in self.legitimate_domains:
                company_name = legit_domain.split('.')[0]
                if company_name in sender_name.lower() and legit_domain not in email_domain:
                    risk_score += 25
                    issues.append(f"Sender name mentions '{company_name}' but email is from '{email_domain}'")
        
        return risk_score, issues
    
    def analyze_urls(self, urls):
        """Analyze URLs for suspicious characteristics"""
        risk_score = 0
        issues = []
        
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check for IP address instead of domain name
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                risk_score += 15
                issues.append(f"URL uses IP address: {url}")
            
            # Check for suspicious TLDs (top-level domains)
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                risk_score += 10
                issues.append(f"Suspicious domain extension: {url}")
            
            # Check for URL shorteners (could hide malicious links)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                risk_score += 5
                issues.append(f"URL shortener detected: {url}")
            
            # Check for excessive subdomains (e.g., paypal.login.secure.evil.com)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                risk_score += 10
                issues.append(f"Excessive subdomains: {url}")
            
            # Check for lookalike domains (homograph attacks)
            # Example: paypa1.com instead of paypal.com (using '1' instead of 'l')
            suspicious_chars = ['1', '0', 'rn', 'vv']
            if any(char in domain for char in suspicious_chars):
                for legit_domain in self.legitimate_domains:
                    if legit_domain.replace('l', '1') in domain or \
                       legit_domain.replace('o', '0') in domain:
                        risk_score += 20
                        issues.append(f"Possible lookalike domain: {url}")
                        break
        
        return risk_score, issues
    
    def analyze_content(self, email_body):
        """Analyze email content for suspicious language and urgency"""
        risk_score = 0
        issues = []
        
        email_lower = email_body.lower()
        
        # Check for suspicious keywords
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in email_lower:
                found_keywords.append(keyword)
                risk_score += 3
        
        if found_keywords:
            issues.append(f"Suspicious keywords found: {', '.join(found_keywords[:5])}")
        
        # Check for excessive urgency indicators
        urgency_words = ['urgent', 'immediately', 'now', 'today', 'hurry', 'quick', 'fast']
        urgency_count = sum(email_lower.count(word) for word in urgency_words)
        if urgency_count > 3:
            risk_score += 10
            issues.append(f"Excessive urgency language ({urgency_count} instances)")
        
        # Check for requests for sensitive information
        sensitive_requests = ['password', 'social security', 'ssn', 'credit card', 'bank account']
        found_sensitive = [word for word in sensitive_requests if word in email_lower]
        if found_sensitive:
            risk_score += 15
            issues.append(f"Requests sensitive information: {', '.join(found_sensitive)}")
        
        # Check for poor grammar (basic check - count of common mistakes)
        grammar_issues = 0
        if '  ' in email_body:  # Double spaces
            grammar_issues += 1
        if re.search(r'[a-z]\.[A-Z]', email_body):  # No space after period
            grammar_issues += 1
        
        if grammar_issues > 0:
            risk_score += 5
            issues.append("Potential grammar/formatting issues detected")
        
        return risk_score, issues
    
    def analyze_headers(self, headers):
        """Analyze email headers for red flags"""
        risk_score = 0
        issues = []
        
        # Check for missing or suspicious Reply-To address
        reply_to = headers.get('reply_to', '').lower()
        sender_email = headers.get('sender_email', '').lower()
        
        if reply_to and reply_to != sender_email:
            # Extract domains
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
            reply_domain = reply_to.split('@')[-1] if '@' in reply_to else ''
            
            if sender_domain != reply_domain:
                risk_score += 15
                issues.append(f"Reply-To address ({reply_to}) differs from sender")
        
        # Check for SPF/DKIM failures (if provided)
        if headers.get('spf_result') == 'fail':
            risk_score += 20
            issues.append("SPF authentication failed")
        
        if headers.get('dkim_result') == 'fail':
            risk_score += 20
            issues.append("DKIM authentication failed")
        
        return risk_score, issues
    
    def get_risk_level(self, score):
        """Determine risk level based on score"""
        for level, (min_score, max_score) in self.risk_levels.items():
            if min_score <= score < max_score:
                return level
        return 'high'
    
    def analyze_email(self, email_data):
        """Main analysis function - brings everything together"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}EMAIL PHISHING ANALYSIS REPORT")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        total_risk_score = 0
        all_issues = []
        
        # 1. Analyze sender
        print(f"{Fore.YELLOW}[1] Analyzing Sender Information...")
        sender_score, sender_issues = self.check_sender_spoofing(
            email_data.get('sender_email', ''),
            email_data.get('sender_name', '')
        )
        total_risk_score += sender_score
        all_issues.extend(sender_issues)
        
        if sender_issues:
            for issue in sender_issues:
                print(f"  {Fore.RED}⚠ {issue}")
        else:
            print(f"  {Fore.GREEN}✓ No sender issues detected")
        
        # 2. Analyze URLs
        print(f"\n{Fore.YELLOW}[2] Analyzing URLs...")
        urls = self.extract_urls(email_data.get('body', ''))
        if urls:
            print(f"  Found {len(urls)} URL(s)")
            url_score, url_issues = self.analyze_urls(urls)
            total_risk_score += url_score
            all_issues.extend(url_issues)
            
            if url_issues:
                for issue in url_issues:
                    print(f"  {Fore.RED}⚠ {issue}")
            else:
                print(f"  {Fore.GREEN}✓ URLs appear legitimate")
        else:
            print(f"  {Fore.GREEN}✓ No URLs found")
        
        # 3. Analyze content
        print(f"\n{Fore.YELLOW}[3] Analyzing Email Content...")
        content_score, content_issues = self.analyze_content(email_data.get('body', ''))
        total_risk_score += content_score
        all_issues.extend(content_issues)
        
        if content_issues:
            for issue in content_issues:
                print(f"  {Fore.RED}⚠ {issue}")
        else:
            print(f"  {Fore.GREEN}✓ Content appears safe")
        
        # 4. Analyze headers
        print(f"\n{Fore.YELLOW}[4] Analyzing Email Headers...")
        header_score, header_issues = self.analyze_headers(email_data.get('headers', {}))
        total_risk_score += header_score
        all_issues.extend(header_issues)
        
        if header_issues:
            for issue in header_issues:
                print(f"  {Fore.RED}⚠ {issue}")
        else:
            print(f"  {Fore.GREEN}✓ Headers appear legitimate")
        
        # Final assessment
        risk_level = self.get_risk_level(total_risk_score)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}FINAL ASSESSMENT")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"\nRisk Score: {total_risk_score}/100")
        
        # Color-code the risk level
        if risk_level == 'low':
            color = Fore.GREEN
            recommendation = "This email appears relatively safe, but always exercise caution."
        elif risk_level == 'medium':
            color = Fore.YELLOW
            recommendation = "This email shows some suspicious indicators. Verify before taking action."
        else:
            color = Fore.RED
            recommendation = "HIGH RISK! This email shows strong phishing indicators. DO NOT click links or provide information."
        
        print(f"Risk Level: {color}{risk_level.upper()}{Style.RESET_ALL}")
        print(f"\n{color}Recommendation:{Style.RESET_ALL} {recommendation}")
        
        print(f"\n{Fore.CYAN}Issues Found ({len(all_issues)}):")
        if all_issues:
            for i, issue in enumerate(all_issues, 1):
                print(f"  {i}. {issue}")
        else:
            print(f"  {Fore.GREEN}No issues detected")
        
        print(f"\n{Fore.CYAN}{'='*60}\n")
        
        return {
            'risk_score': total_risk_score,
            'risk_level': risk_level,
            'issues': all_issues,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }


# Example usage
if __name__ == "__main__":
    # Create detector instance
    detector = PhishingDetector()
    
    # Example phishing email (for testing)
    test_email = {
        'sender_email': 'security@paypa1-verify.com',
        'sender_name': 'PayPal Security',
        'subject': 'URGENT: Verify Your Account Now!',
        'body': '''
        Dear Valued Customer,
        
        Your PayPal account has been suspended due to unusual activity. 
        You must verify your account immediately to avoid permanent closure.
        
        Click here to verify: http://paypal-secure.tk/verify?id=12345
        
        You have 24 hours to act now or your account will be permanently closed.
        Please confirm your password and credit card information.
        
        Thank you,
        PayPal Security Team
        ''',
        'headers': {
            'reply_to': 'support@suspicious-domain.ru',
            'spf_result': 'fail',
            'dkim_result': 'fail'
        }
    }
    
    # Analyze the email
    result = detector.analyze_email(test_email)
    
    print(f"\n{Fore.MAGENTA}Test completed! This was an example phishing email for demonstration.")
    print(f"Now you can analyze your own emails using this system.{Style.RESET_ALL}\n")
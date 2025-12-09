"""
Interactive Email Phishing Analyzer
User-friendly interface for analyzing emails
"""

from phishing_detector import PhishingDetector
from colorama import Fore, Style, init
import sys

init(autoreset=True)


def print_banner():
    """Display welcome banner"""
    banner = f"""
    {Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║       EMAIL PHISHING DETECTION SYSTEM v1.0                ║
    ║       Analyze emails for phishing indicators              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def get_multiline_input(prompt):
    """Get multiple lines of input from user"""
    print(f"\n{Fore.YELLOW}{prompt}")
    print(f"{Fore.YELLOW}(Press Enter twice when done, or type 'CANCEL' to go back){Style.RESET_ALL}\n")
    
    lines = []
    empty_line_count = 0
    
    while True:
        line = input()
        
        if line.upper() == 'CANCEL':
            return None
        
        if line == '':
            empty_line_count += 1
            if empty_line_count >= 2:
                break
        else:
            empty_line_count = 0
            lines.append(line)
    
    return '\n'.join(lines)


def collect_email_data():
    """Collect email information from user"""
    print(f"\n{Fore.GREEN}Let's analyze an email. I'll need some information:{Style.RESET_ALL}\n")
    
    email_data = {}
    
    # Get sender email
    while True:
        sender_email = input(f"{Fore.CYAN}Sender Email Address: {Style.RESET_ALL}").strip()
        if sender_email:
            email_data['sender_email'] = sender_email
            break
        print(f"{Fore.RED}Please enter a sender email address{Style.RESET_ALL}")
    
    # Get sender name (optional)
    sender_name = input(f"{Fore.CYAN}Sender Display Name (optional, press Enter to skip): {Style.RESET_ALL}").strip()
    email_data['sender_name'] = sender_name
    
    # Get subject
    subject = input(f"{Fore.CYAN}Email Subject: {Style.RESET_ALL}").strip()
    email_data['subject'] = subject
    
    # Get email body
    body = get_multiline_input("Email Body (paste the full email content):")
    if body is None:
        return None
    email_data['body'] = body
    
    # Ask about headers (optional advanced section)
    print(f"\n{Fore.YELLOW}Optional: Advanced header information")
    print(f"(Press Enter to skip if you don't have this information){Style.RESET_ALL}")
    
    headers = {}
    
    reply_to = input(f"{Fore.CYAN}Reply-To Address (if different from sender): {Style.RESET_ALL}").strip()
    if reply_to:
        headers['reply_to'] = reply_to
    
    print(f"\n{Fore.CYAN}SPF Result (pass/fail/none): {Style.RESET_ALL}", end='')
    spf = input().strip().lower()
    if spf in ['pass', 'fail', 'none']:
        headers['spf_result'] = spf
    
    print(f"{Fore.CYAN}DKIM Result (pass/fail/none): {Style.RESET_ALL}", end='')
    dkim = input().strip().lower()
    if dkim in ['pass', 'fail', 'none']:
        headers['dkim_result'] = dkim
    
    email_data['headers'] = headers
    
    return email_data


def save_report(result, email_data):
    """Save analysis report to a file"""
    filename = f"phishing_report_{result['timestamp'].replace(':', '-').replace(' ', '_')}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("EMAIL PHISHING ANALYSIS REPORT\n")
        f.write("="*60 + "\n\n")
        f.write(f"Timestamp: {result['timestamp']}\n\n")
        
        f.write("Email Details:\n")
        f.write(f"  From: {email_data.get('sender_name', 'N/A')} <{email_data.get('sender_email', 'N/A')}>\n")
        f.write(f"  Subject: {email_data.get('subject', 'N/A')}\n\n")
        
        f.write("Analysis Results:\n")
        f.write(f"  Risk Score: {result['risk_score']}/100\n")
        f.write(f"  Risk Level: {result['risk_level'].upper()}\n\n")
        
        f.write(f"Issues Found ({len(result['issues'])}):\n")
        if result['issues']:
            for i, issue in enumerate(result['issues'], 1):
                f.write(f"  {i}. {issue}\n")
        else:
            f.write("  No issues detected\n")
        
        f.write("\n" + "="*60 + "\n")
    
    return filename


def main_menu():
    """Display main menu and handle user choices"""
    detector = PhishingDetector()
    
    while True:
        print(f"\n{Fore.GREEN}╔═══════════════════════════════════╗")
        print(f"║          MAIN MENU                ║")
        print(f"╚═══════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Analyze New Email")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Run Demo Analysis (Example Phishing Email)")
        print(f"{Fore.CYAN}3.{Style.RESET_ALL} View Detection Criteria")
        print(f"{Fore.CYAN}4.{Style.RESET_ALL} Exit")
        
        choice = input(f"\n{Fore.YELLOW}Enter your choice (1-4): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            # Analyze new email
            email_data = collect_email_data()
            
            if email_data is None:
                print(f"\n{Fore.YELLOW}Analysis cancelled.{Style.RESET_ALL}")
                continue
            
            # Run analysis
            result = detector.analyze_email(email_data)
            
            # Ask if user wants to save report
            save_choice = input(f"\n{Fore.CYAN}Save this report to a file? (y/n): {Style.RESET_ALL}").strip().lower()
            if save_choice == 'y':
                filename = save_report(result, email_data)
                print(f"{Fore.GREEN}✓ Report saved to: {filename}{Style.RESET_ALL}")
        
        elif choice == '2':
            # Run demo
            print(f"\n{Fore.MAGENTA}Running demo analysis with example phishing email...{Style.RESET_ALL}")
            
            demo_email = {
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
            
            detector.analyze_email(demo_email)
            print(f"\n{Fore.MAGENTA}This was a simulated phishing email for demonstration purposes.{Style.RESET_ALL}")
        
        elif choice == '3':
            # Show detection criteria
            print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗")
            print(f"║              PHISHING DETECTION CRITERIA                  ║")
            print(f"╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
            
            print(f"{Fore.YELLOW}This system checks for:{Style.RESET_ALL}\n")
            
            print(f"{Fore.GREEN}1. Sender Verification:")
            print(f"   • Invalid email formats")
            print(f"   • Display name spoofing (name doesn't match email domain)")
            print(f"   • Mismatched Reply-To addresses\n")
            
            print(f"{Fore.GREEN}2. URL Analysis:")
            print(f"   • IP addresses instead of domain names")
            print(f"   • Suspicious domain extensions (.tk, .ml, etc.)")
            print(f"   • URL shorteners (bit.ly, tinyurl, etc.)")
            print(f"   • Excessive subdomains")
            print(f"   • Lookalike domains (paypa1.com vs paypal.com)\n")
            
            print(f"{Fore.GREEN}3. Content Analysis:")
            print(f"   • Urgent/threatening language")
            print(f"   • Requests for sensitive information")
            print(f"   • Common phishing keywords")
            print(f"   • Grammar and formatting issues\n")
            
            print(f"{Fore.GREEN}4. Header Authentication:")
            print(f"   • SPF (Sender Policy Framework) failures")
            print(f"   • DKIM (DomainKeys Identified Mail) failures\n")
            
            print(f"{Fore.CYAN}Risk Levels:")
            print(f"  • LOW (0-30):    Email appears relatively safe")
            print(f"  • MEDIUM (30-60): Some suspicious indicators present")
            print(f"  • HIGH (60+):    Strong phishing indicators - avoid interaction{Style.RESET_ALL}\n")
            
            input(f"{Fore.YELLOW}Press Enter to return to main menu...{Style.RESET_ALL}")
        
        elif choice == '4':
            # Exit
            print(f"\n{Fore.GREEN}Thank you for using the Email Phishing Detection System!")
            print(f"Stay safe online! 🛡️{Style.RESET_ALL}\n")
            sys.exit(0)
        
        else:
            print(f"\n{Fore.RED}Invalid choice. Please enter 1-4.{Style.RESET_ALL}")


if __name__ == "__main__":
    print_banner()
    print(f"{Fore.YELLOW}Welcome! This tool helps you identify phishing attempts in emails.")
    print(f"Stay vigilant and always verify suspicious emails.{Style.RESET_ALL}")
    
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Program interrupted by user. Goodbye!{Style.RESET_ALL}\n")
        sys.exit(0)
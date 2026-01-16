import mailparser
import requests
import hashlib
import os
import base64
import glob
import re
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

class PhishingAnalyzer:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.mail = mailparser.parse_from_file(eml_path)
        
    def defang(self, text):
        return text.replace("http", "hXXp").replace(".", "[.]")

    def get_file_hash(self, content):
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()

    def check_vt_url(self, url):
        if not VT_API_KEY or VT_API_KEY == "your_api_key_here":
            return "API Key Missing"
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        
        try:
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"
            return "No record found"
        except Exception:
            return "Connection Error"

    def analyze(self):
        print(f"\n{'='*15} ANALYSIS REPORT {'='*15}")
        print(f"[ File     ]: {os.path.basename(self.eml_path)}")
        print(f"[ Subject  ]: {self.mail.subject}")
        print(f"[ From     ]: {self.mail.from_}")
        
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_urls = list(set(re.findall(url_pattern, self.mail.body)))

        print(f"\n[!] Scanning URLs:")
        if not found_urls:
            print("    No URLs found.")
        else:
            for url in found_urls:
                verdict = self.check_vt_url(url)
                print(f"  - {self.defang(url)}")
                print(f"    Verdict: {verdict}")

        print(f"\n[!] Scanning Attachments:")
        if not self.mail.attachments:
            print("    No attachments found.")
        else:
            for attach in self.mail.attachments:
                f_hash = self.get_file_hash(attach['payload'])
                print(f"  - File: {attach['filename']}")
                print(f"    SHA256: {f_hash}")

        print(f"\n{'='*47}")

if __name__ == "__main__":
    eml_files = glob.glob("*.eml")
    if not eml_files:
        print("[-] No .eml files found.")
    else:
        print(f"[*] Found {len(eml_files)} file(s). Starting Triage...")
        for file in eml_files:
            scanner = PhishingAnalyzer(file)
            scanner.analyze()
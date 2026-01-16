SafeMail - Phishing Email Analyzer
This tool is designed to automate the analysis of phishing email files (.eml). It extracts URLs and attachments, calculates file hashes, and checks reputation via the VirusTotal API to streamline the triage process for SOC analysts.

Features
URL Extraction: Uses Regular Expressions (Regex) to identify all links within the email body.

URL Defanging: Automatically neutralizes URLs (e.g., converting http to hXXp) to prevent accidental clicks during analysis.

Attachment Hashing: Calculates the SHA256 hash for all attached files to facilitate malware database lookups.

VirusTotal Integration: Connects to the VirusTotal API to provide an automated reputation verdict for extracted URLs.

Requirements
Install the necessary Python libraries using the following command:

Bash

pip install mail-parser requests python-dotenv
Setup and Usage
Clone the repository to your local machine.

Create a .env file in the root directory and add your VirusTotal API key:

Plaintext

VT_API_KEY="your_api_key_here"
Place the .eml files you wish to analyze in the same folder as the script.

Run the analyzer:

Bash

python parser.py
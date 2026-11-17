# Vulnerability Scanner (Mini Project)

A lightweight Python vulnerability scanner built to detect common network and web application security issues on authorized local test environments.

## Key Features
- **Open Port & Banner Scanning:** Scans common service ports (FTP, SSH, Telnet, HTTP, HTTPS, MySQL, HTTP-Proxy) and captures service banners.
- **Version & Information Disclosure Detection:** Inspects `Server` and `X-Powered-By` HTTP response headers to identify exposed software versions.
- **Weak Configuration Checks:** Audits responses for missing security headers (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`) and unencrypted HTTP usage.
- **Automated Reporting:** Generates a timestamped Markdown assessment report with remediation steps.

## Setup & Usage
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start a local test server (in a separate terminal):
   ```bash
   python -m http.server 8080
   ```
3. Run the scanner:
   ```bash
   python scanner.py
   ```
4. Enter `http://127.0.0.1:8080` when prompted.

## Disclaimer
Only run this tool against systems you own or have explicit written permission to test.

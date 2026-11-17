import socket
import requests
from datetime import datetime
from urllib.parse import urlparse

# Common ports to check and their associated services
COMMON_PORTS = {
    21: "FTP (Unencrypted file transfer)",
    22: "SSH",
    23: "Telnet (Insecure unencrypted remote access)",
    80: "HTTP (Unencrypted web traffic)",
    443: "HTTPS",
    3306: "MySQL Database",
    8080: "HTTP-Proxy / Alternate Web Server"
}

# Security headers that should be present on modern web apps
REQUIRED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

def scan_ports(target_ip):
    """Scans common ports and attempts basic banner grabbing to identify service versions."""
    open_ports = []
    print(f"[*] Scanning common ports on {target_ip}...")
    
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            banner = "No banner retrieved"
            try:
                # Attempt to grab service banner
                if port in [80, 8080]:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_bytes = sock.recv(1024)
                lines = banner_bytes.decode("utf-8", errors="ignore").strip().splitlines()
                if lines:
                    banner = lines[0]
            except Exception:
                pass
            
            open_ports.append({
                "port": port,
                "service": service,
                "banner": banner
            })
        sock.close()
    return open_ports

def check_web_vulnerabilities(target_url):
    """Checks for exposed server versions and missing HTTP security headers."""
    findings = []
    print(f"[*] Auditing web configuration for {target_url}...")
    
    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        # 1. Identify Server / Technology Versions (Information Disclosure)
        server_header = headers.get("Server")
        powered_by = headers.get("X-Powered-By")
        
        if server_header:
            findings.append(f"[INFO/LOW] Server version exposed: '{server_header}'. Verify if this version is outdated and patch if necessary.")
        if powered_by:
            findings.append(f"[LOW] Technology stack exposed via X-Powered-By: '{powered_by}'. Recommend disabling this header.")

        # 2. Check for Weak Configuration (Missing Security Headers)
        for header in REQUIRED_SECURITY_HEADERS:
            if header not in headers:
                findings.append(f"[MEDIUM] Missing security header: '{header}'. Leaves application more vulnerable to XSS or clickjacking.")

        # 3. Check if using unencrypted HTTP
        if target_url.startswith("http://"):
            findings.append("[MEDIUM] Target is served over unencrypted HTTP instead of HTTPS.")

    except requests.exceptions.RequestException as e:
        findings.append(f"[ERROR] Could not connect to web service: {e}")
        
    return findings

def generate_report(target, target_ip, open_ports, web_findings):
    """Generates a clean Markdown vulnerability assessment report."""
    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    
    with open(filename, "w", encoding="utf-8") as report:
        report.write("# Vulnerability Assessment Report\n\n")
        report.write(f"- **Target URL:** {target}\n")
        report.write(f"- **Resolved IP:** {target_ip}\n")
        report.write(f"- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        report.write("## 1. Open Ports & Service Banners\n")
        if open_ports:
            report.write("| Port | Service Description | Detected Banner / Version |\n")
            report.write("| :--- | :--- | :--- |\n")
            for item in open_ports:
                report.write(f"| {item['port']} | {item['service']} | `{item['banner']}` |\n")
        else:
            report.write("No common open ports detected.\n")
            
        report.write("\n## 2. Web Configuration & Version Findings\n")
        if web_findings:
            for finding in web_findings:
                report.write(f"- {finding}\n")
        else:
            report.write("No obvious web configuration issues detected.\n")
            
        report.write("\n## 3. Remediation Recommendations\n")
        report.write("1. **Close Unnecessary Ports:** Use a firewall (e.g., UFW or Windows Defender Firewall) to restrict access to non-essential ports.\n")
        report.write("2. **Patch Outdated Software:** Compare detected service banners against the NVD (National Vulnerability Database) and update to the latest stable releases.\n")
        report.write("3. **Harden HTTP Headers:** Configure your web server (Nginx/Apache) to include `Content-Security-Policy`, `X-Frame-Options`, and `Strict-Transport-Security`.\n")

    print(f"\n[+] Scan complete! Report saved to: {filename}")

if __name__ == "__main__":
    print("=== Mini Vulnerability Scanner ===")
    print("NOTE: Only scan systems you own or have explicit permission to test.\n")
    
    target_input = input("Enter target URL (e.g., http://127.0.0.1:8080): ").strip()
    if not target_input.startswith(("http://", "https://")):
        target_input = "http://" + target_input

    parsed_url = urlparse(target_input)
    hostname = parsed_url.hostname

    try:
        ip_address = socket.gethostbyname(hostname)
        ports_data = scan_ports(ip_address)
        web_data = check_web_vulnerabilities(target_input)
        generate_report(target_input, ip_address, ports_data, web_data)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{hostname}'.")

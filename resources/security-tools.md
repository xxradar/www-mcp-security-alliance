# Security Tools for MCP

## Static Analysis Tools

### Code Scanners
- **Bandit**: Python security scanner
- **Semgrep**: Multi-language static analysis
- **CodeQL**: Semantic code analysis
- **SonarQube**: Code quality and security

### Dependency Scanners
```bash
# Check for vulnerable dependencies
npm audit
pip-audit
safety check
```

## Dynamic Analysis Tools

### Web Application Scanners
- **OWASP ZAP**: Web app security scanner
- **Burp Suite**: Professional web security testing
- **Nuclei**: Fast vulnerability scanner

### API Security Testing
```bash
# Example using OWASP ZAP
zap-baseline.py -t http://localhost:8000/api
```

## MCP-Specific Tools

### Custom Security Scanner
```python
#!/usr/bin/env python3
"""
MCP Security Scanner
Scans MCP servers for common vulnerabilities
"""

import requests
import json
import sys

class MCPScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def scan_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT NULL--"
        ]
        
        vulnerabilities = []
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.target_url}/query",
                    json={"query": payload}
                )
                
                if "error" not in response.text.lower():
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "payload": payload,
                        "response": response.text[:200]
                    })
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")
        
        return vulnerabilities
    
    def scan_command_injection(self):
        """Test for command injection vulnerabilities"""
        payloads = [
            "; ls -la",
            "&& whoami",
            "| cat /etc/passwd"
        ]
        
        vulnerabilities = []
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.target_url}/execute",
                    json={"command": f"echo hello{payload}"}
                )
                
                if any(indicator in response.text for indicator in ["root:", "bin:", "usr:"]):
                    vulnerabilities.append({
                        "type": "Command Injection",
                        "payload": payload,
                        "response": response.text[:200]
                    })
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")
        
        return vulnerabilities
    
    def scan_authentication_bypass(self):
        """Test for authentication bypass"""
        bypass_attempts = [
            {"Authorization": "Bearer invalid_token"},
            {"Authorization": ""},
            {}  # No auth header
        ]
        
        vulnerabilities = []
        for headers in bypass_attempts:
            try:
                response = self.session.get(
                    f"{self.target_url}/admin",
                    headers=headers
                )
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Authentication Bypass",
                        "method": "Missing/Invalid Auth",
                        "headers": headers,
                        "status": response.status_code
                    })
            except Exception as e:
                print(f"Error testing auth bypass: {e}")
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities):
        """Generate security report"""
        report = {
            "target": self.target_url,
            "scan_time": "2024-01-01T00:00:00Z",
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulns": len(vulnerabilities),
                "critical": len([v for v in vulnerabilities if v["type"] in ["SQL Injection", "Command Injection"]]),
                "high": len([v for v in vulnerabilities if v["type"] == "Authentication Bypass"])
            }
        }
        
        return json.dumps(report, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python mcp_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = MCPScanner(sys.argv[1])
    
    all_vulns = []
    all_vulns.extend(scanner.scan_sql_injection())
    all_vulns.extend(scanner.scan_command_injection())
    all_vulns.extend(scanner.scan_authentication_bypass())
    
    print(scanner.generate_report(all_vulns))
```

## Container Security

### Docker Security Scanning
```bash
# Scan container images
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image your-mcp-server:latest

# Use docker-bench-security
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

### Kubernetes Security
```bash
# Scan Kubernetes configurations
kubebench run --targets master,node,etcd,policies

# Use kube-hunter
kube-hunter --remote some.node.com
```

## Network Security Tools

### TLS/SSL Testing
```bash
# Test SSL configuration
sslyze --regular your-mcp-server.com:443

# Use testssl.sh
testssl.sh https://your-mcp-server.com
```

### Network Scanning
```bash
# Port scanning with nmap
nmap -sV -sC your-mcp-server.com

# Service discovery
nmap -sU -sS your-mcp-server.com
```

## Monitoring and Logging

### Security Monitoring Stack
```yaml
# docker-compose.yml for security monitoring
version: '3.8'
services:
  elasticsearch:
    image: elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
  
  kibana:
    image: kibana:7.14.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
  
  logstash:
    image: logstash:7.14.0
    depends_on:
      - elasticsearch
  
  filebeat:
    image: elastic/filebeat:7.14.0
    volumes:
      - /var/log:/var/log:ro
    depends_on:
      - elasticsearch
```

### SIEM Integration
```python
# Example: Send security events to SIEM
import requests
import json

def send_security_event(event_type, details):
    event = {
        "timestamp": "2024-01-01T00:00:00Z",
        "source": "mcp-server",
        "event_type": event_type,
        "details": details,
        "severity": get_severity(event_type)
    }
    
    # Send to SIEM/SOAR platform
    requests.post(
        "https://your-siem.com/api/events",
        headers={"Authorization": "Bearer TOKEN"},
        json=event
    )

def get_severity(event_type):
    severity_map = {
        "sql_injection_attempt": "HIGH",
        "auth_bypass_attempt": "MEDIUM",
        "unusual_activity": "LOW"
    }
    return severity_map.get(event_type, "MEDIUM")
```

## Automated Security Testing

### CI/CD Integration
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Bandit Security Scan
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json
      
      - name: Run Safety Check
        run: |
          pip install safety
          safety check --json --output safety-report.json
      
      - name: Run Semgrep
        run: |
          python -m pip install semgrep
          semgrep --config=auto --json --output=semgrep-report.json
      
      - name: Upload Security Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: |
            bandit-report.json
            safety-report.json
            semgrep-report.json
```

### Penetration Testing Framework
```python
# Simple penetration testing framework
class MCPPenTest:
    def __init__(self, target):
        self.target = target
        self.results = []
    
    def run_all_tests(self):
        self.test_authentication()
        self.test_injection_attacks()
        self.test_access_controls()
        self.test_data_exposure()
        return self.results
    
    def test_authentication(self):
        # Implementation for auth testing
        pass
    
    def test_injection_attacks(self):
        # Implementation for injection testing
        pass
    
    def test_access_controls(self):
        # Implementation for access control testing
        pass
    
    def test_data_exposure(self):
        # Implementation for data exposure testing
        pass
```

## Threat Intelligence

### OSINT Tools
```bash
# Gather threat intelligence
theHarvester -d your-domain.com -b all
recon-ng
amass enum -d your-domain.com
```

### Vulnerability Databases
- CVE Database
- NVD (National Vulnerability Database)
- OWASP Dependency Check
- Snyk Vulnerability Database

## Incident Response Tools

### Forensics Tools
```bash
# Memory analysis
volatility -f memory.dump --profile=Win10x64 pslist

# Network forensics
wireshark -r network_capture.pcap

# Log analysis
grep -i "error\|fail\|attack" /var/log/mcp-server.log
```

### Response Automation
```python
# Automated incident response
def incident_response_handler(alert):
    if alert.severity == "CRITICAL":
        # Immediate actions
        block_ip(alert.source_ip)
        notify_security_team(alert)
        
        # Evidence collection
        collect_logs(alert.timestamp)
        create_incident_ticket(alert)
        
        # Containment
        if alert.type == "sql_injection":
            disable_affected_endpoint(alert.endpoint)
```

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Security Tools](https://www.sans.org/tools/)
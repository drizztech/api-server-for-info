import threading
import requests
import json
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request
from tools.base_agent import BaseAgent
import psycopg2
from psycopg2 import sql

# Heuristics and Signatures
SQLI_PAYLOADS = ["'", "\"", "1=1", "' OR '1'='1", "\"; DROP TABLE users; --"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
SENSITIVE_PATTERNS = {
    "sql_error": r"SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.",
    "java_exception": r"java\.lang\.|Servlet\.service|Apache Tomcat",
    "php_error": r"PHP Warning|PHP Error|PHP Parse error",
    "secrets": r"(?i)(api_key|secret|password|token)[ =:]+['\"]?[\w\-]+['\"]?"
}

class FatalisScanner(BaseAgent):
    def __init__(self, db_config=None, max_threads=5, webhook_port=5000):
        super().__init__()
        self.db_config = db_config
        self.max_threads = max_threads
        self.webhook_port = webhook_port
        self.webhook_app = Flask(__name__)
        self.findings = []
        self.visited_urls = set()
        self.lock = threading.Lock()

        # Setup Webhook Route
        @self.webhook_app.route('/webhook', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def webhook_listener():
            data = {
                "method": request.method,
                "headers": dict(request.headers),
                "args": request.args,
                "form": request.form,
                "data": request.get_data(as_text=True),
                "remote_addr": request.remote_addr
            }
            print(f"[+] Webhook received interaction: {data}")
            self.log_finding({
                "type": "WEBHOOK_INTERACTION",
                "details": data,
                "severity": "INFO"
            })
            return "OK", 200

    def start_webhook_server(self):
        """Starts the webhook listener in a separate thread."""
        try:
            print(f"[*] Starting webhook listener on port {self.webhook_port}...")
            # Using run_simple or similar might be better for threading,
            # but app.run with threaded=True is okay for basic testing.
            # We run it in a daemon thread so it dies when main script exits.
            t = threading.Thread(target=self.webhook_app.run, kwargs={'port': self.webhook_port, 'debug': False, 'use_reloader': False})
            t.daemon = True
            t.start()
        except Exception as e:
            print(f"[!] Failed to start webhook server: {e}")

    def log_to_db(self, finding):
        """Logs a finding to the Postgres database if configured."""
        if not self.db_config:
            return

        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS vulns (
                    id SERIAL PRIMARY KEY,
                    url TEXT,
                    type TEXT,
                    severity TEXT,
                    details JSONB,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute(
                "INSERT INTO vulns (url, type, severity, details) VALUES (%s, %s, %s, %s)",
                (finding.get('url'), finding.get('type'), finding.get('severity'), json.dumps(finding.get('details')))
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"[!] Database error: {e}")

    def log_finding(self, finding):
        """Thread-safe logging of findings."""
        with self.lock:
            self.findings.append(finding)
            print(f"[!] VULN FOUND: {finding['type']} at {finding.get('url', 'N/A')}")
            self.log_to_db(finding)

    def extract_forms(self, url, soup):
        """Extracts forms from BeautifulSoup object."""
        forms = []
        for form in soup.find_all("form"):
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                if input_name:
                    inputs.append({"type": input_type, "name": input_name})

            form_details = {
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs
            }
            forms.append(form_details)
        return forms

    def check_sqli(self, url, forms):
        """Checks for SQL Injection in forms."""
        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            for payload in SQLI_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    if input_tag["type"] in ["text", "search"]:
                        data[input_tag["name"]] = payload
                    else:
                        data[input_tag["name"]] = "test"

                try:
                    if method == "post":
                        res = requests.post(action, data=data, timeout=5)
                    else:
                        res = requests.get(action, params=data, timeout=5)

                    for error_type, pattern in SENSITIVE_PATTERNS.items():
                        if re.search(pattern, res.text):
                            finding_type = "SQL_INJECTION" if "sql" in error_type or "mysql" in error_type else "SENSITIVE_INFO_LEAK"
                            self.log_finding({
                                "url": action,
                                "type": finding_type,
                                "severity": "HIGH",
                                "details": {"payload": payload, "pattern": error_type, "input": data}
                            })
                            break
                except Exception as e:
                    pass

    def check_xss(self, url, forms):
        """Checks for Reflected XSS in forms."""
        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            for payload in XSS_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    if input_tag["type"] in ["text", "search"]:
                        data[input_tag["name"]] = payload
                    else:
                        data[input_tag["name"]] = "test"

                try:
                    if method == "post":
                        res = requests.post(action, data=data, timeout=5)
                    else:
                        res = requests.get(action, params=data, timeout=5)

                    if payload in res.text:
                         self.log_finding({
                            "url": action,
                            "type": "REFLECTED_XSS",
                            "severity": "MEDIUM",
                            "details": {"payload": payload, "input": data}
                        })
                except Exception:
                    pass

    def check_heuristics(self, url, text):
        """Checks page content for sensitive info or injection spots."""
        # Java/HTML injection spots (basic regex search)
        if re.search(r"javax\.faces|JSF|struts", text, re.I):
             self.log_finding({
                "url": url,
                "type": "JAVA_FRAMEWORK_DETECTED",
                "severity": "INFO",
                "details": "Potential Java framework (JSF/Struts) detected."
            })

        # IDOR candidates in URL
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for key, vals in qs.items():
            for val in vals:
                if val.isdigit():
                    self.log_finding({
                        "url": url,
                        "type": "IDOR_CANDIDATE",
                        "severity": "LOW",
                        "details": {"param": key, "value": val}
                    })

    def scan_url(self, url):
        """Scans a single URL."""
        if url in self.visited_urls:
            return

        with self.lock:
            self.visited_urls.add(url)

        print(f"[*] Scanning: {url}")
        try:
            res = requests.get(url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")

            # 1. Passive Checks
            self.check_heuristics(url, res.text)

            # 2. Extract Forms & Links
            forms = self.extract_forms(url, soup)

            # 3. Active Checks
            self.check_sqli(url, forms)
            self.check_xss(url, forms)

            # 4. Spidering (Basic: extract same-domain links to queue?)
            # For this tool, we will just log found links for now,
            # to avoid infinite recursion in this simple implementation.
            # A full spider would add these back to a queue.

        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")

    def run(self, params=None):
        """
        Main entry point.
        params: dict containing 'targets' (list) or other config.
        """
        self.start_webhook_server()

        targets = []
        if params and 'targets' in params:
            targets = params['targets']
        else:
            # Fallback to file reading
            for filename in ['maintargets.txt', 'urls.txt']:
                try:
                    with open(filename, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and line.startswith("http"):
                                targets.append(line)
                except FileNotFoundError:
                    pass

        # Deduplicate
        targets = list(set(targets))
        print(f"[*] Loaded {len(targets)} unique targets.")

        # Tip: To proxy traffic through Burp/ZAP, set the HTTP_PROXY and HTTPS_PROXY
        # environment variables before running this script.
        # Example: export HTTP_PROXY=http://127.0.0.1:8080

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_url, target) for target in targets]
            for future in as_completed(futures):
                future.result()

        # Report Generation
        report = {
            "timestamp": time.time(),
            "findings": self.findings
        }

        print("\n[*] Scan Complete. Generating Report...")
        print(json.dumps(report, indent=2))
        return report

if __name__ == "__main__":
    # Example standalone usage
    # DB Config can be passed via env vars or args in real usage
    scanner = FatalisScanner()
    scanner.run()

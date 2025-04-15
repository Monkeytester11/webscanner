import requests
from bs4 import BeautifulSoup

class XSSScanner:
    def scan_url(self, url):
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        try:
            for payload in payloads:
                res = requests.post(url, data={'input': payload}, timeout=5)
                if payload in res.text:
                    return f"XSS Vulnerable! Payload: {payload}"
            return "No XSS found"
        except Exception as e:
            return f"Scan error: {str(e)}"

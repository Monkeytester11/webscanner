# core/subdomains.py
import dns.resolver
from urllib.parse import urlparse

class SubdomainScanner:
    """
    A simple subdomain scanner that checks for common subdomains of a given domain.
    It uses a predefined list of common subdomains and attempts DNS resolution.
    """
    def __init__(self):
        # List of common subdomains to check
        self.common_subdomains = [
            "www", "mail", "ftp", "test", "dev", "admin", "vpn", "api", "beta", "staging"
        ]

    def scan(self, url):
        results = {
            "vulnerable": False,
            "details": [],
            "errors": []
        }
        try:
            # Parse the URL to extract the hostname (base domain)
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname is None:
                results["errors"].append("Invalid URL provided.")
                return results

            base_domain = hostname
            discovered = []

            # Iterate over the common subdomains and try to resolve each one.
            for sub in self.common_subdomains:
                subdomain = f"{sub}.{base_domain}"
                try:
                    # If the DNS resolution succeeds, add the subdomain to the discovered list.
                    dns.resolver.resolve(subdomain, 'A', lifetime=3)
                    discovered.append(subdomain)
                except Exception:
                    # If resolution fails, ignore and try the next subdomain.
                    continue

            if discovered:
                results["vulnerable"] = True
                results["details"] = discovered
            else:
                results["details"].append("No subdomains found.")
        except Exception as e:
            results["errors"].append(str(e))
        return results

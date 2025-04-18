# core/csrf.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class CSRFScanner:
    """
    CSRFScanner checks a target URL for potential CSRF vulnerabilities by:
      1. Verifying that HTML forms include anti-CSRF tokens (e.g., fields containing 'csrf', 'token', or 'auth').
      2. Checking for the presence of meta tags (e.g., <meta name="csrf-token" ...>) that may provide CSRF protection.
    """

    def __init__(self, target_url):
        """
        Initialize with a target URL.
        """
        self.target_url = target_url
        self.session = requests.Session()

    def scan(self):
        """
        Scans the page for:
            - HTML forms lacking anti-CSRF tokens.
            - Meta tags that indicate CSRF protection (e.g., a meta tag with name "csrf-token").
        
        Returns a dictionary with the scan results.
        """
        results = {
            "vulnerable": False,
            "details": [],
            "errors": []
        }
        try:
            response = self.session.get(self.target_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Check for meta tag based protection
            meta_token = soup.find("meta", attrs={"name": "csrf-token"})
            if meta_token and meta_token.get("content"):
                results["details"].append("Meta tag 'csrf-token' found, indicating some CSRF protection is present.")
            else:
                results["details"].append("No meta tag 'csrf-token' found.")

            # Check available forms on the page.
            forms = soup.find_all("form")
            if not forms:
                results["details"].append("No forms found on the page to assess for CSRF protection.")
                return results

            # List of token indicators found in input field names.
            token_indicators = ["csrf", "token", "authenticity"]
            for index, form in enumerate(forms, start=1):
                has_token = False
                for input_tag in form.find_all("input"):
                    name_attr = input_tag.get("name", "").lower()
                    if any(indicator in name_attr for indicator in token_indicators):
                        has_token = True
                        break

                action = form.get("action", self.target_url)
                form_url = urljoin(self.target_url, action) if action else self.target_url

                if not has_token:
                    results["vulnerable"] = True
                    results["details"].append(
                        f"Form {index} (action: {form_url}) appears to lack an anti-CSRF token."
                    )
            if not results["vulnerable"] and not any(
                "lacks" in detail.lower() for detail in results["details"]
            ):
                results["details"].append("All forms appear to have anti-CSRF protection.")
        except Exception as e:
            results["errors"].append(str(e))
        return results

if __name__ == "__main__":
    # Test on an authorized target.
    target = "https://www.hackerone.com"  # Replace with your target.
    scanner = CSRFScanner(target)
    result = scanner.scan()
    print(result)

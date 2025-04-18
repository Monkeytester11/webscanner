# core/headers.py
import requests

def analyze_headers(url):
    """Analyze security headers for the given URL and return their values."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        return {
            "X-Frame-Options": headers.get("X-Frame-Options", "Not Found"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Found"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Found"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Found")
        }
    except Exception as e:
        return {"error": str(e)}

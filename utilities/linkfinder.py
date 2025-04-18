# utilities/linkfinder.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def find_vulnerable_links(base_url, additional_keywords=None):
    """
    Scans the base URL for links that might point to vulnerable endpoints.
    
    It looks for query parameters or path segments that contain common keywords
    (e.g., 'id=', 'user=', 'page=', 'admin', etc.) and returns a list of unique URLs.
    
    Args:
        base_url (str): The URL to scan.
        additional_keywords (list, optional): Extra keywords to include in the search.
    
    Returns:
        list of str: A list of potentially vulnerable links.
    """
    # Default keywords for filtering vulnerable endpoints
    keywords = ['id=', 'user=', 'view=', 'page=', 'admin', 'cat=', 'item=', 'product=', 'article=']
    if additional_keywords and isinstance(additional_keywords, list):
        keywords.extend(additional_keywords)
    
    try:
        resp = requests.get(base_url, timeout=5)
        resp.raise_for_status()  # Raise exception for non-success status codes
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        found_links = set()  # Use a set to collect unique links
        
        for link in soup.find_all('a', href=True):
            full_link = urljoin(base_url, link['href'])
            parsed_link = urlparse(full_link)
            
            # Only process HTTP/HTTPS links
            if parsed_link.scheme not in ['http', 'https']:
                continue
            
            # Check query parameters for keywords
            if parsed_link.query:
                lower_query = parsed_link.query.lower()
                if any(keyword in lower_query for keyword in keywords):
                    found_links.add(full_link)
            else:
                # Also check the URL path for vulnerable segments
                if any(keyword in parsed_link.path.lower() for keyword in keywords):
                    found_links.add(full_link)
        
        return list(found_links)  # Convert set back to list
    except Exception as e:
        return [f"Error during link scan: {str(e)}"]

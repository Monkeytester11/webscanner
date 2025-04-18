import requests
from flask import Flask, render_template, request
from core.sqli import SQLiScanner          # Ensure your SQLiScanner accepts target_url as a parameter
from core.csrf import CSRFScanner          # Ensure your CSRFScanner accepts target_url as a parameter
# from core.bac import BACScanner         # Uncomment if implemented; stub otherwise
from utilities.linkfinder import find_vulnerable_links   # Your vulnerable links detection logic
from core.subdomains import SubdomainScanner              # Subdomain scanner that accepts the target URL
from utilities.xss_payload_generator import generate_all_payloads  # XSS payload generator

# (Optional) Import security headers analyzer if available.
from core.headers import analyze_headers  # See below for a simple headers analyzer snippet

app = Flask(__name__)

@app.route('/')
def home():
    """
    Render the homepage with a simple scanning form.
    """
    # Default values to avoid template errors.
    return render_template('scan.html',
                           result={},
                           target=None,
                           xss_payloads=[],
                           progress_logs=[],
                           security_headers={})

@app.route('/scan', methods=['POST'])
def scan():
    """
    Handle the POST request from the scanning form.
    Initiate vulnerability scans and compile extensive output fields.
    """
    target = request.form.get('url')
    if not target:
        return render_template('scan.html',
                               result={"error": "No target provided."},
                               target=None,
                               xss_payloads=[],
                               progress_logs=["No target provided."],
                               security_headers={})
    
    results = {}
    progress_logs = []

    ### SQL Injection Scan ###
    progress_logs.append("Starting SQL Injection scan...")
    try:
        sqli_scanner = SQLiScanner(target)
        sqli_result_text = sqli_scanner.scan_url(target)
        sqli_vulnerable = False if sqli_result_text.strip() == "No SQLi found" else True
        results['SQL Injection'] = {
            "Status": "Vulnerable" if sqli_vulnerable else "Safe",
            "Details": [sqli_result_text or "No details available."],
            "Errors": []
        }
        progress_logs.append("SQL Injection scan completed.")
    except Exception as e:
        results['SQL Injection'] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"SQL Injection scan error: {str(e)}")
    
    ### CSRF Scan ###
    progress_logs.append("Starting CSRF scan...")
    try:
        csrf_scanner = CSRFScanner(target)
        csrf_result = csrf_scanner.scan()
        results['CSRF'] = {
            "Status": "Vulnerable" if csrf_result.get("vulnerable") else "Safe",
            "Details": csrf_result.get("details", []),
            "Errors": csrf_result.get("errors", [])
        }
        progress_logs.append("CSRF scan completed.")
    except Exception as e:
        results['CSRF'] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"CSRF scan error: {str(e)}")
    
    ### Broken Access Control (Stub) ###
    progress_logs.append("Starting Broken Access Control scan (stub)...")
    try:
        bac_result = {
            "Status": "Safe",
            "Details": ["Broken Access Control scan not yet implemented."],
            "Errors": []
        }
        results['Broken Access Control'] = bac_result
        progress_logs.append("Broken Access Control scan completed (stub).")
    except Exception as e:
        results['Broken Access Control'] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"Broken Access Control scan error: {str(e)}")
    
    ### Vulnerable Links Scan ###
    progress_logs.append("Starting Vulnerable Links scan...")
    try:
        vuln_links = find_vulnerable_links(target)
        results['Vulnerable Links'] = {
            "Status": "Vulnerable" if vuln_links else "Safe",
            "Details": vuln_links if vuln_links else ["No potentially vulnerable links found."],
            "Errors": []
        }
        progress_logs.append("Vulnerable Links scan completed.")
    except Exception as e:
        results['Vulnerable Links'] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"Vulnerable Links scan error: {str(e)}")
    
    ### Vulnerable Subdomains Scan ###
    progress_logs.append("Starting Subdomain scan...")
    try:
        subdomain_scanner = SubdomainScanner(target)
        subdomain_result = subdomain_scanner.scan(target)
        # Expecting subdomain_result to be a dict such as { "vulnerable": bool, "details": [list of subdomains], "errors": [] }
        results["Vulnerable Subdomains"] = {
            "Status": "Vulnerable" if subdomain_result.get("vulnerable") else "Safe",
            "Details": subdomain_result.get("details", []),
            "Errors": subdomain_result.get("errors", [])
        }
        progress_logs.append("Subdomain scan completed.")
    except Exception as e:
        results["Vulnerable Subdomains"] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"Subdomain scan error: {str(e)}")
    
    ### Bugs Scan (Stub) ###
    progress_logs.append("Starting Bug scan (stub)...")
    try:
        bugs_result = {
            "Status": "Safe",
            "Details": ["Bug scanning not yet implemented."],
            "Errors": []
        }
        results["Bugs"] = bugs_result
        progress_logs.append("Bug scan completed (stub).")
    except Exception as e:
        results["Bugs"] = {
            "Status": "Error",
            "Details": [],
            "Errors": [str(e)]
        }
        progress_logs.append(f"Bug scan error: {str(e)}")
    
    ### Security Headers Analysis ###
    progress_logs.append("Starting Security Headers analysis...")
    try:
        security_headers = analyze_headers(target)
        progress_logs.append("Security Headers analysis completed.")
    except Exception as e:
        security_headers = {"error": str(e)}
        progress_logs.append(f"Security Headers analysis error: {str(e)}")
    
    ### XSS Payload Generation ###
    progress_logs.append("Generating XSS payloads...")
    try:
        # For now, we pass an empty list as the discovered subdomains.
        discovered_subdomains = []  # Replace with actual discovered subdomains if available.
        xss_payloads = generate_all_payloads(discovered_subdomains)
        progress_logs.append("XSS payload generation completed.")
    except Exception as e:
        xss_payloads = []
        progress_logs.append(f"XSS payload generation error: {str(e)}")
    
    # Render the scan results along with detailed output fields on the screen.
    return render_template('scan.html',
                           result=results,
                           target=target,
                           xss_payloads=xss_payloads,
                           progress_logs=progress_logs,
                           security_headers=security_headers)

if __name__ == '__main__':
    # Run the app in debug mode for development purposes; adjust for production.
    app.run(debug=True)

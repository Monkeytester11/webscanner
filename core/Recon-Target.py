#!/usr/bin/env python3
"""
Recon-Target.py

This module performs reconnaissance on a given target by:
  1. Enumerating subdomains from the provided domain/IP using multiple tools.
     (Using external commands like assetfinder, amass, sublist3r, etc.)
     The goal is to discover a large attack surface (minimum 400 subdomains if possible).
  2. For each discovered subdomain, performing a symbol filtering test:
     Checking the handling of special symbols ((), <>, {}, []) by sending a GET request
     with each symbol as part of a query parameter, then determining whether the symbol is
     reflected in the response ("Allowed") or removed/sanitized ("Blocked").
  3. Printing real-time status, progress, and results to the screen.
"""

import subprocess
import os
import sys
import requests
from urllib.parse import urljoin, urlparse, quote

# Define the symbols to test.
TEST_SYMBOLS = ["(", ")", "<", ">", "{", "}", "[", "]"]

class ReconTarget:
    def __init__(self, target):
        # Normalize target – ensure it has no trailing slashes and extract the domain.
        if target.startswith("http"):
            self.target = target.rstrip("/")
        else:
            self.target = "https://" + target.rstrip("/")
        parsed = urlparse(self.target)
        self.domain = parsed.hostname
        self.subdomains = set()

    def run_command(self, command):
        """Run a shell command and return its output as a list of lines."""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            return result.stdout.splitlines()
        except Exception as e:
            print(f"[Error] Running command '{command}' failed: {e}")
            return []

    def enumerate_subdomains(self):
        """Enumerate subdomains using various external tools."""
        print(f"[+] Starting subdomain enumeration for {self.domain}...")
        all_subdomains = set()

        # Tool 1: assetfinder
        print("[*] Running assetfinder...")
        cmd_assetfinder = f"assetfinder --subs-only {self.domain}"
        output = self.run_command(cmd_assetfinder)
        all_subdomains.update(line.strip() for line in output if self.domain in line)
        print(f"   -> assetfinder discovered {len(output)} entries.")

        # Tool 2: amass (passive mode)
        print("[*] Running amass (passive mode)...")
        cmd_amass = f"amass enum -passive -d {self.domain}"
        output = self.run_command(cmd_amass)
        all_subdomains.update(line.strip() for line in output if self.domain in line)
        print(f"   -> amass discovered {len(output)} entries.")

        # Tool 3: sublist3r (if available)
        print("[*] Running sublist3r...")
        cmd_sublist3r = f"sublist3r -d {self.domain} -n -o temp_subs.txt"
        self.run_command(cmd_sublist3r)
        if os.path.exists("temp_subs.txt"):
            with open("temp_subs.txt", "r") as f:
                lines = f.readlines()
            all_subdomains.update(line.strip() for line in lines if self.domain in line)
            os.remove("temp_subs.txt")
            print(f"   -> sublist3r discovered {len(lines)} entries.")
        else:
            print("   -> sublist3r output not found.")

        # Tool 4: chaos (if available)
        print("[*] Running chaos (if installed)...")
        cmd_chaos = f"chaos -d {self.domain} -o temp_chaos.txt"
        self.run_command(cmd_chaos)
        if os.path.exists("temp_chaos.txt"):
            with open("temp_chaos.txt", "r") as f:
                lines = f.readlines()
            all_subdomains.update(line.strip() for line in lines if self.domain in line)
            os.remove("temp_chaos.txt")
            print(f"   -> chaos discovered {len(lines)} entries.")
        else:
            print("   -> chaos output not found or chaos not installed.")
        
        self.subdomains = all_subdomains
        total = len(self.subdomains)
        print(f"[+] Total unique subdomains discovered: {total}")
        if total < 400:
            print("[WARNING] Fewer than 400 subdomains discovered. Consider tuning your tools or settings for a larger attack surface!")
        return list(self.subdomains)

    def check_symbol_filtering(self, subdomain):
        """
        For a given subdomain, test if special symbols are 'allowed' (reflected) or 'blocked' (sanitized)
        by sending a GET request with a query parameter `test` set to the symbol.
        """
        status = {}
        # Here we assume the endpoint simply reflects the 'test' parameter in its HTML.
        for sym in TEST_SYMBOLS:
            test_param = quote(sym)
            # Construct test URL. For simplicity, we query the root with ?test={symbol}
            test_url = f"https://{subdomain}?test={test_param}"
            try:
                response = requests.get(test_url, timeout=10)
                # Check if the symbol appears in the response text.
                if sym in response.text:
                    status[sym] = "Allowed"
                else:
                    status[sym] = "Blocked"
            except Exception as e:
                status[sym] = f"Error: {e}"
        return status

    def perform_recon(self):
        """Perform the full recon process: enumerate subdomains and check symbol filtering."""
        # Enumerate subdomains.
        subdomains_list = self.enumerate_subdomains()
        print("\n[+] Beginning symbol filtering tests on discovered subdomains...\n")
        symbol_results = {}
        for idx, sub in enumerate(subdomains_list, start=1):
            print(f"[*] Testing symbols on subdomain {idx}/{len(subdomains_list)}: {sub}")
            test_result = self.check_symbol_filtering(sub)
            symbol_results[sub] = test_result
            # Print results for each subdomain.
            for sym, result in test_result.items():
                print(f"    Symbol '{sym}': {result}")
            print("-" * 50)
        # Print a final summary:
        print("\n[+] Reconnaissance complete.")
        print(f"[+] Total subdomains tested: {len(subdomains_list)}")
        return {
            "subdomains": list(self.subdomains),
            "symbol_filtering": symbol_results
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python Recon-Target.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    print(f"=== Starting Recon for target: {target} ===")
    recon = ReconTarget(target)
    results = recon.perform_recon()
    # Optionally, print a JSON summary.
    print("\n[+] Final Aggregated Results:")
    import json
    print(json.dumps(results, indent=4))

import asyncio
import aiohttp
import json
import os

class SecureScan:
    def __init__(self, target_url, auth_token=None):
        self.target = target_url.rstrip('/')
        self.headers = {'Authorization': f'Bearer {auth_token}'} if auth_token else {}
        self.results = {"headers": {}, "findings": [], "directories": [], "robots": False}
        self.semaphore = asyncio.Semaphore(10)
        
        # --- IN-MEMORY DATA STORAGE ---
        # Stores findings in the format: {ip_address: [list_of_attacks]}
        self.findings_db = {}
        
        self.remediation = {
            'Content-Security-Policy': {"severity": "High", "advice": "Prevents XSS. Define a strict CSP policy."},
            'Strict-Transport-Security': {"severity": "Medium", "advice": "Prevents SSL stripping."},
            'X-Frame-Options': {"severity": "Low", "advice": "Prevents Clickjacking."}
        }

    async def log_to_memory(self, ip, attack_type):
        """Logs findings to the in-memory dictionary."""
        if ip not in self.findings_db:
            self.findings_db[ip] = []
        self.findings_db[ip].append(attack_type)
        print(f"[+] Logged to memory: {attack_type} for {ip}")

    async def get_info(self, session, url):
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                return resp.status, len(await resp.read())
        except: return 404, 0

    async def run_audit(self, wordlist_path):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            print(f"[*] Starting audit on: {self.target}")
            
            # Header Audit
            async with session.head(self.target, timeout=5, ssl=False) as resp:
                for h in self.remediation.keys():
                    if h not in resp.headers:
                        # Log to memory storage
                        await self.log_to_memory("SYSTEM", f"MISSING_{h.upper()}")
                        self.results["findings"].append({"issue": h, "severity": self.remediation[h]["severity"]})

            # Save Final Report
            with open('audit_report.json', 'w') as f:
                json.dump(self.results, f, indent=4)
            
            print(f"[+] Audit complete. Memory storage contains {len(self.findings_db)} entries.")

if __name__ == "__main__":
    target = input("Target URL: ")
    scanner = SecureScan(target)
    asyncio.run(scanner.run_audit('wordlist.txt'))
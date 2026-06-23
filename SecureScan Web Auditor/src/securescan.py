import asyncio
import aiohttp
import json
import os

class SecureScan:
    def __init__(self, target_url, auth_token=None):
        self.target = target_url.rstrip('/')
        self.headers = {'Authorization': f'Bearer {auth_token}'} if auth_token else {}
        self.results = {"headers": {}, "findings": [], "directories": [], "robots": False}
        self.semaphore = asyncio.Semaphore(10)  # Rate limiting: 10 concurrent requests
        
        # Security Mapping for Report
        self.remediation = {
            'Content-Security-Policy': {"severity": "High", "advice": "Prevents XSS. Define a strict CSP policy."},
            'Strict-Transport-Security': {"severity": "Medium", "advice": "Prevents SSL stripping. Set max-age >= 31536000."},
            'X-Frame-Options': {"severity": "Low", "advice": "Prevents Clickjacking. Use SAMEORIGIN or DENY."}
        }

    async def get_info(self, session, url):
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                return resp.status, len(await resp.read())
        except: return 404, 0

    async def verify(self, session, path, base_len):
        status, length = await self.get_info(session, f"{self.target}{path}")
        return path if status == 200 and length != base_len else None

    async def verify_with_limit(self, session, path, base_len):
        async with self.semaphore:  # Enforce rate limiting
            return await self.verify(session, path, base_len)

    async def run_audit(self, wordlist_path):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            print(f"[*] Starting audit on: {self.target}")
            
            # 1. Baseline for Soft 404
            _, base_len = await self.get_info(session, f"{self.target}/non-existent-12345")
            
            # 2. Header Audit
            async with session.head(self.target, timeout=5, ssl=False) as resp:
                for h in self.remediation.keys():
                    value = resp.headers.get(h, "NOT FOUND")
                    self.results["headers"][h] = value
                    if value == "NOT FOUND":
                        self.results["findings"].append({
                            "issue": h,
                            "severity": self.remediation[h]["severity"],
                            "recommendation": self.remediation[h]["advice"]
                        })

            # 3. Robots Check
            status, _ = await self.get_info(session, f"{self.target}/robots.txt")
            self.results["robots"] = (status == 200)

            # 4. Wordlist Scanning with Rate Limiting
            if os.path.exists(wordlist_path):
                with open(wordlist_path, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                tasks = [self.verify_with_limit(session, line, base_len) for line in lines]
                found = await asyncio.gather(*tasks)
                self.results["directories"] = [p for p in found if p]

            # 5. Save Final Report
            with open('audit_report.json', 'w') as f:
                json.dump(self.results, f, indent=4)
            print("[+] Audit complete. Report saved to audit_report.json")

if __name__ == "__main__":
    target = input("Target URL: ")
    token = input("Auth Token (leave blank if none): ")
    if not os.path.exists('wordlist.txt'):
        print("[-] wordlist.txt not found! Please create one.")
    else:
        scanner = SecureScan(target, token if token else None)
        asyncio.run(scanner.run_audit('wordlist.txt'))
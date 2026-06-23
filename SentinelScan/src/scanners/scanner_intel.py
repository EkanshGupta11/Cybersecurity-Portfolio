import re
import requests

def extract_service_info(banner):
    """Parses a banner string to extract service name and version."""
    # Matches common patterns like "Apache/2.4.49" or "SSH-2.0-OpenSSH_8.2"
    pattern = r"([a-zA-Z]+)[/-]?([0-9.]+)"
    match = re.search(pattern, banner)
    if match:
        return match.group(1), match.group(2)
    return "Unknown", "Unknown"

def query_cve_database(service, version):
    """
    Simulates a query to a CVE database API.
    In a real-world scenario, you would interface with NVD or cve-search.
    """
    # This is a placeholder for actual API logic
    print(f"[*] Querying CVE database for {service} {version}...")
    # Example logic: If service is 'Apache' and version < 2.4.50, flag high risk
    if service.lower() == "apache" and float(version.split('.')[1]) < 4:
        return {"risk": "HIGH", "cve": "CVE-2021-41773"}
    return {"risk": "LOW", "cve": "None"}
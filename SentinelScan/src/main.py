import argparse
import asyncio
import sys
import traceback
from scanners import (
    run_scanner, run_stealth_scan, DatabaseManager, 
    extract_service_info, query_cve_database, 
    generate_html_report, generate_pdf_report,
    check_service_encryption
)

def main():
    try:
        parser = argparse.ArgumentParser(description="Pro Security Suite v8.0")
        subparsers = parser.add_subparsers(dest="mode", required=True)

        # Fast Mode
        fast = subparsers.add_parser("fast", help="Fast Async Scan")
        fast.add_argument("target", help="Target IP")
        fast.add_argument("--start", type=int, default=1, help="Start Port")
        fast.add_argument("--end", type=int, default=1024, help="End Port")

        # Stealth Mode
        stealth = subparsers.add_parser("stealth", help="Stealth SYN Scan")
        stealth.add_argument("target", help="Target IP")
        stealth.add_argument("port", type=int, help="Port to scan")

        # Audit Mode
        audit = subparsers.add_parser("audit", help="Audit Service Security")
        audit.add_argument("target", help="Target IP")
        audit.add_argument("port", type=int, help="Port to audit")

        args = parser.parse_args()
        db = DatabaseManager()

        if args.mode == "fast":
            print(f"[*] Starting Fast Async Scan on {args.target}...")
    
            # This now matches the function definition we just updated
            semaphore = asyncio.Semaphore(100) 
            results = asyncio.run(run_scanner(args.target, args.start, args.end, semaphore))
            
            report_data = []
            for res in results:
                if res: # Only process open ports
                    service, version = extract_service_info(res.get('banner', ''))
                    intel = query_cve_database(service, version)
                    res['risk'] = intel['risk']
                    report_data.append(res)
                    db.log(args.target, res)
            
            generate_html_report(report_data)
            generate_pdf_report(report_data)
            print("[*] Scan and reporting complete.")

        elif args.mode == "stealth":
            print(f"[*] Starting Stealth SYN Scan on {args.target} port {args.port}...")
            result = run_stealth_scan(args.target, args.port)
            if result:
                print(f"[+] Result: {result}")
                db.log(args.target, result)
        
        elif args.mode == "audit":
            status = check_service_encryption(args.target, args.port)
            print(f"[*] Audit Result for {args.target}:{args.port} -> {status}")

    except Exception as e:
        traceback.print_exc()
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
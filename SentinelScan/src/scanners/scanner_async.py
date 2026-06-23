import asyncio
import json

MAX_CONCURRENT_TASKS = 50 
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 902, 912, 3306, 3389, 8080]

async def scan_port(target, port, semaphore):
    """
    Optimized scan_port: Performs connection and banner grab in one flow
    with strict timeouts to prevent hanging.
    """
    async with semaphore:
        try:
            # 1. Connection with strict timeout
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=0.5)
            
            # 2. Try to grab banner if connected
            banner = "No Banner"
            try:
                # Send a probe/newline to trigger service response
                writer.write(b'\n')
                await writer.drain()
                # Read response with separate timeout
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = banner_data.decode(errors='ignore').strip()
            except:
                pass # Banner grabbing failed, but port is still OPEN
            
            writer.close()
            await writer.wait_closed()
            
            print(f"[+] Port {port:5} is OPEN | Banner: {banner}")
            return {"port": port, "status": "OPEN", "banner": banner}
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed or filtered, return None to be filtered out later
            return None

async def run_scanner(target, start_port=None, end_port=None, semaphore=None):
    # If no semaphore is provided, create a default one
    if semaphore is None:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    
    # Logic: Use common ports if range is not provided
    ports_to_scan = range(start_port, end_port + 1) if (start_port and end_port) else COMMON_PORTS
    
    print(f"[*] Dispatching {len(ports_to_scan)} tasks...")
    tasks = [asyncio.create_task(scan_port(target, p, semaphore)) for p in ports_to_scan]
    results = await asyncio.gather(*tasks)
    
    return [r for r in results if r is not None]
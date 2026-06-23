from scapy.all import IP, TCP, sr1, conf

conf.verb = 0

def run_stealth_scan(target, port):
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1)
        
        if resp is None:
            return {"port": port, "status": "Filtered", "banner": "N/A"}
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12: # SYN-ACK
                sr1(IP(dst=target)/TCP(dport=port, flags='R'), timeout=1)
                return {"port": port, "status": "OPEN", "banner": "N/A"}
            elif resp[TCP].flags == 0x14: # RST-ACK
                return {"port": port, "status": "CLOSED", "banner": "N/A"}
        return {"port": port, "status": "Filtered", "banner": "N/A"}
    except PermissionError:
        print("[!] Error: Stealth scan requires Administrator/Root privileges.")
        return None
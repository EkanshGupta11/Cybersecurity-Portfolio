# scanners/scanner_audit.py
import socket
import ssl

def check_service_encryption(target, port):
    """
    Checks if a service supports TLS/SSL encryption.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((target, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return "ENCRYPTED"
    except:
        return "PLAIN/UNENCRYPTED"
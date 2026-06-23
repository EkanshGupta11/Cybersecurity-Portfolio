import time
import random

# A few "malicious" and "normal" log lines
logs = [
    '192.168.1.1 - - [23/Jun/2026:01:30:00 +0000] "GET /index.html HTTP/1.1" 200',
    '192.168.1.1 - - [23/Jun/2026:01:30:05 +0000] "GET /admin?id=1\' OR 1=1 HTTP/1.1" 200',
    '10.0.0.5 - - [23/Jun/2026:01:30:10 +0000] "GET /<script>alert(1)</script> HTTP/1.1" 200',
    '192.168.1.100 - - [23/Jun/2026:01:30:15 +0000] "POST /login HTTP/1.1" 401'
]

with open("access.log", "a") as f:
    print("Generating fake logs into access.log...")
    for _ in range(20):
        f.write(random.choice(logs) + "\n")
        f.flush() # Forces the data to be written immediately
        time.sleep(1)
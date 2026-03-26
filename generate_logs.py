import random
from datetime import datetime, timedelta

logs = []

# Shared pool of IPs that can appear across multiple attack types
# This is what enables kill chain detection
shared_ips = [f"192.168.1.{i}" for i in random.sample(range(1, 255), 20)]
brute_only = [f"192.168.1.{i}" for i in random.sample(range(1, 255), 30)]
ddos_only  = [f"10.0.0.{i}" for i in random.sample(range(1, 255), 50)]
port_only  = [f"172.16.0.{i}" for i in random.sample(range(1, 255), 30)]

# shared_ips appear in BOTH port scan and brute force
# This simulates a real attacker: scan first, then brute force

for i in range(10000):
    log_type = random.choice(["brute", "ddos", "normal", "port", "kill_chain"])

    if log_type == "brute":
        ip = random.choice(brute_only)
        logs.append(f"Failed password for root from {ip} port 22")

    elif log_type == "ddos":
        ip = random.choice(ddos_only)
        logs.append(f"{random.randint(1000, 10000)} requests received from {ip}")

    elif log_type == "port":
        ip = random.choice(port_only)
        logs.append(f"Connection attempt on port {random.choice([21, 22, 80, 443])} from {ip}")

    elif log_type == "kill_chain":
        # Same IP does port scan AND brute force = kill chain
        ip = random.choice(shared_ips)
        action = random.choice(["port", "brute"])
        if action == "port":
            logs.append(f"Connection attempt on port {random.choice([21, 22, 80, 443])} from {ip}")
        else:
            logs.append(f"Failed password for root from {ip} port 22")

    else:
        logs.append("User logged in successfully")

with open("logs.txt", "w") as f:
    for log in logs:
        f.write(log + "\n")

print(f"Generated {len(logs)} logs")
print(f"Shared IPs that will trigger kill chain: {shared_ips[:5]} ...")
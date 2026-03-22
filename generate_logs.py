import random

logs = []

for i in range(10000):
    log_type = random.choice(["brute", "ddos", "normal", "port"])

    if log_type == "brute":
        logs.append(f"Failed password for root from 192.168.1.{random.randint(1,255)}")

    elif log_type == "ddos":
        logs.append(f"{random.randint(1000,10000)} requests received from 10.0.0.{random.randint(1,255)}")

    elif log_type == "port":
        logs.append(f"Connection attempt on port {random.choice([21,22,80,443])} from 172.16.0.{random.randint(1,255)}")

    else:
        logs.append("User logged in successfully")

# Save to file
with open("logs.txt", "w") as f:
    for log in logs:
        f.write(log + "\n")
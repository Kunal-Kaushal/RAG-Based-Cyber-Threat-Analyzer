from fastapi import FastAPI,UploadFile, File
import main2
import json
import re



app = FastAPI()

@app.on_event("startup")
def startup_event():
    pass



@app.get("/")
def home():
    return {"message": "AI SOC system running"}



@app.post("/upload")
async def upload_logs(file: UploadFile = File(...)):
    import shutil
    try:
        with open("logs.txt", "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {"message": "File uploaded successfully", "filename": file.filename}
    except Exception as e:
        return {"error": str(e)}

@app.post("/analyze")
def analyze_logs():
    main2.init()
    main2.init_db()
    main2.init_blocklist()
    
    groups = main2.stream_logs("logs.txt", main2.KEYWORDS)

    results = {}

    for attack_type, group_logs in groups.items():
        if not group_logs:
            continue

        ips = list(set(main2.extract_ip(log) for log in group_logs[:main2.MAX_LOGS]))

        raw , parsed = main2.analyze_attack(attack_type, group_logs,ips)

        if parsed.get("severity") in ["High", "Critical"]:
            for ip in parsed.get("top_ips", []):
                main2.block_ip(
                    ip,
                    reason=attack_type,
                    severity=parsed.get("severity")
                )

        main2.save_results(ips, attack_type, parsed.get("severity","Unknown"), raw, group_logs)

        kill_chain_ips=main2.run_kill_chain_check(attack_type, ips)
        parsed["kill_chain_ips"] = kill_chain_ips

        # Explicitly block instantly if kill chain pattern is recognized
        for kc_ip in kill_chain_ips:
            main2.block_ip(kc_ip, reason="Kill Chain: Port Scan -> Brute Force", severity="Critical")

        results[attack_type] = {
            "ips": ips,
            "analysis": parsed
        }

    return {"results": results}


@app.get("/blocked")
def get_blocked_ips():
    import sqlite3
    conn = sqlite3.connect("attack_memory.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
    rows = cursor.fetchall()
    conn.close()

    return {"blocked_ips": rows}
    
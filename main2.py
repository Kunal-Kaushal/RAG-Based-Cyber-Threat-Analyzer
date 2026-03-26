import os
import faiss
import numpy as np
from google import genai
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
import re
from memory import init_db, save_attack, get_ip_history, check_kill_chain

load_dotenv()

# ============================================================
# SETUP — Load API key, embedding model, and knowledge base
# ============================================================
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY is missing from environment")

client = genai.Client(api_key=api_key)
model = SentenceTransformer("all-MiniLM-L6-v2")


# ============================================================
# STEP 1 — Load cyber_data.txt (RAG knowledge base)
# This is what FAISS will search to find relevant context
# for each attack type before sending to Gemini
# ============================================================
with open("cyber_data.txt", "r") as f:
    sentences = [s.strip() for s in f.read().splitlines() if s.strip()]

if not sentences:
    raise ValueError("cyber_data.txt is empty — cannot build FAISS index")


# ============================================================
# STEP 2 — Build FAISS index from knowledge base
# Encode sentences into vectors and store in FAISS
# Cache to disk so we don't re-encode every run
# ============================================================
if os.path.exists("embeddings.npy"):
    embeddings = np.load("embeddings.npy")
else:
    embeddings = np.array(model.encode(sentences))
    np.save("embeddings.npy", embeddings)

dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(embeddings)


# ============================================================
# STEP 3 — Load logs.txt and split into attack groups
# Read one line at a time instead of loading all into memory
# Each line is checked for keywords and placed into a bucket
# ============================================================
KEYWORDS = {
    "Brute Force": "Failed password",
    "DDoS":        "requests",
    "Port Scan":   "Connection attempt",
}

def stream_logs(filepath: str, attack_groups: dict) -> dict:
    """
    Read logs one line at a time instead of loading all into memory.
    Filter into groups on the fly. One pass through the file.
    """
    groups = {key: [] for key in attack_groups}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for attack_type, keyword in attack_groups.items():
                if keyword in line:
                    groups[attack_type].append(line)
                    break
    return groups

groups = stream_logs("logs.txt", KEYWORDS)


# ============================================================
# CONSTANTS
# ============================================================
K        = 3    # number of context sentences to retrieve from FAISS
MAX_LOGS = 250  # max logs to analyze per group per run


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def ask_gemini(prompt: str) -> str:
    """Send prompt to Gemini and return its response text."""
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return response.text


def extract_ip(log: str) -> str:
    """Extract the first IP address found in a log line."""
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
    return match.group(0) if match else "unknown"


def extract_severity(analysis: str) -> str:
    """Parse Gemini's response to extract the severity rating."""
    match = re.search(r'severity[:\s]*(low|medium|high|critical)',
                      analysis.lower())
    return match.group(1).capitalize() if match else "Unknown"


def build_prompt(attack_type: str, batch: str, context: str, ip_history: str = None) -> str:
    """
    Combine logs + IP history + FAISS context into one prompt.
    If IP history exists, inject it so Gemini can escalate severity.
    If no history, Gemini gets logs and context only (first time IP).
    """
    history_section = ""
    if ip_history:
        history_section = f"""
Previous Activity:
{ip_history}
NOTE: This IP has been seen before. Factor this into severity.
"""
    return f"""You are a cybersecurity analyst.

STRICT RULE: Only use the provided context. Do not guess.

Attack Type (detected by keyword): {attack_type}
{history_section}
Logs:
{batch}

Context:
{context}

Tasks:
1. Identify the type of attack.
2. Explain why these logs indicate that attack.
3. Give a severity rating (Low / Medium / High / Critical).
   If this IP has previous activity, escalate severity accordingly.
4. Suggest concrete mitigation steps.
5. If previous activity exists, mention this is a repeat offender.
"""


# ============================================================
# STEP FUNCTIONS — One function per step in the pipeline
# ============================================================

def get_ip_history_text(ips: list) -> str:
    """
    STEP 4 — Check memory for each IP.
    Returns formatted history string to inject into prompt.
    """
    ip_history_text = ""
    for ip in ips:
        history = get_ip_history(ip)
        if history:
            ip_history_text += f"\nIP {ip} previous attacks:\n"
            for row in history:
                ip_history_text += f"  - {row[0]} | {row[1]} severity | seen at {row[2]}\n"
    return ip_history_text


def get_faiss_context(attack_type: str) -> str:
    """
    STEP 5 — Search FAISS for relevant context.
    Encodes attack type and returns top K matching sentences.
    """
    query_embedding = np.array(model.encode([attack_type]))
    distances, indices = index.search(query_embedding, K)
    return "\n".join(sentences[i] for i in indices[0])


def analyze_attack(attack_type: str, group_logs: list, ips: list) -> str:
    """
    STEP 6 — Build prompt and send to Gemini.
    Combines logs + IP history + FAISS context.
    Returns Gemini's full analysis.
    """
    
    batch = "\n".join(group_logs[:MAX_LOGS])
    ip_history_text = get_ip_history_text(ips)
    context = get_faiss_context(attack_type)
    prompt = build_prompt(attack_type, batch, context, ip_history_text or None)

    try:
        return ask_gemini(prompt)
    except Exception as e:
        return f"[Error calling Gemini API: {e}]"


def save_results(ips: list, attack_type: str, result: str, group_logs: list):
    """
    STEP 7 — Save every IP from this batch to memory.
    Stores attack type, severity, log sample, and full analysis.
    """
    for ip in ips:
        save_attack(
            ip=ip,
            attack_type=attack_type,
            severity=extract_severity(result),
            log_sample=group_logs[0],
            analysis=result
        )


def run_kill_chain_check(attack_type: str, ips: list):
    """
    STEP 8 — Check if any IP performed Port Scan → Brute Force
    within the time window. Prints results.
    """
    print(f"\n----- Kill Chain Check: {attack_type} -----")
    kill_chain_found = False
    for ip in ips:
        kc = check_kill_chain(ip)
        if kc:
            kill_chain_found = True
            print(f"KILL CHAIN DETECTED")
            print(f"  IP      : {kc['ip']}")
            print(f"  Pattern : {kc['pattern']}")
            print(f"  Gap     : {kc['minutes']} minutes")
            print(f"  Severity: {kc['severity']}")
    if not kill_chain_found:
        print("No kill chain patterns detected.")


def process_attack_group(attack_type: str, group_logs: list):
    """
    Master function — runs all steps for one attack group.
    Calls each step function in order.
    """
    if not group_logs:
        print(f"\n===== {attack_type} =====")
        print("No matching logs found.")
        return

    if len(group_logs) > MAX_LOGS:
        print(f"[Warning] {attack_type}: {len(group_logs)} logs found, analyzing first {MAX_LOGS}.")

    ips = list(set(extract_ip(log) for log in group_logs[:MAX_LOGS]))

    result = analyze_attack(attack_type, group_logs,ips)
    save_results(ips, attack_type, result, group_logs)
    run_kill_chain_check(attack_type, ips)

    print(f"\n===== {attack_type} =====")
    print(result)


# ============================================================
# MAIN — Initialize DB and process each attack group
# ============================================================
if __name__ == "__main__":
    init_db()
    for attack_type, group_logs in groups.items():
        process_attack_group(attack_type, group_logs)
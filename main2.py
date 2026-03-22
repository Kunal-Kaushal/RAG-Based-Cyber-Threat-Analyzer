import os
import faiss
import numpy as np
from google import genai
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
import re  # regional expression for IP extraction
from memory import init_db, save_attack, get_ip_history


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
    embeddings = np.load("embeddings.npy")       # load cached embeddings
else:
    embeddings = np.array(model.encode(sentences))
    np.save("embeddings.npy", embeddings)         # cache for next run

dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)             # exact search, no restrictions
index.add(embeddings)                            # add all sentence vectors


# ============================================================
# STEP 3 — Load logs.txt and split into attack groups
# Each log line is checked for keywords and placed into
# the matching bucket: Brute Force, DDoS, or Port Scan
# ============================================================
with open("logs.txt", "r") as f:
    logs = [line.strip() for line in f.readlines() if line.strip()]

groups = {
    "Brute Force": [log for log in logs if "Failed password" in log],
    "DDoS":        [log for log in logs if "requests" in log],
    "Port Scan":   [log for log in logs if "Connection attempt" in log],
}


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
# MAIN LOOP — Process each attack group one by one
# ============================================================
K = 3          # number of context sentences to retrieve from FAISS
MAX_LOGS = 100 # max logs to analyze per group per run

if __name__ == "__main__":

    # Initialize SQLite database (creates file if it doesn't exist)
    init_db()

    for attack_type, group_logs in groups.items():

        # Skip if no logs found for this attack type
        if not group_logs:
            print(f"\n===== {attack_type} =====")
            print("No matching logs found.")
            continue

        if len(group_logs) > MAX_LOGS:
            print(f"[Warning] {attack_type}: {len(group_logs)} logs found, analyzing first {MAX_LOGS}.")

        # --------------------------------------------------------
        # STEP 4 — Extract IPs and check memory (attack_memory.db)
        # For each IP in this batch, look up past attack history
        # If history found → inject into prompt for escalation
        # If no history → first time IP, no escalation
        # --------------------------------------------------------
        ips = list(set(extract_ip(log) for log in group_logs[:MAX_LOGS]))

        ip_history_text = ""
        for ip in ips:
            history = get_ip_history(ip)          # query SQLite
            if history:
                ip_history_text += f"\nIP {ip} previous attacks:\n"
                for row in history:
                    ip_history_text += f"  - {row[0]} | {row[1]} severity | seen at {row[2]}\n"

        # --------------------------------------------------------
        # STEP 5 — FAISS context search
        # Encode the attack type name as a query vector
        # Search cyber_data.txt embeddings for top K matches
        # These become the grounding context for Gemini
        # --------------------------------------------------------
        batch = "\n".join(group_logs[:MAX_LOGS])
        query_embedding = np.array(model.encode([attack_type]))
        distances, indices = index.search(query_embedding, K)
        context = "\n".join(sentences[i] for i in indices[0])

        # --------------------------------------------------------
        # STEP 6 — Build prompt and send to Gemini
        # Prompt = logs + IP history (if any) + FAISS context
        # Gemini reasons about severity — escalates if repeat offender
        # --------------------------------------------------------
        prompt = build_prompt(attack_type, batch, context, ip_history_text or None)

        try:
            result = ask_gemini(prompt)
        except Exception as e:
            result = f"[Error calling Gemini API: {e}]"

        # --------------------------------------------------------
        # STEP 7 — Save results to memory (attack_memory.db)
        # Every IP from this batch gets saved with attack type,
        # severity, timestamp, and Gemini's full analysis.
        # This becomes the history for the NEXT run.
        # --------------------------------------------------------
        for ip in ips:
            save_attack(
                ip=ip,
                attack_type=attack_type,
                severity=extract_severity(result),
                log_sample=group_logs[0],
                analysis=result
            )

        print(f"\n===== {attack_type} =====")
        print(result)
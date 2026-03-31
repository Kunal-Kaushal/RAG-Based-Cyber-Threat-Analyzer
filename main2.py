import os
import json
import faiss
import numpy as np
from google import genai
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
import re
from openai import OpenAI
from memory import init_db, save_attack, get_ip_history, check_kill_chain, init_blocklist,block_ip


load_dotenv()

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=os.getenv("NVIDIA_API_KEY")
)

def ask_llama(prompt: str) -> str:
    completion = client.chat.completions.create(
        model="meta/llama-3.1-8b-instruct",
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=False
    )

    return completion.choices[0].message.content

# ============================================================
# GLOBALS — Initialized once by init(), used across functions
# ============================================================
model     = None
sentences = None
index     = None


def init():
    """
    Initialize API client, embedding model, knowledge base, and FAISS index.
    Must be called once before using any analyze functions.
    Safe to call multiple times — skips if already initialized.
    """
    global client, model, sentences, index

    if model is not None:
        return

    # # --- API client ---
    # api_key = os.getenv("GEMINI_API_KEY")
    # if not api_key:
    #     raise ValueError("GEMINI_API_KEY is missing from .env")
    # client = genai.Client(api_key=api_key)

    # --- Embedding model ---
    model = SentenceTransformer("all-MiniLM-L6-v2")

    # --- RAG knowledge base ---
    with open("cyber_data.txt", "r") as f:
        sentences = [s.strip() for s in f.read().splitlines() if s.strip()]
    if not sentences:
        raise ValueError("cyber_data.txt is empty — cannot build FAISS index")

    # --- FAISS index (load from cache or build fresh) ---
    if os.path.exists("embeddings.npy"):
        embeddings = np.load("embeddings.npy")
    else:
        embeddings = np.array(model.encode(sentences))
        np.save("embeddings.npy", embeddings)

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)


# ============================================================
# CONSTANTS
# ============================================================
K        = 3    # FAISS context sentences to retrieve
MAX_LOGS = 250  # max logs to analyze per attack group per run

KEYWORDS = {
    "Port Scan":   "Connection attempt",
    "Brute Force": "Failed password",
    "DDoS":        "requests",
}


# ============================================================
# STEP 3 — Log loading
# Reads logs.txt one line at a time — memory efficient.
# Single pass through the file, routes each line to a bucket.
# ============================================================
def stream_logs(filepath: str, attack_groups: dict) -> dict:
    """
    Read and filter logs in one pass without loading all into memory.
    Each line goes into the first matching attack group bucket.
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


# ============================================================
# HELPER FUNCTIONS
# ============================================================

# def ask_gemini(prompt: str) -> str:
#     """Send prompt to Gemini and return raw response text."""
#     response = client.models.generate_content(
#         model="gemini-2.5-flash-lite",
#         contents=prompt,
#     )
#     return response.text


def extract_ip(log: str) -> str:
    """Extract the first IPv4 address found in a log line."""
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
    return match.group(0) if match else "unknown"


def extract_severity(analysis: str) -> str:
    """
    Parse severity from Gemini response.
    Handles both plain text and JSON output formats.
    """
    # Try JSON format first
    try:
        data = json.loads(analysis)
        severity = data.get("severity", "")
        if severity.lower() in ["low", "medium", "high", "critical"]:
            return severity.capitalize()
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fall back to regex on plain text
    match = re.search(r'severity["\s:]*(["\s]*(low|medium|high|critical))',
                      analysis.lower())
    if match:
        return match.group(2).capitalize()

    return "Unknown"


def parse_gemini_response(raw: str) -> dict:
    """
    Parse Gemini JSON response into a clean dict.
    Strips markdown fences if Gemini added them.
    Falls back gracefully if JSON is malformed — pipeline never breaks.
    """
    try:
        cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return {
            "attack_type": "Unknown",
            "explanation": raw[:300] if raw else "No response",
            "severity": extract_severity(raw),
            "top_ips": [],
            "repeat_offenders": [],
            "mitigation": ["Manual review required — response was not valid JSON"]
        }


def build_prompt(attack_type: str, batch: str, context: str, ip_history: str = None) -> str:
    """
    Build a structured prompt for Gemini.
    Injects IP history if available so Gemini can escalate severity.
    Always requests strict JSON output — no markdown, no prose.
    """
    history_section = ""
    if ip_history:
        history_section = f"""
Previous Activity:
{ip_history}
IMPORTANT: These IPs have prior attack history. This indicates an ongoing threat.
"""

    return f"""You are a cybersecurity AI system analyzing network security logs.

STRICT OUTPUT RULES:
- OUTPUT ONLY VALID JSON — no text before or after
- DO NOT use markdown or code fences
- DO NOT change field names
- LIMIT top_ips to maximum 10 entries

SEVERITY CLASSIFICATION RUBRIC (STRICT):
- Low: < 5 attempts per IP. Very likely normal noise, user typos, or random scanning.
- Medium: 5 to 20 attempts per IP. Suspicious targeted activity, small-scale scanning.
- High: 20 to 100 attempts per IP. Clear malicious intent, brute forcing, or aggressive bot.
- Critical: > 100 attempts, confirmed Kill Chain patterns, or exploiting known critical vulnerabilities.

RESPONSE FORMAT:
{{
  "attack_type": "string",
  "explanation": "max 2 sentences",
  "severity": "Low | Medium | High | Critical",
  "top_ips": ["max 10 IPs from the logs"],
  "repeat_offenders": ["IPs with prior history, empty list if none"],
  "mitigation": ["specific actionable steps, max 4"]
}}

Attack Type: {attack_type}
{history_section}
Logs:
{batch}

Context:
{context}

Tasks:
1. Identify attack type
2. Write a short explanation (max 2 sentences)
3. Assign severity STRICTLY using the RUBRIC above based on the count of log lines per IP. Escalate by one level if there is extensive prior history.
4. List top 10 most active IPs only
5. Flag repeat offenders from prior history
6. List concrete mitigation steps
"""


# ============================================================
# STEP FUNCTIONS — One function per pipeline step
# ============================================================

def get_ip_history_text(ips: list) -> str:
    """
    STEP 4 — Query memory for each IP.
    Returns formatted history string to inject into the Gemini prompt.
    Empty string if no history found.
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
    STEP 5 — Semantic context retrieval.
    Encodes attack type as a query vector and returns top K
    matching sentences from the cyber_data.txt knowledge base.
    """
    query_embedding = np.array(model.encode([attack_type]))
    distances, indices = index.search(query_embedding, K)
    return "\n".join(sentences[i] for i in indices[0])


def analyze_attack(attack_type: str, group_logs: list, ips: list) -> tuple:
    """
    STEP 6 — Core analysis.
    Builds prompt from logs + IP history + FAISS context.
    Sends to Gemini. Returns (raw_response, parsed_dict).
    """
    batch           = "\n".join(group_logs[:MAX_LOGS])
    ip_history_text = get_ip_history_text(ips)
    context         = get_faiss_context(attack_type)
    prompt          = build_prompt(attack_type, batch, context, ip_history_text or None)

    try:
        raw = ask_llama(prompt)
    except Exception as e:
        raw = json.dumps({
            "attack_type": attack_type,
            "explanation": f"LLM API error: {e}",
            "severity": "Unknown",
            "top_ips": [],
            "repeat_offenders": [],
            "mitigation": ["Check API key and network connection"]
        })

    parsed = parse_gemini_response(raw)
    return raw, parsed


def save_results(ips: list, attack_type: str, severity: str, raw: str, group_logs: list):
    """
    STEP 7 — Persist results to attack_memory.db.
    Saves every IP from this batch with attack type, severity,
    timestamp, log sample, and full Gemini analysis.
    This becomes history for the next run.
    """
    for ip in ips:
        save_attack(
            ip=ip,
            attack_type=attack_type,
            severity=severity,
            log_sample=group_logs[0],
            analysis=raw
        )


def run_kill_chain_check(attack_type: str, ips: list) -> list:
    """
    STEP 8 — Kill chain detection.
    Checks if any IP performed Port Scan -> Brute Force
    within the configured time window.
    Returns list of IPs where kill chain was confirmed.
    """
    print(f"\n----- Kill Chain Check: {attack_type} -----")
    kill_chain_ips = []

    for ip in ips:
        kc = check_kill_chain(ip)
        if kc:
            kill_chain_ips.append(ip)
            print(f"  [KILL CHAIN DETECTED]")
            print(f"  IP      : {kc['ip']}")
            print(f"  Pattern : {kc['pattern']}")
            print(f"  Gap     : {kc['minutes']} minutes")
            print(f"  Severity: {kc['severity']}")

    if not kill_chain_ips:
        print("  No kill chain patterns detected.")

    return kill_chain_ips


def print_summary(attack_type: str, parsed: dict, kill_chain_ips: list):
    """
    Print a clean, readable summary of the analysis result.
    Uses parsed JSON fields — not raw Gemini text.
    """
    print(f"\n{'='*55}")
    print(f"  {attack_type.upper()}")
    print(f"{'='*55}")
    print(f"  Severity    : {parsed.get('severity', 'Unknown')}")
    print(f"  Explanation : {parsed.get('explanation', '')}")

    top_ips = parsed.get("top_ips", [])
    if top_ips:
        display = top_ips[:5]
        extra   = len(top_ips) - 5
        print(f"  Top IPs     : {', '.join(display)}" +
              (f" (+{extra} more)" if extra > 0 else ""))

    repeat = parsed.get("repeat_offenders", [])
    if repeat:
        print(f"  Repeat IPs  : {', '.join(repeat[:5])}")

    if kill_chain_ips:
        print(f"  Kill Chain  : {', '.join(kill_chain_ips[:5])}")

    mitigation = parsed.get("mitigation", [])
    if mitigation:
        print(f"  Mitigation  :")
        for step in mitigation:
            print(f"    - {step}")
    print()


def process_attack_group(attack_type: str, group_logs: list):
    """
    Master function — orchestrates all pipeline steps for one attack group.

    Flow:
      extract IPs
        -> analyze (history + FAISS + Gemini)
        -> save to DB
        -> kill chain check
        -> print summary
    """
    if not group_logs:
        print(f"\n[{attack_type}] No matching logs found.")
        return

    total = len(group_logs)
    if total > MAX_LOGS:
        print(f"\n[Warning] {attack_type}: {total} logs found, analyzing first {MAX_LOGS}.")

    ips = list(set(extract_ip(log) for log in group_logs[:MAX_LOGS]))

    raw, parsed    = analyze_attack(attack_type, group_logs, ips)
    severity       = parsed.get("severity", "Unknown")

    save_results(ips, attack_type, severity, raw, group_logs)
    kill_chain_ips = run_kill_chain_check(attack_type, ips)

    print_summary(attack_type, parsed, kill_chain_ips)


# ============================================================
# MAIN — Entry point
# ============================================================
if __name__ == "__main__":
    init()
    init_db()
    init_blocklist()
    groups = stream_logs("logs.txt", KEYWORDS)
    for attack_type, group_logs in groups.items():
        process_attack_group(attack_type, group_logs)
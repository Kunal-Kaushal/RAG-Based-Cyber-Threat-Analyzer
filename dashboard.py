"""
AI SOC Dashboard — Streamlit Frontend
Connects to the FastAPI backend to display real-time threat analysis.
Run: streamlit run dashboard.py
"""

import streamlit as st
import requests
import time
import pandas as pd

# ============================================================
# CONFIG
# ============================================================
API_BASE = "http://127.0.0.1:8000"

SEVERITY_COLORS = {
    "Critical": "#ff1744",
    "High":     "#ff6d00",
    "Medium":   "#ffc400",
    "Low":      "#00e676",
    "Unknown":  "#78909c",
}

SEVERITY_ICONS = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Unknown":  "⚪",
}

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM CSS — Dark SOC theme
# ============================================================
st.markdown("""
<style>
    /* ---- Global ---- */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

    .stApp {
        background: #0a0e17;
        color: #e0e6ed;
        font-family: 'Inter', sans-serif;
    }

    /* Hide default streamlit elements */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 1.5rem; max-width: 1400px; }

    /* ---- Header ---- */
    .soc-header {
        background: linear-gradient(135deg, #0d1520 0%, #131b2e 50%, #0d1520 100%);
        border: 1px solid rgba(56, 189, 248, 0.12);
        border-radius: 16px;
        padding: 1.8rem 2.2rem;
        margin-bottom: 1.8rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .soc-header h1 {
        font-size: 1.7rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .soc-header .subtitle {
        color: #64748b;
        font-size: 0.82rem;
        margin-top: 3px;
        font-weight: 400;
    }
    .soc-header .status-badge {
        background: rgba(0, 230, 118, 0.1);
        border: 1px solid rgba(0, 230, 118, 0.3);
        color: #00e676;
        padding: 6px 16px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }

    /* ---- Severity Cards ---- */
    .severity-card {
        background: linear-gradient(145deg, #111827, #0f172a);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 1.4rem 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    .severity-card:hover {
        transform: translateY(-3px);
        border-color: rgba(255,255,255,0.12);
        box-shadow: 0 8px 30px rgba(0,0,0,0.4);
    }
    .severity-card .count {
        font-size: 2.6rem;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
        margin-bottom: 6px;
    }
    .severity-card .label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 600;
        opacity: 0.7;
    }
    .severity-card .glow {
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        border-radius: 14px 14px 0 0;
    }

    /* ---- Section Headers ---- */
    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: #e2e8f0;
        margin: 2rem 0 1rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .section-header .icon {
        font-size: 1.2rem;
    }
    .section-line {
        height: 1px;
        background: linear-gradient(90deg, rgba(56,189,248,0.3), transparent);
        margin-bottom: 1.2rem;
    }

    /* ---- Attack Cards ---- */
    .attack-card {
        background: linear-gradient(145deg, #111827, #0f172a);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 1.5rem 1.8rem;
        margin-bottom: 1rem;
        transition: all 0.3s ease;
    }
    .attack-card:hover {
        border-color: rgba(56, 189, 248, 0.2);
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    .attack-card .attack-title {
        font-size: 1.05rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 8px;
    }
    .attack-card .attack-explanation {
        font-size: 0.88rem;
        color: #94a3b8;
        line-height: 1.6;
        margin-bottom: 12px;
    }
    .severity-badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 8px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* ---- Detail panels ---- */
    .detail-panel {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        margin-bottom: 0.8rem;
    }
    .detail-panel .panel-title {
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #64748b;
        margin-bottom: 10px;
    }
    .ip-tag {
        display: inline-block;
        background: rgba(56, 189, 248, 0.08);
        border: 1px solid rgba(56, 189, 248, 0.2);
        color: #38bdf8;
        padding: 3px 10px;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        margin: 3px 4px 3px 0;
    }
    .ip-tag.danger {
        background: rgba(255, 23, 68, 0.08);
        border-color: rgba(255, 23, 68, 0.25);
        color: #ff1744;
    }
    .ip-tag.warning {
        background: rgba(255, 109, 0, 0.08);
        border-color: rgba(255, 109, 0, 0.25);
        color: #ff6d00;
    }
    .mitigation-item {
        font-size: 0.85rem;
        color: #cbd5e1;
        padding: 6px 0;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        display: flex;
        align-items: flex-start;
        gap: 8px;
    }
    .mitigation-item:last-child { border-bottom: none; }
    .mitigation-bullet {
        color: #00e676;
        font-weight: 700;
        flex-shrink: 0;
    }

    /* ---- Blocked IPs Table ---- */
    .blocked-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
    }
    .blocked-table th {
        background: rgba(15, 23, 42, 0.8);
        color: #64748b;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 600;
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .blocked-table td {
        padding: 11px 16px;
        font-size: 0.85rem;
        color: #cbd5e1;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        font-family: 'JetBrains Mono', monospace;
    }
    .blocked-table tr:hover td {
        background: rgba(56, 189, 248, 0.03);
    }

    /* ---- Empty state ---- */
    .empty-state {
        text-align: center;
        padding: 3rem 1rem;
        color: #475569;
    }
    .empty-state .icon { font-size: 2.5rem; margin-bottom: 12px; }
    .empty-state .text { font-size: 0.95rem; }

    /* ---- Loading spinner ---- */
    .analyzing-banner {
        background: linear-gradient(135deg, rgba(56,189,248,0.08), rgba(129,140,248,0.08));
        border: 1px solid rgba(56,189,248,0.15);
        border-radius: 12px;
        padding: 2rem;
        text-align: center;
        margin: 2rem 0;
    }
    .analyzing-banner .text {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 10px;
    }

    /* Fix streamlit button */
    .stButton > button {
        background: linear-gradient(135deg, #1e40af, #7c3aed) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.6rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        letter-spacing: 0.5px !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button:hover {
        box-shadow: 0 4px 20px rgba(124, 58, 237, 0.4) !important;
        transform: translateY(-1px) !important;
    }

    /* Streamlit expander override */
    .streamlit-expanderHeader {
        background: transparent !important;
        color: #e2e8f0 !important;
        font-weight: 600 !important;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# API HELPERS
# ============================================================
def fetch_analysis():
    """Call POST /analyze and return results dict."""
    try:
        resp = requests.post(f"{API_BASE}/analyze", timeout=120)
        resp.raise_for_status()
        return resp.json().get("results", {})
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to API. Make sure FastAPI is running on port 8000.")
        return None
    except Exception as e:
        st.error(f"⚠️ API error: {e}")
        return None


def fetch_blocked():
    """Call GET /blocked and return list of blocked IP rows."""
    try:
        resp = requests.get(f"{API_BASE}/blocked", timeout=10)
        resp.raise_for_status()
        return resp.json().get("blocked_ips", [])
    except Exception:
        return []


# ============================================================
# UI COMPONENTS
# ============================================================
def render_header():
    st.markdown("""
    <div class="soc-header">
        <div>
            <h1>SOC Dashboard</h1>
            <div class="subtitle">RAG-Powered Cyber Threat Analyzer &nbsp;•&nbsp; Real-Time Log Analysis</div>
        </div>
        <div class="status-badge">● SYSTEM ONLINE</div>
    </div>
    """, unsafe_allow_html=True)


def render_severity_cards(results):
    """Render the 4 overview severity cards."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for data in results.values():
        severity = data.get("analysis", {}).get("severity", "Unknown")
        if severity in counts:
            counts[severity] += 1

    cols = st.columns(4, gap="medium")
    for i, (level, count) in enumerate(counts.items()):
        color = SEVERITY_COLORS[level]
        with cols[i]:
            st.markdown(f"""
            <div class="severity-card">
                <div class="glow" style="background: linear-gradient(90deg, transparent, {color}, transparent);"></div>
                <div class="count" style="color: {color};">{count}</div>
                <div class="label" style="color: {color};">{level}</div>
            </div>
            """, unsafe_allow_html=True)


def render_section_header(icon, title):
    st.markdown(f"""
    <div class="section-header">
        <span class="icon">{icon}</span> {title}
    </div>
    <div class="section-line"></div>
    """, unsafe_allow_html=True)


def render_attack_feed(results):
    """Render the live attack feed cards."""
    render_section_header("📡", "Live Attack Feed")

    if not results:
        st.markdown("""
        <div class="empty-state">
            <div class="icon">📭</div>
            <div class="text">No attacks detected. Run analysis to scan logs.</div>
        </div>
        """, unsafe_allow_html=True)
        return

    for attack_type, data in results.items():
        analysis = data.get("analysis", {})
        severity = analysis.get("severity", "Unknown")
        explanation = analysis.get("explanation", "No details available.")
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Unknown"])
        icon = SEVERITY_ICONS.get(severity, "⚪")

        st.markdown(f"""
        <div class="attack-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="attack-title">{icon} {attack_type}</div>
                <span class="severity-badge" style="background: {color}15; color: {color}; border: 1px solid {color}40;">
                    {severity}
                </span>
            </div>
            <div class="attack-explanation">{explanation}</div>
        </div>
        """, unsafe_allow_html=True)


def render_attack_details(results):
    """Render detailed breakdown for each attack type."""
    render_section_header("🔍", "Attack Details")

    if not results:
        return

    for attack_type, data in results.items():
        analysis = data.get("analysis", {})
        severity = analysis.get("severity", "Unknown")
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Unknown"])

        with st.expander(f"{SEVERITY_ICONS.get(severity, '⚪')}  {attack_type} — {severity}", expanded=False):

            col1, col2 = st.columns(2)

            # Top IPs
            with col1:
                top_ips = analysis.get("top_ips", [])
                ip_html = "".join(f'<span class="ip-tag">{ip}</span>' for ip in top_ips[:10])
                st.markdown(f"""
                <div class="detail-panel">
                    <div class="panel-title">🎯 Top IPs ({len(top_ips)})</div>
                    {ip_html if ip_html else '<span style="color:#475569;">None detected</span>'}
                </div>
                """, unsafe_allow_html=True)

            # Repeat Offenders
            with col2:
                repeat = analysis.get("repeat_offenders", [])
                repeat_html = "".join(f'<span class="ip-tag warning">{ip}</span>' for ip in repeat[:10])
                st.markdown(f"""
                <div class="detail-panel">
                    <div class="panel-title">🔄 Repeat Offenders ({len(repeat)})</div>
                    {repeat_html if repeat_html else '<span style="color:#475569;">None detected</span>'}
                </div>
                """, unsafe_allow_html=True)

            col3, col4 = st.columns(2)

            # Kill Chain IPs
            with col3:
                kc_ips = analysis.get("kill_chain_ips", [])
                kc_html = "".join(f'<span class="ip-tag danger">{ip}</span>' for ip in kc_ips[:10])
                st.markdown(f"""
                <div class="detail-panel">
                    <div class="panel-title">⛓️ Kill Chain IPs ({len(kc_ips)})</div>
                    {kc_html if kc_html else '<span style="color:#475569;">No kill chain detected</span>'}
                </div>
                """, unsafe_allow_html=True)

            # Mitigation
            with col4:
                mitigation = analysis.get("mitigation", [])
                if mitigation:
                    items_html = "".join(
                        f'<div class="mitigation-item"><span class="mitigation-bullet">→</span> {step}</div>'
                        for step in mitigation
                    )
                else:
                    items_html = '<span style="color:#475569;">No steps provided</span>'
                st.markdown(f"""
                <div class="detail-panel">
                    <div class="panel-title">🛡️ Mitigation Steps</div>
                    {items_html}
                </div>
                """, unsafe_allow_html=True)


def render_blocked_ips(blocked):
    """Render the blocked IPs table."""
    render_section_header("🚫", "Blocked IPs")

    if not blocked:
        st.markdown("""
        <div class="empty-state">
            <div class="icon">✅</div>
            <div class="text">No IPs have been blocked yet.</div>
        </div>
        """, unsafe_allow_html=True)
        return

    df = pd.DataFrame(blocked[:50], columns=["IP Address", "Reason", "Severity", "Blocked At"])
    
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )

    st.markdown(f"""
    <div style="color: #475569; font-size: 0.75rem; text-align: right; margin-top: 6px;">
        Showing {min(len(blocked), 50)} of {len(blocked)} blocked IPs
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# MAIN APP
# ============================================================
def main():
    render_header()

    # --- Controls row ---
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1.5, 1.5, 5])
    with ctrl_col1:
        analyze_btn = st.button("🚀 Run Analysis", use_container_width=True)
    with ctrl_col2:
        refresh_btn = st.button("🔄 Refresh Blocked", use_container_width=True)
    with ctrl_col3:
        # Align uploader and button side-by-side inside col3
        up_col1, up_col2 = st.columns([3, 1])
        with up_col1:
            uploaded_file = st.file_uploader("Upload custom logs (Optional)", type=["txt"], label_visibility="collapsed")
        with up_col2:
            if uploaded_file is not None:
                if st.button("⬆️ Upload", use_container_width=True):
                    with st.spinner("Uploading logs..."):
                        try:
                            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/plain")}
                            res = requests.post(f"{API_BASE}/upload", files=files)
                            res.raise_for_status()
                            st.success("Uploaded!")
                        except Exception as e:
                            st.error(f"Failed: {e}")

    # --- Run Analysis ---
    if analyze_btn:
        with st.spinner("⚙️ Analyzing logs with AI... This may take a moment."):
            results = fetch_analysis()
            if results is not None:
                st.session_state["results"] = results
                st.rerun()

    # --- Get stored results or empty ---
    results = st.session_state.get("results", {})

    # --- Render sections ---
    render_severity_cards(results)

    st.markdown("<div style='height: 0.5rem;'></div>", unsafe_allow_html=True)

    left_col, right_col = st.columns([1, 1], gap="large")

    with left_col:
        render_attack_feed(results)
        render_attack_details(results)

    with right_col:
        # Always fetch blocked IPs on load or refresh
        if refresh_btn or "blocked" not in st.session_state:
            st.session_state["blocked"] = fetch_blocked()

        render_blocked_ips(st.session_state.get("blocked", []))

        # Stats panel
        if results:
            total_ips = sum(len(d.get("ips", [])) for d in results.values())
            total_attacks = len(results)
            blocked_count = len(st.session_state.get("blocked", []))

            render_section_header("📊", "Quick Stats")
            st.markdown(f"""
            <div class="detail-panel">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                    <div>
                        <div style="color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px;">Attack Types</div>
                        <div style="font-size: 1.8rem; font-weight: 800; color: #818cf8; font-family: 'JetBrains Mono', monospace;">{total_attacks}</div>
                    </div>
                    <div>
                        <div style="color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px;">Unique IPs</div>
                        <div style="font-size: 1.8rem; font-weight: 800; color: #38bdf8; font-family: 'JetBrains Mono', monospace;">{total_ips}</div>
                    </div>
                    <div>
                        <div style="color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px;">Blocked IPs</div>
                        <div style="font-size: 1.8rem; font-weight: 800; color: #ff1744; font-family: 'JetBrains Mono', monospace;">{blocked_count}</div>
                    </div>
                    <div>
                        <div style="color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px;">Engine</div>
                        <div style="font-size: 0.85rem; font-weight: 600; color: #00e676; margin-top: 8px;">LLaMA 3.1 + FAISS</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()

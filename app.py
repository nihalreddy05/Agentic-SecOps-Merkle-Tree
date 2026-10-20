import streamlit as st
import json, time, math, threading, os
import pandas as pd
import tempfile
import hashlib
from watchdog.observers import Observer
from guard_agent import GuardAgent
from hacker_agent import HackerAgent
from setup_engine import process_multiple_csvs
from cryptography.fernet import Fernet
from forensics import AuditChain

st.set_page_config(page_title="Distributed DB SOC", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #c9d1d9; font-family: 'Inter', sans-serif; }
    .stSidebar { background-color: #161b22; border-right: 1px solid #30363d; }
    h1, h2, h3 { color: #58a6ff; }
    .stMetric { background-color: #161b22; padding: 18px; border-radius: 8px; border: 1px solid #30363d; }
    .stMetric label { color: #8b949e; } .stMetric div { color: #ffffff; font-weight: 800; }
    table { width: 100%; } th { background-color: #21262d !important; color: #8b949e !important; } td { background-color: #0d1117 !important; color: #c9d1d9 !important; border-top: 1px solid #21262d !important; }
    .stButton button { background-color: #238636; color: white; border: none; border-radius: 6px; font-weight: 600; }
    .stButton button:hover { background-color: #2ea043; }
    div[data-testid="stFileUploader"] { background-color: #161b22; border: 1px dashed #30363d; border-radius: 8px; padding: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("🏢 Distributed Database Security Operations Center")
st.markdown("**Autonomous Multi-Shard Integrity Agent |** Authorized Updates & Threat Detection")

if 'flash_success' in st.session_state:
    st.success(st.session_state.pop('flash_success'))

if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.guard_agent = GuardAgent()
    observer = Observer()
    observer.schedule(st.session_state.guard_agent, path='live_db', recursive=False)
    observer.start()
    st.session_state.observer = observer
    st.session_state.hacker_agent = HackerAgent()
    threading.Thread(target=st.session_state.hacker_agent.run, daemon=True).start()
    st.session_state.start_time = time.time()
    st.session_state.last_attack_time = 0
    st.session_state.last_log_len = 0
    st.session_state.authenticated = False
    st.session_state.current_file_id = ""
    st.session_state.db_loaded = any(f.startswith('shard') for f in os.listdir('live_db')) if os.path.exists(
        'live_db') else False

guard = st.session_state.guard_agent
hacker = st.session_state.hacker_agent

st.sidebar.title("⚙️ Admin Control Panel")
st.sidebar.subheader("1. Initialize Cluster (Upload CSVs)")
uploaded_files = st.sidebar.file_uploader("Upload one or more CSVs to shard independently", type=['csv'],
                                          accept_multiple_files=True)

if uploaded_files:
    current_file_ids = tuple(f.file_id for f in uploaded_files)
    if st.session_state.get('current_file_id') != current_file_ids:
        st.session_state.guard_agent.is_active = False
        if 'observer' in st.session_state and st.session_state.observer.is_alive():
            st.session_state.observer.stop()
            st.session_state.observer.join()

        temp_paths = []
        for i, file in enumerate(uploaded_files):
            temp_path = os.path.join(tempfile.gettempdir(), f"uploaded_{i}.csv")
            with open(temp_path, "wb") as f: f.write(file.getbuffer())
            temp_paths.append(temp_path)

        with st.spinner(f"Encrypting & sharding {len(uploaded_files)} datasets..."):
            count = process_multiple_csvs(temp_paths)

        st.session_state.guard_agent = GuardAgent()
        new_obs = Observer()
        new_obs.schedule(st.session_state.guard_agent, path='live_db', recursive=False)
        new_obs.start()
        st.session_state.observer = new_obs
        guard = st.session_state.guard_agent

        st.session_state.start_time = time.time()
        st.session_state.last_attack_time = 0
        st.session_state.last_log_len = 0
        st.session_state.current_file_id = current_file_ids
        st.session_state.db_loaded = True
        st.session_state.authenticated = False

        st.sidebar.success(f"✅ Cluster Live: {count} records split across {len(uploaded_files) * 3} shards.")
        time.sleep(1)
        st.rerun()

st.sidebar.divider()
st.sidebar.subheader("2. Admin Authentication")
if not st.session_state.authenticated:
    pwd = st.sidebar.text_input("Enter Admin Password", type="password")
    if st.sidebar.button("Login"):
        if pwd == "admin123":
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.sidebar.error("❌ Access Denied.")
else:
    st.sidebar.success("✅ Authenticated as DB Admin.")

st.sidebar.divider()
st.sidebar.subheader("3. Threat Simulation")
auto_hack = st.sidebar.toggle("🤖 Enable Autonomous Hacker", value=False)
hacker.is_running = auto_hack

if hacker.is_running:
    st.sidebar.error("🔴 HACKER AGENT IS ACTIVE")
else:
    st.sidebar.success("🟢 HACKER AGENT IS OFFLINE")

st.sidebar.divider()
st.sidebar.subheader("Manual Attack")
manual_vector = st.sidebar.selectbox("Manual Attack Vector:", ("Tamper", "Delete", "Insert"))
if st.sidebar.button("🚨 Execute Manual Hack (1 Attack)"):
    hacker.is_running = True
    hacker.execute_attack(manual_vector.lower())
    hacker.is_running = False
    st.sidebar.warning("Attack Deployed!")

if st.sidebar.button("🧹 Clear Audit Logs"):
    guard.audit_chain = AuditChain()
    st.session_state.last_log_len = 0
    st.sidebar.success("Logs Cleared!")

if not st.session_state.db_loaded or not guard.shards:
    st.info("👆 Upload CSV(s) in the sidebar to initialize the distributed database cluster.")
    time.sleep(2)
    st.rerun()
    st.stop()

total_records = sum(len(s['data']) for s in guard.shards.values())
log_count = 0
node = guard.audit_chain.head
last_idx_display = "N/A"
while node:
    log_count += 1
    if node.next is None:
        last_idx_display = node.index
    node = node.next

is_under_attack = (
                              time.time() - st.session_state.last_attack_time) < 3 if st.session_state.last_attack_time > 0 else False

c1, c2, c3, c4 = st.columns(4)
c1.metric("Cluster Status", "🔴 UNDER ATTACK" if is_under_attack else "🟢 SECURE")
c2.metric("Uptime", f"{int(time.time() - st.session_state.start_time)}s")
c3.metric("Total Records (All Shards)", f"{total_records:,}")
c4.metric("Last Attacked Index", last_idx_display)

st.divider()

if st.session_state.get('authenticated', False):
    update_panel = st.container()
    with update_panel:
        st.subheader("🔓 Authorized Database Update Panel")
        st.markdown("Select a shard to update. Legitimate updates will **not** trigger the Guard Agent.")
        shard_files = list(guard.shards.keys())
        if shard_files:
            sel_shard = st.selectbox("Select Shard to Update", shard_files)
            sel_data = guard.shards[sel_shard]['data']
            row_idx = st.number_input("Enter Row Index to Update", 0, len(sel_data) - 1, 0)
            try:
                cipher_suite = Fernet(open('secret.key', 'rb').read())
                current_enc = sel_data[int(row_idx)]
                current_dec = json.loads(cipher_suite.decrypt(current_enc.encode('utf-8')).decode('utf-8'))
                st.write("**Current Value:**")
                st.json(current_dec)
                st.write("**Enter New Value (JSON format):**")
                new_val_str = st.text_area("Update Data", json.dumps(current_dec, indent=2), height=200,
                                           key="update_text_area")
                if st.button("✅ Apply Authorized Update"):
                    try:
                        new_dict = json.loads(new_val_str)
                        guard.authorized_update(sel_shard, int(row_idx), new_dict)
                        st.session_state.flash_success = f"Row {row_idx} updated legally. Trees re-anchored. You have been securely logged out."
                        update_panel.empty()
                        st.session_state.authenticated = False
                        st.rerun()
                    except Exception as e:
                        st.error(f"Invalid JSON: {e}")
            except Exception as e:
                st.error(f"Error reading row: {e}")
    st.divider()

st.subheader("💾 Live Database Shards")
sel_shard_view = st.selectbox("View Shard", list(guard.shards.keys()))

live_data = None
for attempt in range(5):
    try:
        with open(f'live_db/{sel_shard_view}', 'r') as f:
            live_data = json.load(f, strict=False)
            break
    except (json.JSONDecodeError, IOError):
        time.sleep(0.1)

if live_data:
    table_data = []
    for i in range(min(10, len(live_data))):
        orig_hash = guard.shards[sel_shard_view]['tree'].leaves[i] if i < len(
            guard.shards[sel_shard_view]['tree'].leaves) else "N/A"
        curr_hash = hashlib.sha256(str(live_data[i]).encode('utf-8')).hexdigest()
        table_data.append({
            "Row ID": i,
            "Encrypted Data": live_data[i][:30] + "...",
            "Validation": "🚨 BREACH" if orig_hash != curr_hash else "✅ SECURE"
        })
    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

st.divider()

st.subheader("🕵️‍♂️ Forensic Audit Logs")
if log_count <= 1:
    st.info("Awaiting threat detection...")
else:
    logs, curr = [], guard.audit_chain.head.next
    while curr:
        logs.append({
            "Time": curr.timestamp,
            "Vector": curr.attack_type,
            "Target Index": curr.index,
            "Compromised Column": curr.compromised_column,
            "Severity": curr.severity,
            "Action": curr.action
        })
        curr = curr.next
    if len(logs) > st.session_state.last_log_len:
        st.session_state.last_attack_time = time.time()
        st.session_state.last_log_len = len(logs)
    st.dataframe(pd.DataFrame(logs[::-1]), use_container_width=True, hide_index=True)

time.sleep(3)
st.rerun()
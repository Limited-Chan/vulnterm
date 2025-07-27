import streamlit as st
import numpy as np
import pandas as pd
import time
import re
from sklearn.metrics.pairwise import cosine_similarity
import html
from datetime import datetime

# データとモデルの読み込み
vectors = np.load("data/cve_vectors_sbert.npy")
cve_ids = np.load("data/cve_vocab_ids.npy", allow_pickle=True)
df = pd.read_csv("cve-summary.csv", names=["CVE_ID", "CVSS", "Summary"])

# Streamlitページ設定
st.set_page_config(page_title="vulnterm - CVE検索", layout="wide")

# セッション状態の初期化
if "submitted" not in st.session_state:
    st.session_state.submitted = False
if "history" not in st.session_state:
    st.session_state.history = []
if "sqli_count" not in st.session_state:
    st.session_state.sqli_count = 0

# ターミナル風の見た目
st.markdown("""
<style>
body {
    background-color: #000000;
    color: #C0C0C0;
    font-family: 'Courier New', monospace;
}
[data-testid="stHeader"] {visibility: hidden;}
.block-container {
    padding-top: 2rem;
}
.terminal {
    background-color: #000000;
    color: #00FF00;
    padding: 1rem;
    border-radius: 5px;
    font-family: 'Courier New', monospace;
    font-size: 16px;
}
.result-box {
    background-color: #101010;
    color: #C0C0C0;
    padding: 1rem;
    margin-top: 1rem;
    border-left: 3px solid #00FF00;
    white-space: pre-wrap;
    font-family: 'Courier New', monospace;
    font-size: 17px;
}
input[type="text"] {
    background-color: #111111 !important;
    color: #00FF00 !important;
    font-family: 'Courier New', monospace;
    border: 1px solid #00FF00 !important;
    border-radius: 4px;
    padding: 0.4rem 0.5rem 0.4rem 1.5rem;
    position: relative;
}
input[type="text"]::before {
    content: ">";
    position: absolute;
    left: 0.5rem;
    color: #00FF00;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# --- 5. ページヘッダーの表示 ---
st.markdown("""
<h1 style='font-family:Courier New; color:#FFFFFF;'>
vulnterm <span style='color:#444'>| CVE intelligence shell</span>
</h1>
<p style='color:#888888; font-family:Courier New; font-size:19px; margin-top:-10px;'>
Explore vulnerability similarities in a terminal-like environment.<br>
Type commands like <code>search CVE-2020-0601</code> or <code>help</code> to get started.
</p>
""", unsafe_allow_html=True)

# --- 6. ユーティリティ関数群 ---
# CVSSスコアに応じて深刻度レベルと色を返す
def cvss_level(cvss_score):
    try:
        score = float(cvss_score)
        if score < 4.0:
            return ("LOW", "#00FF00")
        elif score < 7.0:
            return ("MID", "#FFFF00")
        else:
            return ("HIGH", "#FF4444")
    except:
        return ("N/A", "#AAAAAA")

# 深刻度レベルに応じたアイコンを返す
def cvss_icon(level):
    return {
        "LOW": "🟢",
        "MID": "🟡",
        "HIGH": "🔴",
        "N/A": "⚪️"
    }.get(level, "⚪️")

# 概要文中の特定キーワードをハイライトする
def highlight_keywords(text):
    keywords = ["Windows", "Linux", "privilege", "spoofing", "RCE", "XSS", "DoS", "SQL", "code execution"]
    for word in keywords:
        text = re.sub(rf"(?i)({word})", r"<span style='color:#FFD700'><b>\1</b></span>", text)
    return text

# テキストをタイプライター風に一文字ずつ表示する
def type_writer(text, container, delay=0.01):
    final_html = ""
    # HTMLタグを維持しつつ、テキスト部分のみを分割
    parts = re.split(r'(<[^>]+>)', text)
    for part in parts:
        if part.startswith("<") and part.endswith(">"):
            final_html += part
        else:
            for char in part:
                final_html += "<br>" if char == "\n" else html.escape(char)
                container.markdown(
                    f"<div class='result-box'><code>{final_html}</code></div>",
                    unsafe_allow_html=True
                )
                time.sleep(delay)

# --- 7. メインのUIレイアウト ---
# コマンド入力欄と結果表示エリアを定義
st.markdown("""
<div class='terminal'>Search CVE by ID (e.g., <code>search CVE-2020-0601</code>)</div>
<div style="font-family:Courier New; font-size:16px; color:#00FF00;">
<b>vulnterm > </b> <span class="cursor"></span>
</div>
""", unsafe_allow_html=True)

command = st.text_input(label="Command", value="", label_visibility="collapsed", placeholder="Type: search CVE-2020-0601 or help")
container = st.empty()

# 入力されたコマンドを履歴に追加（'history'コマンド自体は除く）
if command.strip() and command.strip().lower() != "history":
    st.session_state.history.append(command)

# SQLインジェクション検知用のパターンと関数
sqli_patterns = [r"'", r"--", r";", r" or ", r" and ", r"union", r"select", r"=", r"1=1"]
def looks_like_sqli(cmd):
    return any(re.search(pat, cmd, re.IGNORECASE) for pat in sqli_patterns)

# --- 8. コマンド処理のメインロジック ---
# 入力されたコマンドに応じて、異なる処理を実行する
cmd = command.strip().lower()

# 'help' コマンド: 利用可能なコマンドを表示
if cmd == "help":
    text = """[+] Available commands:
  search <CVE-ID>   - Find similar vulnerabilities  
  history           - View your search history  
  help              - Show this help menu
[?] Psst... Try some other commands:)"""
    type_writer(text, container)

# 'search' コマンド: CVE-IDに基づいて類似の脆弱性を検索
elif cmd.startswith("search "):
    query_id = command.replace("search ", "").strip()
    if query_id in cve_ids:
        idx = list(cve_ids).index(query_id)
        target_vec = vectors[idx].reshape(1, -1)
        sims = cosine_similarity(target_vec, vectors)[0]
        top_indices = sims.argsort()[::-1][1:6]

        output = f"[+] Search result for {query_id}\n\nMatching CVEs\n==============================\n"
        for i, index in enumerate(top_indices):
            cve_id = cve_ids[index]
            sim = sims[index]
            row = df[df["CVE_ID"] == cve_id]
            cvss = row["CVSS"].values[0] if not row.empty else "N/A"
            summary = row["Summary"].values[0] if not row.empty else "No summary."
            level, color = cvss_level(cvss)
            icon = cvss_icon(level)
            summary = highlight_keywords(summary)
            output += f"{i}  ID: {cve_id}\n   CVSS: {icon} [{level}] {cvss}\n   Similarity: {sim:.3f}\n   Summary: {summary}\n\n"
        type_writer(output, container)
    else:
        type_writer(f"[-] No results for {query_id}", container)
    # 検索コマンドも履歴に追加
    st.session_state.history.append(command)

# SQLiっぽい入力のとき
elif looks_like_sqli(command):
    st.session_state.sqli_count += 1
    responses = [
        "[!] Detected use of UNION. This ain't a hacker movie, bro.",
        "[-] Malicious input detected:)",
        "[-] Injection attempt flagged. Nice try.",
        "[!] Are you trying SQLi on a fake terminal?"
    ]
    if st.session_state.sqli_count >= 3:
        msg = "[-] Suspicious behavior detected. Please prove you're not a pentester."
    else:
        msg = np.random.choice(responses)
    type_writer(msg, container)

# --- 面白隠しコマンド群 ---
elif cmd == "whoami":
    type_writer("You!", container)

elif cmd == "uname -a":
    type_writer("vulnterm 6.6.6 #1 SMP Sat Jul 27 2025", container)

elif cmd == "sudo rm -rf /":
    type_writer("[-] Permission denied. Nice try, script kiddie.", container)

elif cmd == "rm -rf /*":
    type_writer("[-] You monster. But vulnterm is immutable.", container)

elif cmd == "lightmode":
    type_writer("[-] No. Just no.", container)

elif cmd == "nc -lnvp 4444":
    type_writer("[-] Reverse shell refused. vulnterm is not that kind of terminal.", container)

elif command.strip().lower() == "sudo su":
    type_writer("[-] Permission denied. You're not root, and you never will be.", container)

elif command.strip().lower() == "sudo -l":
    fake_sudo_l = """Matching Defaults entries for user on vulnterm:
    insult, lecture, require_password=always

User user may run the following commands on vulnterm:
    (ALL : ALL) NOPASSWD: /bin/echo "nope"
"""
    type_writer(fake_sudo_l, container)

elif command.strip().lower().startswith("sudo "):
    type_writer("[-] This ain't Kali, buddy.", container)

elif command.strip().lower().startswith("cd"):
    type_writer("[-] Access denied. vulnterm is a chroot jail.", container)

# 'ls' コマンド: 仮想的なファイルリストを表示
elif command.strip().lower() in ["ls", "ls -la", "ls -lta"]:
    fake_ls = """drwxr-xr-x   ./                       Jul 27 21:00
drwxr-xr-x   ../                      Jul 27 20:59
-rw-r--r--   flag.txt.enc             Jul 27 20:58
-rw-r--r--   password.txt             Jul 27 20:57
-rwxr-xr-x   decrypt_flag.py          Jul 27 20:56
-rw-r--r--   config_backup.tar.gz     Jul 27 20:55
-rw-r--r--   todo.md                  Jul 27 20:54
-rwx------   id_rsa.old               Jul 27 20:53
drwx------   .vault/                  Jul 27 20:52
drwx------   .ssh/                    Jul 27 20:51"""
    type_writer(fake_ls, container)

# 'cat' コマンド: 仮想的なファイルの内容を表示
elif cmd.startswith("cat "):
    filename = cmd.split(" ", 1)[1].strip()

    # システム関連の仮想ファイル
    if filename == "/etc/passwd":
        text = """root:x:0:0:root:/root:/bin/bash
user:x:1337:1337:/home/user:/bin/fish
...
[!] Redacted for your safety."""
        type_writer(text, container)
    elif filename == "/etc/shadow":
        text = """root:$6$rounds=5000$REDACTEDHASH:18703:0:99999:7:::
user:$6$rounds=5000$FAKEHASHVALUE:18703:0:99999:7:::
[!] You wish you had these hashes."""
        type_writer(text, container)

    # カレントディレクトリの仮想ファイル
    elif filename == "flag.txt.enc":
        type_writer("U2FsdGVkX1+X8A1F12R3Rbb3JZ91c9...==\n[!] AES-256 encrypted. Need password.", container)
    elif filename == "password.txt":
        type_writer("password123\n# TODO: rotate this before audit", container)
    elif filename == "decrypt_flag.py":
        type_writer("""#!/usr/bin/env python3
from Crypto.Cipher import AES
# Placeholder script. You didn't think it would be that easy, did you?
print("[!] Work in progress...")""", container)
    elif filename == "config_backup.tar.gz":
        type_writer("[!] Binary blob detected. Try extracting it (not implemented).", container)
    elif filename == "todo.md":
        type_writer("- [x] Patch CVE-2023-XXXX\n- [ ] Rotate SSH keys\n- [ ] Delete old backups\n- [ ] Replace password123", container)
    elif filename == "id_rsa.old":
        type_writer("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n[REDACTED]\n-----END OPENSSH PRIVATE KEY-----", container)
    elif filename in [".vault", ".ssh"]:
        type_writer("[-] Permission denied: directory is protected.", container)
    else:
        type_writer(f"cat: {filename}: No such file or unsupported.", container)

# 'wget' コマンド: 外部へのリクエストを模倣・ブロック
elif cmd.startswith("wget "):
    url = cmd.replace("wget ", "").strip()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        host = url.split("/")[2]
    except:
        host = "unknown"
    text = f"""--{now}--  {url}
Resolving {host}... 127.0.0.1
Connecting to {host}|127.0.0.1|:80... failed: Connection refused.

[-] Suspicious outbound request blocked."""
    type_writer(text, container)

# 'clear' コマンド: 画面をクリア
elif cmd == "clear":
    container.empty()
    type_writer("[+] Screen cleared. But not your sins.", container)

# リバースシェルを試みる典型的なコマンドパターンを検知
elif re.search(r"/dev/tcp/\d+\.\d+\d+\.\d+/\d+", command):
    type_writer("[-] Whoa whoa whoa. Trying to spawn a reverse shell here?\n[!] Don't even.", container)
elif re.search(r"nc\s+-e", command):
    type_writer("[-] Netcat with -e? Real subtle, skiddy.", container)
elif re.search(r"sh\s+-i\s+>&", command) or re.search(r"bash\s+-i\s+>&", command):
    type_writer("[-] Interactive shell redirection? Not in this terminal, my friend.", container)
elif re.search(r"perl.*Socket", command, re.IGNORECASE):
    type_writer("[-] Perl reverse shell attempt detected. I thought we left 2003 behind.", container)

# 'history' コマンド: コマンド履歴を表示
elif cmd == "history":
    if st.session_state.history:
        numbered = [f"{i+1}  {c}" for i, c in enumerate(st.session_state.history)]
        type_writer("\n".join(numbered), container)
    else:
        type_writer("[-] No history yet.", container)

# 未定義のコマンドが入力された場合の処理
elif command.strip():
    st.session_state.history.append(command)
    type_writer("[-] Unknown command. Try help.", container)
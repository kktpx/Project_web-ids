import joblib
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import sqlite3
from datetime import datetime
import requests
import urllib.parse
import math
import html as html_lib
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "super_secret_ids_key"
app.config['SESSION_COOKIE_NAME'] = 'ids_session' # ป้องกัน Cookie ชนกับ todo_app.py

DB_PATH = '/tmp/logs.db' if os.environ.get('VERCEL') == '1' else 'logs.db'

# ==============================
# Load ML model
# ==============================

model = joblib.load("models/model.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")

# ==============================
# Discord Webhook
# ==============================

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1480176307965792399/BpllTJGok1w55SLCh_abFjGCiFg0K9kI2zOlipTtTE5wu9Z1BhzR1iZ9JarYjEfBAJcQ"


# ==============================
# Send Discord Alert
# ==============================

def send_discord_alert(payload, ip):

    message = {
        "content": f"""
⚠ Web IDS Alert

Attack Detected

Payload:
{payload}

IP:
{ip}

Time:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    }

    try:
        if DISCORD_WEBHOOK.startswith("http"):
            response = requests.post(DISCORD_WEBHOOK, json=message, timeout=3)
            print("Discord response:", response.status_code)
        else:
            print("⚠ Discord Webhook ไม่ถูกต้อง กรุณาใส่ URL ให้ถูกต้องในโค้ด app.py")
    except Exception as e:
        print("⚠ ไม่สามารถส่งแจ้งเตือน Discord ได้:", e)


# ==============================
# Database Init
# ==============================

def init_db():

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            payload TEXT,
            prediction TEXT,
            confidence REAL,
            ip TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    
    # Create default admin if not exists
    c.execute("SELECT * FROM admins WHERE username = 'admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash("admin123")
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", hashed_pw))

    conn.commit()
    conn.close()


init_db()


# ==============================
# Authentication
# ==============================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM admins WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and check_password_hash(row[0], password):
            session['logged_in'] = True
            session['username'] = username
            next_url = request.args.get("next")
            return redirect(next_url or url_for('dashboard'))
        else:
            error = "รหัสผ่านไม่ถูกต้อง (Invalid username or password)"

    return render_template_string("""
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — Web IDS</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f7f5f2;
            --surface: #ffffff;
            --border: rgba(0,0,0,0.06);
            --text: #1a1a2e;
            --text-muted: #8a8a9e;
            --accent: #b8942e;
            --accent-hover: #a07e20;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
        }
        [data-theme="dark"] {
            --bg: #0d0d1a;
            --surface: #16162a;
            --border: rgba(255,255,255,0.06);
            --text: #e8e6e3;
            --text-muted: #7a7a8e;
            --accent: #c9a96e;
            --accent-hover: #dfc088;
            --danger: #e05252;
            --danger-bg: rgba(224,82,82,0.1);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            transition: background-color 0.4s ease, color 0.4s ease;
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .login-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 48px 40px 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.06);
            animation: fadeInUp 0.5s ease-out;
            transition: background-color 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease;
        }
        [data-theme="dark"] .login-card {
            background: rgba(22,22,42,0.8);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .logo-icon {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .logo-icon svg {
            color: var(--accent);
        }
        .login-card h1 {
            text-align: center;
            font-weight: 700;
            font-size: 24px;
            letter-spacing: -0.02em;
            margin-bottom: 6px;
        }
        .subtitle {
            text-align: center;
            font-size: 14px;
            color: var(--text-muted);
            margin-bottom: 32px;
            font-weight: 400;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 13px;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--text);
            font-size: 15px;
            font-family: 'Inter', sans-serif;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(201,169,110,0.1);
        }
        [data-theme="dark"] .form-group input:focus {
            box-shadow: 0 0 0 3px rgba(201,169,110,0.15);
        }
        .login-btn {
            width: 100%;
            padding: 14px;
            border-radius: 10px;
            border: none;
            background: var(--accent);
            color: #fff;
            font-weight: 600;
            font-size: 15px;
            font-family: 'Inter', sans-serif;
            cursor: pointer;
            transition: background-color 0.2s ease, transform 0.1s ease;
            margin-top: 8px;
            letter-spacing: 0.01em;
        }
        .login-btn:hover { background: var(--accent-hover); }
        .login-btn:active { transform: scale(0.98); }
        .error-msg {
            color: var(--danger);
            background: var(--danger-bg);
            border: 1px solid rgba(220,38,38,0.15);
            padding: 12px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
            font-weight: 500;
        }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            cursor: pointer;
            color: var(--text-muted);
            transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease;
        }
        [data-theme="dark"] .theme-toggle {
            background: rgba(22,22,42,0.6);
        }
        .theme-toggle:hover {
            color: var(--accent);
        }
    </style>
</head>
<body>
    <button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme">
        <svg id="moon-icon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg id="sun-icon" style="display:none;" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
    </button>
    <div class="login-card">
        <div class="logo-icon">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        </div>
        <h1>Web IDS</h1>
        <p class="subtitle">Intrusion Detection System</p>
        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="off" placeholder="admin">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="admin123">
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
    </div>
    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');

        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {
            root.setAttribute('data-theme', 'dark');
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
        }

        toggleBtn.addEventListener('click', () => {
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {
                root.setAttribute('data-theme', 'light');
                localStorage.setItem('theme', 'light');
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
            } else {
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                moonIcon.style.display = 'none';
                sunIcon.style.display = 'block';
            }
        });
    </script>
</body>
</html>
    """, error=error)

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# ==============================
# Home
# ==============================

@app.route("/")
def home():
    return redirect(url_for('login'))


# ==============================
# Detect Endpoint
# ==============================

@app.route("/detect", methods=["POST"])
def detect():

    data = request.json

    if not data or "payload" not in data:
        return jsonify({"error": "No payload provided"}), 400

    payload = data.get("payload")

    if payload.strip() == "":
        return jsonify({"error": "Empty payload"}), 400

    payload = urllib.parse.unquote(payload.strip())

    X = vectorizer.transform([payload])

    import numpy as np
    threshold = joblib.load("models/threshold.pkl")
    classes = list(model.classes_)
    attack_index = classes.index("Attack")
    prob = model.predict_proba(X)[0]
    confidence = float(max(prob))
    prediction = "Attack" if prob[attack_index] >= threshold else "Normal"

    prob = model.predict_proba(X)[0]
    confidence = float(max(prob))

    ip = request.remote_addr

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute(
        """
        INSERT INTO request_log
        (timestamp, payload, prediction, confidence, ip)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            payload,
            prediction,
            confidence,
            ip
        )
    )

    conn.commit()
    conn.close()

    if prediction == "Attack":
        send_discord_alert(payload, ip)

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "ip": ip
    })


# ==============================
# View Logs
# ==============================

@app.route("/logs")
@login_required
def view_logs():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    limit = 20
    offset = (page - 1) * limit

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if search:
        search_query = f"%{search}%"
        c.execute("SELECT COUNT(*) FROM request_log WHERE payload LIKE ? OR ip LIKE ? OR prediction LIKE ?", (search_query, search_query, search_query))
        total_records = c.fetchone()[0]
        c.execute("SELECT * FROM request_log WHERE payload LIKE ? OR ip LIKE ? OR prediction LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", (search_query, search_query, search_query, limit, offset))
    else:
        c.execute("SELECT COUNT(*) FROM request_log")
        total_records = c.fetchone()[0]
        c.execute("SELECT * FROM request_log ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        
    rows = c.fetchall()
    conn.close()

    total_pages = math.ceil(total_records / limit) if total_records > 0 else 1

    rows_html = ""
    if not rows:
        rows_html = "<tr><td colspan='6' style='text-align:center; padding: 20px;'>No logs found matching your criteria.</td></tr>"

    for row in rows:
        is_attack = row[3] == "Attack"
        badge_class = "badge-attack" if is_attack else "badge-normal"
        safe_payload = html_lib.escape(str(row[2]))
        
        rows_html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td><span class="payload-cell">{safe_payload}</span></td>
            <td><span class="badge {badge_class}">{row[3]}</span></td>
            <td>{(row[4]*100):.1f}%</td>
            <td>{row[5]}</td>
        </tr>
        """

    prev_btn = f'<a href="/logs?page={page-1}&search={urllib.parse.quote(search)}" class="back-btn">Previous</a>' if page > 1 else ''
    next_btn = f'<a href="/logs?page={page+1}&search={urllib.parse.quote(search)}" class="back-btn">Next</a>' if page < total_pages else ''

    html = f"""
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Logs — Web IDS</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #f7f5f2;
            --surface: #ffffff;
            --surface-hover: #faf9f7;
            --border: rgba(0,0,0,0.06);
            --text: #1a1a2e;
            --text-muted: #8a8a9e;
            --accent: #b8942e;
            --accent-hover: #a07e20;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
            --success: #16a34a;
            --success-bg: #f0fdf4;
        }}
        [data-theme="dark"] {{
            --bg: #0d0d1a;
            --surface: #16162a;
            --surface-hover: #1e1e36;
            --border: rgba(255,255,255,0.06);
            --text: #e8e6e3;
            --text-muted: #7a7a8e;
            --accent: #c9a96e;
            --accent-hover: #dfc088;
            --danger: #e05252;
            --danger-bg: rgba(224,82,82,0.1);
            --success: #4ade80;
            --success-bg: rgba(74,222,128,0.1);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            transition: background-color 0.4s ease, color 0.4s ease;
        }}
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .container {{
            width: 100%;
            max-width: 1200px;
            animation: fadeInUp 0.5s ease-out;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .back-btn {{
            color: var(--text);
            text-decoration: none;
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
        }}
        .back-btn:hover {{ background: var(--surface-hover); }}
        .header h1 {{
            font-weight: 600;
            font-size: 24px;
            letter-spacing: -0.02em;
        }}
        .search-container {{
            margin-bottom: 24px;
        }}
        .search-form {{
            display: flex;
            gap: 12px;
        }}
        .search-input {{
            flex: 1;
            padding: 12px 16px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            font-family: 'Inter', sans-serif;
            font-size: 14px;
            transition: border-color 0.2s;
        }}
        .search-input:focus {{
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(201,169,110,0.1);
        }}
        .search-btn {{
            padding: 12px 24px;
            border-radius: 10px;
            border: none;
            background: var(--accent);
            color: #fff;
            cursor: pointer;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            transition: background-color 0.2s;
        }}
        .search-btn:hover {{ background: var(--accent-hover); }}
        .clear-btn {{
            padding: 12px 24px;
            border-radius: 10px;
            text-decoration: none;
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            display: flex;
            align-items: center;
            font-weight: 500;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        .clear-btn:hover {{ background: var(--surface-hover); }}
        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0,0,0,0.02);
            transition: background-color 0.4s ease, border-color 0.4s ease;
        }}
        [data-theme="dark"] .table-container {{
            background: rgba(22,22,42,0.6);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th, td {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: rgba(0,0,0,0.01);
        }}
        [data-theme="dark"] th {{ background: rgba(255,255,255,0.02); }}
        td {{ font-size: 14px; color: var(--text); }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background-color: var(--surface-hover); }}
        .payload-cell {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0,0,0,0.03);
            padding: 6px 10px;
            border-radius: 6px;
            word-break: break-all;
            display: inline-block;
            max-width: 400px;
            font-size: 13px;
        }}
        [data-theme="dark"] .payload-cell {{ background: rgba(0,0,0,0.2); }}
        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        .badge-attack {{
            background-color: var(--danger-bg);
            color: var(--danger);
            border: 1px solid rgba(220,38,38,0.2);
        }}
        .badge-normal {{
            background-color: var(--success-bg);
            color: var(--success);
            border: 1px solid rgba(22,163,74,0.2);
        }}
        .pagination {{
            margin-top: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
            color: var(--text-muted);
        }}
        .theme-toggle {{
            position: fixed;
            top: 20px;
            right: 20px;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            cursor: pointer;
            color: var(--text-muted);
            transition: all 0.3s ease;
        }}
        [data-theme="dark"] .theme-toggle {{ background: rgba(22,22,42,0.6); }}
        .theme-toggle:hover {{ color: var(--accent); }}
        .logout-btn {{
            position: fixed;
            top: 20px;
            right: 70px;
            text-decoration: none;
            color: var(--danger);
            font-weight: 500;
            font-size: 14px;
            background: var(--danger-bg);
            padding: 10px 16px;
            border-radius: 10px;
            transition: opacity 0.2s;
        }}
        .logout-btn:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme">
        <svg id="moon-icon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg id="sun-icon" style="display:none;" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
    </button>
    <a href="/logout" class="logout-btn">Logout</a>

    <div class="container">
        <div class="header">
            <div class="header-left">
                <a href="/dashboard" class="back-btn">&larr; Dashboard</a>
                <h1>Request Logs</h1>
            </div>
        </div>

        <div class="search-container">
            <form class="search-form" method="GET" action="/logs">
                <input type="text" name="search" class="search-input" value="{search}" placeholder="Search IP, Payload, Prediction...">
                <button type="submit" class="search-btn">Search</button>
                <a href="/logs" class="clear-btn">Clear</a>
            </form>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Time</th>
                        <th>Payload</th>
                        <th>Prediction</th>
                        <th>Confidence</th>
                        <th>IP</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        
        <div class="pagination">
            <div>Showing page {page} of {total_pages} (Total: {total_records} records)</div>
            <div style="display: flex; gap: 10px;">
                {prev_btn}
                {next_btn}
            </div>
        </div>
    </div>

    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');

        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {{
            root.setAttribute('data-theme', 'dark');
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
        }}

        toggleBtn.addEventListener('click', () => {{
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {{
                root.setAttribute('data-theme', 'light');
                localStorage.setItem('theme', 'light');
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
            }} else {{
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                moonIcon.style.display = 'none';
                sunIcon.style.display = 'block';
            }}
        }});
    </script>
</body>
</html>
"""

    return html


# ==============================
# Dashboard Stats
# ==============================

def get_dashboard_stats():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM request_log")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_log WHERE prediction='Attack'")
    attack = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_log WHERE prediction='Normal'")
    normal = cursor.fetchone()[0]

    conn.close()

    attack_rate = 0

    if total > 0:
        attack_rate = (attack / total) * 100

    return total, attack, normal, round(attack_rate, 2)


# ==============================
# Dashboard
# ==============================

@app.route("/dashboard")
@login_required
def dashboard():

    total, attack, normal, attack_rate = get_dashboard_stats()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp, payload, ip
    FROM request_log
    WHERE prediction='Attack'
    ORDER BY id DESC
    LIMIT 5
    """)

    recent_attacks = cursor.fetchall()

    conn.close()

    recent_html = ""

    for a in recent_attacks:
        safe_payload = html_lib.escape(str(a[1]))
        recent_html += f"""
        <tr>
        <td>{a[0]}</td>
        <td><span class="payload-cell">{safe_payload}</span></td>
        <td>{a[2]}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta http-equiv="refresh" content="5">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web IDS Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #f7f5f2;
            --surface: #ffffff;
            --surface-hover: #faf9f7;
            --border: rgba(0,0,0,0.06);
            --text: #1a1a2e;
            --text-muted: #8a8a9e;
            --accent: #b8942e;
            --accent-hover: #a07e20;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
            --success: #16a34a;
            --success-bg: #f0fdf4;
            --purple: #8b5cf6;
        }}
        [data-theme="dark"] {{
            --bg: #0d0d1a;
            --surface: #16162a;
            --surface-hover: #1e1e36;
            --border: rgba(255,255,255,0.06);
            --text: #e8e6e3;
            --text-muted: #7a7a8e;
            --accent: #c9a96e;
            --accent-hover: #dfc088;
            --danger: #e05252;
            --danger-bg: rgba(224,82,82,0.1);
            --success: #4ade80;
            --success-bg: rgba(74,222,128,0.1);
            --purple: #a78bfa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            transition: background-color 0.4s ease, color 0.4s ease;
        }}
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .container {{
            width: 100%;
            max-width: 1200px;
            animation: fadeInUp 0.5s ease-out;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .header h1 {{
            font-weight: 700;
            font-size: 26px;
            letter-spacing: -0.02em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.02);
            display: flex;
            flex-direction: column;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        [data-theme="dark"] .stat-card {{
            background: rgba(22,22,42,0.6);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.04);
        }}
        [data-theme="dark"] .stat-card:hover {{
            box-shadow: 0 12px 40px rgba(0,0,0,0.3);
        }}
        .stat-card .title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
        }}
        .stat-card .value {{
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .c-accent {{ color: var(--accent); }}
        .c-danger {{ color: var(--danger); }}
        .c-success {{ color: var(--success); }}
        .c-purple {{ color: var(--purple); }}
        .recent-section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0,0,0,0.02);
        }}
        [data-theme="dark"] .recent-section {{
            background: rgba(22,22,42,0.6);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }}
        .recent-section-header {{
            padding: 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .recent-section h2 {{
            font-size: 18px;
            font-weight: 600;
        }}
        .view-all-link {{
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            transition: color 0.2s;
        }}
        .view-all-link:hover {{ color: var(--accent-hover); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th, td {{
            padding: 16px 24px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: rgba(0,0,0,0.01);
        }}
        [data-theme="dark"] th {{ background: rgba(255,255,255,0.02); }}
        td {{ font-size: 14px; color: var(--text); }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background-color: var(--surface-hover); }}
        .payload-cell {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0,0,0,0.03);
            padding: 6px 10px;
            border-radius: 6px;
            word-break: break-all;
            display: inline-block;
            max-width: 500px;
            font-size: 13px;
        }}
        [data-theme="dark"] .payload-cell {{ background: rgba(0,0,0,0.2); }}
        .theme-toggle {{
            position: fixed;
            top: 20px;
            right: 20px;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            cursor: pointer;
            color: var(--text-muted);
            transition: all 0.3s ease;
        }}
        [data-theme="dark"] .theme-toggle {{ background: rgba(22,22,42,0.6); }}
        .theme-toggle:hover {{ color: var(--accent); }}
        .logout-btn {{
            position: fixed;
            top: 20px;
            right: 70px;
            text-decoration: none;
            color: var(--danger);
            font-weight: 500;
            font-size: 14px;
            background: var(--danger-bg);
            padding: 10px 16px;
            border-radius: 10px;
            transition: opacity 0.2s;
        }}
        .logout-btn:hover {{ opacity: 0.8; }}
        .empty-state {{
            padding: 40px;
            text-align: center;
            color: var(--text-muted);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme">
        <svg id="moon-icon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg id="sun-icon" style="display:none;" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
    </button>
    <a href="/logout" class="logout-btn">Logout</a>

    <div class="container">
        <div class="header">
            <div class="header-left">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <h1>Dashboard</h1>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="title">Total Requests</span>
                <span class="value c-accent">{total}</span>
            </div>
            <div class="stat-card">
                <span class="title">Attacks Detected</span>
                <span class="value c-danger">{attack}</span>
            </div>
            <div class="stat-card">
                <span class="title">Normal Traffic</span>
                <span class="value c-success">{normal}</span>
            </div>
            <div class="stat-card">
                <span class="title">Attack Rate</span>
                <span class="value c-purple">{attack_rate}%</span>
            </div>
        </div>

        <div class="recent-section">
            <div class="recent-section-header">
                <h2>Recent Attacks</h2>
                <a href="/logs" class="view-all-link">View All Logs &rarr;</a>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Payload</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    {recent_html if recent_html else '<tr><td colspan="3" class="empty-state">No recent attacks detected. System is secure.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');

        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {{
            root.setAttribute('data-theme', 'dark');
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
        }}

        toggleBtn.addEventListener('click', () => {{
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {{
                root.setAttribute('data-theme', 'light');
                localStorage.setItem('theme', 'light');
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
            }} else {{
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                moonIcon.style.display = 'none';
                sunIcon.style.display = 'block';
            }}
        }});
    </script>
</body>
</html>
"""

    return html


if __name__ == "__main__":
    app.run(debug=True)
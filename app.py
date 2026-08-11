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
    <title>Login - Web IDS</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f8f9fa;
            --text-color: #212529;
            --card-bg: #ffffff;
            --border-color: #e9ecef;
            --accent-blue: #3b82f6;
            --btn-bg: #e2e8f0;
            --danger: #ef4444;
        }

        [data-theme="dark"] {
            --bg-color: #0f172a;
            --text-color: #f8fafc;
            --card-bg: #1e293b;
            --border-color: #334155;
            --btn-bg: #334155;
            --danger: #ef4444;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
            animation: fadeIn 0.4s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .login-card h1 {
            text-align: center;
            margin-top: 0;
            margin-bottom: 30px;
            font-weight: 600;
            color: var(--text-color);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 600;
            color: #64748b;
        }

        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-color);
            color: var(--text-color);
            font-size: 15px;
            font-family: 'Inter', sans-serif;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--accent-blue);
        }

        .login-btn {
            width: 100%;
            padding: 14px;
            border-radius: 8px;
            border: none;
            background: var(--accent-blue);
            color: white;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.1s;
            margin-top: 10px;
        }

        .login-btn:hover { opacity: 0.9; }
        .login-btn:active { transform: scale(0.98); }

        .error-msg {
            color: #b91c1c;
            background: #fee2e2;
            border: 1px solid #fca5a5;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
            font-weight: 600;
        }

        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 20px;
            background: var(--card-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <button class="theme-toggle" id="theme-toggle">
        <svg id="moon-icon" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg id="sun-icon" style="display:none;" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
        <span id="theme-text">Dark Mode</span>
    </button>
    <div class="login-card">
        <h1>🛡️ Web IDS Login</h1>
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
            <button type="submit" class="login-btn">เข้าสู่ระบบ</button>
        </form>
    </div>
    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const themeText = document.getElementById('theme-text');
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');

        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {
            root.setAttribute('data-theme', 'dark');
            themeText.textContent = 'Light Mode';
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
        }

        toggleBtn.addEventListener('click', () => {
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {
                root.setAttribute('data-theme', 'light');
                localStorage.setItem('theme', 'light');
                themeText.textContent = 'Dark Mode';
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
            } else {
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                themeText.textContent = 'Light Mode';
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Logs - Web IDS</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #f8f9fa;
            --text-color: #212529;
            --card-bg: #ffffff;
            --border-color: #e9ecef;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --btn-bg: #e2e8f0;
            --btn-text: #1e293b;
            --badge-bg-red: #fee2e2;
            --badge-text-red: #b91c1c;
            --badge-bg-green: #d1fae5;
            --badge-text-green: #047857;
        }}

        [data-theme="dark"] {{
            --bg-color: #0f172a;
            --text-color: #f8fafc;
            --card-bg: #1e293b;
            --border-color: #334155;
            --btn-bg: #334155;
            --btn-text: #f8fafc;
            --badge-bg-red: #7f1d1d;
            --badge-text-red: #fca5a5;
            --badge-bg-green: #064e3b;
            --badge-text-green: #6ee7b7;
        }}

        * {{
            box-sizing: border-box;
            transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .header {{
            width: 100%;
            max-width: 1200px;
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
            color: var(--text-color);
            text-decoration: none;
            background: var(--btn-bg);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
        }}
        
        .back-btn:hover {{
            opacity: 0.9;
        }}

        .header h1 {{
            margin: 0;
            font-weight: 600;
            font-size: 24px;
            letter-spacing: -0.5px;
        }}

        .theme-toggle {{
            background: var(--btn-bg);
            color: var(--btn-text);
            border: none;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            outline: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .theme-toggle:hover {{
            opacity: 0.9;
        }}

        .search-container {{
            width: 100%;
            max-width: 1200px;
            margin-bottom: 20px;
        }}
        
        .search-form {{
            display: flex;
            gap: 10px;
        }}
        
        .search-input {{
            flex: 1;
            padding: 10px 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--card-bg);
            color: var(--text-color);
            font-family: inherit;
            font-size: 14px;
        }}
        
        .search-input:focus {{
            outline: none;
            border-color: var(--accent-blue);
        }}
        
        .search-btn {{
            padding: 10px 20px;
            border-radius: 8px;
            border: none;
            background: var(--accent-blue);
            color: white;
            cursor: pointer;
            font-weight: 600;
        }}
        
        .clear-btn {{
            padding: 10px 20px;
            border-radius: 8px;
            text-decoration: none;
            background: var(--btn-bg);
            color: var(--btn-text);
            display: flex;
            align-items: center;
            font-weight: 600;
            font-size: 14px;
        }}

        .table-container {{
            width: 100%;
            max-width: 1200px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th, td {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            font-size: 13px;
            font-weight: 600;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background-color: rgba(0,0,0,0.02);
        }}

        [data-theme="dark"] th {{
            color: #94a3b8;
            background-color: rgba(255,255,255,0.02);
        }}

        td {{
            font-size: 14px;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover td {{
            background-color: rgba(0,0,0,0.01);
        }}

        [data-theme="dark"] tr:hover td {{
            background-color: rgba(255,255,255,0.01);
        }}

        .payload-cell {{
            font-family: monospace;
            background: var(--bg-color);
            padding: 6px 10px;
            border-radius: 6px;
            word-break: break-all;
            display: inline-block;
            max-width: 400px;
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}

        .badge-attack {{
            background-color: var(--badge-bg-red);
            color: var(--badge-text-red);
        }}

        .badge-normal {{
            background-color: var(--badge-bg-green);
            color: var(--badge-text-green);
        }}
        
        .pagination {{
            width: 100%;
            max-width: 1200px;
            margin-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
            color: #64748b;
        }}
        
        [data-theme="dark"] .pagination {{
            color: #94a3b8;
        }}

    </style>
</head>
<body>

    <div class="header">
        <div class="header-left">
            <a href="/dashboard" class="back-btn">&larr; Dashboard</a>
            <h1>Request Logs</h1>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
            <a href="/logout" style="color: var(--accent-red); font-weight: 600; text-decoration: none; padding: 10px 16px; border-radius: 8px; background: rgba(239, 68, 68, 0.1);">Logout</a>
            <button class="theme-toggle" id="theme-toggle">
                <svg id="moon-icon" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                <svg id="sun-icon" style="display:none;" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                <span id="theme-text">Dark Mode</span>
            </button>
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
        <div>
            Showing page {page} of {total_pages} (Total: {total_records} records)
        </div>
        <div style="display: flex; gap: 10px;">
            {prev_btn}
            {next_btn}
        </div>
    </div>

    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');
        const themeText = document.getElementById('theme-text');

        // Check local storage so theme matches dashboard
        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {{
            root.setAttribute('data-theme', 'dark');
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
            themeText.textContent = 'Light Mode';
        }}

        toggleBtn.addEventListener('click', () => {{
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {{
                root.removeAttribute('data-theme');
                localStorage.setItem('theme', 'light');
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
                themeText.textContent = 'Dark Mode';
            }} else {{
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                moonIcon.style.display = 'none';
                sunIcon.style.display = 'block';
                themeText.textContent = 'Light Mode';
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
<html lang="en">
<head>
    <meta http-equiv="refresh" content="1">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web IDS Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #f8f9fa;
            --text-color: #212529;
            --card-bg: #ffffff;
            --border-color: #e9ecef;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-purple: #8b5cf6;
            --btn-bg: #e2e8f0;
            --btn-text: #1e293b;
        }}

        [data-theme="dark"] {{
            --bg-color: #0f172a;
            --text-color: #f8fafc;
            --card-bg: #1e293b;
            --border-color: #334155;
            --btn-bg: #334155;
            --btn-text: #f8fafc;
        }}

        * {{
            box-sizing: border-box;
            transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .header {{
            width: 100%;
            max-width: 1000px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
        }}

        .header h1 {{
            margin: 0;
            font-weight: 600;
            font-size: 24px;
            letter-spacing: -0.5px;
        }}

        .theme-toggle {{
            background: var(--btn-bg);
            color: var(--btn-text);
            border: none;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            outline: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .theme-toggle:hover {{
            opacity: 0.9;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            width: 100%;
            max-width: 1000px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            display: flex;
            flex-direction: column;
        }}

        .stat-card .title {{
            font-size: 14px;
            font-weight: 600;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}

        [data-theme="dark"] .stat-card .title {{
            color: #94a3b8;
        }}

        .stat-card .value {{
            font-size: 32px;
            font-weight: 600;
        }}

        .c-blue {{ color: var(--accent-blue); }}
        .c-red {{ color: var(--accent-red); }}
        .c-green {{ color: var(--accent-green); }}
        .c-purple {{ color: var(--accent-purple); }}

        .recent-section {{
            width: 100%;
            max-width: 1000px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}

        .recent-section h2 {{
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 18px;
            font-weight: 600;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th, td {{
            padding: 16px 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            font-size: 14px;
            font-weight: 600;
            color: #64748b;
        }}

        [data-theme="dark"] th {{
            color: #94a3b8;
        }}

        td {{
            font-size: 14px;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        .payload-cell {{
            font-family: monospace;
            background: var(--bg-color);
            padding: 4px 8px;
            border-radius: 6px;
            word-break: break-all;
        }}
        
        .nav-links {{
            margin-top: 30px;
        }}
        
        .nav-links a {{
            color: var(--accent-blue);
            text-decoration: none;
            font-weight: 600;
        }}
        
        .nav-links a:hover {{
            text-decoration: underline;
        }}

    </style>
</head>
<body>

    <div class="header">
        <h1>Web IDS Dashboard</h1>
        <div style="display: flex; gap: 10px; align-items: center;">
            <a href="/logout" style="color: var(--accent-red); font-weight: 600; text-decoration: none; padding: 10px 16px; border-radius: 8px; background: rgba(239, 68, 68, 0.1);">Logout</a>
            <button class="theme-toggle" id="theme-toggle">
                <svg id="moon-icon" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                <svg id="sun-icon" style="display:none;" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                <span id="theme-text">Dark Mode</span>
            </button>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <span class="title">Total Requests</span>
            <span class="value c-blue">{total}</span>
        </div>
        <div class="stat-card">
            <span class="title">Attacks</span>
            <span class="value c-red">{attack}</span>
        </div>
        <div class="stat-card">
            <span class="title">Normal</span>
            <span class="value c-green">{normal}</span>
        </div>
        <div class="stat-card">
            <span class="title">Attack Rate</span>
            <span class="value c-purple">{attack_rate}%</span>
        </div>
    </div>

    <div class="recent-section">
        <h2>Recent Attacks</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Payload</th>
                    <th>IP</th>
                </tr>
            </thead>
            <tbody>
                {recent_html}
            </tbody>
        </table>
    </div>

    <div class="nav-links">
        <a href="/logs">View All Logs &rarr;</a>
    </div>

    <script>
        const toggleBtn = document.getElementById('theme-toggle');
        const root = document.documentElement;
        const moonIcon = document.getElementById('moon-icon');
        const sunIcon = document.getElementById('sun-icon');
        const themeText = document.getElementById('theme-text');

        const currentTheme = localStorage.getItem('theme') || 'light';
        if (currentTheme === 'dark') {{
            root.setAttribute('data-theme', 'dark');
            moonIcon.style.display = 'none';
            sunIcon.style.display = 'block';
            themeText.textContent = 'Light Mode';
        }}

        toggleBtn.addEventListener('click', () => {{
            const isDark = root.getAttribute('data-theme') === 'dark';
            if (isDark) {{
                root.removeAttribute('data-theme');
                localStorage.setItem('theme', 'light');
                moonIcon.style.display = 'block';
                sunIcon.style.display = 'none';
                themeText.textContent = 'Dark Mode';
            }} else {{
                root.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                moonIcon.style.display = 'none';
                sunIcon.style.display = 'block';
                themeText.textContent = 'Light Mode';
            }}
        }});
    </script>
</body>
</html>
"""

    return html


if __name__ == "__main__":
    app.run(debug=True)
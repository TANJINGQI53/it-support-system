import os
import sqlite3
from datetime import datetime
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "it-support-super-secret-key-2026")
DATABASE_URL = os.environ.get("DATABASE_URL")
DB_FILE = "it_support.db"

MAX_ADMINS = 3
MAX_USERS = 100

def get_db():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    if DATABASE_URL:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                plain_password TEXT DEFAULT '',
                role TEXT DEFAULT 'user'
            )
        ''')
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS plain_password TEXT DEFAULT ''")
        c.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                id SERIAL PRIMARY KEY,
                owner_username TEXT NOT NULL,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                admin_reply TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        ''')
        c.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS admin_reply TEXT DEFAULT ''")
    else:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                plain_password TEXT DEFAULT '',
                role TEXT DEFAULT 'user'
            )
        ''')
        c.execute("PRAGMA table_info(users)")
        u_cols = [row[1] for row in c.fetchall()]
        if "plain_password" not in u_cols:
            c.execute("ALTER TABLE users ADD COLUMN plain_password TEXT DEFAULT ''")

        c.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_username TEXT NOT NULL,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                admin_reply TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        ''')
        c.execute("PRAGMA table_info(tickets)")
        t_cols = [row[1] for row in c.fetchall()]
        if "admin_reply" not in t_cols:
            c.execute("ALTER TABLE tickets ADD COLUMN admin_reply TEXT DEFAULT ''")

    admin_user = os.environ.get("ADMIN_USER", "admin")
    admin_pass = os.environ.get("ADMIN_PASS", "admin123")
    admin_hash = generate_password_hash(admin_pass)

    if DATABASE_URL:
        c.execute("SELECT id FROM users WHERE username = %s", (admin_user,))
        if not c.fetchone():
            c.execute(
                "INSERT INTO users (username, password_hash, plain_password, role) VALUES (%s, %s, %s, 'admin')",
                (admin_user, admin_hash, admin_pass)
            )
        else:
            c.execute(
                "UPDATE users SET plain_password = %s WHERE username = %s AND (plain_password IS NULL OR plain_password = '')",
                (admin_pass, admin_user)
            )
    else:
        c.execute("SELECT id FROM users WHERE username = ?", (admin_user,))
        if not c.fetchone():
            c.execute(
                "INSERT INTO users (username, password_hash, plain_password, role) VALUES (?, ?, ?, 'admin')",
                (admin_user, admin_hash, admin_pass)
            )
        else:
            c.execute(
                "UPDATE users SET plain_password = ? WHERE username = ? AND (plain_password IS NULL OR plain_password = '')",
                (admin_pass, admin_user)
            )

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({
            'logged_in': True,
            'username': session['username'],
            'role': session.get('role', 'user')
        })
    return jsonify({'logged_in': False})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'user').strip().lower()

    if role not in ('user', 'admin'):
        role = 'user'

    if len(username) < 3 or len(password) < 4:
        return jsonify({'error': 'Username must be at least 3 chars and password at least 4 chars.'}), 400

    conn = get_db()
    c = conn.cursor()

    if DATABASE_URL:
        c.execute("SELECT COUNT(*) FROM users WHERE role = %s", (role,))
    else:
        c.execute("SELECT COUNT(*) FROM users WHERE role = ?", (role,))
    current_count = c.fetchone()[0]

    limit = MAX_ADMINS if role == 'admin' else MAX_USERS
    if current_count >= limit:
        conn.close()
        role_label = "Admin" if role == 'admin' else "User"
        return jsonify({'error': f'{role_label} account limit reached.'}), 403

    pw_hash = generate_password_hash(password)
    try:
        if DATABASE_URL:
            c.execute(
                "INSERT INTO users (username, password_hash, plain_password, role) VALUES (%s, %s, %s, %s)",
                (username, pw_hash, password, role)
            )
        else:
            c.execute(
                "INSERT INTO users (username, password_hash, plain_password, role) VALUES (?, ?, ?, ?)",
                (username, pw_hash, password, role)
            )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({'error': 'Username already exists. Please choose another.'}), 409

    conn.close()
    return jsonify({'message': f'{role.upper()} account registered successfully! Please log in.'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    conn = get_db()
    if DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE username = %s", (username,))
    else:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))

    user = c.fetchone()

    if user and check_password_hash(user['password_hash'], password):
        if not user.get('plain_password'):
            c2 = conn.cursor()
            if DATABASE_URL:
                c2.execute("UPDATE users SET plain_password = %s WHERE id = %s", (password, user['id']))
            else:
                c2.execute("UPDATE users SET plain_password = ? WHERE id = ?", (password, user['id']))
            conn.commit()
        conn.close()
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({
            'message': 'Login successful',
            'username': user['username'],
            'role': user['role']
        })

    conn.close()
    return jsonify({'error': 'Invalid username or password.'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required.'}), 403

    conn = get_db()
    if DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT id, username, plain_password, role FROM users ORDER BY role ASC, id ASC")
    else:
        c = conn.cursor()
        c.execute("SELECT id, username, plain_password, role FROM users ORDER BY role ASC, id ASC")

    rows = c.fetchall()
    conn.close()
    return jsonify({
        'max_admins': MAX_ADMINS,
        'max_users': MAX_USERS,
        'current_username': session.get('username'),
        'users': [dict(row) for row in rows]
    })

@app.route('/api/admin/users/<int:user_id>/password', methods=['PUT'])
def reset_user_password(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required.'}), 403

    data = request.get_json()
    new_password = data.get('password', '').strip()
    if len(new_password) < 4:
        return jsonify({'error': 'New password must be at least 4 characters.'}), 400

    pw_hash = generate_password_hash(new_password)
    conn = get_db()
    c = conn.cursor()
    if DATABASE_URL:
        c.execute(
            "UPDATE users SET password_hash = %s, plain_password = %s WHERE id = %s",
            (pw_hash, new_password, user_id)
        )
    else:
        c.execute(
            "UPDATE users SET password_hash = ?, plain_password = ? WHERE id = ?",
            (pw_hash, new_password, user_id)
        )
    conn.commit()
    conn.close()
    return jsonify({'message': 'Password updated successfully.'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required.'}), 403

    conn = get_db()
    c = conn.cursor()
    if DATABASE_URL:
        c.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    else:
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Account not found.'}), 404
    if row[0] == session.get('username'):
        conn.close()
        return jsonify({'error': 'You cannot delete your own currently logged-in account.'}), 400

    if DATABASE_URL:
        c.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Account deleted successfully.'})

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    username = session['username']
    role = session.get('role', 'user')

    conn = get_db()
    if DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
        if role == 'admin':
            c.execute('SELECT * FROM tickets ORDER BY id DESC')
        else:
            c.execute('SELECT * FROM tickets WHERE owner_username = %s ORDER BY id DESC', (username,))
    else:
        c = conn.cursor()
        if role == 'admin':
            c.execute('SELECT * FROM tickets ORDER BY id DESC')
        else:
            c.execute('SELECT * FROM tickets WHERE owner_username = ? ORDER BY id DESC', (username,))

    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    if 'username' not in session:
        return jsonify({'error': 'Please log in first.'}), 401

    data = request.get_json()
    owner_username = session['username']
    name = data.get('name', '').strip()
    department = data.get('department', 'General').strip()
    category = data.get('category', 'Other').strip()
    priority = data.get('priority', 'Medium').strip()
    description = data.get('description', '').strip()

    if not name or not description:
        return jsonify({'error': 'Name and description are required.'}), 400

    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    c = conn.cursor()
    if DATABASE_URL:
        c.execute('''
            INSERT INTO tickets (owner_username, name, department, category, priority, description, status, admin_reply, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'Open', '', %s)
        ''', (owner_username, name, department, category, priority, description, created_at))
    else:
        c.execute('''
            INSERT INTO tickets (owner_username, name, department, category, priority, description, status, admin_reply, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', '', ?)
        ''', (owner_username, name, department, category, priority, description, created_at))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Ticket created successfully'}), 201

@app.route('/api/tickets/<int:ticket_id>', methods=['PUT'])
def update_ticket(ticket_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required.'}), 403

    data = request.get_json()
    new_status = data.get('status', 'Resolved')
    admin_reply = data.get('admin_reply')

    conn = get_db()
    c = conn.cursor()
    if admin_reply is not None:
        if DATABASE_URL:
            c.execute('UPDATE tickets SET status = %s, admin_reply = %s WHERE id = %s', (new_status, admin_reply.strip(), ticket_id))
        else:
            c.execute('UPDATE tickets SET status = ?, admin_reply = ? WHERE id = ?', (new_status, admin_reply.strip(), ticket_id))
    else:
        if DATABASE_URL:
            c.execute('UPDATE tickets SET status = %s WHERE id = %s', (new_status, ticket_id))
        else:
            c.execute('UPDATE tickets SET status = ? WHERE id = ?', (new_status, ticket_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Ticket updated'})

def get_instant_kb_recommendation(category, description):
    kb = {
        "Network / Wi-Fi": (
            "1. Quick Diagnosis\n"
            "Likely DNS cache conflict, DHCP IP lease stall, or local Wi-Fi adapter driver glitch.\n\n"
            "2. Step-by-Step Resolution Checklist\n"
            "• Toggle Wi-Fi / Airplane mode OFF for 10 seconds, then reconnect.\n"
            "• Open Command Prompt / Terminal and run: ipconfig /flushdns (Windows) or sudo dscacheutil -flushcache (macOS).\n"
            "• Forget the Wi-Fi network and re-enter credentials, or test with an Ethernet cable.\n"
            "• Restart your router / access point if multiple devices are affected.\n\n"
            "3. Escalation Criteria\n"
            "Submit a ticket if only your workstation fails to obtain an IP address (port/VLAN assignment check required)."
        ),
        "Hardware": (
            "1. Quick Diagnosis\n"
            "Peripheral connection drop, power state lockup, or thermal/port hardware fault.\n\n"
            "2. Step-by-Step Resolution Checklist\n"
            "• Unplug all external USB hubs, monitors, and power cables; hold the power button for 15 seconds (hard power drain).\n"
            "• Test the device on a different wall outlet or port to rule out cable/dock failure.\n"
            "• Check Device Manager / System Information for warning icons on the affected component.\n\n"
            "3. Escalation Criteria\n"
            "Submit a ticket immediately if there is physical damage, overheating, battery swelling, or no power indicator."
        ),
        "Software": (
            "1. Quick Diagnosis\n"
            "Application cache corruption, hung background process, or pending OS/app version mismatch.\n\n"
            "2. Step-by-Step Resolution Checklist\n"
            "• Open Task Manager (Ctrl+Shift+Esc) / Activity Monitor and force-quit all instances of the frozen app.\n"
            "• Restart the computer to clear locked temporary files and memory leaks.\n"
            "• Check for pending app or OS updates and clear the application's local cache folder.\n\n"
            "3. Escalation Criteria\n"
            "Submit a ticket if reinstallation, license activation, or local administrator elevation is required."
        ),
        "Account / Password": (
            "1. Quick Diagnosis\n"
            "Credential cache expiration, account lockout after failed attempts, or MFA token sync drift.\n\n"
            "2. Step-by-Step Resolution Checklist\n"
            "• Verify Caps Lock is off and test signing in via an Incognito/Private browser window.\n"
            "• Wait 15 minutes if temporary brute-force lockout was triggered.\n"
            "• Clear saved passwords in Windows Credential Manager / macOS Keychain.\n\n"
            "3. Escalation Criteria\n"
            "Submit a ticket with your username and department so an IT Admin can reset your password or unlock your account."
        ),
        "Printer": (
            "1. Quick Diagnosis\n"
            "Stalled print spooler queue, offline printer status, or paper/toner sensor fault.\n\n"
            "2. Step-by-Step Resolution Checklist\n"
            "• Check the printer LCD screen for paper jam, low toner, or offline warnings.\n"
            "• Cancel all stuck documents in 'Printers & Scanners' -> 'Open print queue'.\n"
            "• Restart the printer and verify both PC and printer are on the same office subnet.\n\n"
            "3. Escalation Criteria\n"
            "Submit a ticket if the print spooler service needs restarting or network printer IP remapping is needed."
        )
    }
    base = kb.get(category, kb["Software"])
    return f"[Auto-Matched IT Knowledge Base Solution]\nIssue Summary: {description}\n\n{base}"

@app.route('/api/recommend', methods=['POST'])
def ai_recommendation():
    if 'username' not in session:
        return jsonify({'recommendation': 'Please log in to get AI recommendations.'}), 401

    data = request.get_json()
    category = data.get('category', 'General').strip()
    priority = data.get('priority', 'Medium').strip()
    department = data.get('department', 'General').strip()
    description = data.get('description', '').strip()

    if not description:
        return jsonify({'recommendation': 'Please enter an issue description first.'}), 400

    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        return jsonify({
            'recommendation': get_instant_kb_recommendation(category, description),
            'source': 'kb'
        })

    model_name = os.environ.get("AI_MODEL", "gemini-3.8-flash")
    sys_prompt = (
        "You are an automated IT Troubleshooting Recommendation Engine. Given a user's issue category, priority, and description, "
        "provide a concise, structured self-service recommendation:\n"
        "1. Quick Diagnosis\n"
        "2. Step-by-Step Fix to Try Now (3-4 steps)\n"
        "3. When to Submit a Ticket"
    )
    user_prompt = (
        f"Department: {department}\n"
        f"Category: {category}\n"
        f"Priority: {priority}\n"
        f"Issue Description: {description}"
    )

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key
    }
    payload = {
        "systemInstruction": {"parts": [{"text": sys_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"temperature": 0.4}
    }

    try:
        res = requests.post(api_url, headers=headers, json=payload, timeout=6)
        if res.ok:
            rec_text = res.json()['candidates'][0]['content']['parts'][0]['text']
            return jsonify({'recommendation': rec_text, 'source': 'ai'})
    except Exception:
        pass

    return jsonify({
        'recommendation': get_instant_kb_recommendation(category, description),
        'source': 'kb'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

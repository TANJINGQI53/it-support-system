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
                role TEXT DEFAULT 'user'
            )
        ''')
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
                created_at TEXT NOT NULL
            )
        ''')
    else:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
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
                created_at TEXT NOT NULL
            )
        ''')

    admin_user = os.environ.get("ADMIN_USER", "admin")
    admin_pass = os.environ.get("ADMIN_PASS", "admin123")
    admin_hash = generate_password_hash(admin_pass)

    if DATABASE_URL:
        c.execute("SELECT id FROM users WHERE username = %s", (admin_user,))
        if not c.fetchone():
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                (admin_user, admin_hash)
            )
    else:
        c.execute("SELECT id FROM users WHERE username = ?", (admin_user,))
        if not c.fetchone():
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (admin_user, admin_hash)
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

    if len(username) < 3 or len(password) < 4:
        return jsonify({'error': 'Username must be at least 3 chars and password at least 4 chars.'}), 400

    pw_hash = generate_password_hash(password)
    conn = get_db()
    c = conn.cursor()
    try:
        if DATABASE_URL:
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'user')",
                (username, pw_hash)
            )
        else:
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                (username, pw_hash)
            )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({'error': 'Username already exists. Please choose another.'}), 409

    conn.close()
    return jsonify({'message': 'Registration successful! Please log in.'}), 201

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
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({
            'message': 'Login successful',
            'username': user['username'],
            'role': user['role']
        })

    return jsonify({'error': 'Invalid username or password.'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

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
            INSERT INTO tickets (owner_username, name, department, category, priority, description, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'Open', %s)
        ''', (owner_username, name, department, category, priority, description, created_at))
    else:
        c.execute('''
            INSERT INTO tickets (owner_username, name, department, category, priority, description, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)
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
    conn = get_db()
    c = conn.cursor()
    if DATABASE_URL:
        c.execute('UPDATE tickets SET status = %s WHERE id = %s', (new_status, ticket_id))
    else:
        c.execute('UPDATE tickets SET status = ? WHERE id = ?', (new_status, ticket_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Status updated'})

@app.route('/api/chat', methods=['POST'])
def ai_chat():
    if 'username' not in session:
        return jsonify({'reply': 'Please log in to use the AI Assistant.'}), 401

    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'reply': 'Please enter a question.'}), 400

    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        return jsonify({
            'reply': '⚠️ AI_API_KEY is not configured on the server yet. Please add it in Render Environment Variables, or submit a ticket directly.'
        }), 500

    api_url = os.environ.get("AI_API_URL", "https://api.deepseek.com/chat/completions")
    model_name = os.environ.get("AI_MODEL", "deepseek-chat")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": "You are a professional IT Support Assistant. Give clear, concise, step-by-step troubleshooting solutions for computer, network, printer, password, and software issues. If the issue requires hardware repair or admin privileges, advise the user to submit an IT support ticket on this page."
            },
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.6
    }

    try:
        res = requests.post(api_url, headers=headers, json=payload, timeout=20)
        res.raise_for_status()
        reply = res.json()['choices'][0]['message']['content']
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'reply': f'AI service is temporarily unavailable. Please submit a ticket instead. ({str(e)})'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

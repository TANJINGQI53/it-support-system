import os
import sqlite3
from datetime import datetime
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
DB_FILE = "it_support.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM tickets ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    data = request.get_json()
    name = data.get('name', '').strip()
    department = data.get('department', 'General').strip()
    category = data.get('category', 'Other').strip()
    priority = data.get('priority', 'Medium').strip()
    description = data.get('description', '').strip()

    if not name or not description:
        return jsonify({'error': 'Name and description are required'}), 400

    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO tickets (name, department, category, priority, description, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'Open', ?)
    ''', (name, department, category, priority, description, created_at))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Ticket created successfully'}), 201

@app.route('/api/tickets/<int:ticket_id>', methods=['PUT'])
def update_ticket(ticket_id):
    data = request.get_json()
    new_status = data.get('status', 'Resolved')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE tickets SET status = ? WHERE id = ?', (new_status, ticket_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Status updated'})

@app.route('/api/chat', methods=['POST'])
def ai_chat():
    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'reply': 'Please enter a question.'}), 400

    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        return jsonify({
            'reply': '⚠️ AI_API_KEY is not configured on the server yet. Please add it in Render Environment Variables, or submit a ticket directly.'
        }), 500

    # 支持自定义接口地址和模型，默认使用 DeepSeek（兼容 OpenAI 格式）
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
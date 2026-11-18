from flask import Flask, render_template, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# ==============================
# DATABASE CONNECTION & SETUP
# ==============================
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "it_support.db")

def get_db_connection():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    # 2. Tickets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        subject TEXT,
        description TEXT,
        category TEXT,
        priority TEXT,
        technician TEXT,
        ai_recommendation TEXT,
        status TEXT
    )
    """)

    # 自动补全旧数据库缺失的列
    cursor.execute("PRAGMA table_info(tickets)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    for col_name in ["username", "subject", "description", "category", "priority", "technician", "ai_recommendation", "status"]:
        if col_name not in existing_columns:
            cursor.execute(f"ALTER TABLE tickets ADD COLUMN {col_name} TEXT")

    # 初始化默认账号
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'Admin')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('user', 'user123', 'User')")

    conn.commit()
    conn.close()

init_db()


# ==============================
# AI PROBLEM ANALYSIS ENGINE
# ==============================
def analyze_user_problem(subject, description):
    text = (subject + " " + description).lower()

    if any(k in text for k in ["net", "wifi", "internet", "disconnect", "slow", "connection", "connect", "router"]):
        category = "Network"
        ai_rec = "【AI Troubleshooting Suggestion】\n1. Check if your wireless network is accidentally turned off.\n2. Try unplugging your Wi-Fi router or modem, wait 10 seconds, and plug it back in.\n3. If it still doesn't work, contact IT support to check your IP settings or network adapter."
    elif any(k in text for k in ["password", "login", "account", "locked", "sign in", "forgot", "log in"]):
        category = "Software"
        ai_rec = "【AI Troubleshooting Suggestion】\n1. Check if the Caps Lock key is accidentally turned on.\n2. If you forgot your password, contact the system administrator to reset it to a temporary default."
    elif any(k in text for k in ["printer", "power", "black screen", "monitor", "mouse", "keyboard", "screen", "hardware", "computer", "boot", "turn on"]):
        category = "Hardware"
        ai_rec = "【AI Troubleshooting Suggestion】\n1. Check if all power cables and connection cords are securely plugged in.\n2. If it's a printer, check if it's out of paper, has a paper jam, or needs ink.\n3. If the device completely fails to respond, submit a ticket for hardware replacement."
    elif any(k in text for k in ["software", "crash", "freeze", "frozen", "error", "app", "application", "stuck", "bluescreen"]):
        category = "Software"
        ai_rec = "【AI Troubleshooting Suggestion】\n1. Force close the application and try opening it again.\n2. Restart your computer to clear temporary software glitches.\n3. If errors persist, the software may need an update or reinstallation."
    else:
        category = "Other"
        ai_rec = "【AI Troubleshooting Suggestion】\nThank you for your feedback! Your request has been received, and our technicians will look into it soon."

    if any(k in text for k in ["urgent", "asap", "down", "broken", "critical", "emergency", "immediately"]):
        priority = "High"
    elif category == "Network":
        priority = "Medium"
    else:
        priority = "Low"

    return category, priority, ai_rec


# ==============================
# WEB ROUTES & API ENDPOINTS
# ==============================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db_connection()
    user = conn.execute("SELECT username, role FROM users WHERE username=? AND password=?", (username, password)).fetchone()
    conn.close()

    if user:
        return jsonify({"success": True, "username": user["username"], "role": user["role"]})
    return jsonify({"success": False, "message": "Invalid username or password. Please try again."})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Please enter username and password!"})

    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'User')", (username, password))
        conn.commit()
        return jsonify({"success": True, "message": "Registration successful! You can now log in."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists. Please choose another one."})
    finally:
        conn.close()


@app.route("/api/tickets", methods=["GET"])
def api_get_tickets():
    role = request.args.get("role")
    username = request.args.get("username")

    conn = get_db_connection()
    if role == "Admin":
        rows = conn.execute("SELECT * FROM tickets ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM tickets WHERE username=? ORDER BY id DESC", (username,)).fetchall()
    conn.close()

    tickets = [dict(row) for row in rows]
    return jsonify({"success": True, "tickets": tickets})


@app.route("/api/tickets", methods=["POST"])
def api_submit_ticket():
    data = request.json
    username = data.get("username", "").strip()
    subject = data.get("subject", "").strip()
    description = data.get("description", "").strip()

    if not subject or not description:
        return jsonify({"success": False, "message": "Please fill in both the summary and description fields!"})

    category, priority, ai_rec = analyze_user_problem(subject, description)

    conn = get_db_connection()
    conn.execute(
        """INSERT INTO tickets (username, subject, description, category, priority, technician, ai_recommendation, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (username, subject, description, category, priority, "Unassigned", ai_rec, "Pending")
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "category": category,
        "priority": priority,
        "ai_recommendation": ai_rec
    })


@app.route("/api/tickets/<int:ticket_id>/assign", methods=["PUT"])
def api_assign_tech(ticket_id):
    data = request.json
    technician = data.get("technician")

    conn = get_db_connection()
    conn.execute("UPDATE tickets SET technician=? WHERE id=?", (technician, ticket_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Ticket #{ticket_id} successfully assigned to {technician}."})


@app.route("/api/tickets/<int:ticket_id>/resolve", methods=["PUT"])
def api_resolve_ticket(ticket_id):
    conn = get_db_connection()
    conn.execute("UPDATE tickets SET status='Resolved' WHERE id=?", (ticket_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Ticket #{ticket_id} marked as Resolved."})


if __name__ == "__main__":
    # host="0.0.0.0" 允许同一局域网下的其他设备通过你的 IP 地址访问
    app.run(host="0.0.0.0", port=5000, debug=True)
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

    model_name = os.environ.get("AI_MODEL", "gemini-2.5-flash")
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "systemInstruction": {
            "parts": [{
                "text": "You are a professional IT Support Assistant. Give clear, concise, step-by-step troubleshooting solutions for computer, network, printer, password, and software issues. If the issue requires hardware repair or admin privileges, advise the user to submit an IT support ticket on this page."
            }]
        },
        "contents": [{
            "role": "user",
            "parts": [{"text": user_message}]
        }],
        "generationConfig": {
            "temperature": 0.6
        }
    }

    try:
        res = requests.post(api_url, headers=headers, json=payload, timeout=20)
        res.raise_for_status()
        reply = res.json()['candidates'][0]['content']['parts'][0]['text']
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'reply': f'AI service error: {str(e)}. Please submit a ticket instead.'}), 500

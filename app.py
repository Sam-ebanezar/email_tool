import csv
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import dns.resolver
import smtplib
import re

# Flask setup
app = Flask(__name__)
app.secret_key = 'supersecretkey123'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user storage
users = {}

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Email verification logic
def verify_email(email):
    # Simple regex for syntax check
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(regex, email):
        return "Invalid Syntax"

    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
    except:
        return "No MX Records"

    try:
        server = smtplib.SMTP()
        server.connect(mx_host)
        server.helo()
        server.mail('verify@example.com')
        code, message = server.rcpt(email)
        server.quit()
        
        if code == 250:
            return "Valid"
        else:
            return "Invalid"
    except Exception as e:
        return f"SMTP Error: {e}"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = str(len(users) + 1)
        password_hash = generate_password_hash(password)
        user = User(user_id, username, password_hash)
        users[user_id] = user
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users.values():
            if user.username == username and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    emails = []
    if request.method == 'POST' and 'email_file' in request.files:
        file = request.files['email_file']
        if file.filename.endswith('.csv'):
            csv_reader = csv.reader(file.stream.read().decode('utf-8').splitlines())
            for row in csv_reader:
                if row:  # if the row is not empty
                    email = row[0].strip()
                    status = verify_email(email)
                    emails.append((email, status))
    return render_template('dashboard.html', username=current_user.username, emails=emails)

if __name__ == '__main__':
    app.run(debug=True)

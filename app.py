
import sqlite3
from flask import Flask, render_template, request, session, redirect, flash, url_for, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DATABASE = 'database.db'

def init_db():
    """Initialize the database with the users table."""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            course TEXT NOT NULL,
            section TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
        ''')

def get_user_by_email(email):
    """Retrieve a user by email."""
    with sqlite3.connect(DATABASE) as conn:
        return conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

def get_user_by_id(user_id):
    """Retrieve a user by ID."""
    with sqlite3.connect(DATABASE) as conn:
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('dashboard') if 'user_id' in session else 'login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = {key: request.form[key].strip() for key in ['first_name', 'last_name', 'course', 'section', 'email']}
        password = request.form['password']

        for field, value in data.items():
            if not value:
                flash('Required!', field)
        if not password:
            flash('Required!', 'password')
        if ('@' not in data['email'] or '.' not in data['email']) and data['email'].strip():
            flash('Invalid email format!', 'email')

        if not get_flashed_messages(with_categories=True):
            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('''
                    INSERT INTO users (first_name, last_name, course, section, email, password)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''', (*data.values(), generate_password_hash(password)))
                flash('Registration successful!', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already exists!', 'email')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']

        if not email:
            flash('Required!', 'email')
        elif not password:
            flash('Required!', 'password')
        else:
            user = get_user_by_email(email)
            if user and check_password_hash(user[6], password):
                session.update({
                    'user_id': user[0],
                    'full_name': f"{user[1]} {user[2]}",
                    'course': user[3],
                    'section': user[4],
                    'email': user[5]
                })
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password!', 'email')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    return render_template('dashboard.html', user=user, show_nav_bar=True)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

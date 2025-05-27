
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'users.db'
ALLOWED_SECTIONS = {'2A', '2B', '2C'}
EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database using db.sql schema."""
    with app.app_context():
        db = get_db()
        try:
            with open('db.sql', 'r') as f:
                db.executescript(f.read())
            db.commit()
        except Exception as e:
            print(f"Error initializing database: {e}")
            db.rollback()
            raise

def valid_email(email):
    """Validate email format using regex."""
    return re.match(EMAIL_REGEX, email)

def valid_section(section):
    """Validate section is one of the allowed values."""
    return section in ALLOWED_SECTIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        course = request.form.get('course', '').strip()
        section = request.form.get('section', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not all([first_name, last_name, course, section, email, password]):
            flash('All fields are required.', 'danger')
        elif not valid_email(email):
            flash('Invalid email format.', 'danger')
        elif not valid_section(section):
            flash(f"Section must be one of {', '.join(ALLOWED_SECTIONS)}.", 'danger')
        else:
            db = get_db()
            try:
                user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if user:
                    flash('Email already registered.', 'danger')
                else:
                    password_hash = generate_password_hash(password)
                    db.execute(
                        'INSERT INTO users (first_name, last_name, course, section, email, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
                        (first_name, last_name, course, section, email, password_hash)
                    )
                    db.commit()
                    flash('Registration successful! Please log in.', 'success')
                    return redirect(url_for('login'))
            except sqlite3.Error as e:
                db.rollback()
                flash(f"Database error: {e}", 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            elif user is None:
                flash('Email not registered.', 'danger')
            else:
                flash('Incorrect password.', 'danger')
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    try:
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    except sqlite3.Error as e:
        flash(f"Database error: {e}", 'danger')
        user = None
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
from datetime import datetime
import os

app = Flask(__name__)

secret_key = os.urandom(24).hex()
app.secret_key = secret_key

# Create SQLite database and table if they don't exist
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        email_id TEXT UNIQUE,
        password TEXT,
        department TEXT,
        designation TEXT,
        location TEXT,
        created_at TIMESTAMP
    )
''')
conn.close()


@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    # Authenticate user based on username and password
    # You should hash and compare the password securely (e.g., using hashlib)
    username = request.form['username']
    password = request.form['password']

    # Check if the username and password match a record in the database

    # If authentication is successful, store user information in the session
    session['username'] = username

    return redirect(url_for('success'))

@app.route('/create_account')
def create_account_page():
    return render_template('create_account.html')


@app.route('/create_account', methods=['POST'])
def create_account():
    # Retrieve user data from the registration form
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email_id = request.form['email_id']
    password = request.form['password']
    department = request.form['department']
    designation = request.form['designation']
    location = request.form['location']

    # Hash the password before storing it in the database
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Get the current timestamp for created_at
    created_at = datetime.now()

    # Insert user data into the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (first_name, last_name, email_id, password, department, designation, location, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, email_id, password_hash, department, designation, location, created_at))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

@app.route('/success')
def success():
    # Check if the user is logged in (session has their username)
    if 'username' in session:
        return redirect('https://www.google.com')
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port = 5004)


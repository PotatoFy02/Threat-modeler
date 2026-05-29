import sqlite3
from datetime import datetime
from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

auth = Blueprint('auth', __name__)
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

def init_users_db():
    conn = sqlite3.connect('threats.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE,
            name TEXT,
            plan TEXT DEFAULT 'free',
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_or_create_user(google_id, email, name):
    conn = sqlite3.connect('threats.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
    user = cursor.fetchone()
    if not user:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO users (google_id, email, name, plan, created_at)
            VALUES (?, ?, ?, 'free', ?)
        """, (google_id, email, name, now))
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        user = cursor.fetchone()
    conn.close()
    return user

@auth.route('/login')
def login():
    redirect_uri = url_for('auth.callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth.route('/callback')
def callback():
    token = oauth.google.authorize_access_token()
    userinfo = token['userinfo']
    user = get_or_create_user(
        google_id=userinfo['sub'],
        email=userinfo['email'],
        name=userinfo.get('name', '')
    )
    session['user_id'] = user[0]
    session['user_name'] = user[3]
    session['user_email'] = user[2]
    return redirect('/')

@auth.route('/logout')
def logout():
    session.clear()
    return redirect('/')
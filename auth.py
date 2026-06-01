import psycopg2
from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os

auth = Blueprint('auth', __name__)
oauth = OAuth()

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_conn():
    return psycopg2.connect(DATABASE_URL)

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
    pass

def get_or_create_user(google_id, email, name):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
    user = cursor.fetchone()
    if not user:
        cursor.execute("""
            INSERT INTO users (google_id, email, name, plan)
            VALUES (%s, %s, %s, 'free') RETURNING *
        """, (google_id, email, name))
        user = cursor.fetchone()
        conn.commit()
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
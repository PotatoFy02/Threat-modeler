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
        server_metadata_url='https://accounts.google.co
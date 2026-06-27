import os
from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from database import get_conn, put_conn   # reuse pool, no duplicate connection logic

load_dotenv()

auth = Blueprint("auth", __name__)
oauth = OAuth()


def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name="google",
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def init_users_db():
    # Schema now lives in database.init_db(); kept for backwards-compat.
    pass


def get_or_create_user(google_id, email, name):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, name FROM users WHERE google_id = %s",
                (google_id,),
            )
            user = cur.fetchone()
            if not user:
                cur.execute("""
                    INSERT INTO users (google_id, email, name, plan)
                    VALUES (%s, %s, %s, 'free')
                    RETURNING id, email, name
                """, (google_id, email, name))
                user = cur.fetchone()
                conn.commit()
        return user  # (id, email, name) — fixed, named order
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)


@auth.route("/login")
def login():
    # Dynamic redirect — works locally AND in production
    redirect_uri = url_for("auth.callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth.route("/callback")
def callback():
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get("userinfo")
        if not userinfo or "sub" not in userinfo or "email" not in userinfo:
            return redirect("/?error=auth_failed")
    except Exception:
        return redirect("/?error=auth_failed")

    user = get_or_create_user(
        google_id=userinfo["sub"],
        email=userinfo["email"],
        name=userinfo.get("name", ""),
    )
    if not user:
        return redirect("/?error=auth_failed")

    session.clear()                 # prevent session fixation
    session["user_id"] = user[0]
    session["user_email"] = user[1]
    session["user_name"] = user[2]
    return redirect("/")


@auth.route("/logout")
def logout():
    session.clear()
    return redirect("/")

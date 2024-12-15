import os
from flask import Flask, render_template, request, make_response, redirect, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from db import get_connection, init_db
from user_service import get_user_by_username, validate_user_exists, validate_register_data, register_user, verify_password_and_totp
import sqlite3
import bleach

app = Flask(__name__)
load_dotenv()
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL')
app.secret_key = os.getenv('SECRET_KEY')
login_manager = LoginManager()
login_manager.init_app(app)


with app.app_context():
    if not os.path.exists(app.config['DATABASE_URL']):
        init_db()

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    row = get_user_by_username(username)
    try:
        id, username, email, password, publicKey, privateKey, totp = row
    except:
        return None
    user = User()
    user.id = username
    user.userId = id
    user.password = password
    user.email = email
    user.public_key = publicKey
    user.private_key = privateKey
    user.totp = totp
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        totp_code = request.form.get("totp_code").strip()
        if not password or not username:
            return render_template("index.html", error='Username and/or password not provided'), 401
        user = user_loader(username)  
        if user is None:
            return render_template("index.html", error='Wrong username and/or password provided'), 401

        if not verify_password_and_totp(user, password, totp_code):
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        login_user(user)
        return redirect('/home')

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        password_repeat = request.form.get("password_repeat").strip()
        email = request.form.get("email").strip()

        validation_result  = validate_register_data(username, email, password, password_repeat)
        if not validation_result["valid"]:
            return render_template("register.html", errors=validation_result['errors']), 401

        escaped_username = bleach.clean(username)
        escaped_email = bleach.clean(email)

        doesExist = validate_user_exists(escaped_username, escaped_email)
        if doesExist:
            return render_template("register.html", error='User with this username or email already exists'), 401
        
        totp_secret = register_user(escaped_username, escaped_email, password)
        user = user_loader(username)
        if not user:
            return render_template("register.html", error="Couldn't register user"), 401

        login_user(user)
        session['totp_secret'] = totp_secret
        return redirect('/home')

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/home")
@login_required
def home():
    if request.method == 'GET':
        totp_secret = session.pop('totp_secret', None)
        username = current_user.id
        return render_template("home.html", username = username, totp_secret=totp_secret)

if __name__ == "__main__":
    app.run()

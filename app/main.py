import os
from flask import Flask, render_template, request, make_response, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from db import get_connection, init_db, get_user
import sqlite3

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

    row = get_user(username)
    try:
        id, username, email, password = row
    except:
        return None
    user = User()
    user.id = username
    user.password = password
    user.email = email
    print(user)
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
        if not password or not username:
            return render_template("index.html", error='Username and/or password not provided'), 401
        user = user_loader(username)

        if user is None:
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        #if sha256_crypt.verify(password, user.password):
        login_user(user)
        return redirect('/home')
        #else:
        #    return "Wrong username or password", 401

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        print(username, password, email)
        user = user_loader(username)
        return redirect('/hello')

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/home")
@login_required
def home():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id
        print(current_user)
        return render_template("home.html", username = username)

if __name__ == "__main__":
    app.run()

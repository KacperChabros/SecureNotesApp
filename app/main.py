import os
from flask import Flask, render_template, request, make_response, redirect, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from db import init_db
import user_service
import note_service
from mappers import get_login_attempts_dict, get_notes_dict_list, get_note_dict
from helpers import delay_to_min_required_delay
import markdown
import secrets
import time
from datetime import timedelta
import random


app = Flask(__name__)
load_dotenv()
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = os.getenv('SECRET_KEY')
login_manager = LoginManager()
login_manager.login_view = 'login'
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

    row = user_service.get_user_by_username(username)
    try:
        id, username, password_hash, totp = row
    except:
        return None
    user = User()
    user.id = username
    user.userId = id
    user.password_hash = password_hash
    user.totp = totp
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})

@app.before_request
def validate_csrf_and_hp():
    if request.method in ["POST", "PUT", "DELETE"]:
        csrf_token = session.get('_csrf_token', None)
        form_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != form_token:
            return "<h1>You are forbidden to perform this action</h1>", 403
    
    honeypot = request.form.get('hp_field')
    if honeypot:
        return "<h1>You are forbidden to perform this action</h1>", 403

@app.before_request
def refresh_session():
    session.permanent = True

@app.after_request
def add_csp_header(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' https:; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

@login_manager.unauthorized_handler
def unauthorized():
    flash("Please, log in to access this website")
    return redirect("/")

@app.errorhandler(Exception)
def handle_exception(e):
    print(e)
    return render_template("error.html"), 500

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect('/home')
        return render_template("index.html")
    if request.method == "POST":
        start_time = time.time()
        min_duration = 0.7 + random.uniform(0, 0.4)
        is_success = False
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        username = request.form.get("username").strip()
        password = request.form.get("password")
        totp_code = request.form.get("totp_code").strip()

        validation_result = user_service.validate_login_data(username, password, totp_code)
        if not validation_result["valid"]:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("index.html", errors=validation_result['errors']), 401
        
        if user_service.is_locked_out(ip_address):
            delay_to_min_required_delay(min_duration, start_time)
            user_service.register_login_attempt(None, ip_address, is_success, user_agent)
            return render_template("index.html", error='You have been locked out due to too many failed login attempts. Try again in 20 minutes'), 401
        
        user = user_loader(username)  
        if user is None:
            user_service.register_login_attempt(None, ip_address, is_success, user_agent)
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("index.html", error='Wrong username and/or password provided'), 401

        start_time = time.time()
        if not user_service.verify_password_and_totp(user, password, totp_code):
            user_service.register_login_attempt(user.userId, ip_address, is_success, user_agent)
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        login_user(user)
        is_success = True
        user_service.register_login_attempt(user.userId, ip_address, is_success, user_agent)
        delay_to_min_required_delay(min_duration, start_time)
        return redirect('/home')

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect('/home')
        return render_template("register.html")
    if request.method == "POST":
        start_time = time.time()
        min_duration = 1.7 + random.uniform(0, 0.4)
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        username = request.form.get("username").strip()
        password = request.form.get("password")
        password_repeat = request.form.get("password_repeat")
        email = request.form.get("email").strip()

        validation_result = user_service.validate_register_data(username, email, password, password_repeat)
        if not validation_result["valid"]:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("register.html", errors=validation_result['errors']), 401

        user_service.register_registration_attempt(ip_address, user_agent)

        if user_service.is_locked_out_on_registration(ip_address):
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("register.html", error='You have been locked out due to too many failed registration attempts. Try again in 60 minutes'), 401

        doesExist = user_service.validate_user_exists(username, email)
        if doesExist:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("register.html", error='User with this username or email already exists'), 401
        
        totp_secret = user_service.register_user(username, email, password)
        user = user_loader(username)
        if not user:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("register.html", error="Couldn't register user"), 401

        login_user(user)

        user_service.register_login_attempt(user.userId, ip_address, True, user_agent)
        delay_to_min_required_delay(min_duration, start_time)
        return render_template('registered_user.html', totp_secret=totp_secret)

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/home")
@login_required
def home():
    if request.method == 'GET':
        username = note_service.clean_displayed_content(current_user.id)
        login_attempts = user_service.get_failed_logins_since_last_successful(current_user.userId)
        login_attempts_dict = get_login_attempts_dict(login_attempts)

        user_notes = note_service.get_notes_created_by_user(current_user.userId)
        user_notes_list = get_notes_dict_list(user_notes)
        shared_notes = note_service.get_notes_shared_with_user(current_user.userId)
        shared_notes_list = get_notes_dict_list(shared_notes)
        public_notes = note_service.get_public_notes()
        public_notes_list = get_notes_dict_list(public_notes)

        return render_template("home.html", username = username, login_attempts=login_attempts_dict, user_notes_list=user_notes_list, shared_notes_list=shared_notes_list, public_notes_list=public_notes_list)

@app.route("/rendered_note/<note_id>", methods=["GET", "POST"])
@login_required
def rendered_note(note_id):
    note = note_service.fetch_note_if_user_can_view_it(note_id, current_user.userId)   
    if not note:
        return render_template('forbidden.html'), 403

    note_dict = get_note_dict(note)
    if not note['isCiphered']:
        is_valid_note = note_service.verify_note_authorship(note['userId'], note['sign'], note['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = note_service.clean_displayed_content(markdown.markdown(note_dict['content']))
        return render_template("rendered_note.html", note_dict=note_dict)
    
    if request.method == "GET":
        return render_template("ciphered_note.html", note_id=note_id)
    
    if request.method == "POST":
        start_time = time.time()
        min_duration = 0.7 + random.uniform(0, 0.4)
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        note_password = request.form.get("note_password")
        validation_result = note_service.validate_ciphered_note_data(note_password)
        if not validation_result["valid"]:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("ciphered_note.html", note_id=note_id, error=validation_result['error']), 401
        
        if note_service.is_locked_out_on_note_decrypt(ip_address):
            note_service.register_note_decrypt_attempt(ip_address, user_agent, False, note_id)
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("ciphered_note.html", note_id=note_id, error='You have been locked out due to too many failed note decryption attempts. Try again in 15 minutes.'), 401

        decrypted_content = note_service.decrypt_note(note_password, note['notePasswordHash'], note['content'])
        if not decrypted_content:
            note_service.register_note_decrypt_attempt(ip_address, user_agent, False, note_id)
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("ciphered_note.html", note_id=note_id, error="Wrong credentials provided")
        
        note_dict['content'] = decrypted_content
        is_valid_note = note_service.verify_note_authorship(note['userId'], note['sign'], note_dict['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = note_service.clean_displayed_content(markdown.markdown(note_dict['content']))
        note_service.register_note_decrypt_attempt(ip_address, user_agent, True, note_id)
        delay_to_min_required_delay(min_duration, start_time)
        return render_template("rendered_note.html", note_dict=note_dict)    

    
@app.route("/add_note", methods=["POST"])
@login_required
def add_note():
    if request.method == "GET":
        return redirect("/home")
    if request.method == "POST":
        start_time = time.time()
        min_duration = 1.1 + random.uniform(0, 0.4)
        title = request.form.get("title").strip()
        content = request.form.get("content").strip()
        is_public = 1 if request.form.get("isPublic") == "on" else 0
        shared_to_username = request.form.get("sharedToUsername").strip()
        user_password = request.form.get("user_password")
        note_password = request.form.get("note_password")
        note_password_repeat = request.form.get("note_password_repeat")
        totp_code = request.form.get("totp_code").strip()

        validation_result = note_service.validate_note_data(title, content, user_password, shared_to_username, note_password, note_password_repeat, totp_code)
        if not validation_result["valid"]:
            for error_key, error_msg in validation_result["errors"].items():
                flash(f"{error_key}: {error_msg}", 'error')
            delay_to_min_required_delay(min_duration, start_time)
            return redirect("/home")  
        
        if not user_service.verify_password_and_totp(current_user, user_password, totp_code):
            delay_to_min_required_delay(min_duration, start_time)
            flash(f'Wrong credentials provided', "error")
            return redirect("/home")  
        
        result = note_service.sign_and_add_note(current_user.userId, title, content, shared_to_username, is_public, user_password, note_password)
        if not result:
            delay_to_min_required_delay(min_duration, start_time)
            flash(f'There was an error while adding the note', "error")
            return redirect("/home") 

        delay_to_min_required_delay(min_duration, start_time)
        flash("Note added successfully!", "success")
        return redirect("/home")  

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    if request.method == "POST":
        start_time = time.time()
        min_duration = 0.7 + random.uniform(0, 0.4)
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        validation_result = user_service.validate_forgot_password_data(username, email)
        if not validation_result["valid"]:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("forgot_password.html", errors=validation_result['errors']), 401
        
        user_service.register_pass_reset_attempt(ip_address=ip_address, is_generating_token=True, user_agent=user_agent)
        if user_service.is_locked_out_on_pass_reset(ip_address, is_generating_token=True):
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("forgot_password.html", error='You have been locked out due to too many failed password reset attempts. Try again in an hour'), 401

        user = user_service.get_user_by_username_and_email(username, email)
        if not user:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")
        user_service.generate_reset_password_token(user['id'], email)
        delay_to_min_required_delay(min_duration, start_time)
        return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):  
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    
    if request.method == "POST":
        start_time = time.time()
        min_duration = 2.2 + random.uniform(0, 0.4)
        password = request.form.get("password")
        password_repeat = request.form.get("password_repeat")
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')

        pass_val_error = user_service.validate_password(password, password_repeat)
        if pass_val_error:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("reset_password.html", error=pass_val_error, token=token)
        
        user_service.register_pass_reset_attempt(ip_address=ip_address, is_generating_token=False, user_agent=user_agent)
        if user_service.is_locked_out_on_pass_reset(ip_address, is_generating_token=False):
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("reset_password.html", error='You have been locked out due to too many failed password reset attempts. Try again in an hour', token=token), 401

        validation_result = user_service.validate_token(token)
        if not validation_result['valid']:
            delay_to_min_required_delay(min_duration, start_time)
            return render_template("reset_password.html", error=validation_result['error'], token=token)
        totp_secret = user_service.change_password(validation_result['userId'], password)
        delay_to_min_required_delay(min_duration, start_time)
        return render_template("reset_password.html", success=True, totp_secret=totp_secret, token=token)

if __name__ == "__main__":
    app.run()

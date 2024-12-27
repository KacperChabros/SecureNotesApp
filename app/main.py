import os
from flask import Flask, render_template, request, make_response, redirect, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from db import get_connection, init_db
import user_service
import note_service
from mappers import get_login_attempts_dict, get_notes_dict_list, get_note_dict
import markdown
import secrets
import time

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

    row = user_service.get_user_by_username(username)
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

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})

@app.before_request
def validate_csrf():
    if request.method in ["POST", "PUT", "DELETE"]:
        csrf_token = session.get('_csrf_token', None)
        form_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != form_token:
            return "<h1>You are forbidden to perform this action CSRF</h1>", 403
    
    honeypot = request.form.get('hp_field')
    if honeypot:
        return "<h1>You are forbidden to perform this action BOT</h1>", 403

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

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        time.sleep(0.4)
        is_success = False
        ip_address = request.remote_addr
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        totp_code = request.form.get("totp_code").strip()

        validation_result = user_service.validate_login_data(username, password, totp_code)
        if not validation_result["valid"]:
            return render_template("index.html", errors=validation_result['errors']), 401
        
        user = user_loader(username)  
        if user is None:
            time.sleep(0.230)
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        if user_service.is_locked_out(user.userId):
            time.sleep(0.230)
            return render_template("index.html", error='Your account has been locked out due to too many failed login attempts. Try again in 15 minutes'), 401

        start_time = time.time()
        if not user_service.verify_password_and_totp(user, password, totp_code):
            elapsed_time = time.time() - start_time
            user_service.register_login_attempt(user.userId, ip_address, is_success)
            if elapsed_time < 0.3:
                time.sleep(0.3 - elapsed_time)
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        login_user(user)
        is_success = True
        user_service.register_login_attempt(user.userId, ip_address, is_success)
        return redirect('/home')

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        time.sleep(0.3)
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        password_repeat = request.form.get("password_repeat").strip()
        email = request.form.get("email").strip()

        validation_result = user_service.validate_register_data(username, email, password, password_repeat)
        if not validation_result["valid"]:
            return render_template("register.html", errors=validation_result['errors']), 401


        doesExist = user_service.validate_user_exists(username, email)
        if doesExist:
            time.sleep(0.540)
            return render_template("register.html", error='User with this username or email already exists'), 401
        
        totp_secret = user_service.register_user(username, email, password)
        user = user_loader(username)
        if not user:
            return render_template("register.html", error="Couldn't register user"), 401

        login_user(user)
        ip_address = request.remote_addr
        user_service.register_login_attempt(user.userId, ip_address, True)
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
        username = note_service.clean_displayed_content(current_user.id)
        login_attempts = user_service.get_failed_logins_since_last_successful(current_user.userId)
        login_attempts_dict = get_login_attempts_dict(login_attempts)

        user_notes = note_service.get_notes_created_by_user(current_user.userId)
        user_notes_list = get_notes_dict_list(user_notes)
        shared_notes = note_service.get_notes_shared_with_user(current_user.userId)
        shared_notes_list = get_notes_dict_list(shared_notes)
        public_notes = note_service.get_public_notes()
        public_notes_list = get_notes_dict_list(public_notes)

        return render_template("home.html", username = username, totp_secret=totp_secret, login_attempts=login_attempts_dict, user_notes_list=user_notes_list, shared_notes_list=shared_notes_list, public_notes_list=public_notes_list)

@app.route("/rendered_note/<note_id>", methods=["GET", "POST"])
@login_required
def rendered_note(note_id):
    note = note_service.fetch_note_if_user_can_view_it(note_id, current_user.userId)
    note_dict = get_note_dict(note)
    if not note:
        return "<h1>You are forbidden to perform this action</h1>", 403
    if not note['isCiphered']:
        is_valid_note = note_service.verify_note_authorship(note['userId'], note['sign'], note['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = note_service.clean_displayed_content(markdown.markdown(note_dict['content']))
        return render_template("rendered_note.html", note_dict=note_dict)
    
    if request.method == "GET":
        return render_template("ciphered_note.html", note_id=note_id)
    
    if request.method == "POST":
        time.sleep(0.4)
        note_password = request.form.get("note_password")
        start_time = time.time()
        decrypted_content = note_service.decrypt_note(note_password, note['notePasswordHash'], note['content'])
        elapsed_time = time.time() - start_time
        if elapsed_time < 0.3:
                time.sleep(0.3 - elapsed_time)
        if not decrypted_content:
            return render_template("ciphered_note.html", note_id=note_id, error="Wrong credentials provided")
        note_dict['content'] = decrypted_content
        is_valid_note = note_service.verify_note_authorship(note['userId'], note['sign'], note_dict['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = note_service.clean_displayed_content(markdown.markdown(note_dict['content']))
        return render_template("rendered_note.html", note_dict=note_dict)    

    
@app.route("/add_note", methods=["POST"])
@login_required
def add_note():
    if request.method == "GET":
        return redirect("/home")
    if request.method == "POST":
        time.sleep(0.4)
        title = request.form.get("title").strip()
        content = request.form.get("content").strip()
        is_public = 1 if request.form.get("isPublic") == "on" else 0
        shared_to_username = request.form.get("sharedToUsername").strip()
        user_password = request.form.get("user_password").strip()
        note_password = request.form.get("note_password").strip()
        note_password_repeat = request.form.get("note_password_repeat").strip()
        totp_code = request.form.get("totp_code").strip()

        validation_result = note_service.validate_note_data(title, content, shared_to_username, note_password, note_password_repeat, totp_code)
        if not validation_result["valid"]:
            for error_key, error_msg in validation_result["errors"].items():
                flash(f"{error_key}: {error_msg}", 'error')
            return redirect("/home")  
        
        start_time = time.time()
        if not user_service.verify_password_and_totp(current_user, user_password, totp_code):
            elapsed_time = time.time() - start_time
            if elapsed_time < 0.3:
                time.sleep(0.3 - elapsed_time)
            time.sleep(0.25)
            flash(f'Wrong credentials provided', "error")
            return redirect("/home")  
        
        result = note_service.sign_and_add_note(current_user.userId, title, content, shared_to_username, is_public, user_password, note_password)
        if not result:
            flash(f'There was an error while adding the note', "error")
            return redirect("/home") 

        flash("Note added successfully!", "success")
        return redirect("/home")  

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    if request.method == "POST":
        time.sleep(0.5)
        username = request.form.get('username')
        email = request.form.get('email')
        validation_result = user_service.validate_forgot_password_data(username, email)
        if not validation_result["valid"]:
            return render_template("forgot_password.html", errors=validation_result['errors']), 401
        user = user_service.get_user_by_username_and_email(username, email)
        if not user:
            return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")
        user_service.generate_reset_password_token(user['id'], email)
        return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):  
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    if request.method == "POST":
        time.sleep(0.3)
        password = request.form.get("password").strip()
        password_repeat = request.form.get("password_repeat").strip()

        pass_val_error = user_service.validate_password(password, password_repeat)
        if pass_val_error:
            time.sleep(0.85)
            return render_template("reset_password.html", error=pass_val_error, token=token)
        validation_result = user_service.validate_token(token)
        if not validation_result['valid']:
            time.sleep(0.81)
            return render_template("reset_password.html", error=validation_result['error'], token=token)
        totp_secret = user_service.change_password(validation_result['userId'], password)
        return render_template("reset_password.html", success=True, totp_secret=totp_secret, token=token)
if __name__ == "__main__":
    app.run()

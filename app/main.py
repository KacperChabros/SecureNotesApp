import os
from flask import Flask, render_template, request, make_response, redirect, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from db import get_connection, init_db
from user_service import get_user_by_username, validate_user_exists, validate_register_data, register_user, verify_password_and_totp, register_login_attempt, get_failed_logins_since_last_successful, is_locked_out, validate_login_data, get_user_by_username_and_email, validate_forgot_password_data, generate_reset_password_token, validate_password, validate_token, change_password
from note_service import get_notes_created_by_user, get_notes_shared_with_user, get_public_notes, validate_note_data, sign_and_add_note, fetch_note_if_user_can_view_it, decrypt_note, verify_note_authorship, clean_displayed_content
from mappers import get_login_attempts_dict, get_notes_dict_list, get_note_dict
import markdown

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
        is_success = False
        ip_address = request.remote_addr
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        totp_code = request.form.get("totp_code").strip()

        validation_result  = validate_login_data(username, password, totp_code)
        if not validation_result["valid"]:
            return render_template("index.html", errors=validation_result['errors']), 401
        
        user = user_loader(username)  
        if user is None:
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        if is_locked_out(user.userId):
            return render_template("index.html", error='Your account has been locked out due to too many failed login attempts. Try again in 15 minutes'), 401

        if not verify_password_and_totp(user, password, totp_code):
            register_login_attempt(user.userId, ip_address, is_success)
            return render_template("index.html", error='Wrong username and/or password provided'), 401
        
        login_user(user)
        is_success = True
        register_login_attempt(user.userId, ip_address, is_success)
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

        # escaped_username = bleach.clean(username)
        # escaped_email = bleach.clean(email)

        doesExist = validate_user_exists(username, email)
        if doesExist:
            return render_template("register.html", error='User with this username or email already exists'), 401
        
        totp_secret = register_user(username, email, password)
        user = user_loader(username)
        if not user:
            return render_template("register.html", error="Couldn't register user"), 401

        login_user(user)
        ip_address = request.remote_addr
        register_login_attempt(user.userId, ip_address, True)
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
        username = clean_displayed_content(current_user.id)
        login_attempts = get_failed_logins_since_last_successful(current_user.userId)
        login_attempts_dict = get_login_attempts_dict(login_attempts)

        user_notes = get_notes_created_by_user(current_user.userId)
        user_notes_list = get_notes_dict_list(user_notes)
        shared_notes = get_notes_shared_with_user(current_user.userId)
        shared_notes_list = get_notes_dict_list(shared_notes)
        public_notes = get_public_notes()
        public_notes_list = get_notes_dict_list(public_notes)

        return render_template("home.html", username = username, totp_secret=totp_secret, login_attempts=login_attempts_dict, user_notes_list=user_notes_list, shared_notes_list=shared_notes_list, public_notes_list=public_notes_list)

@app.route("/rendered_note/<note_id>", methods=["GET", "POST"])
@login_required
def rendered_note(note_id):
    note = fetch_note_if_user_can_view_it(note_id, current_user.userId)
    note_dict = get_note_dict(note)
    if not note:
        return "<h1>You are unauthorized to view this resource</h1>", 401
    if not note['isCiphered']:
        is_valid_note = verify_note_authorship(note['userId'], note['sign'], note['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = clean_displayed_content(markdown.markdown(note_dict['content']))
        print(note_dict['content'])
        return render_template("rendered_note.html", note_dict=note_dict)
    
    if request.method == "GET":
        return render_template("ciphered_note.html", note_id=note_id)
    
    if request.method == "POST":
        note_password = request.form.get("note_password")
        decrypted_content = decrypt_note(note_password, note['notePasswordHash'], note['content'])
        if not decrypted_content:
            return render_template("ciphered_note.html", note_id=note_id, error="Wrong credentials provided")
        note_dict['content'] = decrypted_content
        is_valid_note = verify_note_authorship(note['userId'], note['sign'], note_dict['content'])
        note_dict['is_valid'] = is_valid_note
        note_dict['content'] = clean_displayed_content(markdown.markdown(note_dict['content']))
        return render_template("rendered_note.html", note_dict=note_dict)
        

    
@app.route("/add_note", methods=["POST"])
@login_required
def add_note():
    if request.method == "GET":
        return redirect("/home")
    if request.method == "POST":
        title = request.form.get("title").strip()
        content = request.form.get("content").strip()
        is_public = 1 if request.form.get("isPublic") == "on" else 0
        shared_to_username = request.form.get("sharedToUsername").strip()
        user_password = request.form.get("user_password").strip()
        note_password = request.form.get("note_password").strip()
        note_password_repeat = request.form.get("note_password_repeat").strip()
        totp_code = request.form.get("totp_code").strip()

        validation_result = validate_note_data(title, content, shared_to_username, note_password, note_password_repeat, totp_code)
        if not validation_result["valid"]:
            for error_key, error_msg in validation_result["errors"].items():
                flash(f"{error_key}: {error_msg}", 'error')
            return redirect("/home")  
        
        if not verify_password_and_totp(current_user, user_password, totp_code):
            flash(f'Wrong credentials provided', "error")
            return redirect("/home")  
        
        result = sign_and_add_note(current_user.userId, title, content, shared_to_username, is_public, user_password, note_password)
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
        username = request.form.get('username')
        email = request.form.get('email')
        validation_result = validate_forgot_password_data(username, email)
        if not validation_result["valid"]:
            return render_template("forgot_password.html", errors=validation_result['errors']), 401
        user = get_user_by_username_and_email(username, email)
        if not user:
            return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")
        generate_reset_password_token(user['id'], email)
        return render_template("forgot_password.html", message = "Reset password email was sent to the provided email if user with given username and email exists")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):  
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    if request.method == "POST":
        password = request.form.get("password").strip()
        password_repeat = request.form.get("password_repeat").strip()

        pass_val_error = validate_password(password, password_repeat)
        if pass_val_error:
            return render_template("reset_password.html", error=pass_val_error, token=token)
        validation_result = validate_token(token)
        if not validation_result['valid']:
            return render_template("reset_password.html", error=validation_result['error'], token=token)
        totp_secret = change_password(validation_result['userId'], password)
        return render_template("reset_password.html", success=True, totp_secret=totp_secret, token=token)
if __name__ == "__main__":
    app.run()

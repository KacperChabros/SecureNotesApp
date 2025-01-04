from flask import current_app, url_for
from db import get_connection
import re
from passlib.hash import sha256_crypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import base64
import pyotp
from datetime import datetime, timezone, timedelta
import math
import secrets
import time



def get_user_by_username(username: str):
    """Method for getting user by username"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT id, username, passwordHash, totpSecretEncrypted FROM users WHERE username=?", (username,))
        
        row = cursor.fetchone()
        
        db.close()

        return row
    
def get_userId_by_username(username: str):
    '''Method for getting just user id based on the username'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        
        row = cursor.fetchone()
        
        db.close()

        if row:
            return row['id']
        return None
    
def get_user_by_username_and_email(username: str, email: str):
    '''Method for getting user based on the username and email'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username=? AND email=?", (username, email))
        
        row = cursor.fetchone()
        
        db.close()

        return row
    
def get_user_public_key(userId: int):
    '''Method for getting user public key'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT publicKey FROM users WHERE id=?", (userId,))
        
        row = cursor.fetchone()
        
        db.close()

        if row:
            return row['publicKey']
        return None

def validate_user_exists(username: str, email: str):
    '''Method for validating the existance of a user based on username or email'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        if username and email:
            cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        elif username:
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        elif email:
             cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        
        db.close()

        return row is not None
    
def validate_register_data(username: str, email: str, password: str, password_repeat: str):
    '''Method for validating user data during registration'''
    errors = {}
    
    if not username or not email or not password or not password_repeat:
        errors['general'] = 'Filling all fields is required'
    
    if len(username) < 3 or len(username) > 40:
        errors['username'] = 'Username must be between 3 and 40 characters'

    username_regex = r"^[a-z][a-z0-9]*$"
    if not re.fullmatch(username_regex, username):
        err = "Only lower letters and digits are permitted for username (first character must be a letter) | "
        if 'username' in errors:
            errors['username'] = err + errors['username']
        else:
            errors['username'] = err

    if len(email) < 6 or len(email) > 320:
        errors['email'] = 'Email must be between 6 and 320 characters'

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.fullmatch(email_pattern, email):
        err = "Email is invalid | "
        if 'email' in errors:
            errors['email'] = err + errors['email']
        else:
            errors['email'] = err

    pass_error = validate_password(password, password_repeat)
    if pass_error:
        errors['password'] = pass_error
    if errors:
        return {"valid": False, "errors": errors}
    
    return {'valid': True}

def validate_password(password, password_repeat):
    pass_error = ''
    charSetSize = 0

    if not password or not password_repeat:
        pass_error = 'Password and Password repeat cannot be empty'
        return pass_error

    if len(password) < 12:
        pass_error = 'Password must be at least 12 characters | '
    if not re.search(r"[a-z]", password):
        pass_error += "Password must contain a lowercase | "
    else:
        charSetSize += 26

    if not re.search(r"[A-Z]", password):
        pass_error +=  "Password must contain an uppercase | "
    else:
        charSetSize += 26

    if not re.search(r"\d", password):
        pass_error +=  "Password must contain a digit | "
    else:
        charSetSize += 10

    if not re.search(r'[ !"#$%&\'()*+,\-./:;<=>?@[\]\\^_`{|}~]', password):
        pass_error +=  "Password must contain a special character | "
    else:
        charSetSize += 32

    password_regex = r"^[a-zA-Z0-9 !\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~]+$"
    if not re.fullmatch(password_regex, password):
        pass_error += "Password contains an illegal character | "

    entropy = len(password) * math.log2(charSetSize)
    if entropy < 59:
        pass_error += "Password is too weak | "

    if not pass_error:
        if password != password_repeat:
            pass_error = 'Passwords do not match'
    return pass_error


def validate_login_data(username: str, password: str, totp_code: str):
    '''Method to validate user input during login'''
    errors = {} 
    if not username or not password or not totp_code:
        errors['general'] = 'Filling all fields is required'
    
    if len(username) < 3 or len(username) > 40:
        errors['username'] = 'Username must be between 3 and 40 characters'

    username_regex = r"^[a-z][a-z0-9]*$"
    if not re.fullmatch(username_regex, username):
        err = "Only lower letters and digits are permitted for username (first character must be a letter) | "
        if 'username' in errors:
            errors['username'] = err + errors['username']
        else:
            errors['username'] = err

    totp_regex = r"^[0-9]{6}$"
    if not re.fullmatch(totp_regex, totp_code):
        errors['TOTP'] = 'Invalid TOTP code format'

    if errors:
        return {"valid": False, "errors": errors}
    
    return {'valid': True}

def validate_forgot_password_data(username: str, email: str):
    errors = {}
    
    if not username or not email:
        errors['general'] = 'Filling all fields is required'
    
    if len(username) < 3 or len(username) > 40:
        errors['username'] = 'Username must be between 3 and 40 characters'

    username_regex = r"^[a-z][a-z0-9]*$"
    if not re.fullmatch(username_regex, username):
        err = "Only lower letters and digits are permitted for username (first character must be a letter) | "
        if 'username' in errors:
            errors['username'] = err + errors['username']
        else:
            errors['username'] = err

    if len(email) < 6 or len(email) > 320:
        errors['email'] = 'Email must be between 6 and 320 characters'

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.fullmatch(email_pattern, email):
        err = "Email is invalid | "
        if 'email' in errors:
            errors['email'] = err + errors['email']
        else:
            errors['email'] = err

    if errors:
        return {"valid": False, "errors": errors}
    
    return {'valid': True}

def register_user(username: str, email: str, password: str):
    '''Method to register user'''
    password_hash = hash_password(password)
    keys, encrypted_priv_key = get_rsa_keys(password)
    public_key = keys.publickey().export_key()
    totp_secret, encrypted_totp_secret = get_totp_secret(password)
    del keys
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()      
        cursor.execute("INSERT INTO users(username, email, passwordHash, publicKey, privateKeyEncrypted, totpSecretEncrypted) VALUES(?,?,?,?,?,?)", (username, email, password_hash, public_key, encrypted_priv_key, encrypted_totp_secret))
        db.commit()
        db.close()
    return totp_secret

def hash_password(password: str):
    return sha256_crypt.hash(password, rounds=550000)

def get_rsa_keys(password: str):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16) 
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)


    keys = RSA.generate(2048)
    private_key = keys.export_key()
    public_key = keys.publickey().export_key()

    padded_priv_key = pad(private_key, AES.block_size)
    ciphertext = cipher.encrypt(padded_priv_key)
    encrypted_priv_key = base64.b64encode(iv + salt + ciphertext).decode('utf-8')
    del salt
    del iv
    del key
    del cipher
    del private_key
    del padded_priv_key
    del ciphertext
    return keys, encrypted_priv_key

def get_totp_secret(password: str):
    totp_secret = pyotp.random_base32()
    salt_totp = get_random_bytes(16)
    iv_totp = get_random_bytes(16)
    key_totp = PBKDF2(password, salt_totp, dkLen=32)
    cipher_totp = AES.new(key_totp, AES.MODE_CBC, iv_totp)
    padded_totp = pad(totp_secret.encode('utf-8'), AES.block_size)
    encrypted_totp = cipher_totp.encrypt(padded_totp)
    encrypted_totp_secret = base64.b64encode(iv_totp + salt_totp + encrypted_totp).decode('utf-8')
    del salt_totp
    del iv_totp
    del key_totp
    del cipher_totp
    del padded_totp
    del encrypted_totp
    return totp_secret, encrypted_totp_secret

def verify_password_and_totp(user, password: str, totp_code: str):
    '''Method to check if the credentials are valid'''
    if sha256_crypt.verify(password, user.password_hash):
        decoded_totp = base64.b64decode(user.totp)
        iv = decoded_totp[:16]
        salt = decoded_totp[16:32]
        totp_ciphertext = decoded_totp[32:]
        key = PBKDF2(password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_deciphered = cipher.decrypt(totp_ciphertext)
        retrieved_totp_secret = unpad(padded_deciphered, AES.block_size).decode('utf-8')
        totp = pyotp.TOTP(retrieved_totp_secret)
        del retrieved_totp_secret
        if totp.verify(totp_code):
            return True
    else:
        time.sleep(0.04)
    return False

def register_login_attempt(userId: int, ip_address: str, is_success: bool):
    with current_app.app_context():
        curr_time = datetime.now(timezone.utc)
        db = get_connection()
        cursor = db.cursor()

        cursor.execute("INSERT INTO loginAttempts(userId, time, ipAddress, isSuccess) VALUES(?,?,?,?)", (userId, curr_time, ip_address, is_success))

        db.commit()
        
        db.close()


def get_failed_logins_since_last_successful(userId: int):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("""SELECT * FROM  loginAttempts WHERE userId = ? AND isSuccess = 0 AND time BETWEEN (SELECT time FROM loginAttempts WHERE userId = ? AND isSuccess = 1 ORDER BY time DESC LIMIT 1 OFFSET 1) 
                       AND (SELECT time FROM loginAttempts WHERE userId = ? AND isSuccess = 1 ORDER BY time DESC LIMIT 1) ORDER BY time;""", (userId, userId, userId))
        
        rows = cursor.fetchall()
        
        db.close()

        return rows
    
def is_locked_out(ip_address: str):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        curr_time = datetime.now(timezone.utc)
        time_threshold = curr_time - timedelta(minutes=20)
        cursor.execute("SELECT COUNT(*) FROM  loginAttempts WHERE ipAddress = ? AND isSuccess = 0 AND time >= ?", (ip_address, time_threshold))
        number_of_attempts = cursor.fetchone()
        
        db.close()

        return number_of_attempts[0] >= 5
    
def is_locked_out_on_pass_reset(ip_address: str, is_generating_token=True):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        curr_time = datetime.now(timezone.utc)
        time_threshold = curr_time - timedelta(minutes=60)
        cursor.execute("SELECT COUNT(*) FROM  resetPasswordAttempts WHERE ipAddress = ? AND time >= ? AND isGeneratingToken = ?", (ip_address, time_threshold, is_generating_token))
        number_of_attempts = cursor.fetchone()
        
        db.close()

        return number_of_attempts[0] >= 3
    
def register_pass_reset_attempt(ip_address: str, is_generating_token: bool):
    with current_app.app_context():
        curr_time = datetime.now(timezone.utc)
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("INSERT INTO resetPasswordAttempts(time, ipAddress, isGeneratingToken) VALUES(?,?,?)", (curr_time, ip_address, is_generating_token))
        
        db.commit()
        
        db.close()

def generate_reset_password_token(userId: int, email: str):
    with current_app.app_context():
        token = secrets.token_urlsafe(32)
        token_hash = SHA256.new(token.encode()).hexdigest()
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(minutes=5)
        reset_link = url_for('reset_password', token=token, _external=True)
        save_token_to_db(userId, created_at, expires_at, token_hash)
        print("------------------------------------------------")
        print(f"Reset password link for {email}: {reset_link}")
        print("------------------------------------------------")

def save_token_to_db(userId, created_at, expires_at, token_hash):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()      
        cursor.execute("INSERT INTO resetPasswordTokens(userId, createdAt, expiresAt, tokenHash) VALUES(?,?,?,?)", (userId, created_at, expires_at, token_hash))
        db.commit()
        db.close()

def get_token_from_db(token_hash):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        curr_time = datetime.now(timezone.utc)
        cursor.execute("SELECT * FROM resetPasswordTokens WHERE tokenHash=? AND isUsed=FALSE AND expiresAt>?", (token_hash, curr_time))    
        row = cursor.fetchone()       
        db.close()
        return row
    
def expire_token(token_id):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()      
        cursor.execute("UPDATE resetPasswordTokens SET isUsed=TRUE WHERE tokenId=?", (token_id,))
        db.commit()
        db.close()

def validate_token(token: str):
    token_hash = SHA256.new(token.encode()).hexdigest()
    token_row = get_token_from_db(token_hash)
    if not token_row:
        return {"valid": False, "error": 'Invalid token'}
    expire_token(token_row['tokenId'])
    return {'valid': True, "userId": token_row['userId']}

def change_password(userId: int, password: str):
    from note_service import sign_message, get_not_encrypted_user_notes, update_signature
    password_hash = hash_password(password)
    keys, encrypted_priv_key = get_rsa_keys(password)
    priv_key_text = keys.export_key()
    public_key = keys.publickey().export_key()
    totp_secret, encrypted_totp_secret = get_totp_secret(password)
    update_user_after_password_change(userId, password_hash, public_key, encrypted_priv_key, encrypted_totp_secret)
    notes = get_not_encrypted_user_notes(userId)
    for note in notes:
        signature = sign_message(priv_key_text, note['content'])
        update_signature(note['noteId'], signature)
    del priv_key_text
    del keys

    return totp_secret

def update_user_after_password_change(userId, password_hash, public_key, encrypted_priv_key, encrypted_totp_secret):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()      
        cursor.execute("UPDATE users SET passwordHash=?, publicKey=?, privateKeyEncrypted=?, totpSecretEncrypted=? WHERE id=?", (password_hash, public_key, encrypted_priv_key, encrypted_totp_secret, userId))
        db.commit()
        db.close()

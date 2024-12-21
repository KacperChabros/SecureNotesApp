import sqlite3
from flask import current_app
from db import get_connection
import re
import os
from passlib.hash import sha256_crypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import pyotp
from datetime import datetime, timezone, timedelta
import math



def get_user_by_username(username: str):
    """Method for getting user by username"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        
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
    
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.fullmatch(email_pattern, email):
        errors['email'] = 'Email is invalid'

    pass_error = validate_password(password, password_repeat)
    if pass_error:
        errors['password'] = pass_error
    if errors:
        return {"valid": False, "errors": errors}
    
    return {'valid': True}

def validate_password(password, password_repeat):
    pass_error = ''
    charSetSize = 0
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

    if len(totp_code) != 6:
        errors['TOTP'] = 'Invalid TOTP code format'

    if errors:
        return {"valid": False, "errors": errors}
    
    return {'valid': True}

def register_user(username: str, email: str, password: str):
    '''Method to register user'''
    password_hash = sha256_crypt.hash(password, rounds=550000)
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
    
    totp_secret = pyotp.random_base32()
    salt_totp = get_random_bytes(16)
    iv_totp = get_random_bytes(16)
    key_totp = PBKDF2(password, salt_totp, dkLen=32)
    cipher_totp = AES.new(key_totp, AES.MODE_CBC, iv_totp)
    padded_totp = pad(totp_secret.encode('utf-8'), AES.block_size)
    encrypted_totp = cipher_totp.encrypt(padded_totp)
    encrypted_totp_secret = base64.b64encode(iv_totp + salt_totp + encrypted_totp).decode('utf-8')

    del padded_priv_key
    del padded_totp
    del private_key
    del keys
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()      
        cursor.execute("INSERT INTO users(username, email, passwordHash, publicKey, privateKeyEncrypted, totpSecretEncrypted) VALUES(?,?,?,?,?,?)", (username, email, password_hash, public_key, encrypted_priv_key, encrypted_totp_secret))
        db.commit()
        db.close()
    return totp_secret
    

def verify_password_and_totp(user, password: str, totp_code: str):
    '''Method to check if the credentials are valid'''
    if sha256_crypt.verify(password, user.password):
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
    
def is_locked_out(userId: int):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        curr_time = datetime.now(timezone.utc)
        time_threshold = curr_time - timedelta(minutes=15)
        cursor.execute("SELECT COUNT(*) FROM  loginAttempts WHERE userId = ? AND isSuccess = 0 AND time >= ?", (userId, time_threshold))
        
        number_of_attempts = cursor.fetchone()
        
        db.close()

        return number_of_attempts[0] >= 3
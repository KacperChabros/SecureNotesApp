from flask import current_app
from db import get_connection
from user_service import validate_password, validate_user_exists, get_userId_by_username, get_user_public_key
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from passlib.hash import sha256_crypt
from bleach import clean
from datetime import datetime, timezone, timedelta
import re
import os
from dotenv import load_dotenv

load_dotenv()

TOTP_PEPPER = os.getenv('TOTP_PEPPER', '')
RSA_PEPPER = os.getenv('RSA_PEPPER', '')
NOTE_PEPPER = os.getenv('NOTE_PEPPER', '')

def get_notes_created_by_user(userId: int):
    """Method for getting all user's notes"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM notes WHERE userId=?", (userId,))

        rows = cursor.fetchall()

        db.close()

        return rows

def get_notes_shared_with_user(userId: int):
    """Method for getting all notes shared to user"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM notes WHERE sharedToUserId=?", (userId,))

        rows = cursor.fetchall()

        db.close()

        return rows

def get_public_notes():
    """Method for getting all public notes"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM notes WHERE isPublic=TRUE")

        rows = cursor.fetchall()

        db.close()

        return rows


def validate_note_data(title: str, content: str, user_password: str, sharedToUsername: str, note_password: str, note_password_repeat: str, totp_code: str):
    '''Method for validating note data'''
    errors = {}

    if not title or not content or not user_password or not totp_code:
        errors['general'] = 'Title, Content, User\'s password and TOTP fields are required.'
    
    title_regex = r"^[a-zA-Z0-9.,!?()\-\ ]{4,50}$"
    if not re.fullmatch(title_regex, title):
        errors['title'] = 'Title must be between 4 and 50 characters and contain only lowercase, uppercase, digits and following characters: \'.,!? ()-'

    if len(content) < 5 or len(content) > 2500:
        errors['content'] = 'Content must be between 5 and 2500 characters.'

    username_regex = r"^[a-z][a-z0-9]*$"
    if sharedToUsername and (len(sharedToUsername) < 3 or len(sharedToUsername) > 40):
        errors['sharedToUsername'] = 'If set, Username must be between 3 and 40 characters.'
    elif sharedToUsername and not re.fullmatch(username_regex, sharedToUsername):
        errors['sharedToUsername'] = 'If set, "Only lower letters and digits are permitted for username (first character must be a letter)'
    elif sharedToUsername and not validate_user_exists(sharedToUsername, None):
        errors['sharedToUsername'] = 'This user does not exist'


    if(note_password is None and note_password_repeat is not None) or (note_password is not None and note_password_repeat is None):
        errors['note_password'] = 'Both note password and note password repeat must be provided when one is'
    
    if note_password and note_password_repeat:
        passError = validate_password(note_password, note_password_repeat)
        if passError:
            errors['note_password'] = passError

    totp_regex = r"^[0-9]{6}$"
    if not re.fullmatch(totp_regex, totp_code):
        errors['TOTP'] = 'Invalid TOTP code format'

    if errors:
        return {"valid": False, "errors": errors}

    return {"valid": True}

def validate_ciphered_note_data(password: str):
    error = None

    if not password:
        error = "Password cannot be empty"
        
    if error:
        return {"valid": False, "error": error}

    return {"valid": True}


def sign_and_add_note(curr_user_id: int, title: str, content: str, shared_with_username: str, is_public: bool, user_password: str, note_password: str):
    '''Method to sign and add note'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=?", (curr_user_id,))
        row = cursor.fetchone()
        
        if row is None:
            return False

        priv_key_text = decrypt_priv_key(row['privateKeyEncrypted'], user_password)
        if not priv_key_text:
            return False
        title = clean_displayed_content(title)
        content = clean_displayed_content(content)

        signature = sign_message(priv_key_text, content)
        del priv_key_text
        del user_password

        is_shared = False
        is_ciphered = False
        shared_with_user_id = None
        note_password_hash = None
        if shared_with_username:
            shared_with_user_id = get_userId_by_username(shared_with_username)
            if not shared_with_username:
                return False
            is_public = False
            is_shared = True
        
        content_to_add = content
        if note_password:
            note_password_hash = sha256_crypt.hash(note_password, rounds=550000)
            encrypted_note = encrypt_note(note_password, content)
            is_ciphered = True
            content_to_add = encrypted_note
            del note_password
        
        
        db.execute('INSERT INTO notes(userId, title, content, notePasswordHash, sign, isCiphered, isPublic, isShared, sharedToUserId) VALUES (?,?,?,?,?,?,?,?,?)', (curr_user_id, title, content_to_add, note_password_hash, signature, is_ciphered, is_public, is_shared, shared_with_user_id))
        db.commit()
        db.close()

    return True

def decrypt_priv_key(encrypted_priv_key, user_password):
    decoded_priv_key = base64.b64decode(encrypted_priv_key)
    nonce_d = decoded_priv_key[:12]
    salt_d = decoded_priv_key[12:28]
    tag_d = decoded_priv_key[28:44]
    ciphertext_d = decoded_priv_key[44:]
    key_d = PBKDF2(user_password + RSA_PEPPER, salt_d, dkLen=32, count=200000)
    cipher = AES.new(key_d, AES.MODE_GCM, nonce=nonce_d)
    retrieved_priv_key = None
    try:
        retrieved_priv_key = cipher.decrypt_and_verify(ciphertext_d, tag_d).decode('utf-8')
    except (ValueError, KeyError):
        pass
    del decoded_priv_key
    del nonce_d
    del salt_d
    del ciphertext_d
    del key_d
    del cipher
    del tag_d

    return retrieved_priv_key

def encrypt_note(note_password: str, content: str):
    nonce = get_random_bytes(12)
    salt = get_random_bytes(16)
    key = PBKDF2(note_password + NOTE_PEPPER, salt, dkLen=32, count=200000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encrypted_note_content, tag = cipher.encrypt_and_digest(content.encode('utf-8'))
    encrypted_note_base64 = base64.b64encode(nonce + salt + tag + encrypted_note_content).decode('utf-8')
    del salt
    del nonce
    del key
    del cipher
    del tag
    del encrypted_note_content

    return encrypted_note_base64 

def sign_message(priv_key_text: str, content: str):
    rsa_keys = RSA.import_key(priv_key_text)
    hash = SHA256.new(content.encode())
    sig = pkcs1_15.new(rsa_keys).sign(hash)
    del rsa_keys
    signature_base64 = base64.b64encode(sig).decode('utf-8')
    return signature_base64

def fetch_note_if_user_can_view_it(noteId: int, userId: int):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("""SELECT notes.noteId, notes.userId, notes.title, notes.content, notes.notePasswordHash, notes.sign, notes.isCiphered, notes.isPublic, notes.isShared, users_owner.username AS owner_username, users_shared.username AS shared_to_username 
                       FROM notes 
                       JOIN users AS users_owner ON notes.userId = users_owner.id
                       LEFT JOIN users AS users_shared ON notes.sharedToUserId = users_shared.id
                       WHERE noteId=? AND (userId=? OR sharedToUserId=? OR isPublic=TRUE)""", (noteId, userId, userId))

        row = cursor.fetchone()

        db.close()

        return row
    
def decrypt_note(note_password: str, note_password_hash: str, encrypted_note: str):
    if not sha256_crypt.verify(note_password, note_password_hash):
        return False
    decoded_note = base64.b64decode(encrypted_note)
    nonce = decoded_note[:12]
    salt = decoded_note[12:28]
    tag = decoded_note[28:44]
    note_ciphertext = decoded_note[44:]
    key = PBKDF2(note_password + NOTE_PEPPER, salt, dkLen=32, count=200000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_note = None
    try:
        decrypted_note = cipher.decrypt_and_verify(note_ciphertext, tag).decode('utf-8')
    except (ValueError, KeyError):
        pass
    del decoded_note
    del nonce
    del salt
    del note_ciphertext
    del key
    del cipher
    del tag
    
    return decrypted_note
    
def verify_note_authorship(user_owner_id: int, sign: str, content: str):
    '''Method to verify if note hasn't be altered'''
    decoded_sign = base64.b64decode(sign)
    public_key_text = get_user_public_key(user_owner_id)
    if not public_key_text:
        return False
    hash = SHA256.new(content.encode())
    public_key = RSA.import_key(public_key_text)
    try:
        pkcs1_15.new(public_key).verify(hash, decoded_sign)
        return True 
    except:
        return False

def clean_displayed_content(html_to_clean: str):
    '''Method to bleach html content'''
    if not html_to_clean:
        return None
    allowed_tags = [
        'b', 'strong', 'i', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'img', 'ul', 'ol', 'li', 'p', 'br', 'hr', 'blockquote', 'code', 'pre'
    ]

    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title'], 
    }

    return clean(html_to_clean, tags=allowed_tags, attributes=allowed_attributes)

def get_not_encrypted_user_notes(userId: int):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM notes WHERE userId=? and isCiphered=FALSE", (userId,))

        rows = cursor.fetchall()

        db.close()

        return rows
    
def update_signature(noteId: int, signature: str):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        cursor.execute("UPDATE notes SET sign=? WHERE noteId=?", (signature, noteId))
        db.commit()
        db.close()

def register_note_decrypt_attempt(ip_address: str, user_agent: str, is_success: bool, note_id: int):
    with current_app.app_context():
        curr_time = datetime.now(timezone.utc)
        db = get_connection()
        cursor = db.cursor()

        cursor.execute("INSERT INTO decryptNoteAttempts(time, ipAddress, userAgent, isSuccess, noteId) VALUES(?,?,?,?,?)", ( curr_time, ip_address, user_agent, is_success, note_id))

        db.commit()
        
        db.close()

def register_add_note_attempt(ip_address: str, user_agent: str, is_success: bool):
    with current_app.app_context():
        curr_time = datetime.now(timezone.utc)
        db = get_connection()
        cursor = db.cursor()

        cursor.execute("INSERT INTO addNoteAttempts(time, ipAddress, userAgent, isSuccess) VALUES(?,?,?,?)", ( curr_time, ip_address, user_agent, is_success))

        db.commit()
        
        db.close()

def is_locked_out_on_note_decrypt(ip_address: str):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        curr_time = datetime.now(timezone.utc)
        time_threshold = curr_time - timedelta(minutes=15)
        cursor.execute("SELECT COUNT(*) FROM  decryptNoteAttempts WHERE ipAddress = ? AND isSuccess = 0 AND time >= ?", (ip_address, time_threshold))
        number_of_attempts = cursor.fetchone()
        
        db.close()

        return number_of_attempts[0] >= 5
    
def is_locked_out_on_add_note(ip_address: str):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        curr_time = datetime.now(timezone.utc)
        time_threshold = curr_time - timedelta(minutes=15)
        cursor.execute("SELECT COUNT(*) FROM  addNoteAttempts WHERE ipAddress = ? AND isSuccess = 0 AND time >= ?", (ip_address, time_threshold))
        number_of_attempts = cursor.fetchone()
        
        db.close()

        return number_of_attempts[0] >= 5
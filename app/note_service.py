import sqlite3
from flask import current_app
from db import get_connection
from user_service import validate_password, validate_user_exists
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

def get_notes_created_by_user(userId: int):
    """Method for getting all user's notes"""
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM notes WHERE userId=?", (userId,))

        rows = cursor.fetchall()

        # db.execute('INSERT INTO notes(userId, title, content, unencryptedContentHash, sign, isCiphered, isPublic, isShared, sharedToUserId) VALUES (?,?,?,?,?,?,?,?,?)', (userId, 'Tytul', 'moja pierwsza wiad', 'hasz', 'podpisalem', 0, 1, 0, None))
        # db.commit()
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


def validate_note_data(title: str, content: str, sharedToUsername: str, note_password: str, note_password_repeat: str, totp_code: str):
    '''Method for validating note data'''
    errors = {}

    if not title or not content:
        errors['general'] = 'Title and Content fields are required.'
    
    if len(title) < 4 or len(title) > 50:
        errors['title'] = 'Title must be between 4 and 50 characters.'

    if len(content) < 5 or len(content) > 2000:
        errors['content'] = 'Content must be between 5 and 2000 characters.'

    if sharedToUsername and (len(sharedToUsername) < 3 or len(sharedToUsername) > 40):
        errors['sharedToUsername'] = 'If set, Username must be between 3 and 40 characters.'
    # elif sharedToUsername and not validate_user_exists(sharedToUsername, None):
    #     errors['sharedToUsername'] = 'This user does not exist'


    if(note_password is None and note_password_repeat is not None) or (note_password is not None and note_password_repeat is None):
        errors['note_password'] = 'Both note password and note password repeat must be provided when one is'
    
    if note_password and note_password_repeat:
        passError = validate_password(note_password, note_password_repeat)
        if passError:
            errors['note_password'] = passError

    if len(totp_code) != 6:
        errors['TOTP'] = 'Invalid TOTP code format'

    if errors:
        return {"valid": False, "errors": errors}

    return {"valid": True}

def sign_and_add_note(curr_user_id: int, title: str, content: str, shared_to_username: str, is_public: bool, user_password: str, note_password: str):
    '''Method to sign and add note'''
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=?", (curr_user_id,))
        row = cursor.fetchone()

        if row is None:
            return False

        priv_key = decrypt_priv_key(row['privateKeyEncrypted'], user_password)
        

        del priv_key
        db.close()

    return True

def decrypt_priv_key(encrypted_priv_key, user_password):
    decoded_priv_key = base64.b64decode(encrypted_priv_key)
    iv_d = decoded_priv_key[:16]
    salt_d = decoded_priv_key[16:32]
    ciphertext_d = decoded_priv_key[32:]
    key_d = PBKDF2(user_password, salt_d, dkLen=32)
    cipher_d = AES.new(key_d, AES.MODE_CBC, iv_d)
    padded_decyphered = cipher_d.decrypt(ciphertext_d)
    retrieved_priv_key = unpad(padded_decyphered, AES.block_size).decode('utf-8')
    del padded_decyphered
    del key_d
    del iv_d
    del salt_d
    del ciphertext_d
    del decoded_priv_key
    del encrypted_priv_key
    del cipher_d
    return retrieved_priv_key
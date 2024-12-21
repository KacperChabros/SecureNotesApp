import sqlite3
from flask import current_app
from db import get_connection
from user_service import validate_password, validate_user_exists, get_userId_by_username
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from passlib.hash import sha256_crypt

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
    elif sharedToUsername and not validate_user_exists(sharedToUsername, None):
        errors['sharedToUsername'] = 'This user does not exist'


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
    iv_d = decoded_priv_key[:16]
    salt_d = decoded_priv_key[16:32]
    ciphertext_d = decoded_priv_key[32:]
    key_d = PBKDF2(user_password, salt_d, dkLen=32)
    cipher_d = AES.new(key_d, AES.MODE_CBC, iv_d)
    padded_decyphered = cipher_d.decrypt(ciphertext_d)
    retrieved_priv_key = unpad(padded_decyphered, AES.block_size).decode('utf-8')
    del decoded_priv_key
    del iv_d
    del salt_d
    del ciphertext_d
    del key_d
    del cipher_d
    del padded_decyphered
    return retrieved_priv_key

def encrypt_note(note_password: str, content: str):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = PBKDF2(note_password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_note_content = pad(content.encode('utf-8'), AES.block_size)
    encrypted_note_content = cipher.encrypt(padded_note_content)
    encrypted_note_base64 = base64.b64encode(iv + salt + encrypted_note_content).decode('utf-8')
    del salt
    del iv
    del key
    del cipher
    del padded_note_content
    del encrypted_note_content
    return encrypted_note_base64 

def sign_message(priv_key_text: str, content: str):
        rsa_keys = RSA.import_key(priv_key_text)
        del priv_key_text
        hash = SHA256.new(content.encode())
        sig = pkcs1_15.new(rsa_keys).sign(hash)
        del rsa_keys
        signature_base64 = base64.b64encode(sig).decode('utf-8')
        return signature_base64

def fetch_note_if_user_can_view_it(noteId: int, userId: int):
    with current_app.app_context():
        db = get_connection()
        cursor = db.cursor()
        
        cursor.execute("""SELECT notes.noteId, notes.title, notes.content, notes.notePasswordHash, notes.sign, notes.isCiphered, notes.isPublic, notes.isShared, users_owner.username AS owner_username, users_shared.username AS shared_to_username 
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
    iv = decoded_note[:16]
    salt = decoded_note[16:32]
    note_ciphertext = decoded_note[32:]
    key = PBKDF2(note_password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_deciphered = cipher.decrypt(note_ciphertext)
    decrypted_note = unpad(padded_deciphered, AES.block_size).decode('utf-8')
    del decoded_note
    del iv
    del salt
    del note_ciphertext
    del key
    del cipher
    del padded_deciphered
    
    return decrypted_note
    
    
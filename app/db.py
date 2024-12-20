import sqlite3
import os
from flask import current_app


def get_connection():
    """Function to get connection to the db"""
    conn = sqlite3.connect(current_app.config['DATABASE_URL'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize db"""
    with current_app.app_context():
        db = get_connection()
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                passwordHash TEXT NOT NULL,
                publicKey TEXT NOT NULL,
                privateKeyEncrypted TEXT NOT NULL,
                totpSecretEncrypted TEXT NOT NULL         
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS notes (
                noteId INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                notePasswordHash TEXT NULL,
                sign TEXT NOT NULL,
                isCiphered BOOLEAN NOT NULL,
                isPublic BOOLEAN NOT NULL,
                isShared BOOLEAN NOT NULL,
                sharedToUserId INTEGER,
                FOREIGN KEY (userId) REFERENCES users(id),
                FOREIGN KEY (sharedToUserId) REFERENCES users(id)
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS loginAttempts (
                attemptId INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER NOT NULL,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                isSuccess BOOLEAN NOT NULL,
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        ''')

        db.commit()
        db.close()


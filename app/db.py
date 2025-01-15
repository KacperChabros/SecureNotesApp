import sqlite3
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
                userId INTEGER NULL,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                isSuccess BOOLEAN NOT NULL,
                userAgent TEXT NULL,
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS registrationAttempts (
                attemptId INTEGER PRIMARY KEY AUTOINCREMENT,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                userAgent TEXT NULL            
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS decryptNoteAttempts (
                attemptId INTEGER PRIMARY KEY AUTOINCREMENT,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                userAgent TEXT NULL,
                isSuccess BOOLEAN NOT NULL,
                noteId INTEGER NOT NULL,
                FOREIGN KEY (noteId) REFERENCES notes(noteId)      
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS addNoteAttempts (
                attemptId INTEGER PRIMARY KEY AUTOINCREMENT,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                userAgent TEXT NULL,
                isSuccess BOOLEAN NOT NULL
                );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS resetPasswordTokens (
                tokenId INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER NOT NULL,
                createdAt DATETIME NOT NULL,
                expiresAt DATETIME NOT NULL,
                tokenHash TEXT NOT NULL,
                isUsed BOOLEAN NOT NULL DEFAULT FALSE,
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        ''')
        db.cursor().execute('''
            CREATE TABLE IF NOT EXISTS resetPasswordAttempts (
                attemptId INTEGER PRIMARY KEY AUTOINCREMENT,
                time DATETIME NOT NULL,
                ipAddress TEXT NOT NULL,
                isGeneratingToken BOOLEAN NOT NULL,
                userAgent TEXT NULL
            );
        ''')

        db.commit()
        db.close()


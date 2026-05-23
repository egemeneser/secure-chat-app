import sqlite3
import json
import hashlib
import os
from datetime import datetime


DATABASE_NAME = "server_database.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            identity_key_type TEXT NOT NULL,
            identity_public_key TEXT NOT NULL,
            signed_prekey_type TEXT NOT NULL,
            signed_prekey_public_key TEXT NOT NULL,
            signed_prekey_signature TEXT NOT NULL,
            one_time_prekey_type TEXT NOT NULL,
            one_time_prekeys TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message_number INTEGER NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            sender_ephemeral_public_key TEXT,
            used_one_time_prekey_id TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Indexes for faster lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_username
        ON users(username)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_key_bundles_username
        ON key_bundles(username)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_receiver
        ON messages(receiver)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_sender
        ON messages(sender)
    """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# Password helpers (salted SHA-256)
# ---------------------------------------------------------

def generate_salt():
    """Generate a random 16-byte salt as hex string."""
    return os.urandom(16).hex()


def hash_password(password, salt):
    """Hash password with salt using SHA-256."""
    salted = salt + password
    password_bytes = salted.encode("utf-8")
    hashed_password = hashlib.sha256(password_bytes).hexdigest()

    return hashed_password


def check_password(password, salt, password_hash):
    """Verify password against stored salt and hash."""
    return hash_password(password, salt) == password_hash


# ---------------------------------------------------------
# User functions
# ---------------------------------------------------------

def add_user(username, password):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        created_at = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, salt, created_at))

        connection.commit()
        connection.close()

        return True

    except sqlite3.IntegrityError:
        connection.close()
        return False


def user_exists(username):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()
    connection.close()

    return user is not None


def verify_user(username, password):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT password_hash, salt FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()
    connection.close()

    if user is None:
        return False

    return check_password(password, user["salt"], user["password_hash"])


def get_user_info(username):
    """Return basic user info (for admin/debug purposes)."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username, created_at FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()
    connection.close()

    if user is None:
        return None

    return {
        "username": user["username"],
        "created_at": user["created_at"]
    }


# ---------------------------------------------------------
# Key bundle functions
# ---------------------------------------------------------

def save_key_bundle(key_bundle):
    connection = get_connection()
    cursor = connection.cursor()

    one_time_prekeys_json = json.dumps(key_bundle.one_time_prekeys)
    updated_at = datetime.utcnow().isoformat()

    cursor.execute("""
        INSERT OR REPLACE INTO key_bundles (
            username,
            identity_key_type,
            identity_public_key,
            signed_prekey_type,
            signed_prekey_public_key,
            signed_prekey_signature,
            one_time_prekey_type,
            one_time_prekeys,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        key_bundle.username,
        key_bundle.identity_key_type,
        key_bundle.identity_public_key,
        key_bundle.signed_prekey_type,
        key_bundle.signed_prekey_public_key,
        key_bundle.signed_prekey_signature,
        key_bundle.one_time_prekey_type,
        one_time_prekeys_json,
        updated_at
    ))

    connection.commit()
    connection.close()


def get_key_bundle(username):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM key_bundles
        WHERE username = ?
    """, (username,))

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    one_time_prekeys = json.loads(row["one_time_prekeys"])

    key_bundle = {
        "username": row["username"],

        "identity_key_type": row["identity_key_type"],
        "identity_public_key": row["identity_public_key"],

        "signed_prekey_type": row["signed_prekey_type"],
        "signed_prekey_public_key": row["signed_prekey_public_key"],
        "signed_prekey_signature": row["signed_prekey_signature"],

        "one_time_prekey_type": row["one_time_prekey_type"],
        "one_time_prekeys": one_time_prekeys
    }

    return key_bundle


def get_key_bundle_info(username):
    """
    Return key bundle metadata for display purposes.
    Shows key types, truncated public keys, and OTK count.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT identity_key_type, identity_public_key,
               signed_prekey_type, signed_prekey_public_key,
               one_time_prekeys, updated_at
        FROM key_bundles
        WHERE username = ?
    """, (username,))

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    one_time_prekeys = json.loads(row["one_time_prekeys"])

    return {
        "identity_key_type": row["identity_key_type"],
        "identity_public_key": row["identity_public_key"],
        "signed_prekey_type": row["signed_prekey_type"],
        "signed_prekey_public_key": row["signed_prekey_public_key"],
        "one_time_prekeys_remaining": len(one_time_prekeys),
        "updated_at": row["updated_at"]
    }


def remove_one_time_prekey(username, one_time_prekey_id):
    key_bundle = get_key_bundle(username)

    if key_bundle is None:
        return False

    old_prekeys = key_bundle["one_time_prekeys"]
    new_prekeys = []

    for prekey in old_prekeys:
        if prekey["id"] != one_time_prekey_id:
            new_prekeys.append(prekey)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE key_bundles
        SET one_time_prekeys = ?
        WHERE username = ?
    """, (
        json.dumps(new_prekeys),
        username
    ))

    connection.commit()
    connection.close()

    return True


# ---------------------------------------------------------
# Message functions
# ---------------------------------------------------------

def save_message(message):
    connection = get_connection()
    cursor = connection.cursor()

    created_at = datetime.utcnow().isoformat()

    cursor.execute("""
        INSERT INTO messages (
            sender,
            receiver,
            message_number,
            nonce,
            ciphertext,
            sender_ephemeral_public_key,
            used_one_time_prekey_id,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        message.sender,
        message.receiver,
        message.message_number,
        message.nonce,
        message.ciphertext,
        message.sender_ephemeral_public_key,
        message.used_one_time_prekey_id,
        created_at
    ))

    connection.commit()
    connection.close()


def get_messages_for_user(username):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM messages
        WHERE receiver = ?
        ORDER BY id ASC
    """, (username,))

    rows = cursor.fetchall()
    connection.close()

    messages = []

    for row in rows:
        message = {
            "sender": row["sender"],
            "receiver": row["receiver"],
            "message_number": row["message_number"],
            "nonce": row["nonce"],
            "ciphertext": row["ciphertext"],
            "sender_ephemeral_public_key": row["sender_ephemeral_public_key"],
            "used_one_time_prekey_id": row["used_one_time_prekey_id"],
            "created_at": row["created_at"]
        }

        messages.append(message)

    return messages


def delete_messages_for_user(username):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM messages
        WHERE receiver = ?
    """, (username,))

    connection.commit()
    connection.close()


def get_message_count():
    """Return total message count stored on server (for stats)."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM messages")

    row = cursor.fetchone()
    connection.close()

    return row["count"]


def get_user_count():
    """Return total registered user count (for stats)."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM users")

    row = cursor.fetchone()
    connection.close()

    return row["count"]
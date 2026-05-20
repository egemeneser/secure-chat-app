import sqlite3
import json
import hashlib


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
            password_hash TEXT NOT NULL
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
            one_time_prekeys TEXT NOT NULL
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
            used_one_time_prekey_id TEXT
        )
    """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# Password helpers
# ---------------------------------------------------------

def hash_password(password):
    password_bytes = password.encode("utf-8")
    hashed_password = hashlib.sha256(password_bytes).hexdigest()

    return hashed_password


def check_password(password, password_hash):
    return hash_password(password) == password_hash


# ---------------------------------------------------------
# User functions
# ---------------------------------------------------------

def add_user(username, password):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        password_hash = hash_password(password)

        cursor.execute("""
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """, (username, password_hash))

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
        SELECT password_hash FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()
    connection.close()

    if user is None:
        return False

    return check_password(password, user["password_hash"])


# ---------------------------------------------------------
# Key bundle functions
# ---------------------------------------------------------

def save_key_bundle(key_bundle):
    connection = get_connection()
    cursor = connection.cursor()

    one_time_prekeys_json = json.dumps(key_bundle.one_time_prekeys)

    cursor.execute("""
        INSERT OR REPLACE INTO key_bundles (
            username,
            identity_key_type,
            identity_public_key,
            signed_prekey_type,
            signed_prekey_public_key,
            signed_prekey_signature,
            one_time_prekey_type,
            one_time_prekeys
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        key_bundle.username,
        key_bundle.identity_key_type,
        key_bundle.identity_public_key,
        key_bundle.signed_prekey_type,
        key_bundle.signed_prekey_public_key,
        key_bundle.signed_prekey_signature,
        key_bundle.one_time_prekey_type,
        one_time_prekeys_json
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

    cursor.execute("""
        INSERT INTO messages (
            sender,
            receiver,
            message_number,
            nonce,
            ciphertext,
            sender_ephemeral_public_key,
            used_one_time_prekey_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        message.sender,
        message.receiver,
        message.message_number,
        message.nonce,
        message.ciphertext,
        message.sender_ephemeral_public_key,
        message.used_one_time_prekey_id
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
            "used_one_time_prekey_id": row["used_one_time_prekey_id"]
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
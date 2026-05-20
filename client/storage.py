import os
import json


DATA_FOLDER = "client_data"
CURRENT_USER_FILE = os.path.join(DATA_FOLDER, "current_user.json")


def create_data_folder():
    if not os.path.exists(DATA_FOLDER):
        os.makedirs(DATA_FOLDER)


def get_user_folder(username):
    create_data_folder()

    user_folder = os.path.join(DATA_FOLDER, username)

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    return user_folder


def save_json_file(file_path, data):
    folder_path = os.path.dirname(file_path)

    if folder_path != "" and not os.path.exists(folder_path):
        os.makedirs(folder_path)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)


def load_json_file(file_path):
    if not os.path.exists(file_path):
        return None

    with open(file_path, "r") as file:
        return json.load(file)


# current user

def save_current_user(username):
    create_data_folder()

    data = {
        "username": username
    }

    save_json_file(CURRENT_USER_FILE, data)


def load_current_user():
    data = load_json_file(CURRENT_USER_FILE)

    if data is None:
        return None

    return data.get("username")


def clear_current_user():
    if os.path.exists(CURRENT_USER_FILE):
        os.remove(CURRENT_USER_FILE)


# local key storage

def save_user_keys(username, key_data):
    user_folder = get_user_folder(username)
    file_path = os.path.join(user_folder, "keys.json")

    save_json_file(file_path, key_data)


def load_user_keys(username):
    user_folder = get_user_folder(username)
    file_path = os.path.join(user_folder, "keys.json")

    return load_json_file(file_path)


# session storage

def save_session(username, contact_username, session_data):
    user_folder = get_user_folder(username)
    session_folder = os.path.join(user_folder, "sessions")

    if not os.path.exists(session_folder):
        os.makedirs(session_folder)

    file_path = os.path.join(session_folder, f"{contact_username}.json")

    save_json_file(file_path, session_data)


def load_session(username, contact_username):
    user_folder = get_user_folder(username)
    file_path = os.path.join(user_folder, "sessions", f"{contact_username}.json")

    return load_json_file(file_path)


def session_exists(username, contact_username):
    session_data = load_session(username, contact_username)

    return session_data is not None


# message counter storage

def get_message_counter(username, contact_username):
    session_data = load_session(username, contact_username)

    if session_data is None:
        return 0

    return session_data.get("message_counter", 0)


def increase_message_counter(username, contact_username):
    session_data = load_session(username, contact_username)

    if session_data is None:
        session_data = {
            "message_counter": 0
        }

    current_counter = session_data.get("message_counter", 0)
    session_data["message_counter"] = current_counter + 1

    save_session(username, contact_username, session_data)

    return session_data["message_counter"]


# chat history storage

def save_message_to_history(username, contact_username, message_data):
    user_folder = get_user_folder(username)
    history_folder = os.path.join(user_folder, "history")

    if not os.path.exists(history_folder):
        os.makedirs(history_folder)

    file_path = os.path.join(history_folder, f"{contact_username}.json")

    history = load_json_file(file_path)

    if history is None:
        history = []

    history.append(message_data)

    save_json_file(file_path, history)


def load_chat_history(username, contact_username):
    user_folder = get_user_folder(username)
    file_path = os.path.join(user_folder, "history", f"{contact_username}.json")

    history = load_json_file(file_path)

    if history is None:
        return []

    return history
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from schemas import (
    RegisterRequest,
    LoginRequest,
    KeyBundleRequest,
    EncryptedMessageRequest
)

from database import (
    create_tables,
    add_user,
    user_exists,
    verify_user,
    get_key_bundle,
    get_key_bundle_info,
    save_key_bundle,
    remove_one_time_prekey,
    save_message,
    get_messages_for_user,
    delete_messages_for_user,
    get_message_count,
    get_user_count
)


app = FastAPI(title="E2EE Messenger Server")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def start_server():
    create_tables()


@app.post("/register")
def register_user(request: RegisterRequest):
    username = request.username.strip()
    password = request.password

    if username == "" or password == "":
        return {
            "success": False,
            "message": "Username and password cannot be empty."
        }

    if user_exists(username):
        return {
            "success": False,
            "message": "Username already exists."
        }

    is_created = add_user(username, password)

    if is_created:
        return {
            "success": True,
            "message": "User registered successfully."
        }

    return {
        "success": False,
        "message": "Registration failed."
    }


@app.post("/login")
def login_user(request: LoginRequest):
    username = request.username.strip()
    password = request.password

    is_valid_user = verify_user(username, password)

    if is_valid_user:
        return {
            "success": True,
            "message": "Login successful."
        }

    return {
        "success": False,
        "message": "Invalid username or password."
    }


@app.post("/upload_keys")
def upload_keys(request: KeyBundleRequest):
    if not user_exists(request.username):
        return {
            "success": False,
            "message": "User does not exist."
        }

    one_time_prekeys = []

    for prekey in request.one_time_prekeys:
        prekey_data = {
            "id": prekey.id,
            "public_key": prekey.public_key
        }

        one_time_prekeys.append(prekey_data)

    normalized_bundle = SimpleNamespace(
        username=request.username,

        identity_key_type=request.identity_key_type,
        identity_public_key=request.identity_public_key,

        signed_prekey_type=request.signed_prekey_type,
        signed_prekey_public_key=request.signed_prekey_public_key,
        signed_prekey_signature=request.signed_prekey_signature,

        one_time_prekey_type=request.one_time_prekey_type,
        one_time_prekeys=one_time_prekeys
    )

    save_key_bundle(normalized_bundle)

    return {
        "success": True,
        "message": "Key bundle uploaded successfully."
    }


@app.get("/keys/{username}")
def get_keys(username: str):
    key_bundle = get_key_bundle(username)

    if key_bundle is None:
        return {
            "success": False,
            "message": "Key bundle not found."
        }

    one_time_prekeys = key_bundle.get("one_time_prekeys", [])

    if len(one_time_prekeys) > 0:
        selected_prekey = one_time_prekeys[0]
        key_bundle["one_time_prekeys"] = [selected_prekey]

        remove_one_time_prekey(
            username,
            selected_prekey["id"]
        )
    else:
        key_bundle["one_time_prekeys"] = []

    return {
        "success": True,
        "message": "Key bundle found.",
        "key_bundle": key_bundle
    }


@app.get("/keys/{username}/info")
def get_keys_info(username: str):
    if not user_exists(username):
        return {
            "success": False,
            "message": "User does not exist."
        }

    key_info = get_key_bundle_info(username)

    if key_info is None:
        return {
            "success": False,
            "message": "Key bundle not found."
        }

    return {
        "success": True,
        "key_info": key_info
    }


@app.post("/send_message")
def send_encrypted_message(request: EncryptedMessageRequest):
    if not user_exists(request.sender):
        return {
            "success": False,
            "message": "Sender does not exist."
        }

    if not user_exists(request.receiver):
        return {
            "success": False,
            "message": "Receiver does not exist."
        }

    save_message(request)

    return {
        "success": True,
        "message": "Encrypted message stored successfully."
    }


@app.get("/messages/{username}")
def get_user_messages(username: str):
    if not user_exists(username):
        return {
            "success": False,
            "message": "User does not exist.",
            "messages": []
        }

    messages = get_messages_for_user(username)

    delete_messages_for_user(username)

    return {
        "success": True,
        "message": "Messages fetched successfully.",
        "messages": messages
    }


@app.get("/")
def home():
    return {
        "success": True,
        "message": "E2EE Messenger Server is running."
    }


@app.get("/user/{username}/exists")
def check_user(username: str):
    if user_exists(username):
        return {
            "success": True,
            "exists": True,
            "message": "User found."
        }

    return {
        "success": True,
        "exists": False,
        "message": "User not found."
    }


@app.get("/stats")
def server_stats():
    stats = {
        "success": True,
        "registered_users": get_user_count(),
        "pending_messages": get_message_count()
    }

    return stats
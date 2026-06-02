import os
import uuid
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def bytes_to_string(data):
    return base64.b64encode(data).decode("utf-8")


def string_to_bytes(data):
    return base64.b64decode(data.encode("utf-8"))


def make_random_id(prefix):
    return prefix + "_" + str(uuid.uuid4())


def generate_identity_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_signed_prekey_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_one_time_prekey_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def export_public_key(public_key):
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return bytes_to_string(key_bytes)


def export_private_key(private_key):
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return bytes_to_string(key_bytes)


def import_public_key(public_key_text, key_type):
    key_bytes = string_to_bytes(public_key_text)

    if key_type == "ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    if key_type == "x25519":
        return x25519.X25519PublicKey.from_public_bytes(key_bytes)

    raise ValueError("Unknown public key type")


def import_private_key(private_key_text, key_type):
    key_bytes = string_to_bytes(private_key_text)

    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

    if key_type == "x25519":
        return x25519.X25519PrivateKey.from_private_bytes(key_bytes)

    raise ValueError("Unknown private key type")


def generate_one_time_prekeys(count=10):
    prekeys = []

    for i in range(count):
        private_key, public_key = generate_one_time_prekey_pair()

        prekeys.append({
            "id": make_random_id("otk"),
            "private_key": export_private_key(private_key),
            "public_key": export_public_key(public_key)
        })

    return prekeys


def sign_prekey(identity_private_key, signed_prekey_public_key):
    public_key_text = export_public_key(signed_prekey_public_key)
    message = public_key_text.encode("utf-8")
    signature = identity_private_key.sign(message)
    return bytes_to_string(signature)


def verify_prekey_signature(identity_public_key, signed_prekey_public_key, signature_text):
    public_key_text = export_public_key(signed_prekey_public_key)
    message = public_key_text.encode("utf-8")
    signature = string_to_bytes(signature_text)

    try:
        identity_public_key.verify(signature, message)
        return True
    except Exception:
        return False


def create_user_key_data(username, one_time_prekey_count=10):
    identity_private_key, identity_public_key = generate_identity_key_pair()
    signed_prekey_private_key, signed_prekey_public_key = generate_signed_prekey_pair()

    signed_prekey_signature = sign_prekey(
        identity_private_key,
        signed_prekey_public_key
    )

    one_time_prekeys = generate_one_time_prekeys(one_time_prekey_count)

    return {
        "username": username,

        "identity_key_type": "ed25519",
        "identity_private_key": export_private_key(identity_private_key),
        "identity_public_key": export_public_key(identity_public_key),

        "signed_prekey_type": "x25519",
        "signed_prekey_private_key": export_private_key(signed_prekey_private_key),
        "signed_prekey_public_key": export_public_key(signed_prekey_public_key),
        "signed_prekey_signature": signed_prekey_signature,

        "one_time_prekey_type": "x25519",
        "one_time_prekeys": one_time_prekeys
    }


def create_public_key_bundle(key_data):
    public_one_time_prekeys = []

    for prekey in key_data["one_time_prekeys"]:
        public_one_time_prekeys.append({
            "id": prekey["id"],
            "public_key": prekey["public_key"]
        })

    return {
        "username": key_data["username"],

        "identity_key_type": "ed25519",
        "identity_public_key": key_data["identity_public_key"],

        "signed_prekey_type": "x25519",
        "signed_prekey_public_key": key_data["signed_prekey_public_key"],
        "signed_prekey_signature": key_data["signed_prekey_signature"],

        "one_time_prekey_type": "x25519",
        "one_time_prekeys": public_one_time_prekeys
    }


def validate_public_key_bundle(bundle):
    try:
        identity_public_key = import_public_key(
            bundle["identity_public_key"],
            "ed25519"
        )

        signed_prekey_public_key = import_public_key(
            bundle["signed_prekey_public_key"],
            "x25519"
        )

        return verify_prekey_signature(
            identity_public_key,
            signed_prekey_public_key,
            bundle["signed_prekey_signature"]
        )

    except Exception:
        return False


def get_first_one_time_prekey_from_bundle(bundle):
    one_time_prekeys = bundle.get("one_time_prekeys", [])

    if len(one_time_prekeys) == 0:
        return None

    return one_time_prekeys[0]


def find_one_time_private_key(key_data, one_time_prekey_id):
    for prekey in key_data["one_time_prekeys"]:
        if prekey["id"] == one_time_prekey_id:
            return prekey["private_key"]

    return None


def remove_used_one_time_prekey(key_data, one_time_prekey_id):
    remaining_prekeys = []

    for prekey in key_data["one_time_prekeys"]:
        if prekey["id"] != one_time_prekey_id:
            remaining_prekeys.append(prekey)

    key_data["one_time_prekeys"] = remaining_prekeys
    return key_data


def hkdf_derive_key(input_data, info_text, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info_text.encode("utf-8")
    )

    return hkdf.derive(input_data)


def derive_sender_session_key(
    sender_ephemeral_private_key,
    receiver_signed_prekey_public_key,
    receiver_one_time_prekey_public_key=None
):
    shared_secrets = []

    shared_secrets.append(
        sender_ephemeral_private_key.exchange(receiver_signed_prekey_public_key)
    )

    if receiver_one_time_prekey_public_key is not None:
        shared_secrets.append(
            sender_ephemeral_private_key.exchange(receiver_one_time_prekey_public_key)
        )

    combined_secret = b"".join(shared_secrets)

    return hkdf_derive_key(
        combined_secret,
        "simple-signal-inspired-session-key"
    )


def derive_receiver_session_key(
    receiver_signed_prekey_private_key,
    sender_ephemeral_public_key,
    receiver_one_time_prekey_private_key=None
):
    shared_secrets = []

    shared_secrets.append(
        receiver_signed_prekey_private_key.exchange(sender_ephemeral_public_key)
    )

    if receiver_one_time_prekey_private_key is not None:
        shared_secrets.append(
            receiver_one_time_prekey_private_key.exchange(sender_ephemeral_public_key)
        )

    combined_secret = b"".join(shared_secrets)

    return hkdf_derive_key(
        combined_secret,
        "simple-signal-inspired-session-key"
    )


def create_sender_session_from_bundle(receiver_bundle):
    if not validate_public_key_bundle(receiver_bundle):
        raise ValueError("Receiver key bundle is not valid")

    sender_ephemeral_private_key = x25519.X25519PrivateKey.generate()
    sender_ephemeral_public_key = sender_ephemeral_private_key.public_key()

    receiver_signed_prekey_public_key = import_public_key(
        receiver_bundle["signed_prekey_public_key"],
        "x25519"
    )

    selected_prekey = get_first_one_time_prekey_from_bundle(receiver_bundle)
    receiver_one_time_prekey_public_key = None
    used_one_time_prekey_id = None

    if selected_prekey is not None:
        receiver_one_time_prekey_public_key = import_public_key(
            selected_prekey["public_key"],
            "x25519"
        )
        used_one_time_prekey_id = selected_prekey["id"]

    session_key = derive_sender_session_key(
        sender_ephemeral_private_key,
        receiver_signed_prekey_public_key,
        receiver_one_time_prekey_public_key
    )

    return {
        "session_key": bytes_to_string(session_key),
        "sender_ephemeral_public_key": export_public_key(sender_ephemeral_public_key),
        "used_one_time_prekey_id": used_one_time_prekey_id,
        "message_counter": 0
    }


def create_receiver_session_from_packet(receiver_key_data, packet):
    sender_ephemeral_public_key = import_public_key(
        packet["sender_ephemeral_public_key"],
        "x25519"
    )

    receiver_signed_prekey_private_key = import_private_key(
        receiver_key_data["signed_prekey_private_key"],
        "x25519"
    )

    used_one_time_prekey_id = packet.get("used_one_time_prekey_id")
    receiver_one_time_prekey_private_key = None

    if used_one_time_prekey_id is not None:
        private_key_text = find_one_time_private_key(
            receiver_key_data,
            used_one_time_prekey_id
        )

        if private_key_text is not None:
            receiver_one_time_prekey_private_key = import_private_key(
                private_key_text,
                "x25519"
            )

    session_key = derive_receiver_session_key(
        receiver_signed_prekey_private_key,
        sender_ephemeral_public_key,
        receiver_one_time_prekey_private_key
    )

    return {
        "session_key": bytes_to_string(session_key),
        "sender_ephemeral_public_key": packet["sender_ephemeral_public_key"],
        "used_one_time_prekey_id": used_one_time_prekey_id,
        "message_counter": 0
    }


def derive_message_key(session_key_text, message_number):
    session_key = string_to_bytes(session_key_text)
    info_text = "message-key-" + str(message_number)

    return hkdf_derive_key(
        session_key,
        info_text
    )


def create_associated_data(sender_username, receiver_username, message_number):
    data_text = sender_username + "|" + receiver_username + "|" + str(message_number)
    return data_text.encode("utf-8")


def encrypt_message(session_key_text, message, message_number, sender_username, receiver_username):
    message_key = derive_message_key(session_key_text, message_number)
    aesgcm = AESGCM(message_key)

    nonce = os.urandom(12)
    message_bytes = message.encode("utf-8")

    associated_data = create_associated_data(
        sender_username,
        receiver_username,
        message_number
    )

    ciphertext = aesgcm.encrypt(
        nonce,
        message_bytes,
        associated_data
    )

    return {
        "nonce": bytes_to_string(nonce),
        "ciphertext": bytes_to_string(ciphertext)
    }


def decrypt_message(session_key_text, encrypted_data, message_number, sender_username, receiver_username):
    message_key = derive_message_key(session_key_text, message_number)
    aesgcm = AESGCM(message_key)

    nonce = string_to_bytes(encrypted_data["nonce"])
    ciphertext = string_to_bytes(encrypted_data["ciphertext"])

    associated_data = create_associated_data(
        sender_username,
        receiver_username,
        message_number
    )

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data
    )

    return plaintext.decode("utf-8")


def create_encrypted_message_packet(
    sender_username,
    receiver_username,
    session_data,
    message
):
    message_number = session_data.get("message_counter", 0) + 1
    session_data["message_counter"] = message_number

    encrypted_data = encrypt_message(
        session_data["session_key"],
        message,
        message_number,
        sender_username,
        receiver_username
    )

    packet = {
        "sender": sender_username,
        "receiver": receiver_username,
        "message_number": message_number,
        "nonce": encrypted_data["nonce"],
        "ciphertext": encrypted_data["ciphertext"]
    }

    if "sender_ephemeral_public_key" in session_data:
        packet["sender_ephemeral_public_key"] = session_data["sender_ephemeral_public_key"]

    if "used_one_time_prekey_id" in session_data:
        packet["used_one_time_prekey_id"] = session_data["used_one_time_prekey_id"]

    return packet, session_data


def decrypt_encrypted_message_packet(session_data, packet):
    encrypted_data = {
        "nonce": packet["nonce"],
        "ciphertext": packet["ciphertext"]
    }

    return decrypt_message(
        session_data["session_key"],
        encrypted_data,
        packet["message_number"],
        packet["sender"],
        packet["receiver"]
    )
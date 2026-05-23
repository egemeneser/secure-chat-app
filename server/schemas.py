from pydantic import BaseModel
from typing import List, Optional


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class OneTimePrekey(BaseModel):
    id: str
    public_key: str


class KeyBundleRequest(BaseModel):
    username: str

    identity_key_type: str
    identity_public_key: str

    signed_prekey_type: str
    signed_prekey_public_key: str
    signed_prekey_signature: str

    one_time_prekey_type: str
    one_time_prekeys: List[OneTimePrekey]


class EncryptedMessageRequest(BaseModel):
    sender: str
    receiver: str

    message_number: int
    nonce: str
    ciphertext: str

    sender_ephemeral_public_key: Optional[str] = None
    used_one_time_prekey_id: Optional[str] = None


class SimpleResponse(BaseModel):
    success: bool
    message: str
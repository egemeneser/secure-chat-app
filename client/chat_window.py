from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox
)

from api_client import ApiClient

from storage import (
    load_user_keys,
    save_user_keys,
    load_session,
    save_session,
    save_message_to_history,
    load_chat_history
)

from encryption import (
    create_user_key_data,
    create_public_key_bundle,
    create_sender_session_from_bundle,
    create_receiver_session_from_packet,
    create_encrypted_message_packet,
    decrypt_encrypted_message_packet,
    remove_used_one_time_prekey
)


class ChatWindow(QWidget):
    def __init__(self, username):
        super().__init__()

        self.username = username
        self.api_client = ApiClient()

        self.setWindowTitle("E2EE Messenger - " + self.username)
        self.setFixedSize(600, 500)

        self.create_ui()
        self.prepare_user_keys()

    def create_ui(self):
        self.user_label = QLabel("Logged in as: " + self.username)

        self.contact_input = QLineEdit()
        self.contact_input.setPlaceholderText("Receiver username")

        self.load_history_button = QPushButton("Load History")
        self.load_history_button.clicked.connect(self.load_selected_chat_history)

        contact_layout = QHBoxLayout()
        contact_layout.addWidget(self.contact_input)
        contact_layout.addWidget(self.load_history_button)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Write your message")

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        self.refresh_button = QPushButton("Refresh Messages")
        self.refresh_button.clicked.connect(self.refresh_messages)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.refresh_button)

        layout = QVBoxLayout()
        layout.addWidget(self.user_label)
        layout.addLayout(contact_layout)
        layout.addWidget(self.chat_area)
        layout.addWidget(self.message_input)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    # ---------------------------------------------------------
    # Key setup
    # ---------------------------------------------------------

    def prepare_user_keys(self):
        key_data = load_user_keys(self.username)

        if key_data is None:
            key_data = create_user_key_data(self.username, one_time_prekey_count=10)
            save_user_keys(self.username, key_data)

        public_key_bundle = create_public_key_bundle(key_data)
        response = self.api_client.upload_key_bundle(public_key_bundle)

        if not response["success"]:
            QMessageBox.warning(
                self,
                "Key Upload Failed",
                response["message"]
            )

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def get_contact_username(self):
        contact_username = self.contact_input.text().strip()

        if contact_username == "":
            QMessageBox.warning(
                self,
                "Missing Contact",
                "Please enter receiver username."
            )
            return None

        if contact_username == self.username:
            QMessageBox.warning(
                self,
                "Invalid Contact",
                "You cannot send a message to yourself."
            )
            return None

        return contact_username

    def show_message(self, sender, message):
        self.chat_area.append(sender + ": " + message)

    # ---------------------------------------------------------
    # Session handling
    # ---------------------------------------------------------

    def get_or_create_sender_session(self, contact_username):
        session_data = load_session(self.username, contact_username)

        if session_data is not None:
            return session_data

        response = self.api_client.get_key_bundle(contact_username)

        if not response["success"]:
            QMessageBox.warning(
                self,
                "Key Error",
                response["message"]
            )
            return None

        receiver_bundle = response["key_bundle"]

        try:
            session_data = create_sender_session_from_bundle(receiver_bundle)
            save_session(self.username, contact_username, session_data)
            return session_data

        except Exception as error:
            QMessageBox.warning(
                self,
                "Session Error",
                "Could not create session: " + str(error)
            )
            return None

    def get_or_create_receiver_session(self, sender_username, packet):
        session_data = load_session(self.username, sender_username)

        if session_data is not None:
            return session_data

        key_data = load_user_keys(self.username)

        if key_data is None:
            QMessageBox.warning(
                self,
                "Key Error",
                "Local key data not found."
            )
            return None

        try:
            session_data = create_receiver_session_from_packet(key_data, packet)
            save_session(self.username, sender_username, session_data)

            used_one_time_prekey_id = packet.get("used_one_time_prekey_id")

            if used_one_time_prekey_id is not None:
                key_data = remove_used_one_time_prekey(
                    key_data,
                    used_one_time_prekey_id
                )
                save_user_keys(self.username, key_data)

            return session_data

        except Exception as error:
            QMessageBox.warning(
                self,
                "Session Error",
                "Could not create receiver session: " + str(error)
            )
            return None

    # ---------------------------------------------------------
    # Sending messages
    # ---------------------------------------------------------

    def send_message(self):
        contact_username = self.get_contact_username()

        if contact_username is None:
            return

        message = self.message_input.text().strip()

        if message == "":
            QMessageBox.warning(
                self,
                "Empty Message",
                "Please write a message."
            )
            return

        session_data = self.get_or_create_sender_session(contact_username)

        if session_data is None:
            return

        try:
            packet, updated_session_data = create_encrypted_message_packet(
                self.username,
                contact_username,
                session_data,
                message
            )

            save_session(
                self.username,
                contact_username,
                updated_session_data
            )

            response = self.api_client.send_message(packet)

            if response["success"]:
                self.show_message("Me", message)

                history_data = {
                    "direction": "sent",
                    "sender": self.username,
                    "receiver": contact_username,
                    "message": message
                }

                save_message_to_history(
                    self.username,
                    contact_username,
                    history_data
                )

                self.message_input.clear()

            else:
                QMessageBox.warning(
                    self,
                    "Send Failed",
                    response["message"]
                )

        except Exception as error:
            QMessageBox.warning(
                self,
                "Encryption Error",
                "Could not encrypt or send message: " + str(error)
            )

    # ---------------------------------------------------------
    # Receiving messages
    # ---------------------------------------------------------

    def refresh_messages(self):
        response = self.api_client.get_messages(self.username)

        if not response["success"]:
            QMessageBox.warning(
                self,
                "Message Error",
                response["message"]
            )
            return

        messages = response.get("messages", [])

        if len(messages) == 0:
            QMessageBox.information(
                self,
                "No Messages",
                "There are no new messages."
            )
            return

        for packet in messages:
            self.handle_incoming_packet(packet)

    def handle_incoming_packet(self, packet):
        sender_username = packet["sender"]

        session_data = self.get_or_create_receiver_session(
            sender_username,
            packet
        )

        if session_data is None:
            return

        try:
            plaintext = decrypt_encrypted_message_packet(
                session_data,
                packet
            )

            self.show_message(sender_username, plaintext)

            history_data = {
                "direction": "received",
                "sender": sender_username,
                "receiver": self.username,
                "message": plaintext
            }

            save_message_to_history(
                self.username,
                sender_username,
                history_data
            )

        except Exception as error:
            QMessageBox.warning(
                self,
                "Decrypt Error",
                "Could not decrypt message: " + str(error)
            )

    # ---------------------------------------------------------
    # Chat history
    # ---------------------------------------------------------

    def load_selected_chat_history(self):
        contact_username = self.get_contact_username()

        if contact_username is None:
            return

        history = load_chat_history(self.username, contact_username)

        self.chat_area.clear()

        for item in history:
            if item["direction"] == "sent":
                self.show_message("Me", item["message"])
            else:
                self.show_message(item["sender"], item["message"])
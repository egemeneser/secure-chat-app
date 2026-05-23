from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QFrame,
    QScrollArea,
    QSizePolicy,
    QListWidget,
    QListWidgetItem,
    QDialog,
    QTextEdit
)
from PyQt6.QtCore import Qt, QTimer

from api_client import ApiClient
from styles import theme_manager

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


def truncate_key(key_string, length=16):
    """Truncate a base64 key string for display."""
    if key_string is None or len(key_string) <= length:
        return key_string
    return key_string[:length] + "..."


class SecurityInfoDialog(QDialog):
    """
    Dialog that displays encryption details for a conversation.
    Shows identity keys, session keys, and encryption parameters
    so the TA can verify E2EE is working correctly.
    """

    def __init__(self, username, contact, api_client, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Security Info")
        self.setFixedSize(520, 480)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = QLabel("Encryption Details")
        title.setObjectName("chat_header_label")
        layout.addWidget(title)

        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet("font-family: monospace; font-size: 12px;")

        lines = []
        lines.append("=" * 50)
        lines.append("  SESSION SECURITY INFORMATION")
        lines.append("=" * 50)
        lines.append("")

        # Local user key info
        from storage import load_user_keys, load_session

        key_data = load_user_keys(username)

        if key_data is not None:
            lines.append("YOUR KEYS (" + username + ")")
            lines.append("-" * 40)
            lines.append("Identity Key Type:   " + key_data.get("identity_key_type", "N/A"))
            lines.append("Identity Public Key: " + truncate_key(key_data.get("identity_public_key", "N/A")))
            lines.append("Signed PreKey Type:  " + key_data.get("signed_prekey_type", "N/A"))
            lines.append("Signed PreKey:       " + truncate_key(key_data.get("signed_prekey_public_key", "N/A")))
            otk_count = len(key_data.get("one_time_prekeys", []))
            lines.append("One-Time PreKeys:    " + str(otk_count) + " remaining")
            lines.append("")

        # Contact key info from server
        if contact is not None:
            response = api_client.get_key_bundle_info(contact)

            if response.get("success"):
                info = response["key_info"]
                lines.append("CONTACT KEYS (" + contact + ")")
                lines.append("-" * 40)
                lines.append("Identity Key Type:   " + info.get("identity_key_type", "N/A"))
                lines.append("Identity Public Key: " + truncate_key(info.get("identity_public_key", "N/A")))
                lines.append("Signed PreKey Type:  " + info.get("signed_prekey_type", "N/A"))
                lines.append("Signed PreKey:       " + truncate_key(info.get("signed_prekey_public_key", "N/A")))
                lines.append("One-Time PreKeys:    " + str(info.get("one_time_prekeys_remaining", 0)) + " remaining")
                lines.append("")

            # Session info
            session_data = load_session(username, contact)

            if session_data is not None:
                lines.append("SESSION DATA")
                lines.append("-" * 40)
                lines.append("Session Key:         " + truncate_key(session_data.get("session_key", "N/A")))
                lines.append("Ephemeral Key:       " + truncate_key(session_data.get("sender_ephemeral_public_key", "N/A")))
                lines.append("Messages Sent:       " + str(session_data.get("message_counter", 0)))
                otk_id = session_data.get("used_one_time_prekey_id")
                lines.append("Used OTK ID:         " + (truncate_key(otk_id) if otk_id else "None"))
                lines.append("")

        lines.append("ENCRYPTION PARAMETERS")
        lines.append("-" * 40)
        lines.append("Protocol:            Signal (simplified)")
        lines.append("Key Exchange:        X3DH (X25519 + Ed25519)")
        lines.append("Symmetric Cipher:    AES-256-GCM")
        lines.append("Key Derivation:      HKDF-SHA256")
        lines.append("Per-Message Keys:    Yes (counter-based)")
        lines.append("")
        lines.append("=" * 50)

        info_text.setPlainText("\n".join(lines))
        layout.addWidget(info_text)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

        self.setLayout(layout)


class MessageBubble(QFrame):
    """
    Custom widget for a single chat message bubble.
    Sent messages are right-aligned, received messages are left-aligned.
    """

    def __init__(self, message_text, sender_name, timestamp, is_sent=True, parent=None):
        super().__init__(parent)

        self.is_sent = is_sent

        if is_sent:
            self.setObjectName("sent_bubble")
        else:
            self.setObjectName("received_bubble")

        bubble_layout = QVBoxLayout()
        bubble_layout.setContentsMargins(12, 8, 12, 6)
        bubble_layout.setSpacing(2)

        # Sender name label (only for received messages)
        if not is_sent:
            name_label = QLabel(sender_name)
            name_label.setObjectName("sender_name")
            bubble_layout.addWidget(name_label)

        # Message text
        text_label = QLabel(message_text)
        text_label.setWordWrap(True)
        text_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        if is_sent:
            text_label.setObjectName("sent_message_text")
        else:
            text_label.setObjectName("received_message_text")

        bubble_layout.addWidget(text_label)

        # Timestamp
        time_label = QLabel(timestamp)

        if is_sent:
            time_label.setObjectName("sent_timestamp")
            time_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        else:
            time_label.setObjectName("received_timestamp")
            time_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        bubble_layout.addWidget(time_label)

        self.setLayout(bubble_layout)
        self.setMaximumWidth(340)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)


class ChatWindow(QWidget):
    def __init__(self, username):
        super().__init__()

        self.username = username
        self.api_client = ApiClient()
        self.current_contact = None

        self.setWindowTitle("E2EE Messenger — " + self.username)
        self.setMinimumSize(800, 540)
        self.resize(860, 580)

        self.create_ui()
        self.prepare_user_keys()

        # Auto-refresh timer
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.silent_refresh)
        self.refresh_timer.start(5000)

    def create_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ==========================================
        # LEFT SIDEBAR
        # ==========================================
        sidebar = QFrame()
        sidebar.setObjectName("sidebar_frame")
        sidebar.setFixedWidth(240)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Sidebar header
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(14, 14, 14, 10)

        self.user_label = QLabel(self.username)
        self.user_label.setObjectName("user_label")
        header_layout.addWidget(self.user_label)

        header_layout.addStretch()

        sidebar_layout.addLayout(header_layout)

        # Separator
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.Shape.HLine)
        sidebar_layout.addWidget(sep)

        # New chat input
        input_row = QHBoxLayout()
        input_row.setContentsMargins(10, 10, 10, 8)
        input_row.setSpacing(6)

        self.contact_input = QLineEdit()
        self.contact_input.setPlaceholderText("Username...")
        self.contact_input.setMinimumHeight(34)
        self.contact_input.returnPressed.connect(self.start_new_chat)
        input_row.addWidget(self.contact_input)

        add_button = QPushButton("+")
        add_button.setObjectName("icon_button")
        add_button.setFixedSize(34, 34)
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.setToolTip("Start new chat")
        add_button.clicked.connect(self.start_new_chat)
        input_row.addWidget(add_button)

        sidebar_layout.addLayout(input_row)

        # Section label
        chats_label = QLabel("CHATS")
        chats_label.setObjectName("section_label")
        sidebar_layout.addWidget(chats_label)

        # Contact list
        self.contact_list = QListWidget()
        self.contact_list.itemClicked.connect(self.on_contact_selected)
        sidebar_layout.addWidget(self.contact_list)

        # Theme toggle at bottom of sidebar
        sidebar_bottom = QHBoxLayout()
        sidebar_bottom.setContentsMargins(10, 6, 10, 10)

        self.theme_button = QPushButton(theme_manager.get_toggle_icon())
        self.theme_button.setObjectName("theme_toggle")
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.setFixedHeight(26)
        self.theme_button.clicked.connect(self.toggle_theme)
        sidebar_bottom.addWidget(self.theme_button)

        sidebar_bottom.addStretch()

        sidebar_layout.addLayout(sidebar_bottom)

        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)

        # ==========================================
        # RIGHT CHAT AREA
        # ==========================================
        chat_panel = QVBoxLayout()
        chat_panel.setContentsMargins(0, 0, 0, 0)
        chat_panel.setSpacing(0)

        # Chat header
        self.chat_header = QFrame()
        self.chat_header.setObjectName("chat_header_frame")
        self.chat_header.setFixedHeight(50)

        chat_header_layout = QHBoxLayout()
        chat_header_layout.setContentsMargins(16, 0, 16, 0)

        self.chat_header_label = QLabel("Select a conversation")
        self.chat_header_label.setObjectName("chat_header_label")
        chat_header_layout.addWidget(self.chat_header_label)

        chat_header_layout.addStretch()

        self.security_button = QPushButton("encrypted")
        self.security_button.setObjectName("theme_toggle")
        self.security_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.security_button.setToolTip("View encryption details")
        self.security_button.setFixedHeight(28)
        self.security_button.clicked.connect(self.show_security_info)
        chat_header_layout.addWidget(self.security_button)

        self.chat_header.setLayout(chat_header_layout)
        chat_panel.addWidget(self.chat_header)

        # Message scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout()
        self.messages_layout.setContentsMargins(16, 12, 16, 12)
        self.messages_layout.setSpacing(6)
        self.messages_layout.addStretch()

        self.messages_container.setLayout(self.messages_layout)
        self.scroll_area.setWidget(self.messages_container)

        # Empty state
        self.empty_label = QLabel("No conversation selected")
        self.empty_label.setObjectName("empty_chat_label")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        chat_panel.addWidget(self.empty_label)
        chat_panel.addWidget(self.scroll_area)
        self.scroll_area.hide()

        # Input area
        self.input_frame = QFrame()
        self.input_frame.setObjectName("input_frame")

        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(14, 8, 14, 8)
        input_layout.setSpacing(8)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setMinimumHeight(38)
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.setEnabled(False)
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("send_button")
        self.send_button.setMinimumHeight(38)
        self.send_button.setFixedWidth(80)
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)
        input_layout.addWidget(self.send_button)

        self.input_frame.setLayout(input_layout)
        chat_panel.addWidget(self.input_frame)

        chat_widget = QWidget()
        chat_widget.setLayout(chat_panel)
        main_layout.addWidget(chat_widget)

        self.setLayout(main_layout)

    # ---------------------------------------------------------
    # Theme toggle
    # ---------------------------------------------------------

    def toggle_theme(self):
        theme_manager.toggle_theme()
        self.theme_button.setText(theme_manager.get_toggle_icon())

    # ---------------------------------------------------------
    # Security info
    # ---------------------------------------------------------

    def show_security_info(self):
        dialog = SecurityInfoDialog(
            self.username,
            self.current_contact,
            self.api_client,
            self
        )
        dialog.exec()

    # ---------------------------------------------------------
    # Contact / conversation management
    # ---------------------------------------------------------

    def start_new_chat(self):
        contact_username = self.contact_input.text().strip()

        if contact_username == "":
            return

        if contact_username == self.username:
            QMessageBox.warning(
                self,
                "Invalid Contact",
                "You cannot chat with yourself."
            )
            return

        # Check if user exists on the server
        response = self.api_client.check_user_exists(contact_username)

        if not response.get("success"):
            QMessageBox.warning(
                self,
                "Connection Error",
                response.get("message", "Could not check user.")
            )
            return

        if not response.get("exists", False):
            QMessageBox.warning(
                self,
                "User Not Found",
                "No registered user named '" + contact_username + "' was found."
            )
            return

        # Add to contact list if not there
        found = False
        for i in range(self.contact_list.count()):
            item = self.contact_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == contact_username:
                found = True
                self.contact_list.setCurrentItem(item)
                break

        if not found:
            item = QListWidgetItem(contact_username)
            item.setData(Qt.ItemDataRole.UserRole, contact_username)
            self.contact_list.addItem(item)
            self.contact_list.setCurrentItem(item)

        self.select_contact(contact_username)
        self.contact_input.clear()

    def on_contact_selected(self, item):
        contact_username = item.data(Qt.ItemDataRole.UserRole)

        if contact_username is not None:
            self.select_contact(contact_username)

    def select_contact(self, contact_username):
        self.current_contact = contact_username

        self.chat_header_label.setText(contact_username)

        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.message_input.setFocus()

        self.empty_label.hide()
        self.scroll_area.show()

        self.load_chat_history_for_contact(contact_username)

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
        if self.current_contact is None or self.current_contact == "":
            QMessageBox.warning(
                self,
                "No Contact",
                "Please select a conversation first."
            )
            return None

        return self.current_contact

    def get_current_time(self):
        return datetime.now().strftime("%H:%M")

    def add_message_bubble(self, message_text, sender_name, is_sent, timestamp=None):
        if timestamp is None:
            timestamp = self.get_current_time()

        bubble = MessageBubble(
            message_text,
            sender_name,
            timestamp,
            is_sent
        )

        container = QHBoxLayout()
        container.setContentsMargins(0, 0, 0, 0)

        if is_sent:
            container.addStretch()
            container.addWidget(bubble)
        else:
            container.addWidget(bubble)
            container.addStretch()

        count = self.messages_layout.count()
        self.messages_layout.insertLayout(count - 1, container)

        QTimer.singleShot(50, self.scroll_to_bottom)

    def scroll_to_bottom(self):
        scrollbar = self.scroll_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_messages(self):
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

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
                self.add_message_bubble(message, self.username, True)

                history_data = {
                    "direction": "sent",
                    "sender": self.username,
                    "receiver": contact_username,
                    "message": message,
                    "timestamp": self.get_current_time()
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
            return

        for packet in messages:
            self.handle_incoming_packet(packet)

    def silent_refresh(self):
        try:
            response = self.api_client.get_messages(self.username)

            if not response["success"]:
                return

            messages = response.get("messages", [])

            for packet in messages:
                self.handle_incoming_packet(packet)

        except Exception:
            pass

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

            timestamp = self.get_current_time()

            # Add sender to contact list if not there
            found = False
            for i in range(self.contact_list.count()):
                item = self.contact_list.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == sender_username:
                    found = True
                    break

            if not found:
                item = QListWidgetItem(sender_username)
                item.setData(Qt.ItemDataRole.UserRole, sender_username)
                self.contact_list.addItem(item)

            # Show bubble if viewing this contact
            if self.current_contact == sender_username:
                self.add_message_bubble(
                    plaintext,
                    sender_username,
                    False,
                    timestamp
                )

            history_data = {
                "direction": "received",
                "sender": sender_username,
                "receiver": self.username,
                "message": plaintext,
                "timestamp": timestamp
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

    def load_chat_history_for_contact(self, contact_username):
        self.clear_messages()

        history = load_chat_history(self.username, contact_username)

        for item in history:
            is_sent = item["direction"] == "sent"
            sender_name = "Me" if is_sent else item["sender"]
            timestamp = item.get("timestamp", "")

            self.add_message_bubble(
                item["message"],
                sender_name,
                is_sent,
                timestamp
            )
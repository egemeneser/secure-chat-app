from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QSpacerItem,
    QSizePolicy,
    QFrame
)
from PyQt6.QtCore import Qt

from api_client import ApiClient
from chat_window import ChatWindow
from storage import save_current_user
from styles import theme_manager


class LoginWindow(QWidget):
    """Login page. Users who already have an account can sign in here."""

    def __init__(self):
        super().__init__()

        self.api_client = ApiClient()
        self.chat_window = None
        self.register_window = None

        self.setWindowTitle("E2EE Messenger - Sign In")
        self.setFixedSize(380, 420)

        self.create_ui()

    def create_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(40, 35, 40, 25)
        main_layout.setSpacing(0)

        main_layout.addSpacerItem(
            QSpacerItem(20, 30, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        )

        # Title
        title_label = QLabel("Sign In")
        title_label.setObjectName("title_label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Welcome back to E2EE Messenger")
        subtitle_label.setObjectName("subtitle_label")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(subtitle_label)

        main_layout.addSpacing(8)

        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.Shape.HLine)
        main_layout.addWidget(separator)

        main_layout.addSpacing(24)

        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setMinimumHeight(42)
        main_layout.addWidget(self.username_input)

        main_layout.addSpacing(10)

        # Password
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(42)
        self.password_input.returnPressed.connect(self.login_user)
        main_layout.addWidget(self.password_input)

        main_layout.addSpacing(22)

        # Sign In button
        self.login_button = QPushButton("Sign In")
        self.login_button.setObjectName("send_button")
        self.login_button.setMinimumHeight(42)
        self.login_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_button.clicked.connect(self.login_user)
        main_layout.addWidget(self.login_button)

        main_layout.addStretch()

        # Link to register page
        switch_layout = QHBoxLayout()

        no_account_label = QLabel("Don't have an account?")
        no_account_label.setObjectName("status_label")
        switch_layout.addWidget(no_account_label)

        self.switch_button = QPushButton("Create one")
        self.switch_button.setObjectName("theme_toggle")
        self.switch_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.switch_button.setFixedHeight(28)
        self.switch_button.clicked.connect(self.open_register_window)
        switch_layout.addWidget(self.switch_button)

        switch_layout.addStretch()

        main_layout.addLayout(switch_layout)

        main_layout.addSpacing(8)

        # Theme toggle
        footer_layout = QHBoxLayout()

        self.theme_button = QPushButton(theme_manager.get_toggle_icon())
        self.theme_button.setObjectName("theme_toggle")
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.setFixedHeight(28)
        self.theme_button.clicked.connect(self.toggle_theme)
        footer_layout.addWidget(self.theme_button)

        footer_layout.addStretch()

        main_layout.addLayout(footer_layout)

        self.setLayout(main_layout)

    def toggle_theme(self):
        theme_manager.toggle_theme()
        self.theme_button.setText(theme_manager.get_toggle_icon())

    def get_form_values(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if username == "" or password == "":
            QMessageBox.warning(self, "Missing Information", "Please enter username and password.")
            return None, None

        return username, password

    def login_user(self):
        username, password = self.get_form_values()

        if username is None:
            return

        response = self.api_client.login(username, password)

        if response["success"]:
            save_current_user(username)
            self.open_chat_window(username)
        else:
            QMessageBox.warning(self, "Login Failed", response["message"])

    def open_chat_window(self, username):
        self.chat_window = ChatWindow(username)
        self.chat_window.show()
        self.close()

    def open_register_window(self):
        from register_window import RegisterWindow

        self.register_window = RegisterWindow()
        self.register_window.show()
        self.close()
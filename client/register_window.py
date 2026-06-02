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


class RegisterWindow(QWidget):

    def __init__(self):
        super().__init__()

        self.api_client = ApiClient()
        self.chat_window = None
        self.login_window = None

        self.setWindowTitle("E2EE Messenger - Register")
        self.setFixedSize(380, 480)

        self.create_ui()

    def create_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(40, 35, 40, 25)
        main_layout.setSpacing(0)

        spacer = QSpacerItem(
            20,
            30,
            QSizePolicy.Policy.Minimum,
            QSizePolicy.Policy.Fixed
        )
        main_layout.addSpacerItem(spacer)

        title_label = QLabel("Create Account")
        title_label.setObjectName("title_label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        subtitle_label = QLabel("Join E2EE Messenger")
        subtitle_label.setObjectName("subtitle_label")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(subtitle_label)

        main_layout.addSpacing(8)

        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.Shape.HLine)
        main_layout.addWidget(separator)

        main_layout.addSpacing(24)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        self.username_input.setMinimumHeight(42)
        main_layout.addWidget(self.username_input)

        main_layout.addSpacing(10)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Choose a password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(42)
        main_layout.addWidget(self.password_input)

        main_layout.addSpacing(10)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setMinimumHeight(42)
        self.confirm_password_input.returnPressed.connect(self.register_user)
        main_layout.addWidget(self.confirm_password_input)

        main_layout.addSpacing(22)

        self.register_button = QPushButton("Create Account")
        self.register_button.setObjectName("send_button")
        self.register_button.setMinimumHeight(42)
        self.register_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.register_button.clicked.connect(self.register_user)
        main_layout.addWidget(self.register_button)

        main_layout.addStretch()

        switch_layout = QHBoxLayout()

        has_account_label = QLabel("Already have an account?")
        has_account_label.setObjectName("status_label")
        switch_layout.addWidget(has_account_label)

        self.switch_button = QPushButton("Sign in")
        self.switch_button.setObjectName("theme_toggle")
        self.switch_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.switch_button.setFixedHeight(28)
        self.switch_button.clicked.connect(self.open_login_window)
        switch_layout.addWidget(self.switch_button)

        switch_layout.addStretch()
        main_layout.addLayout(switch_layout)

        main_layout.addSpacing(8)

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

    def validate_form(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_password_input.text()

        if username == "" or password == "":
            QMessageBox.warning(
                self,
                "Missing Information",
                "Please fill in all fields."
            )
            return None, None

        if len(username) < 3:
            QMessageBox.warning(
                self,
                "Invalid Username",
                "Username must be at least 3 characters."
            )
            return None, None

        if len(password) < 4:
            QMessageBox.warning(
                self,
                "Weak Password",
                "Password must be at least 4 characters."
            )
            return None, None

        if password != confirm:
            QMessageBox.warning(
                self,
                "Password Mismatch",
                "Passwords do not match."
            )
            return None, None

        return username, password

    def register_user(self):
        username, password = self.validate_form()

        if username is None:
            return

        response = self.api_client.register(username, password)

        if response["success"]:
            save_current_user(username)
            QMessageBox.information(
                self,
                "Success",
                "Account created successfully."
            )
            self.open_chat_window(username)
        else:
            QMessageBox.warning(
                self,
                "Register Failed",
                response["message"]
            )

    def open_chat_window(self, username):
        self.chat_window = ChatWindow(username)
        self.chat_window.show()
        self.close()

    def open_login_window(self):
        from login_window import LoginWindow

        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()
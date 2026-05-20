from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox
)

from api_client import ApiClient
from chat_window import ChatWindow
from storage import save_current_user


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.api_client = ApiClient()
        self.chat_window = None

        self.setWindowTitle("E2EE Messenger - Login")
        self.setFixedSize(350, 250)

        self.create_ui()

    def create_ui(self):
        title_label = QLabel("E2EE Messenger")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Login")
        self.register_button = QPushButton("Register")

        self.login_button.clicked.connect(self.login_user)
        self.register_button.clicked.connect(self.register_user)

        layout = QVBoxLayout()
        layout.addWidget(title_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def get_form_values(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if username == "" or password == "":
            QMessageBox.warning(self, "Missing Information", "Please enter username and password.")
            return None, None

        return username, password

    def register_user(self):
        username, password = self.get_form_values()

        if username is None:
            return

        response = self.api_client.register(username, password)

        if response["success"]:
            save_current_user(username)
            QMessageBox.information(self, "Success", "Registration successful.")
            self.open_chat_window(username)
        else:
            QMessageBox.warning(self, "Register Failed", response["message"])

    def login_user(self):
        username, password = self.get_form_values()

        if username is None:
            return

        response = self.api_client.login(username, password)

        if response["success"]:
            save_current_user(username)
            QMessageBox.information(self, "Success", "Login successful.")
            self.open_chat_window(username)
        else:
            QMessageBox.warning(self, "Login Failed", response["message"])

    def open_chat_window(self, username):
        self.chat_window = ChatWindow(username)
        self.chat_window.show()
        self.close()
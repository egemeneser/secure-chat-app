import sys
from PyQt6.QtWidgets import QApplication
from login_window import LoginWindow
from styles import theme_manager


def main():
    app = QApplication(sys.argv)

    theme_manager.set_app(app)
    theme_manager.apply_theme()

    login_window = LoginWindow()
    login_window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
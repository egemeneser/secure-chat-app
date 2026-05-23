"""
Theme management module for the E2EE Messenger application.
Provides light and dark theme stylesheets and a manager class
to toggle between them at runtime.
"""


# ---------------------------------------------------------
# Color palettes
# ---------------------------------------------------------

DARK_COLORS = {
    "bg_primary": "#1a1a2e",
    "bg_secondary": "#16213e",
    "bg_tertiary": "#0f3460",
    "bg_input": "#1c2541",
    "bg_hover": "#1f3066",

    "text_primary": "#e0e0e0",
    "text_secondary": "#a0a8b8",
    "text_placeholder": "#5c6378",

    "accent": "#3a86ff",
    "accent_hover": "#5a9eff",
    "accent_pressed": "#2670e0",

    "danger": "#e63946",
    "success": "#2ec4b6",
    "warning": "#ffbe0b",

    "bubble_sent": "#3a86ff",
    "bubble_sent_text": "#ffffff",
    "bubble_received": "#252a3a",
    "bubble_received_text": "#e0e0e0",

    "border": "#2a3050",
    "border_focus": "#3a86ff",

    "sidebar_bg": "#12122a",
    "sidebar_item_hover": "#1e2245",
    "sidebar_item_selected": "#252a50",

    "scrollbar_bg": "#1a1a2e",
    "scrollbar_handle": "#2a3050",
}

LIGHT_COLORS = {
    "bg_primary": "#ffffff",
    "bg_secondary": "#f5f6fa",
    "bg_tertiary": "#e8ecf1",
    "bg_input": "#f0f2f5",
    "bg_hover": "#e4e7ec",

    "text_primary": "#1c1e21",
    "text_secondary": "#65676b",
    "text_placeholder": "#8a8d91",

    "accent": "#3a86ff",
    "accent_hover": "#2670e0",
    "accent_pressed": "#1a5cbf",

    "danger": "#e63946",
    "success": "#2ec4b6",
    "warning": "#ffbe0b",

    "bubble_sent": "#3a86ff",
    "bubble_sent_text": "#ffffff",
    "bubble_received": "#e8ecf1",
    "bubble_received_text": "#1c1e21",

    "border": "#d1d5db",
    "border_focus": "#3a86ff",

    "sidebar_bg": "#f0f2f5",
    "sidebar_item_hover": "#e4e7ec",
    "sidebar_item_selected": "#d8dce2",

    "scrollbar_bg": "#f5f6fa",
    "scrollbar_handle": "#c1c5cc",
}


# ---------------------------------------------------------
# Stylesheet generators
# ---------------------------------------------------------

def generate_stylesheet(colors):
    """Generate a full QSS stylesheet from a color palette dictionary."""

    return f"""
    /* ===== Global ===== */
    QWidget {{
        background-color: {colors["bg_primary"]};
        color: {colors["text_primary"]};
        font-family: "Avenir Next", "Avenir", "Helvetica Neue", sans-serif;
        font-size: 14px;
    }}

    /* ===== Labels ===== */
    QLabel {{
        background-color: transparent;
        color: {colors["text_primary"]};
        padding: 0px;
    }}

    QLabel#title_label {{
        font-size: 28px;
        font-weight: bold;
        color: {colors["accent"]};
        padding: 10px 0px;
    }}

    QLabel#subtitle_label {{
        font-size: 13px;
        color: {colors["text_secondary"]};
        padding: 0px 0px 15px 0px;
    }}

    QLabel#user_label {{
        font-size: 15px;
        font-weight: bold;
        color: {colors["accent"]};
        padding: 8px 12px;
    }}

    QLabel#section_label {{
        font-size: 12px;
        font-weight: bold;
        color: {colors["text_secondary"]};
        text-transform: uppercase;
        padding: 12px 12px 6px 12px;
    }}

    QLabel#chat_header_label {{
        font-size: 16px;
        font-weight: bold;
        color: {colors["text_primary"]};
        padding: 12px 16px;
    }}

    QLabel#status_label {{
        font-size: 11px;
        color: {colors["text_secondary"]};
        padding: 0px;
    }}

    QLabel#timestamp_label {{
        font-size: 10px;
        color: {colors["text_secondary"]};
        padding: 0px;
    }}

    QLabel#empty_chat_label {{
        font-size: 16px;
        color: {colors["text_secondary"]};
    }}

    /* ===== Line Edits ===== */
    QLineEdit {{
        background-color: {colors["bg_input"]};
        color: {colors["text_primary"]};
        border: 2px solid {colors["border"]};
        border-radius: 10px;
        padding: 10px 14px;
        font-size: 14px;
        selection-background-color: {colors["accent"]};
    }}

    QLineEdit:focus {{
        border-color: {colors["border_focus"]};
    }}

    QLineEdit::placeholder {{
        color: {colors["text_placeholder"]};
    }}

    /* ===== Push Buttons ===== */
    QPushButton {{
        background-color: {colors["accent"]};
        color: #ffffff;
        border: none;
        border-radius: 10px;
        padding: 10px 20px;
        font-size: 14px;
        font-weight: bold;
        min-height: 20px;
    }}

    QPushButton:hover {{
        background-color: {colors["accent_hover"]};
    }}

    QPushButton:pressed {{
        background-color: {colors["accent_pressed"]};
    }}

    QPushButton:disabled {{
        background-color: {colors["bg_tertiary"]};
        color: {colors["text_secondary"]};
    }}

    QPushButton#secondary_button {{
        background-color: transparent;
        color: {colors["accent"]};
        border: 2px solid {colors["accent"]};
    }}

    QPushButton#secondary_button:hover {{
        background-color: {colors["accent"]};
        color: #ffffff;
    }}

    QPushButton#danger_button {{
        background-color: {colors["danger"]};
    }}

    QPushButton#danger_button:hover {{
        background-color: #cc2f3b;
    }}

    QPushButton#icon_button {{
        background-color: transparent;
        border: none;
        border-radius: 8px;
        padding: 6px 10px;
        font-size: 16px;
        min-height: 16px;
        color: {colors["text_secondary"]};
    }}

    QPushButton#icon_button:hover {{
        background-color: {colors["bg_hover"]};
        color: {colors["text_primary"]};
    }}

    QPushButton#theme_toggle {{
        background-color: {colors["bg_secondary"]};
        color: {colors["text_primary"]};
        border: 1px solid {colors["border"]};
        border-radius: 8px;
        padding: 6px 12px;
        font-size: 13px;
        font-weight: normal;
        min-height: 16px;
    }}

    QPushButton#theme_toggle:hover {{
        background-color: {colors["bg_hover"]};
    }}

    QPushButton#send_button {{
        border-radius: 10px;
        padding: 10px 24px;
        font-size: 14px;
    }}

    /* ===== Text Edit (chat area) ===== */
    QTextEdit {{
        background-color: {colors["bg_primary"]};
        color: {colors["text_primary"]};
        border: none;
        padding: 8px;
        font-size: 14px;
    }}

    /* ===== Scroll Areas ===== */
    QScrollArea {{
        background-color: {colors["bg_primary"]};
        border: none;
    }}

    QScrollBar:vertical {{
        background: {colors["scrollbar_bg"]};
        width: 8px;
        border-radius: 4px;
        margin: 0px;
    }}

    QScrollBar::handle:vertical {{
        background: {colors["scrollbar_handle"]};
        border-radius: 4px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {colors["accent"]};
    }}

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QScrollBar:horizontal {{
        height: 0px;
    }}

    /* ===== List Widget (contacts) ===== */
    QListWidget {{
        background-color: transparent;
        border: none;
        outline: none;
        padding: 4px;
    }}

    QListWidget::item {{
        background-color: transparent;
        border-radius: 8px;
        padding: 10px 12px;
        margin: 2px 4px;
    }}

    QListWidget::item:hover {{
        background-color: {colors["sidebar_item_hover"]};
    }}

    QListWidget::item:selected {{
        background-color: {colors["sidebar_item_selected"]};
        color: {colors["text_primary"]};
    }}

    /* ===== Frames & Containers ===== */
    QFrame#sidebar_frame {{
        background-color: {colors["sidebar_bg"]};
        border-right: 1px solid {colors["border"]};
    }}

    QFrame#chat_header_frame {{
        background-color: rgba(0, 0, 0, 0.08);
        border: none;
    }}

    QFrame#input_frame {{
        background-color: {colors["bg_primary"]};
        border: none;
    }}

    QFrame#separator {{
        background-color: {colors["border"]};
        max-height: 1px;
    }}

    /* ===== Message Bubbles ===== */
    QFrame#sent_bubble {{
        background-color: {colors["bubble_sent"]};
        border-radius: 16px;
        padding: 0px;
    }}

    QFrame#received_bubble {{
        background-color: {colors["bubble_received"]};
        border-radius: 16px;
        padding: 0px;
    }}

    QLabel#sent_message_text {{
        color: {colors["bubble_sent_text"]};
        background-color: transparent;
        font-size: 14px;
        padding: 0px;
    }}

    QLabel#received_message_text {{
        color: {colors["bubble_received_text"]};
        background-color: transparent;
        font-size: 14px;
        padding: 0px;
    }}

    QLabel#sent_timestamp {{
        color: rgba(255, 255, 255, 0.7);
        background-color: transparent;
        font-size: 10px;
        padding: 0px;
    }}

    QLabel#received_timestamp {{
        color: {colors["text_secondary"]};
        background-color: transparent;
        font-size: 10px;
        padding: 0px;
    }}

    QLabel#sender_name {{
        color: {colors["accent"]};
        background-color: transparent;
        font-size: 11px;
        font-weight: bold;
        padding: 0px;
    }}

    /* ===== Message Box (dialogs) ===== */
    QMessageBox {{
        background-color: {colors["bg_primary"]};
    }}

    QMessageBox QLabel {{
        color: {colors["text_primary"]};
        font-size: 14px;
    }}

    QMessageBox QPushButton {{
        min-width: 80px;
        padding: 8px 16px;
    }}
    """


# ---------------------------------------------------------
# Theme manager class
# ---------------------------------------------------------

class ThemeManager:
    """
    Manages the application theme. Provides methods to toggle
    between light and dark modes and apply stylesheets.
    """

    DARK = "dark"
    LIGHT = "light"

    def __init__(self):
        self.current_theme = self.DARK
        self._app = None

    def set_app(self, app):
        """Set the QApplication instance to apply themes on."""
        self._app = app

    def get_stylesheet(self):
        """Return the QSS stylesheet for the current theme."""
        if self.current_theme == self.DARK:
            return generate_stylesheet(DARK_COLORS)
        else:
            return generate_stylesheet(LIGHT_COLORS)

    def get_colors(self):
        """Return the color dictionary for the current theme."""
        if self.current_theme == self.DARK:
            return DARK_COLORS
        else:
            return LIGHT_COLORS

    def apply_theme(self):
        """Apply the current theme to the application."""
        if self._app is not None:
            self._app.setStyleSheet(self.get_stylesheet())

    def toggle_theme(self):
        """Switch between dark and light theme and apply."""
        if self.current_theme == self.DARK:
            self.current_theme = self.LIGHT
        else:
            self.current_theme = self.DARK

        self.apply_theme()

    def is_dark(self):
        """Return True if the current theme is dark."""
        return self.current_theme == self.DARK

    def get_toggle_icon(self):
        """Return a text label for the theme toggle button."""
        if self.current_theme == self.DARK:
            return "Light"
        else:
            return "Dark"


# Global theme manager instance
theme_manager = ThemeManager()

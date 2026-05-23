import requests


class ApiClient:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8000"

    def register(self, username, password):
        url = f"{self.base_url}/register"

        data = {
            "username": username,
            "password": password
        }

        try:
            response = requests.post(url, json=data)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Register request failed."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def login(self, username, password):
        url = f"{self.base_url}/login"

        data = {
            "username": username,
            "password": password
        }

        try:
            response = requests.post(url, json=data)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Login request failed."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def upload_key_bundle(self, key_bundle):
        url = f"{self.base_url}/upload_keys"

        try:
            response = requests.post(url, json=key_bundle)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Key upload failed."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def get_key_bundle(self, username):
        url = f"{self.base_url}/keys/{username}"

        try:
            response = requests.get(url)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Could not get key bundle."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def send_message(self, message_packet):
        url = f"{self.base_url}/send_message"

        try:
            response = requests.post(url, json=message_packet)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Message sending failed."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def get_messages(self, username):
        url = f"{self.base_url}/messages/{username}"

        try:
            response = requests.get(url)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Could not get messages.",
                "messages": []
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server.",
                "messages": []
            }

    def get_key_bundle_info(self, username):
        url = f"{self.base_url}/keys/{username}/info"

        try:
            response = requests.get(url)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Could not get key info."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }

    def check_user_exists(self, username):
        url = f"{self.base_url}/user/{username}/exists"

        try:
            response = requests.get(url)

            if response.status_code == 200:
                return response.json()

            return {
                "success": False,
                "message": "Could not check user."
            }

        except requests.exceptions.RequestException:
            return {
                "success": False,
                "message": "Could not connect to server."
            }
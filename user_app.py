import json
from cryptography.fernet import Fernet


class UserApp:
    def __init__(self):
        with open('secret.key', 'rb') as f: self.cipher_suite = Fernet(f.read())

    def view_user_data(self, user_id):
        try:
            with open('live_db/userdata.json', 'r') as f:
                encrypted_db = json.load(f)
            if user_id < 1 or user_id > len(encrypted_db): return print("User not found.")

            encrypted_block = encrypted_db[user_id - 1]
            user_data = json.loads(self.cipher_suite.decrypt(encrypted_block.encode('utf-8')).decode('utf-8'))

            print("\n" + "=" * 40)
            print(f"👤 SECURE RECORD DASHBOARD (Row ID: {user_id})")
            for key, value in user_data.items(): print(f"{str(key).replace('_', ' ').title():<20} : {value}")
            print("=" * 40 + "\n")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    app = UserApp()
    while True:
        choice = input("Enter a Row ID to view data (1 to 10000), or 0 to exit: ")
        if choice == '0': break
        try:
            app.view_user_data(int(choice))
        except ValueError:
            print("Invalid number.")
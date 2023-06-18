import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QPushButton, QFileDialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class FileEncryptionTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryption Tool")
        self.setGeometry(100, 100, 400, 300)

        self.private_key_pem = None
        self.public_key_pem = None

        self.file_path = None

        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()

        self.label = QLabel("File Encryption Tool")
        layout.addWidget(self.label)

        self.private_key_button = QPushButton("Generate Private Key")
        self.private_key_button.clicked.connect(self.generate_private_key)
        layout.addWidget(self.private_key_button)

        self.public_key_button = QPushButton("Load Public Key")
        self.public_key_button.clicked.connect(self.load_public_key)
        layout.addWidget(self.public_key_button)

        self.select_file_button = QPushButton("Select File")
        self.select_file_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_button)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.result_label = QLabel()
        layout.addWidget(self.result_label)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.result_label.setText("Private key generated successfully.")

    def load_public_key(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Public Key File")
        if file_path:
            with open(file_path, 'rb') as file:
                self.public_key_pem = file.read()
            self.result_label.setText("Public key loaded successfully.")

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.result_label.setText("File selected successfully.")

    def encrypt_file(self):
        if not self.file_path or not self.public_key_pem:
            self.result_label.setText("Please select a file and load the public key.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                plaintext = file.read()

            public_key = serialization.load_pem_public_key(self.public_key_pem)
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            file_dialog = QFileDialog()
            encrypted_file_path, _ = file_dialog.getSaveFileName(self, "Save Encrypted File")
            if encrypted_file_path:
                with open(encrypted_file_path, 'wb') as file:
                    file.write(ciphertext)
                self.result_label.setText("File encrypted and saved successfully.")

        except Exception as e:
            self.result_label.setText(f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        if not self.file_path or not self.private_key_pem:
            self.result_label.setText("Please select a file and generate the private key.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                ciphertext = file.read()

            private_key = serialization.load_pem_private_key(self.private_key_pem, password=None)
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            file_dialog = QFileDialog()
            decrypted_file_path, _ = file_dialog.getSaveFileName(self, "Save Decrypted File")
            if decrypted_file_path:
                with open(decrypted_file_path, 'wb') as file:
                    file.write(plaintext)
                self.result_label.setText("File decrypted and saved successfully.")

        except Exception as e:
            self.result_label.setText(f"Decryption failed: {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptionTool()
    window.show()
    sys.exit(app.exec_())

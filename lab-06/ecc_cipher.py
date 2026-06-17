import sys
import base64
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.uic import loadUi
from cipher.ecc import ECCCipher

class ECCWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi("cipher/ui/ecc.ui", self)
        self.setWindowTitle("ECC Cipher")
        self.cipher = ECCCipher()
        self.cipher.load_keys()

        # Lưu chữ ký hiện tại để dùng cho verify
        self._current_signature = None
        self._signed_message = None

        self.btn_generatekeys.clicked.connect(self.generate_keys)
        self.btn_Sign.clicked.connect(self.sign)
        self.btn_verify.clicked.connect(self.verify)

    def generate_keys(self):
        """Sinh cặp khóa ECC (NIST P-256) và lưu vào cipher/ecc/keys/"""
        try:
            self.cipher.generate_keys()
            QMessageBox.information(self, "Success", "ECC Keys generated successfully!\nSaved to cipher/ecc/keys/")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def sign(self):
        """
        Lấy nội dung từ ô txt_sign (phần Information/văn bản cần ký),
        ký bằng private key, hiển thị chữ ký base64 vào ô txt_verify (Signature).
        """
        message = self.txt_sign.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message in the Sign box.")
            return
        if self.cipher.signing_key is None:
            QMessageBox.warning(self, "Warning", "Please generate or load keys first.")
            return
        try:
            signature = self.cipher.sign(message)
            self._current_signature = signature
            self._signed_message = message

            # Hiển thị chữ ký base64 vào ô txt_verify
            self.txt_verify.setPlainText(base64.b64encode(signature).decode())
            QMessageBox.information(self, "Signed", "Signed Successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signing failed:\n{e}")

    def verify(self):
        """
        Xác minh chữ ký:
        - Văn bản gốc lấy từ ô txt_sign
        - Chữ ký base64 lấy từ ô txt_verify
        Hiển thị kết quả bằng popup (giống ảnh mẫu).
        """
        message = self.txt_sign.toPlainText().strip()
        signature_b64 = self.txt_verify.toPlainText().strip()

        if not message:
            QMessageBox.warning(self, "Warning", "Please enter the original message in the Sign box.")
            return
        if not signature_b64:
            QMessageBox.warning(self, "Warning", "Please enter the signature (base64) in the Verify box.")
            return
        if self.cipher.verifying_key is None:
            QMessageBox.warning(self, "Warning", "Please generate or load keys first.")
            return
        try:
            signature = base64.b64decode(signature_b64)
            valid = self.cipher.verify(message, signature)
            if valid:
                QMessageBox.information(self, "Verified", "Verified Successfully!")
            else:
                QMessageBox.warning(self, "Failed", "Verified Fail!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification error:\n{e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ECCWindow()
    window.show()
    sys.exit(app.exec_())

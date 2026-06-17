import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.uic import loadUi
from cipher.playfair import PlayfairCipher


class PlayfairWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi("cipher/ui/playfair.ui", self)
        self.setWindowTitle("Playfair Cipher")
        self.cipher = PlayfairCipher()

        # Kết nối các nút
        self.btn_encrypt.clicked.connect(self.encrypt)
        self.btn_decrypt.clicked.connect(self.decrypt)
        self.btn_clear.clicked.connect(self.clear_all)
        self.btn_showmatrix.clicked.connect(self.show_matrix)

    def _load_key(self) -> bool:
        """Lấy keyword từ txt_key và khởi tạo ma trận. Trả về False nếu trống."""
        key = self.txt_key.text().strip()
        if not key:
            QMessageBox.warning(self, "Warning", "Vui lòng nhập Keyword trước khi thực hiện!")
            return False
        self.cipher.set_key(key)
        return True

    def show_matrix(self):
        """Hiển thị ma trận 5x5 lên label."""
        if not self._load_key():
            return
        self.lbl_matrix.setText(self.cipher.get_matrix_display())

    def encrypt(self):
        """Mã hoá plaintext bằng Playfair và hiển thị ciphertext."""
        if not self._load_key():
            return
        plaintext = self.txt_plaintext.toPlainText().strip()
        if not plaintext:
            QMessageBox.warning(self, "Warning", "Vui lòng nhập Plaintext cần mã hoá!")
            return
        try:
            ciphertext = self.cipher.encrypt(plaintext)
            self.txt_ciphertext.setPlainText(ciphertext)
            # Cập nhật hiển thị ma trận
            self.lbl_matrix.setText(self.cipher.get_matrix_display())
            QMessageBox.information(self, "Success", "Mã hoá thành công!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Lỗi mã hoá:\n{e}")

    def decrypt(self):
        """Giải mã ciphertext bằng Playfair và hiển thị plaintext."""
        if not self._load_key():
            return
        ciphertext = self.txt_ciphertext.toPlainText().strip()
        if not ciphertext:
            QMessageBox.warning(self, "Warning", "Vui lòng nhập Ciphertext cần giải mã!")
            return
        try:
            plaintext = self.cipher.decrypt(ciphertext)
            self.txt_plaintext.setPlainText(plaintext)
            # Cập nhật hiển thị ma trận
            self.lbl_matrix.setText(self.cipher.get_matrix_display())
            QMessageBox.information(self, "Success", "Giải mã thành công!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Lỗi giải mã:\n{e}")

    def clear_all(self):
        """Xoá toàn bộ nội dung các ô input/output."""
        self.txt_key.clear()
        self.txt_plaintext.clear()
        self.txt_ciphertext.clear()
        self.lbl_matrix.clear()
        self.cipher = PlayfairCipher()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PlayfairWindow()
    window.show()
    sys.exit(app.exec_())

class PlayfairCipher:
    def __init__(self):
        self.key = ""
        self.matrix = []

    def _build_matrix(self, key: str):
        """Tạo ma trận 5x5 từ keyword (I và J gộp chung)."""
        key = key.upper().replace("J", "I")
        seen = []
        for ch in key:
            if ch.isalpha() and ch not in seen:
                seen.append(ch)
        for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if ch not in seen:
                seen.append(ch)
        self.matrix = [seen[i * 5:(i + 1) * 5] for i in range(5)]

    def _find_pos(self, ch: str):
        """Trả về (row, col) của ký tự trong ma trận."""
        for r, row in enumerate(self.matrix):
            if ch in row:
                return r, row.index(ch)
        raise ValueError(f"Ký tự '{ch}' không tìm thấy trong ma trận.")

    def _prepare_text(self, text: str) -> str:
        """Chuẩn bị văn bản: chỉ giữ alpha, thay J->I, chèn X giữa cặp trùng."""
        text = text.upper().replace("J", "I")
        filtered = [ch for ch in text if ch.isalpha()]
        result = []
        i = 0
        while i < len(filtered):
            a = filtered[i]
            if i + 1 < len(filtered):
                b = filtered[i + 1]
                if a == b:
                    result.extend([a, "X"])
                    i += 1
                else:
                    result.extend([a, b])
                    i += 2
            else:
                result.extend([a, "X"])
                i += 1
        return "".join(result)

    def set_key(self, key: str):
        """Đặt keyword và xây dựng ma trận."""
        self.key = key
        self._build_matrix(key)

    def encrypt(self, plaintext: str) -> str:
        """Mã hoá văn bản bằng Playfair."""
        if not self.matrix:
            raise ValueError("Chưa đặt keyword. Gọi set_key() trước.")
        prepared = self._prepare_text(plaintext)
        result = []
        for i in range(0, len(prepared), 2):
            a, b = prepared[i], prepared[i + 1]
            ra, ca = self._find_pos(a)
            rb, cb = self._find_pos(b)
            if ra == rb:
                result.append(self.matrix[ra][(ca + 1) % 5])
                result.append(self.matrix[rb][(cb + 1) % 5])
            elif ca == cb:
                result.append(self.matrix[(ra + 1) % 5][ca])
                result.append(self.matrix[(rb + 1) % 5][cb])
            else:
                result.append(self.matrix[ra][cb])
                result.append(self.matrix[rb][ca])
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Giải mã văn bản bằng Playfair."""
        if not self.matrix:
            raise ValueError("Chưa đặt keyword. Gọi set_key() trước.")
        ciphertext = ciphertext.upper().replace("J", "I")
        filtered = [ch for ch in ciphertext if ch.isalpha()]
        if len(filtered) % 2 != 0:
            raise ValueError("Độ dài ciphertext phải là số chẵn.")
        result = []
        for i in range(0, len(filtered), 2):
            a, b = filtered[i], filtered[i + 1]
            ra, ca = self._find_pos(a)
            rb, cb = self._find_pos(b)
            if ra == rb:
                result.append(self.matrix[ra][(ca - 1) % 5])
                result.append(self.matrix[rb][(cb - 1) % 5])
            elif ca == cb:
                result.append(self.matrix[(ra - 1) % 5][ca])
                result.append(self.matrix[(rb - 1) % 5][cb])
            else:
                result.append(self.matrix[ra][cb])
                result.append(self.matrix[rb][ca])
        return "".join(result)

    def get_matrix_display(self) -> str:
        """Trả về chuỗi hiển thị ma trận 5x5."""
        if not self.matrix:
            return "Chưa có ma trận. Hãy nhập keyword."
        lines = []
        for row in self.matrix:
            lines.append("  ".join(row))
        return "\n".join(lines)

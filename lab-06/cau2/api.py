from flask import Flask, request, jsonify
from cipher.playfair import PlayfairCipher

app = Flask(__name__)

playfair = PlayfairCipher()

# ───────────────────────────────
#  PLAYFAIR
# ───────────────────────────────

@app.route("/api/playfair/set_key", methods=["POST"])
def playfair_set_key():
    """Đặt keyword cho Playfair cipher."""
    data = request.get_json()
    key = data.get("key", "")
    if not key:
        return jsonify({"error": "key is required"}), 400
    try:
        playfair.set_key(key)
        return jsonify({
            "message": f"Key '{key}' set successfully",
            "matrix": playfair.get_matrix_display()
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/playfair/encrypt", methods=["POST"])
def playfair_encrypt():
    """Mã hoá plaintext bằng Playfair."""
    data = request.get_json()
    plaintext = data.get("plaintext", "")
    key = data.get("key", "")
    if not plaintext:
        return jsonify({"error": "plaintext is required"}), 400
    try:
        if key:
            playfair.set_key(key)
        if not playfair.matrix:
            return jsonify({"error": "No key set. Provide 'key' field or call /api/playfair/set_key first"}), 400
        ciphertext = playfair.encrypt(plaintext)
        return jsonify({"ciphertext": ciphertext}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/playfair/decrypt", methods=["POST"])
def playfair_decrypt():
    """Giải mã ciphertext bằng Playfair."""
    data = request.get_json()
    ciphertext = data.get("ciphertext", "")
    key = data.get("key", "")
    if not ciphertext:
        return jsonify({"error": "ciphertext is required"}), 400
    try:
        if key:
            playfair.set_key(key)
        if not playfair.matrix:
            return jsonify({"error": "No key set. Provide 'key' field or call /api/playfair/set_key first"}), 400
        plaintext = playfair.decrypt(ciphertext)
        return jsonify({"plaintext": plaintext}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/playfair/matrix", methods=["POST"])
def playfair_matrix():
    """Trả về ma trận 5x5 từ keyword."""
    data = request.get_json()
    key = data.get("key", "")
    if not key:
        return jsonify({"error": "key is required"}), 400
    try:
        playfair.set_key(key)
        return jsonify({"matrix": playfair.get_matrix_display()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)

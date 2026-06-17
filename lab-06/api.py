import base64
from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCCipher

app = Flask(__name__)

rsa = RSACipher()
rsa.load_keys()

ecc = ECCCipher()
ecc.load_keys()

# ───────────────────────────────
#  RSA
# ───────────────────────────────

@app.route("/api/rsa/generate_keys", methods=["GET"])
def rsa_generate_keys():
    try:
        rsa.generate_keys(2048)
        return jsonify({"message": "RSA keys generated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.get_json()
    plaintext = data.get("plaintext", "")
    if not plaintext:
        return jsonify({"error": "plaintext is required"}), 400
    if rsa.public_key is None:
        return jsonify({"error": "No keys. Call /api/rsa/generate_keys first"}), 400
    try:
        ciphertext = rsa.encrypt(plaintext)
        return jsonify({"ciphertext": base64.b64encode(ciphertext).decode()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.get_json()
    ciphertext_b64 = data.get("ciphertext", "")
    if not ciphertext_b64:
        return jsonify({"error": "ciphertext is required"}), 400
    if rsa.private_key is None:
        return jsonify({"error": "No keys. Call /api/rsa/generate_keys first"}), 400
    try:
        plaintext = rsa.decrypt(base64.b64decode(ciphertext_b64))
        return jsonify({"plaintext": plaintext}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign():
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "message is required"}), 400
    if rsa.private_key is None:
        return jsonify({"error": "No keys. Call /api/rsa/generate_keys first"}), 400
    try:
        signature = rsa.sign(message)
        return jsonify({"signature": base64.b64encode(signature).decode()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify():
    data = request.get_json()
    message = data.get("message", "")
    signature_b64 = data.get("signature", "")
    if not message or not signature_b64:
        return jsonify({"error": "message and signature are required"}), 400
    if rsa.public_key is None:
        return jsonify({"error": "No keys. Call /api/rsa/generate_keys first"}), 400
    try:
        valid = rsa.verify(message, base64.b64decode(signature_b64))
        return jsonify({"verified": valid}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ───────────────────────────────
#  ECC
# ───────────────────────────────

@app.route("/api/ecc/generate_keys", methods=["GET"])
def ecc_generate_keys():
    try:
        ecc.generate_keys()
        return jsonify({"message": "ECC keys generated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ecc/sign", methods=["POST"])
def ecc_sign():
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "message is required"}), 400
    if ecc.signing_key is None:
        return jsonify({"error": "No keys. Call /api/ecc/generate_keys first"}), 400
    try:
        signature = ecc.sign(message)
        return jsonify({"signature": base64.b64encode(signature).decode()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ecc/verify", methods=["POST"])
def ecc_verify():
    data = request.get_json()
    message = data.get("message", "")
    signature_b64 = data.get("signature", "")
    if not message or not signature_b64:
        return jsonify({"error": "message and signature are required"}), 400
    if ecc.verifying_key is None:
        return jsonify({"error": "No keys. Call /api/ecc/generate_keys first"}), 400
    try:
        valid = ecc.verify(message, base64.b64decode(signature_b64))
        return jsonify({"verified": valid}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
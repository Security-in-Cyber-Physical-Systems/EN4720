from flask import Flask, request, jsonify
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app, template_file="swagger.yml")

keys = {}

def generate_aes_key(key_size):
    key = os.urandom(key_size // 8)
    return base64.b64encode(key).decode('utf-8')

@app.route('/generate-key', methods=['POST'])
def generate_key():
    data = request.json
    key_type = data.get('key_type')
    key_size = data.get('key_size')
    
    if key_type != "AES" or key_size not in [128, 192, 256]:
        return jsonify({"error": "Invalid key type or size"}), 400
    
    key_id = str(len(keys) + 1)
    key_value = generate_aes_key(key_size)
    keys[key_id] = base64.b64decode(key_value)
    
    return jsonify({"key_id": key_id, "key_value": key_value})

def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    pkcs7_padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plaintext.encode()) + pkcs7_padder.finalize()
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode('utf-8')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    key_id = data.get('key_id')
    plaintext = data.get('plaintext')
    algorithm = data.get('algorithm')
    
    if key_id not in keys or algorithm != "AES":
        return jsonify({"error": "Invalid key or algorithm"}), 400
    
    ciphertext = encrypt_aes(keys[key_id], plaintext)
    return jsonify({"ciphertext": ciphertext})

def decrypt_aes(key, ciphertext):
    decoded = base64.b64decode(ciphertext)
    iv, encrypted_data = decoded[:16], decoded[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8').strip()

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    key_id = data.get('key_id')
    ciphertext = data.get('ciphertext')
    algorithm = data.get('algorithm')
    
    if key_id not in keys or algorithm != "AES":
        return jsonify({"error": "Invalid key or algorithm"}), 400
    
    plaintext = decrypt_aes(keys[key_id], ciphertext)
    return jsonify({"plaintext": plaintext})

def comput_hash(data, algorithm="SHA-256"):
    if algorithm == "SHA-256":
        hash_value = hashlib.sha256(data.encode()).digest()
    elif algorithm == "SHA-512":
        hash_value = hashlib.sha512(data.encode()).digest()
    else:
        return None
    
    return base64.b64encode(hash_value).decode('utf-8')

@app.route('/generate-hash', methods=['POST'])
def generate_hash_api():
    data = request.json
    text = data.get('data')
    algorithm = data.get('algorithm', "SHA-256")
    
    hash_value = comput_hash(text, algorithm)
    if hash_value is None:
        return jsonify({"error": "Invalid hashing algorithm"}), 400
    
    return jsonify({"hash_value": hash_value, "algorithm": algorithm})


@app.route('/verify-hash', methods=['POST'])
def verify_hash():
    data = request.json
    message = data.get("data")
    given_hash = data.get("hash_value")
    algorithm = data.get("algorithm")

    if algorithm not in ["SHA-256", "SHA-512"]:
        return jsonify({"error": "Unsupported hashing algorithm"}), 400

    computed_hash = comput_hash(message, algorithm)

    if computed_hash == given_hash:
        return jsonify({"is_valid": True, "message": "Hash matches the data."})
    else:
        return jsonify({"is_valid": False, "message": "Hash does not match."})


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

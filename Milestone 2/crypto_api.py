from flask import Flask, request, jsonify
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True)

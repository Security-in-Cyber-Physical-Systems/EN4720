import requests
import json

# Define the URL of the endpoint
url = 'http://127.0.0.1:5000/'

# Generate an AES key
payload = { "key_type": "AES",
"key_size": 256 } 
headers = { 'Content-Type': 'application/json' } 
response = requests.post(url + "generate-key", data = json.dumps(payload), headers = headers) 
if response.status_code == 200: 
    data = response.json() 
    print("Key ID:", data.get("key_id")) 
    print("Key Value:", data.get("key_value"))
else: 
    print("Error:", response.json())

# Encrypt a plaintext using the generated key
key_id = "1"
plaintext = "Hello, AES encryption!"
algorithm = "AES"
payload = {
    "key_id": key_id,
    "plaintext": plaintext,
    "algorithm": algorithm
}
headers = {'Content-Type': 'application/json'}
response = requests.post(url + "encrypt", data=json.dumps(payload), headers=headers)
if response.status_code == 200:
    data = response.json()
    print("Ciphertext:", data.get("ciphertext"))
else:
    print("Error:", response.json())
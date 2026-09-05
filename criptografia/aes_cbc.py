from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

def derive_aes_params(secret_k, secret_iv):
    """Convierte los enteros matemáticos en bytes exactos para AES-256-CBC"""
    key = hashlib.sha256(str(secret_k).encode()).digest()
    iv = hashlib.sha256(str(secret_iv).encode()).digest()[:16]
    return key, iv

def encrypt_aes_cbc(data_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_cbc(ciphertext_b64, key, iv):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    return unpad(padded_data, AES.block_size)
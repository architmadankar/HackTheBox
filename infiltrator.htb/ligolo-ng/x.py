from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_string(key: str, cipher_text: str) -> str:
    key_bytes = key.encode('utf-8')
    cipher_bytes = base64.b64decode(cipher_text)

    if len(key_bytes) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_bytes = decryptor.update(cipher_bytes) + decryptor.finalize()

    return decrypted_bytes.decode('utf-8')

key = 'b14ca5898a4e4133bbce2ea2315a1916'
cipher_text = 'TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE='

print(decrypt_string(key,decrypt_string(key, cipher_text)))

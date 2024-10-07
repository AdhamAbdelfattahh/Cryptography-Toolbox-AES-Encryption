from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESCipher:
    def __init__(self):
        self.key = get_random_bytes(16)  # AES key should be either 16, 24, or 32 bytes long

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')  # Encode IV
        ct = base64.b64encode(ct_bytes).decode('utf-8')  # Encode ciphertext
        return iv, ct

    def decrypt(self, iv, ciphertext):
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
        return plaintext

# Example usage
if __name__ == "__main__":
    aes_cipher = AESCipher()
    
    # Encrypt
    plaintext = "This is a secret message."
    iv, ciphertext = aes_cipher.encrypt(plaintext)
    print(f"IV: {iv}\nCiphertext: {ciphertext}")

    # Decrypt
    decrypted_message = aes_cipher.decrypt(iv, ciphertext)
    print(f"Decrypted: {decrypted_message}")

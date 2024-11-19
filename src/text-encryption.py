import base64
import os
from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# AES Encryption
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

# AES Decryption
def aes_decrypt(cipher_text, key):
    cipher_bytes = base64.b64decode(cipher_text)
    iv = cipher_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(cipher_bytes[AES.block_size:]), AES.block_size)
    return decrypted.decode('utf-8')

# DES Encryption
def des_encrypt(plain_text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

# DES Decryption
def des_decrypt(cipher_text, key):
    cipher_bytes = base64.b64decode(cipher_text)
    iv = cipher_bytes[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(cipher_bytes[DES.block_size:]), DES.block_size)
    return decrypted.decode('utf-8')

# RSA Encryption
def rsa_encrypt(plain_text, public_key):
    ciphertext = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

# RSA Decryption
def rsa_decrypt(cipher_text, private_key):
    ciphertext = base64.b64decode(cipher_text)
    decrypted = private_key.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return decrypted.decode('utf-8')

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption Tool")

        self.label = Label(root, text="Enter text:")
        self.label.pack()

        self.text_input = Text(root, height=5, width=50)
        self.text_input.pack()

        self.algorithm_label = Label(root, text="Select Encryption Algorithm:")
        self.algorithm_label.pack()

        self.algorithm_var = StringVar(value='AES')
        self.algorithm_menu = OptionMenu(root, self.algorithm_var, 'AES', 'DES', 'RSA')
        self.algorithm_menu.pack()

        self.encrypt_button = Button(root, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.decrypt_button = Button(root, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.pack()

        self.result_label = Label(root, text="Result:")
        self.result_label.pack()

        self.result_output = Text(root, height=5, width=50)
        self.result_output.pack()

        # Generate RSA keys
        self.private_key, self.public_key = generate_rsa_keys()

        # Generate random keys for AES and DES
        self.aes_key = os.urandom(16)  # AES key (16 bytes for AES-128)
        self.des_key = os.urandom(8)   # DES key (8 bytes)

    def encrypt_text(self):
        algorithm = self.algorithm_var.get()
        plain_text = self.text_input.get("1.0", END).strip()
        try:
            if algorithm == ' AES':
                encrypted_text = aes_encrypt(plain_text, self.aes_key)
            elif algorithm == 'DES':
                encrypted_text = des_encrypt(plain_text, self.des_key)
            elif algorithm == 'RSA':
                encrypted_text = rsa_encrypt(plain_text, self.public_key)
            else:
                raise ValueError("Invalid algorithm selected.")
            self.result_output.delete("1.0", END)
            self.result_output.insert(END, encrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        algorithm = self.algorithm_var.get()
        cipher_text = self.result_output.get("1.0", END).strip()
        try:
            if algorithm == 'AES':
                decrypted_text = aes_decrypt(cipher_text, self.aes_key)
            elif algorithm == 'DES':
                decrypted_text = des_decrypt(cipher_text, self.des_key)
            elif algorithm == 'RSA':
                decrypted_text = rsa_decrypt(cipher_text, self.private_key)
            else:
                raise ValueError("Invalid algorithm selected.")
            self.result_output.delete("1.0", END)
            self.result_output.insert(END, decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = EncryptionApp(root)
    root.mainloop()

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
"""
Este script desencripta un archivo usando una clave AES. No forma parte de la herramienta, solo demuestra el buen funcionamiento del cifrado.
Para su uso:
    1. Guarda el archivo de clave AES en la misma carpeta que este script.
    2. Guarda el archivo cifrado en la misma carpeta que este script.
    3. Ejecuta el script cambiando el valor de la variable file_path por el nombre del archivo cifrado en el main.
"""
def decrypt_file(file_path, key):
    with open(file_path, "rb") as enc_file:
        iv = enc_file.read(16)  # The first 16 bytes are the IV
        encrypted_data = enc_file.read()

    # Decrypting the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Writing the decrypted data to a file
    with open(file_path[:-4], "wb") as dec_file:  # Remove the .enc extension
        dec_file.write(data)

if __name__ == "__main__":
    file_path = "piratilla.txt.enc"
    key_path = "aes_key.bin"

    with open(key_path, "rb") as key_file:
        key = key_file.read()

    decrypt_file(file_path, key)
    print(f"File {file_path} decrypted successfully.")

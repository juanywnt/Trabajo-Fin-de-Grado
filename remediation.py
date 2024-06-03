import boto3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from botocore.exceptions import ClientError

s3_client = boto3.client('s3')
KEY_FILE = "aes_key.bin"

def generate_key():
    key = os.urandom(32)  # Generate a 256-bit (32-byte) key
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        data = file.read()
    
    # Padding the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypting the data
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Writing the encrypted data and IV to a file
    with open(file_path + ".enc", "wb") as enc_file:
        enc_file.write(iv + encrypted_data)
        
def download_file(bucket_name, object_name, file_path):
    """Descarga un archivo desde un bucket de S3."""
    try:
        s3_client.download_file(bucket_name, object_name, file_path)
        print(f"Archivo descargado: {file_path}")
    except ClientError as e:
        print(f"Error descargando el archivo: {e}")
def upload_file(bucket_name, object_name, file_path):
    """Sube un archivo a un bucket de S3."""
    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        print(f"Archivo subido: {file_path}")
    except ClientError as e:
        print(f"Error subiendo el archivo: {e}")
def delete_file(bucket_name, object_name, local_file_path):
    """Elimina un archivo de un bucket de S3 y de la ruta local"""
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=object_name)
        print(f"Archivo eliminado: {object_name}")
        os.remove(local_file_path)
        os.remove(local_file_path + ".enc")
    except ClientError as e:
        print(f"Error eliminando el archivo: {e}")
    
    
    

def process_file(bucket,object):
    """Descarga, cifra y vuelve a subir un archivo a S3."""
    local_file_path = f"/tmp/{object.replace('/', '_')}"
    download_file(bucket, object, local_file_path)
    if not os.path.exists(KEY_FILE):
        generate_key()
    key = load_key()
    encrypt_file(local_file_path, key)
    print(f"File {local_file_path} encrypted successfully.")
    upload_file(bucket, object + ".enc", local_file_path + ".enc")
    delete_file(bucket, object)

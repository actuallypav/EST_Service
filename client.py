import sys
import time
import socket
import base64
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
import json

def generate_csr():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"mycompany.com"),
        ])
    ).sign(private_key, hashes.SHA256())

    with open("private_key.pem", "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return csr.public_bytes(serialization.Encoding.PEM)

def encrypt_aes256(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # PKCS7 Padding to make data a multiple of 16 bytes
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def retrieve_kv(region, kv_name):
    sm = boto3.client('secretsmanager')
    account_id = boto3.client('sts').get_caller_identity().get('Account')

    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{kv_name}"

    kv = sm.get_secret_value(
        SecretId=arn
    )

    kv_dict = json.loads(kv["SecretString"])

    #b64 decode all
    key = base64.b64decode(kv["aes_key"])
    iv = base64.b64decode(kv["aes_iv"])

    return key, iv

def get_pem(csr):
    server_host = "nlb-dns-name"
    server_port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket
        client_socket.connect((server_host, server_port))

        client_socket.sendall(csr.encode())

        response = client_socket.recv(4096).decode()

    return {"body": response}

def main():    

    with open("config.json") as f:
        config = json.load(f)

    # generate CSR
    csr_data = generate_csr()

    #recover key/iv from secrets
    key, iv = retrieve_kv(config["region"], config["kv_name"])

    # encrypt CSR
    encrypted_csr = encrypt_aes256(csr_data, key, iv)
    
    # encode with Base64
    b64_encoded_csr = base64.b64encode(encrypted_csr).decode()
    
    response = get_pem(b64_encoded_csr).get("body", "")
    response_json = response.json()
    root_ca = base64.b64decode(response_json.get("root_ca","")).decode()
    cert_pem = base64.b64decode(response_json.get("cert_pem","")).decode()

    with open("root_ca.pem", "w") as r:
        r.write(root_ca)

    with open("certificate.pem", "w") as c:
        c.write(cert_pem)

    print("Success find the certificates here!")

    # store in a file
    with open("encrypted_csr.txt", "w") as f:
        f.write(b64_encoded_csr)
    
    print("Encrypted CSR saved to encrypted_csr.txt")
    
if __name__ == "__main__":
    main()
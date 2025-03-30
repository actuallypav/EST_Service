import sys
import time
import socket
import base64
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.x509.oid import ObjectIdentifier
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
import boto3
import json
import requests


def parse_config(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
    est_api_url = data["ESTDetails"]["ESTAPIURL"]
    region = data["ESTDetails"]["Region"]
    KV_name = data["ESTDetails"]["KV_Name"]
    OID_content = data["IoTDetails"]
    return region, KV_name, est_api_url, OID_content


def generate_csr(OID_content):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    #create a custom OID using a non existing OID - register one if you care
    custom_oid = ObjectIdentifier("0.5.100.101.105.116.115")
    OID_content_json = json.dumps(OID_content).encode()

    custom_extension = x509.UnrecognizedExtension(custom_oid, OID_content_json)

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([ 
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Cumbria"),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Keswick"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "PavInc"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "github.com/actuallypav")
        ])
    )

    csr_builder = csr_builder.add_extension(custom_extension, critical=False)

    csr = csr_builder.sign(
        private_key,
        padding.PKCS1v15(), 
        hashes.SHA256(),
    )

    with open("private_key.pem", "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

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
    sm = boto3.client("secretsmanager")
    account_id = boto3.client("sts").get_caller_identity().get("Account")

    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{kv_name}"

    kv = sm.get_secret_value(SecretId=arn)

    kv_dict = json.loads(kv["SecretString"])

    # b64 decode all
    key = base64.b64decode(kv["aes_key"])
    iv = base64.b64decode(kv["aes_iv"])

    return key, iv


def get_pem(csr, api_gateway_url):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    base64_csr = base64.b64encode(csr.encode()).decode()

    body = {
        "requestBody": base64_csr,
    }

    header = {
        "Content-Type": "application/json"
    }

    response = requests.post(api_gateway_url, json=body, headers=header)

    if response.status_code == 200:
        print("Response:", response.json()) 
        return response.json()
    else:
        print(f"ERROR: {response.status_code}, {response.text}")



def main():
    #read the config file for this IoT "VERY IMPORTANY"
    region, kv_name, api_gateway_url, OID_content = parse_config("config_client.json")

    # generate CSR
    csr_data = generate_csr(OID_content)

    # recover key/iv from secrets
    key, iv = retrieve_kv(region, kv_name)

    # encrypt CSR
    encrypted_csr = encrypt_aes256(csr_data, key, iv)

    # encode with Base64
    b64_encoded_csr = base64.b64encode(encrypted_csr).decode()

    response = get_pem((b64_encoded_csr).get("body", ""), api_gateway_url)
    response_json = response.json()
    root_ca = base64.b64decode(response_json.get("root_ca", "")).decode()
    cert_pem = base64.b64decode(response_json.get("cert_pem", "")).decode()

    with open("root_ca.pem", "w") as r:
        r.write(root_ca)

    with open("certificate.pem", "w") as c:
        c.write(cert_pem)

    print("Success find the certificates here!")


if __name__ == "__main__":
    main()
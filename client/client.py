import base64
import os
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

def retrieve_config(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
    device_count = len(data["Devices"])
    api_gw_url = data["ESTDetails"]["ESTAPIURL"]
    KV_name = data["ESTDetails"]["KV_Name"]
    region = data["ESTDetails"]["Region"]
    return device_count, data, region, KV_name, api_gw_url

def parse_devices(i, data):
    device = data["Devices"][i]
    OID_content = device["IoTDetails"]
    return OID_content


def generate_csr(OID_content):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # use unrecognized oid - or request one for your purposes and replace
    custom_oid = ObjectIdentifier("0.5.100.101.105.116.115")
    OID_content_json = json.dumps(OID_content).encode()

    custom_extension = x509.UnrecognizedExtension(custom_oid, OID_content_json)

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "UK"),
                x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Cumbria"),
                x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Keswick"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "PavInc"),
                x509.NameAttribute(
                    x509.oid.NameOID.COMMON_NAME, "github.com/actuallypav"
                ),
            ]
        )
    )

    csr_builder = csr_builder.add_extension(custom_extension, critical=False)

    csr = csr_builder.sign(private_key, hashes.SHA256())

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
    key = base64.b64decode(kv_dict["aes_key"])
    iv = base64.b64decode(kv_dict["aes_iv"])

    return key, iv


def get_pem(csr, api_gateway_url):
    base64_csr = base64.b64encode(csr.encode()).decode()

    body = {
        "requestBody": base64_csr,
    }

    header = {"Content-Type": "application/json"}

    response = requests.post(api_gateway_url, json=body, headers=header)

    if response.status_code == 200:
        return response
    else:
        print(f"ERROR: {response.status_code}, {response.text}")


def main():
    #retrieve important info on the EST/Device count
    device_count, data, region, kv_name, api_gw_url = retrieve_config("config_client.json")

    # recover key/iv from secrets
    key, iv = retrieve_kv(region, kv_name)

    for i in range(device_count):
        # read the config file for this IoT "VERY IMPORTANY"
        OID_content = parse_devices(i, data)

        # generate CSR
        csr_data = generate_csr(OID_content)

        # encrypt CSR
        encrypted_csr = encrypt_aes256(csr_data, key, iv)

        # encode with Base64
        b64_encoded_csr = base64.b64encode(encrypted_csr).decode()

        response = get_pem(b64_encoded_csr, api_gw_url)
        response_json = json.loads(response.text)

        root_ca = response_json["root_ca"]
        cert_pem = response_json["cert_pem"]

        print(root_ca)
        print(cert_pem)

        thing_name = OID_content["ThingName"]
        os.makedirs(f"certs/{thing_name}", exist_ok=True)

        with open(f"certs/{thing_name}/root_ca.pem", "w") as r:
            r.write(root_ca)

        with open(f"certs/{thing_name}/certificate.pem", "w") as c:
            c.write(cert_pem)

        with open(f"certs/{thing_name}/private_key.pem", "wb") as k:
            with open("private_key.pem", "rb") as temp_key:
                k.write(temp_key.read())

    print(f"Success find the certificates in the certs folder!")

if __name__ == "__main__":
    main()

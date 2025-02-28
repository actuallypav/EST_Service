import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import boto3
import os

def lambda_handler(event, context):

    kv_name = os.environ.get["KV_NAME"]
    region = os.environ.get["REGION"]
    root_ca_url =  os.environ.get["ROOT_CA_URL"]

    account_id = boto3.client('sts').get_caller_identity().get('Account')

    # Extract raw TCP Payload
    csr_aes = event.get("body", "")

    if not csr_aes:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No CSR data received"})
        }
    
    csr_pem = decrypt_csr(csr_aes, account_id, region, kv_name).encode()
    csr = x509.load_pem_x509_csr(csr_pem)

    verify_csr(csr)

    root_ca = download_root_ca(root_ca_url)

    cert_pem = sign_csr(csr)
    
    #TODO: send the signed shit back to the client
    print("this is the ROOT CA: ", root_ca)
    print("=============================================================")
    print("=============================================================")
    print("=============================================================")
    print("=============================================================")
    print("=============================================================")
    print("this is the certificate pem: ", cert_pem)

def decrypt_csr(ciphertext, account_id, region, kv_name):
    #retrive key/iv
    sm = boto3.client('secretsmanager')

    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{kv_name}"

    kv = sm.get_secret_value(
        SecretId=arn
    )

    kv_dict = json.loads(kv["SecretString"])

    #b64 decode all
    key = base64.b64decode(kv["aes_key"])
    iv = base64.b64decode(kv["aes_iv"])

    ciphertext = base64.b64decode(ciphertext)

    #decrypt with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor_padded = decryptor.update(plaintext_padded) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    return plaintext.decode()

def verify_csr(csr):
    public_key = csr.public_key()
    
    try:
        public_key.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15,
            csr.signature_hash_algorithm,
        )
        print("CSR is valid")
    except Exception as e:
        print("CSR verification failed ", e)
    
        #TODO: Return error to the client - for now just quit lambda
        raise Exception("Forced Lambda exit - can't verify CSR")

def download_root_ca(ca_url):
    response = requests.get(ca_url)
    if response.status_code == 200:
        return response.content
    else:
        print("Error retriving Amazon Root CA")
        #TODO: Return error to the client - for now just quit lambda
        raise Exception("Forced Lambda exit - can't verify CSR")

def sign_csr(csr):
    #sign csr
    iot = boto3.client("iot")

    response = iot.create_certificate_from_csr(
        certifacteSigningRequest=csr,
        setAsActive=True
    )

    cert_arn = response["certificateARN"]
    cert_id = response["certificateId"]
    cert_pem = response["certificatePem"]

    #TODO: Retrive name/policies from OID for now just make default ones
    thing_name = "IoTPavTest"
    policy_name = "IoTPavTestPolicy"

    iot.attach_thing_principal(
        thingName=thing_name,
        principal=cert_arn
    )

    iot.attach_policy(
        policyName=policy_name,
        target=cert_arn
    )

    return cert_pem
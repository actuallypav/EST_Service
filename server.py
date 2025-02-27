import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
import os

def lambda_handler(event, context):
    kv_name = os.environ.get["KV"]
    region = os.environ.get["REGION"]

    account_id = boto3.client('sts').get_caller_identity().get('Account')

    # Extract raw TCP Payload
    csr_aes = event.get("body", "")

    if not csr_aes:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No CSR data received"})
        }
    
    key, value = retrive_secret(account_id, region, kv_name)

    csr_pem = decrypt_csr(key, value, csr_aes)

    sign_csr(csr_pem)
            
    #send the signed shit back to the client

def retrive_secret(account_id, region, kv_name):
    sm = boto3.client('secretsmanager')
    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{kv_name}"

    kv = sm.get_secret_value(
        SecretId=arn
    )

    kv_dict = json.loads(kv["SecretString"])

    key = base64.b64decode(kv["aes_key"])
    value = base64.b64decode(kv["aes_iv"])
    
    return key, value

def decrypt_csr(key, iv, ciphertext):
    #Decode AES encrypted b64-CSR

    #Convert from B64 to CSR
    pass

def sign_csr(csr_pem):
    #sign csr
    #return all of the shabang
    pass
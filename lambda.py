import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def lambda_handler(event, context):
    code = "FXiJwj/ZkEeDq3JRvAhtaHImq3tcnoEtBbXNOWhfei8="

    # Extract raw TCP Payload
    csr_aes = event.get("body", "")

    if not csr_aes:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No CSR data received"})
        }
    
    key, value = retrive_secret

    csr_pem = decrypt_csr(key, value, csr_aes)

    sign_csr(csr_pem)
            
    #send the signed shit back to the client

def retrive_secret():
    key = ""
    value = ""
    return key, value

def decrypt_csr(key, iv, ciphertext):
    #Decode AES encrypted b64-CSR

    #Convert from B64 to CSR
    pass

def sign_csr(csr_pem):
    #sign csr
    #return all of the shabang
    pass
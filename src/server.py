import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import requests
import boto3
import os
import logging
import traceback

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

import base64

def lambda_handler(event, context):
    try:
        print(event["requestContext"])
        source_ip = event["requestContext"]["identity"]["sourceIp"]
        print(f"Received request from IP: {source_ip}")

        kv_name = os.environ.get("KV_NAME")
        region = os.environ.get("REGION")
        root_ca_url = os.environ.get("ROOT_CA_URL")
        oid = os.environ.get("OID")

        account_id = boto3.client("sts").get_caller_identity().get("Account")

        if "body" not in event or not event["body"]:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "No CSR data received"}),
            }

        body = json.loads(event["body"])
        csr_aes = base64.b64decode(body["requestBody"])
        logger.debug(f"CSR Content with AES: {str(csr_aes)}")

        csr_pem = decrypt_csr(csr_aes, account_id, region, kv_name)
        logger.debug(f"Decrypted CSR (PEM Format): {(csr_pem)}")

        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        logger.debug(f"CSR Structure: {csr}")

        verify_csr(csr)
        logger.info("Successfully verified the CSR.")

        logger.info("Downloading Root CA.")
        root_ca = download_root_ca(root_ca_url)

        logger.info("Signing the CSR and creating the Thing.")
        cert_pem = sign_csr(csr, oid)

        # ensure cert_pem is in text before sending - 
        # probs not the best way but it is what it is
        if isinstance(cert_pem, bytes):
            cert_pem = cert_pem.decode('utf-8')

        if isinstance(root_ca, bytes):
            root_ca = root_ca.decode('utf-8')

        response_data = {
            "root_ca": root_ca,
            "cert_pem": cert_pem
        }
        logger.info("Successfully signed the CSR and prepared response.")

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response_data), 
        }

    except Exception as e:
        logger.error(f"ERROR: {str(e)}")
        logger.error("Traceback: %s", traceback.format_exc())
        return {"statusCode": 500, "body": json.dumps({"ERROR": str(e)})}

def decrypt_csr(ciphertext, account_id, region, kv_name):
    # retrive key/iv
    sm = boto3.client("secretsmanager")

    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{kv_name}"

    kv = sm.get_secret_value(SecretId=arn)

    kv_dict = json.loads(kv["SecretString"])

    # b64 decode all
    key = base64.b64decode(kv_dict["aes_key"])
    iv = base64.b64decode(kv_dict["aes_iv"])

    ciphertext = base64.b64decode(ciphertext)

    # decrypt with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    return plaintext.decode()


def verify_csr(csr):
    public_key = csr.public_key()

    try:
        public_key.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            csr.signature_hash_algorithm,
        )
        print(csr)
        print("CSR is valid")
    except Exception as e:
        print("CSR verification failed ", e)
        # TODO: Return error to the client - for now just quit lambda
        raise Exception("Forced Lambda exit - can't verify CSR")

def download_root_ca(ca_url):
    response = requests.get(ca_url)
    if response.status_code == 200:
        return response.content
    else:
        print("Error retriving Amazon Root CA")
        # TODO: Return error to the client - for now just quit lambda
        raise Exception("Forced Lambda exit - can't verify CA")

def generate_policy(permissions):
    pass

def create_thing(oid, iot, cert_arn):
    #TODO: retrieve the extension for parsing

    #TODO: split it the oid into permissions
    permissions = ""
    thing_policy = generate_policy(permissions)
    
    #TODO: replace below with the extension contents
    thing_name = "IoTPavTest"
    policy_name = "IoTPavTestPolicy"

    print("creating the thing")
    # Verify the above exists - if not create
    try:
        iot.describe_thing(thingName=thing_name)
        print(f"Thing '{thing_name}' exists.")
    except iot.exceptions.ResourceNotFoundException:
        print(f"Thing '{thing_name}' does not exist. Creating it now...")
        iot.create_thing(thingName=thing_name)

    print("creating the policy")
    try:
        iot.get_policy(policyName=policy_name)
        print(f"Policy '{policy_name}' exists.")
    except iot.exceptions.ResourceNotFoundException:
        print(f"Policy '{policy_name}' does not exist. Creating it now...")
        #TODO: replace with thing_policy VVV
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}
            ],
        }
        iot.create_policy(
            policyName=policy_name, policyDocument=json.dumps(policy_document)
        )

    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)

    iot.attach_policy(policyName=policy_name, target=cert_arn)

def sign_csr(oid, csr):
    # sign csr
    iot = boto3.client("iot")

    response = iot.create_certificate_from_csr(
        certificateSigningRequest=csr.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8"),
        setAsActive=True,
    )

    print(response)
    print("certificate signed")
    
    cert_arn = response["certificateArn"]
    cert_pem = response["certificatePem"]

    create_thing(oid, iot, cert_arn)

    print("all good sending back")
    return cert_pem

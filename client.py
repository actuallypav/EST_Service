import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import ConnectionError, Timeout
from requests.models import Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


 #TODO Add in mutual TLS authentication (mTLS) (server and client certs)
# already connecting over 443 - now need to verify shit

# set variables as to who to connect to - change this to .yml later
url = "http://127.0.0.1:8443"
auth = HTTPDigestAuth("admin", "123abc")
response = Response()
response.status_code = 400 

# Generate rsa private key
private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
        )

# Generate CSR 
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "CLIENT.PAV.COM"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PavInc"),
    ])).sign(private_key, hashes.SHA256())


# Serialize Private Key (PEM)
private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )

# Serialize CSR (PEM)
csr_pem = csr.public_bytes(serialization.Encoding.PEM)


# input logic for auth
print(f"Connecting to {url}")
print("Enter your Username: ")
username = input()
print("Enter your Password: ")
password = input()
auth = HTTPDigestAuth(username, password)

try:
    # Ensure the server is verified
    #TODO:set verify to True - in production.
    response = requests.post(url+"/enroll", auth=auth, verify=False, data=csr_pem, headers={"Content-Type": "client/pkcs10"})
except ConnectionError:
    print("Error: Unable to connect to the server. Is it still running?")
except Timeout:
    print("Errorr The request timed out. Try again later.")
except requests.HTTPError as http_err:
    print(f"HTTP Error occurred: {http_err}")
except Exception as err:
    print(f"An error occurred: {err}")

# check if we got in
if response.status_code == 200:
    print(response.text)


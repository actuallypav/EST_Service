from flask import Flask, request
from flask_httpauth import HTTPDigestAuth
import ssl
import os

app = Flask(__name__)

app.secret_key = "abcd1234"
auth = HTTPDigestAuth()

# TODO: store these more securely? Or use common name of a certificate instead?
USERS = {"admin": "123abc"}

#TODO Using a verified CA (in the cloud) sign the server with newly "TRUSTED" certs

def generate_server_CA():
    #communicate with AWS to generate a cert.pem/key.pem/ca.pem
    #return them and pass them to variables
    pass

@auth.get_password
def get_password(username):
    if username in USERS:
        return USERS.get(username)
    return None

# create a server endpoint to allow client to connect
@app.route("/")
@auth.login_required
def index():
    return "Authenticated"

# new endpoint to handle CSR submission
@app.route("/enroll", methods=["POST"])
@auth.login_required
def enroll():
    #get raw csr
    csr_data = request.data 
    
    if not csr_data:
        return "No CSR Received", 400
    #print today add in verification tomorrow
    print("Received CSR:\n", csr_data.decode(), flush=True)
    
    
    return "CSR Received Successfully", 200

if __name__ == "__main__":
    #only the server presents a certificate - client auth will be done in the cloud
    app.run(host='0.0.0.0',port=8443,debug=True)

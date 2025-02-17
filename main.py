from flask import Flask, request
from flask_httpauth import HTTPDigestAuth
import os

print(os.getcwd())
app = Flask(__name__)

app.secret_key = "abcd1234"
auth = HTTPDigestAuth()

# TODO: store these more securely? Or use common name of a certificate instead?
USERS = {"admin": "123abc"}

#TODO Implement TLS with mutual authentication (server and client certificates)
# check if the user/pass exists
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

    #prjint today add in verification tomorrow
    print("Receivedd CSR: ", csr_data.decode())

    return "CSR Received Successfully", 200

if __name__ == "__main__":
    app.run(port=443, ssl_context=('certs/cert.pem', 'certs/key.pem'),debug=True)

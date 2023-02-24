from flask import Flask
from flask_httpauth import HTTPDigestAuth


app = Flask(__name__)

# TODO: investigate why i need a secret key? otherwise error 500
app.secret_key = "abcd1234"
auth = HTTPDigestAuth()

# TODO: store these more securely? Or use common name of a certificate instead?
USERS = {"admin": "123abc"}


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


if __name__ == "__main__":
    app.run(port=5001)

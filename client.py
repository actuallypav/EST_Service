import requests
from requests.auth import HTTPDigestAuth


# set variables as to who to connect to
# TODO: make it so user can input the values... maybe use a basic tkinter?
url = "http://127.0.0.1:5001"
auth = HTTPDigestAuth("admin", "123abc")

# see what the response from the server is
response = requests.get(url, auth=auth)

# check if we got in
if response.status_code == 200:
    print(response.text)
else:
    print(f"Error: {response.status_code}")

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import ConnectionError, Timeout
from requests.models import Response

# set variables as to who to connect to
url = "http://127.0.0.1:5001"
auth = HTTPDigestAuth("admin", "123abc")
response = Response()
response.status_code = 400 

#input logic for auth
print(f"Connecting to {url}")
print("Enter your Username: ")
username = input()
print("Enter your Password: ")
password = input()
auth = HTTPDigestAuth(username, password)

try:
    # see what the response from the server is
    response = requests.get(url, auth=auth)
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


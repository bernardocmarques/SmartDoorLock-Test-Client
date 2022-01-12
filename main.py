import socket
import os
import base64
import hmac
import hashlib
import time

from aes_util import AES_Util
from rsa_util import RSA_Util

AES: AES_Util

door_ip = '192.168.1.139'  # Door ip (Change if necessary)
door_port = 3333  # Door port (Change if necessary)

rsa = RSA_Util("public_key.pem")  # Door private key

# User information, saved in the door
user_id = "0vn3kfl3n"
master_key = "SoLXxAJHi1Z3NKGHNnS5n4SRLv5UmTB4EssASi0MmoI="


def get_session_credentials_base64():
    key = bytearray(os.urandom(32))
    key_b64 = base64.b64encode(key).decode()

    iv = bytearray(os.urandom(16))
    iv_b64 = base64.b64encode(iv).decode()

    return AES_Util(key, iv), "SSC " + key_b64 + " " + iv_b64  # todo remove iv


''' ---------------------------------- '''
''' -------------- Main -------------- '''
''' ---------------------------------- '''

# Connect to door
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((door_ip, door_port))

# Start client side timer
start = time.time()

# Generate session key
AES, cred_b64 = get_session_credentials_base64()

# Send session key to door. "SSC session_key"
cred_b64_enc = rsa.encrypt_msg(cred_b64)
sock.send(cred_b64_enc)

# Get seed to generate authorization_code. "RAC seed"
res = sock.recv(1024)
msg, iv = res.decode().split(" ")
seed = AES.decrypt(msg, iv).split(" ")[1]

# Generate authorization_code based on seed.
auth_code = base64.b64encode(
    hmac.new(base64.b64decode(master_key), base64.b64decode(seed), hashlib.sha256).digest()).decode()

# Send authorization credentials. "SAC user_id authorization_code"
sock.send((AES.encrypt(f"SAC {user_id} {auth_code}")).encode())

# Receive confirmation of authorization. "ACK"
res = sock.recv(1024)
msg, iv = res.decode().split(" ")
confirmation = AES.decrypt(msg, iv)

# Send request to unlock door. "RUD"
sock.send((AES.encrypt(f"RUD")).encode())

# Receive confirmation of unlocking. "ACK"
res = sock.recv(1024)
msg, iv = res.decode().split(" ")
confirmation = AES.decrypt(msg, iv)

# Stop client side timer and print time elapsed
end = time.time()
print(end - start)

# Close connection to door
sock.close()

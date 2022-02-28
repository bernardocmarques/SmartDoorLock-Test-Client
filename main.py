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

rsa = RSA_Util("public_key.pem")  # Door public key. (Hardcoded in the server)

# User information, saved in the door
user_id = "0vn3kfl3n"
master_key = "SoLXxAJHi1Z3NKGHNnS5n4SRLv5UmTB4EssASi0MmoI="

client_times = []
server_t1 = []
server_t2 = []


def get_session_credentials_base64():
    key = bytearray(os.urandom(32))
    key_b64 = base64.b64encode(key).decode()

    return AES_Util(key), f"SSC {key_b64} "


''' ---------------------------------- '''
''' -------------- Main -------------- '''
''' ---------------------------------- '''
s = time.time()
n = int(input("Number of tests?\n> "))
i = 0
while i < n:
    try:
        # Connect to door
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((door_ip, door_port))
        sock.settimeout(3)

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
        confirmation, t1, t2 = AES.decrypt(msg, iv).split(" ")

        # Stop client side timer and print time elapsed
        end = time.time()
        client_times.append(end - start)
        server_t1.append(int(t1))
        server_t2.append(int(t2))

        if i % 25 == 0:
            print(f"Test {i}:\n")

        # Close connection to door
        sock.close()
        i += 1
    except:
        print(f"Error! Retrying, i={i}...")
        pass

print(client_times)
print(server_t1)
print(server_t2)

print(f"Avg. time in client: {sum(client_times) / n} seconds")
print(f"Avg. time to setup secure channel: {sum(server_t1) / n} microseconds")
print(f"Avg. time to lock/unlock door: {sum(server_t2) / n} microseconds")

print(f"Total test time: {time.time()-s} seconds")

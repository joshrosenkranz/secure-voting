from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from functools import reduce
import hashlib
import math
import socket
import sys

def print_votes(votes):
    votes = [x if len(x) == 2 else ('', '') for x in votes]
    largest_index = len(votes) - 1
    size_of_index_col = len(str(largest_index))
    index_col_padding_spaces = max(math.ceil((size_of_index_col - 5) / 2.0), 1)
    index_col_header = " " * index_col_padding_spaces + "INDEX" + " " * index_col_padding_spaces

    longest_vote = reduce(max, map(lambda x: len(x[0]), votes))
    vote_col_padding_spaces = max(math.ceil((longest_vote - 4) / 2.0), 1)
    vote_col_header = " " * vote_col_padding_spaces + "VOTE" + " " * vote_col_padding_spaces

    longest_key = reduce(max, map(lambda x: len(x[1]), votes))
    key_col_padding_spaces = max(math.ceil((longest_key - 10) / 2.0), 1)
    key_col_header = " " * key_col_padding_spaces + "UNIQUE KEY" + " " * key_col_padding_spaces
    print("\n" + index_col_header + "|" + vote_col_header + "|" + key_col_header)
    for i in range(len(votes)):
        vote, key = votes[i]
        index_str = str(i) + " " * (len(index_col_header) - len(str(i)))
        vote_str = vote + " " * (len(vote_col_header) - len(vote))
        key_str = key + " " * (len(key_col_header) - len(key))
        print(index_str + "|" + vote_str + "|" + key_str)

#Get government's public key
with open("PK_Gov", "rb") as public_key_file:
        public_key_gov = serialization.load_ssh_public_key(
            public_key_file.read(), 
            backend=default_backend()
        )

#Encrypt message
symmetric_key = Fernet.generate_key()
vote = input("Who would you like to vote for? ")
message_string = vote + "|" + symmetric_key.decode('utf-8')
default_padding = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                  )
cipher_message = public_key_gov.encrypt(message_string.encode('utf-8'), default_padding)
  
#Create socket connection and send encrypted message
try: 
    vote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
except socket.error as err: 
    print("socket creation failed with error %s" %(err))

vote_host = "127.0.0.1"
vote_port = 12345
vote_socket.connect((vote_host, vote_port))
vote_socket.send(cipher_message)

#Unencrypt index received from government
cipher_index = vote_socket.recv(1024)
cipher_suite = Fernet(symmetric_key)
plain_index = int(cipher_suite.decrypt(cipher_index).decode())

#Verify vote
hashed_symmetric_key = hashlib.sha256(symmetric_key).hexdigest()
print("\nYour vote will appear at index", plain_index, "with key", hashed_symmetric_key)

#Create socket connection and send encrypted message
try: 
    verify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
except socket.error as err: 
    print ("socket creation failed with error %s" %(err))

verify_host = "127.0.0.1"
verify_port = 12000
verify_socket.connect((verify_host, verify_port))
verify_socket.send(cipher_message)
votes_string = verify_socket.recv(1024).decode()
votes_list = votes_string.split(',')
votes = [tuple(v.split("|")) for v in votes_list]
print_votes(votes)
if votes[plain_index] == (vote, hashlib.sha256(symmetric_key).hexdigest()):
    print("\nVote for", vote, "verified")
else:
    print("Error submitting vote")

"""
TODO
-Cleanup code, improve naming
-Figure out better encoding than magic delimiters
-Figure out how to host government and voter code on separate computers
-Put on Github
-Figure out what to do with voting.py file
-Unverified vote handling?
"""



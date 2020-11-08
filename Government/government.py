#### Government ####
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from functools import reduce
import hashlib
import math
import secrets
import socket
import threading

def print_votes(votes):
    votes = [x if x else ('', '') for x in votes]
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

num_voters = 10
votes = [None] * num_voters
lock = threading.Lock()

#Get government's private key
with open("SK_Gov", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

#Create socket
vote_server_socket = socket.socket()          
vote_host = "0.0.0.0"
vote_port = 12345              
vote_server_socket.bind((vote_host, vote_port))
vote_server_socket.listen(5)
print ('Vote server started and listening')

verify_server_socket = socket.socket()          
verify_host = "0.0.0.0"
verify_port = 12000              
verify_server_socket.bind((verify_host, verify_port))
verify_server_socket.listen(5)
print ('Get votes server started and listening')

class VoteServer(threading.Thread):
    def __init__(self, socket, address):
        threading.Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.run()

    def run(self):
        vote_request_text = self.sock.recv(1024)
        #Decrypt message
        default_padding = padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                          )
        plain_message = private_key.decrypt(vote_request_text, default_padding).decode('utf-8')
        vote, symmetric_key = plain_message.split('|')

        #Write vote
        global votes
        hashed_symmetric_key = hashlib.sha256(symmetric_key.encode('utf-8')).hexdigest()
        with lock:
            index = secrets.choice([i for i, v in enumerate(votes) if v == None])
            votes[index] = (vote, hashed_symmetric_key)

        #Encrypt index
        cipher_suite = Fernet(symmetric_key)
        cipher_index = cipher_suite.encrypt(str(index).encode('utf-8'))
        self.sock.send(cipher_index)

def start_vote_server():
    while True:
        socket, address = vote_server_socket.accept()
        VoteServer(socket, address)

class VerifyServer(threading.Thread):
    def __init__(self, socket, address):
        threading.Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.run()

    def run(self):
        #Encrypt index
        vote_string_list = []
        for v in votes:
            if v == None:
                vote_string_list.append('')
            else:
                vote_string_list.append(v[0] + "|" + v[1])
        vote_string = ",".join(vote_string_list)
        print_votes(votes)
        self.sock.send(vote_string.encode('utf-8'))

def start_verify_server():
    while True:
        socket, address = verify_server_socket.accept()
        VerifyServer(socket, address)

vote_thread = threading.Thread(target=start_vote_server)
vote_thread.start()
verify_thread = threading.Thread(target=start_verify_server)
verify_thread.start()


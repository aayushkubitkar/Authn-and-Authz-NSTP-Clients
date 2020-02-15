import socket
import struct
import nstp_v3_pb2
import nacl.utils
import nacl.secret
from nacl.bindings import crypto_kx, crypto_secretbox, crypto_secretbox_open

def append_len(data):
    return struct.pack(f'!H{len(data)}s', len(data), data)

def recv_full_msg(n, s):
    print ("receiving entire message")
    msg=b''
    while n>0:
        chunk = s.recv(n)
        n= n - len(chunk)
        msg = msg+chunk
    return msg

HOST = 'localhost'
PORT = 22300
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
pk_client, sk_client= crypto_kx.crypto_kx_keypair()

#Clienthello
nstp_msg=nstp_v3_pb2.NSTPMessage()
ch=nstp_v3_pb2.ClientHello()
ch.major_version=1
ch.minor_version=2
ch.user_agent="hi server"
ch.public_key=pk_client
nstp_msg.client_hello.CopyFrom(ch)
print("sending data")
s.send(append_len(nstp_msg.SerializeToString()))

data = s.recv(2)
print("receiving data")
len_msg = struct.unpack('!H', data[:2])
print("length of message to be received {}".format(len_msg[0]))
full_msg = recv_full_msg(len_msg[0], s)
res_msg = nstp_v3_pb2.NSTPMessage()
res_msg.ParseFromString(full_msg)
print(res_msg)
s_hello=nstp_v3_pb2.ServerHello()
s_hello.CopyFrom(res_msg.server_hello)

rx ,tx = crypto_kx.crypto_kx_client_session_keys(pk_client, sk_client, s_hello.public_key)
#AuthReq
auth_req=nstp_v3_pb2.AuthenticationRequest()
auth_req.username="mario"
auth_req.password="hello"
random_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encr_auth_req=nstp_v3_pb2.EncryptedMessage()
encr_auth_req.ciphertext = crypto_secretbox(auth_req.SerializeToString(), random_nonce, tx)
encr_auth_req.nonce=random_nonce
print (encr_auth_req.ciphertext, encr_auth_req.nonce)
nstp_req= nstp_v3_pb2.NSTPMessage()
nstp_req.encrypted_message.CopyFrom(encr_auth_req)
s.send(append_len(nstp_req.SerializeToString()))

data = s.recv(2)
print("receiving data")
len_msg = struct.unpack('!H', data[:2])
print("length of message to be received {}".format(len_msg[0]))
full_msg = recv_full_msg(len_msg[0], s)
res_msg = nstp_v3_pb2.NSTPMessage()
res_msg.ParseFromString(full_msg)
print(res_msg)

#10.110.39.71
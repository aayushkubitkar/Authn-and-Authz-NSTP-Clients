import socket
import select
import struct
import nstp_v3_pb2
#from nacl.public import PrivateKey, Box
from nacl.bindings import crypto_kx, crypto_secretbox, crypto_secretbox_open
from nacl import utils, secret
from passlib.context import CryptContext
import threading

def createSessionKey(s, client_pub_key):
    rx ,tx = crypto_kx.crypto_kx_server_session_keys(pk_server, sk_server, client_pub_key)
    return rx, tx

def handleClientHello(s, nstp_msg):
    if s not in client_init:
        client_init[s]=1
        c_hello = nstp_v3_pb2.ClientHello()
        c_hello.CopyFrom(nstp_msg.client_hello)
        if c_hello.major_version==1:
            print("client Initialized")
            rx, tx = createSessionKey(s, c_hello.public_key)
            dict_session_keys[s]=[rx]
            dict_session_keys[s].append(tx)
            print (dict_session_keys[s][0], dict_session_keys[s][1])
            serverHello(s, c_hello.user_agent)
    else:
        print("out of spec")

def serverHello(s, user_agent):
    print ("inside server hello")
    nstp_res= nstp_v3_pb2.NSTPMessage()
    s_hello=nstp_v3_pb2.ServerHello()
    s_hello.major_version=1
    s_hello.minor_version=2
    s_hello.user_agent=user_agent
    s_hello.public_key=pk_server
    nstp_res.server_hello.CopyFrom(s_hello)
    response_message[s]=append_len(nstp_res.SerializeToString())

def handleEncryptedMessage(s, nstp_msg):
    print ("inside handleEncryptedMessage")
    if s in client_init:
        encr_msg = nstp_v3_pb2.EncryptedMessage()
        encr_msg.CopyFrom(nstp_msg.encrypted_message)
        print (encr_msg.ciphertext, encr_msg.nonce)
        decr_msg_b = crypto_secretbox_open(encr_msg.ciphertext, encr_msg.nonce, dict_session_keys[s][0])
        decr_msg=nstp_v3_pb2.DecryptedMessage()
        decr_msg.ParseFromString(decr_msg_b)
        switcher = {
                    'auth_request': handleAuthReq,
                    'ping_request': handlePingReq,
                    'store_request': handleStoreReq,
                    'load_request': handleLoadReq
        }
        func = switcher.get(decr_msg.WhichOneof("message_"))
        func(s, decr_msg)
    else:
        print ("out of spec")

def handleAuthReq(s, decr_msg):
    if s.getpeername()[0] not in list_ip_ban.keys():
        auth_req = nstp_v3_pb2.AuthenticationRequest()
        auth_req.CopyFrom(decr_msg.auth_request)
        ctx = CryptContext(schemes=["md5_crypt", "sha256_crypt", "sha512_crypt"])
        pwhash=getHashFromFile(auth_req.username)
        if pwhash:
            if ctx.verify(auth_req.password, pwhash):
                print ("authentication success")
                list_ip_failed_logins[clientsocket.getpeername()[0]]=0
                AuthRes(s, True)
            else:
                print ("authentication failed")
                val=list_ip_failed_logins[s.getpeername()[0]]
                list_ip_failed_logins[s.getpeername()[0]]=val+1
                if (list_ip_failed_logins[s.getpeername()[0]] > 10)
                    handleRateLimit(s)
                AuthRes(s, False)
        else:
            print ("user not found")
    else:
        print ("IP blocked for too many attempts. Please try again after sometime.")

def AuthRes(s, decision):
    auth_res= nstp_v3_pb2.AuthenticationResponse()
    auth_res.authenticated=decision
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encr_auth_res=nstp_v3_pb2.EncryptedMessage()
    encr_auth_res.ciphertext=crypto_secretbox(auth_res.SerializeToString(), nonce, dict_session_keys[s][1])
    encr_auth_res.nonce=nonce
    nstp_res= nstp_v3_pb2.NSTPMessage()
    nstp_res.encrypted_message.CopyFrom(encr_auth_res)
    response_message[s]= append_len(nstp_res.SerializeToString())
# def handlePingReq():

# def handleStoreReq():

# def handleLoadReq():

def unblockIP(s):
    del list_ip_ban[s.getpeername()[0]]

def handleRateLimit(s):
    list_ip_ban[s.getpeername()[0]]=1
    t = threading.Timer(25, unblockIP, [s])
    t.start()

def clientInitialized(conn):
    try:
        if client_init[conn]==1:
            return True
        else:
            return False
    except KeyError:
        print ("Key error")
        return False

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

def getHashFromFile(s):
    filepath='pass.txt'
    with open(filepath) as fp:
        for line in enumerate(fp):
            if line.split(':')[0]==s:
                return line.split(':')[1]
        return ""

HOST = '0.0.0.0'
PORT = 22300
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

incoming=[server]
outgoing=[]
client_init={}
list_ip_rate_limit={}
list_ip_ban={}
list_ip_failed_logins={}
response_message={}
value_store={}
dict_session_keys={}
sk_server, pk_server = crypto_kx.crypto_kx_keypair()
print (pk_server, len(pk_server))
while incoming:
    print ("waiting for client to connect")
    print (incoming, outgoing)
    reads, writes, exceptions = select.select(incoming, outgoing, incoming)
    for s in reads:
        if s is server:
            print("connection accepted from", s)
            clientsocket, addr = server.accept()
            list_ip_failed_logins[addr[0]]=0
            clientsocket.setblocking(False)
            incoming.append(clientsocket)
        else:
            print("data read from socket", s)
            data=s.recv(2)
            if data:
                outgoing.append(s)
                len_msg = struct.unpack('!H', data[:2])
                print("length of message to be received {}".format(len_msg[0]))
                full_msg = recv_full_msg(len_msg[0], s)
                nstp_msg = nstp_v3_pb2.NSTPMessage()
                nstp_msg.ParseFromString(full_msg)
                print (nstp_msg)
                switcher = {
                    'client_hello': handleClientHello,
                    'encrypted_message': handleEncryptedMessage
                }
                func = switcher.get(nstp_msg.WhichOneof("message_"))
                func(s, nstp_msg)
            else:    
                incoming.remove(s)
    for s in writes:
        print ("inside write")
        try:
            print ("writing data to socket",s)
            s.send(response_message[s])
            outgoing.remove(s)
        except Exception as e:
            print ("exception raised", e)
            outgoing.remove(s)
    # for s in exceptions:

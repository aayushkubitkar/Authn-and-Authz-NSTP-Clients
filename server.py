import socket
import select
import struct
import nstp_v3_pb2
from nacl.bindings import crypto_kx, crypto_secretbox, crypto_secretbox_open
from nacl import utils, secret, hash
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt ,argon2
from passlib.context import CryptContext
import threading

def createSessionKey(s, client_pub_key):
    rx ,tx = crypto_kx.crypto_kx_server_session_keys(pk_server, sk_server, client_pub_key)
    return rx, tx

def handleClientHello(s, nstp_msg):
    print ("inside client hello")
    if s not in client_init:
        client_init[s]=1
        c_hello = nstp_v3_pb2.ClientHello()
        c_hello.CopyFrom(nstp_msg.client_hello)
        print("client Initialized")
        if c_hello.major_version==3:
            print ("client compliant version")
            rx, tx = createSessionKey(s, c_hello.public_key)
            dict_session_keys[s]=[rx]
            dict_session_keys[s].append(tx)
            print (dict_session_keys[s][0], dict_session_keys[s][1])
            serverHello(s, c_hello.user_agent)
        else:
            print ("out of spec")
            errorRes(s, "out of spec")
    else:
        print ("out of spec")
        errorRes(s, "out of spec")

def serverHello(s, user_agent):
    print ("inside server hello")
    nstp_res= nstp_v3_pb2.NSTPMessage()
    s_hello=nstp_v3_pb2.ServerHello()
    s_hello.major_version=3
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
        print(decr_msg_b)
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
        errorRes(s, "out of spec")

def handleAuthReq(s, decr_msg):
    print ("inside handleAuthReq")
    if s in list_ip_authenticated.keys() and list_ip_authenticated[s] != 1:
        auth_req = nstp_v3_pb2.AuthenticationRequest()
        auth_req.CopyFrom(decr_msg.auth_request)
        ctx = CryptContext(schemes=["md5_crypt", "sha256_crypt", "sha512_crypt"])
        print (auth_req.password)
        hashVal=getHashFromFile(auth_req.username)
        authenticated = False
        if hashVal:
            if "argon" in hashVal:
                authenticated = argon2.verify(auth_req.password, hashVal) 
            else:
                authenticated = ctx.verify(auth_req.password, hashVal)
            if authenticated:
                print ("Authentication success")
                list_ip_authenticated[s]=1 #Connections with value 1 are authenticated
                conn_user_map[s]=auth_req.username #Used for private value store
                list_ip_failed_logins[clientsocket.getpeername()[0]]=0 #resetting the failed login attempts
                authRes(s, True)
            else:
                print ("Authentication failed")
                val=list_ip_failed_logins[s.getpeername()[0]]
                list_ip_failed_logins[s.getpeername()[0]]=val+1
                if list_ip_failed_logins[s.getpeername()[0]] > 10:
                    handleRateLimit(s)
                authRes(s, False)
        else:
            print ("User not found")
            errorRes(s, "User not found")
    else:
        print ("User already authentiacted.")
        errorRes(s, "User already authentiacted")

def authRes(s, decision):
    print ("inside AuthRes-->", decision)
    decr_res= nstp_v3_pb2.DecryptedMessage()
    auth_res= nstp_v3_pb2.AuthenticationResponse()
    auth_res.authenticated=decision
    decr_res.auth_response.CopyFrom(auth_res)
    EncryptAndSend(s,decr_res)

def handlePingReq(s, decr_msg):
    if s in list_ip_authenticated and list_ip_authenticated[s]==1:
        ping_req = nstp_v3_pb2.PingRequest()
        ping_req.CopyFrom(decr_msg.ping_request)
        pingRes(s,ping_req)
    else:
        print("User is not authenticated")
        errorRes(s, "User is not authenticated")

def pingRes(s, ping_req):
    ping_res = nstp_v3_pb2.PingResponse()
    if ping_req.hash_algorithm == nstp_v3_pb2.HashAlgorithm.IDENTITY:
        ping_res.hash = ping_req.data
    elif ping_req.hash_algorithm == nstp_v3_pb2.HashAlgorithm.SHA256:
        ping_res.hash = hash.sha256(ping_req.data)
    elif ping_req.hash_algorithm == nstp_v3_pb2.HashAlgorithm.SHA512:
        ping_res.hash = hash.sha512(ping_req.data)
    else:
        return
    decr_res= nstp_v3_pb2.DecryptedMessage()
    decr_res.ping_response.CopyFrom(ping_res)
    EncryptAndSend(s,decr_res)

def handleStoreReq(s, decr_msg):
    print ("inside storeReq")
    if s in list_ip_authenticated and list_ip_authenticated[s]==1:
        store_req = nstp_v3_pb2.StoreRequest()
        store_req.CopyFrom(decr_msg.store_request)
        if store_req.public:
            print ("store public key")
            public_value_store[store_req.key]=store_req.value
            print (store_req.key)
            print (public_value_store)
        else:
            print ("store private key")
            username = conn_user_map[s]
            if username not in priv_value_store.keys():
                priv_value_store[username]={store_req.key:store_req.value}
                print (store_req.key)
                print (priv_value_store)
            else:
                print("++", store_req.key)
                priv_value_store[username].update({store_req.key:store_req.value})
        storeRes(s, store_req.key, store_req.value)
    else:
        print("User is not authenticated")
        errorRes(s, "User is not authenticated")

def storeRes(s, key, value):
    decr_res= nstp_v3_pb2.DecryptedMessage()
    store_res = nstp_v3_pb2.StoreResponse()
    print ("hiii+++++", value)
    store_res.hash = hash.sha256(value)
    store_res.hash_algorithm = nstp_v3_pb2.HashAlgorithm.SHA256
    decr_res.store_response.CopyFrom(store_res)
    EncryptAndSend(s, decr_res)

def handleLoadReq(s, decr_msg):
    print ("inside loadReq")
    if s in list_ip_authenticated and list_ip_authenticated[s]==1:
        load_req = nstp_v3_pb2.LoadRequest()
        load_req.CopyFrom(decr_msg.load_request)
        if load_req.public:
            print ("access public key")
            print ("{}".format(load_req.key))
            if load_req.key in public_value_store.keys():
               loadRes(s, public_value_store[load_req.key])
            else:
                print("Key doesn't exist in public store")
                errorRes(s, "Key doesn't exist in public store")
        else:
            print ("access private key")
            username = conn_user_map[s]
            print ("{}-->{}".format(load_req.key, username))
            if username in priv_value_store.keys() and load_req.key in priv_value_store[username].keys():
                loadRes(s, priv_value_store[username][load_req.key])
            else:
                print ("Unauthorized access to private key")
                errorRes(s, "Unauthorized access to private key")
    else:
        print("User is not authenticated")
        errorRes(s, "User is not authenticated")

def loadRes(s, val):
    load_res = nstp_v3_pb2.LoadResponse()
    load_res.value = val
    decr_res = nstp_v3_pb2.DecryptedMessage()
    decr_res.load_response.CopyFrom(load_res)
    EncryptAndSend(s, decr_res)

def EncryptAndSend(s,res):
    encr_res=nstp_v3_pb2.EncryptedMessage()
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    encr_res.ciphertext=crypto_secretbox(res.SerializeToString(), nonce, dict_session_keys[s][1])
    encr_res.nonce=nonce
    nstp_res= nstp_v3_pb2.NSTPMessage()
    nstp_res.encrypted_message.CopyFrom(encr_res)
    print (nstp_res)
    response_message[s]= append_len(nstp_res.SerializeToString())

def unblockIP(s):
    list_ip_ban[s.getpeername()[0]]=0 #IPs with value 0 are allowed to authenticate

def handleRateLimit(s):
    list_ip_ban[s.getpeername()[0]]=1 #IPs with value 1 are banned
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

def getHashFromFile(username):
    filepath='pass.txt'
    with open(filepath) as fp:
        for cnt, line in enumerate(fp):
            entry = line.split(':')
            if entry[0]==username:
                return entry[1][:len(entry[1])-1]
        return ""

def errorRes(s, msg):
    err = nstp_v3_pb2.ErrorMessage()
    err.error_message=msg
    decr_res = nstp_v3_pb2.DecryptedMessage()
    decr_res.error_message.CopyFrom(err)
    # nstp_res= nstp_v3_pb2.NSTPMessage()
    # nstp_res.error_message.CopyFrom(err)
    # response_message[s]= append_len(nstp_res.SerializeToString())
    EncryptAndSend(s,err)

HOST = '0.0.0.0'
PORT = 22300
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

incoming=[server]
outgoing=[]
client_init={}
list_ip_authenticated={}
list_ip_ban={}
list_ip_failed_logins={}
response_message={}
priv_value_store={}
public_value_store={}
conn_user_map={}
dict_session_keys={}
pk_server, sk_server = crypto_kx.crypto_kx_keypair()
print (pk_server, len(pk_server))
while incoming:
    print ("waiting for client to connect")
    print (incoming, outgoing)
    reads, writes, exceptions = select.select(incoming, outgoing, incoming)
    for s in reads:
        if s is server:
            print("connection accepted from", s)
            clientsocket, addr = server.accept()
            ip = clientsocket.getpeername()[0]
            if ip in list_ip_ban.keys() and list_ip_ban[ip] == 1:
                print ("IP is banned to connect. Please try again after sometime.")
                clientsocket.close()
            else:
                list_ip_failed_logins[clientsocket.getpeername()[0]]=0
                list_ip_authenticated[clientsocket]=0
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
            print ("writing data to socket---->",s)
            if s in response_message:
                print (response_message[s])
                s.send(response_message[s])
                outgoing.remove(s)
            else:
                print ("no message to send")
                outgoing.remove(s)
        except Exception as e:
            print ("exception raised--->", e)
            outgoing.remove(s)
    # for s in exceptions:

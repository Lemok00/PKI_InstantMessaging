import socket
import time
import string
import random
import os

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

input('按回车键开始程序...')

# 设置Client 1的网络配置
HOST = '127.0.0.1'
PORT = 40007
BUF_SIZE = 4096
ENCODING = 'utf-8'
BLOCK_SIZE = 32

letters = string.ascii_lowercase

# CA的IP地址
CA_HOST = '127.0.0.1'
CA_PORT = 40005
# Server的IP地址
Sever_HOST = '127.0.0.1'
Sever_PORT = 40006

print('\n================================')
print('请输入客户端ID:')
ID_Client = 'ID-' + input()

Clients = {}

if os.path.exists(ID_Client):
    print('用户登陆')
    # 从个人文件夹中读取公钥、私钥和对称密钥
    with open(os.path.join(ID_Client, 'privateKey.pem'), 'rb') as f:
        Client_privateKey = RSA.importKey(f.read())
    with open(os.path.join(ID_Client, 'publicKey.pem'), 'rb') as f:
        Client_publicKey = RSA.importKey(f.read())
    with open(os.path.join(ID_Client, 'ServerPublicKey.pem'), 'rb') as f:
        Server_publicKey = RSA.importKey(f.read())
    with open(os.path.join(ID_Client, 'symmetricalKey.pem'), 'rb') as f:
        symmetricalKeyToServer = f.read().decode(ENCODING)

    # print(f'读取私钥 {Client_privateKey.export_key().decode(ENCODING)}')
    # print(f'读取公钥 {Client_publicKey.export_key().decode(ENCODING)}')
    # print(f'读取服务器公钥 {Server_publicKey.export_key().decode(ENCODING)}')
    print(f'读取客户端公钥、客户端私钥和服务器公钥')
    print(f'读取与服务器通信的对称密钥 {symmetricalKeyToServer}')
    print('================================\n')

    input('按回车键连接服务器...')

    # 连接服务器
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
        Client_socket.connect((Sever_HOST, Sever_PORT))
        # 发送客户端的ID
        RSA_message = str({'ID': ID_Client, 'TS': time.time().__trunc__()}).encode(ENCODING)
        print(RSA_message.decode(ENCODING))
        DES_message = str({'ID': ID_Client, 'IP': HOST, 'Port': PORT, 'TS': time.time().__trunc__()}).encode(ENCODING)
        RSA_Cipher = PKCS1_OAEP.new(Server_publicKey)
        DES_Cipher = DES.new(symmetricalKeyToServer.encode(ENCODING), DES.MODE_ECB)
        RSA_message = RSA_Cipher.encrypt(RSA_message)
        DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
        message = str({'Tag': 'LOG', 'RSA': RSA_message, 'DES': DES_message}).encode(ENCODING)
        Client_socket.sendall(message)

        # 从服务器接收登陆回复
        receivedMessage = Client_socket.recv(BUF_SIZE)
        print('\n================================')
        print(f'从服务器接收DES加密信息')
        DES_Cipher = DES.new(symmetricalKeyToServer.encode(ENCODING), DES.MODE_ECB)
        receivedMessage = unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE).decode(ENCODING)
        print(f'信息解密为{receivedMessage}')
        receivedMessage = eval(receivedMessage)
        tmpKey = receivedMessage['Key']
        print(f"登陆成功")
        print(f"与服务器本次会话使用临时密钥 {tmpKey}")
        print('================================\n')

else:
    print(f'用户注册')

    os.makedirs(ID_Client, exist_ok=True)
    # 生成Client的公钥和私钥
    Client_keyPair = RSA.generate(2048)
    Client_privateKey = Client_keyPair
    Client_publicKey = Client_keyPair.public_key()
    print(f'生成客户端公钥私钥对')
    # print(f'客户端公钥为\n{Client_publicKey.export_key().decode(ENCODING)}')
    # print(f'客户端私钥为\n{Client_privateKey.export_key().decode(ENCODING)}')
    with open(os.path.join(ID_Client, 'privateKey.pem'), 'wb') as f:
        f.write(Client_privateKey.export_key())
    with open(os.path.join(ID_Client, 'publicKey.pem'), 'wb') as f:
        f.write(Client_publicKey.export_key())

    # 选取和服务器通信的对称密钥
    symmetricalKeyToServer = (''.join(random.choice(letters) for i in range(8)))
    print(f'生成与服务器通信的对称密钥 {symmetricalKeyToServer}')
    print('================================\n')
    with open(os.path.join(ID_Client, 'symmetricalKey.pem'), 'wb') as f:
        f.write(symmetricalKeyToServer.encode(ENCODING))

    input('按回车键连接服务器...')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
        # 连接服务器
        Client_socket.connect((Sever_HOST, Sever_PORT))
        # 发送客户端的ID
        message = str({'Tag': 'REG', 'ID': ID_Client, 'TS': time.time().__trunc__()}).encode(ENCODING)
        Client_socket.sendall(message)

        # 从服务器接收信息
        receivedMessage = Client_socket.recv(BUF_SIZE).decode(ENCODING)
        print('\n================================')
        print(f'从服务器接收信息')
        receivedMessage = eval(receivedMessage)
        # 获取服务器证书和公钥
        Server_Certificate = receivedMessage['Certificate']
        Server_ID = receivedMessage['ID']
        Server_publicKey = RSA.importKey(receivedMessage['PK'].encode(ENCODING))
        print(f'获取服务器证书')
        print(f'获取服务器ID: {Server_ID}')
        print(f'获取服务器公钥')
        print('================================\n')
        with open(os.path.join(ID_Client, 'ServerPublicKey.pem'), 'wb') as f:
            f.write(Server_publicKey.export_key())

        input('按回车键连接CA以验证服务器证书...')

        # 获取CA的公钥
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as toCA_Socket:
            toCA_Socket.connect((CA_HOST, CA_PORT))
            receivedMessage = toCA_Socket.recv(BUF_SIZE).decode(ENCODING)
            receivedMessage = eval(receivedMessage)
            CA_ID = receivedMessage['ID']
            CA_publicKey = RSA.importKey(receivedMessage['PK'].encode(ENCODING))

            print('\n================================')
            print(f'获取CA ID: {CA_ID}')
            print(f'获取CA公钥')
        # 验证服务器证书
        try:
            pkcs1_15.new(CA_publicKey).verify(
                SHA256.new((Server_ID + CA_ID + Server_publicKey.export_key().decode()).encode(ENCODING)),
                Server_Certificate
            )
            print('服务器证书验证成功')
            print('================================\n')
        except:
            print('服务器证书验证失败')
            print('================================\n')
            exit()

        input('按回车键开始注册...')
        # 客户端给服务器发送注册信息
        RSA_message = str({'Key': symmetricalKeyToServer,
                           'ID': ID_Client,
                           'IP': HOST,
                           'Port': PORT,
                           'TS': time.time().__trunc__()}).encode(ENCODING)
        DES_message = str({'PK': Client_publicKey.export_key().decode(ENCODING),
                           'TS': time.time().__trunc__()}).encode(ENCODING)
        RSA_Cipher = PKCS1_OAEP.new(Server_publicKey)
        RSA_message = RSA_Cipher.encrypt(RSA_message)
        DES_Cipher = DES.new(symmetricalKeyToServer.encode(ENCODING), DES.MODE_ECB)
        DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
        message = str({'RSA': RSA_message, 'DES': DES_message}).encode(ENCODING)
        Client_socket.sendall(message)

        # 从服务器接收注册回复
        receivedMessage = Client_socket.recv(BUF_SIZE)
        print('\n================================')
        print(f'从服务器接收DES加密信息')
        DES_Cipher = DES.new(symmetricalKeyToServer.encode(ENCODING), DES.MODE_ECB)
        receivedMessage = unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE).decode(ENCODING)
        print(f'信息解密为{receivedMessage}')
        receivedMessage = eval(receivedMessage)
        tmpKey = receivedMessage['Key']
        print(f"注册成功")
        print(f"与服务器本次会话使用临时密钥 {tmpKey}")
        print('================================\n')


input('按回车键进入主界面...')

while True:

    print('\n\n================================')
    print('1. 协商密钥')
    print('2. 发送消息')
    print('================================\n\n')

    print('请输入指令:')
    Client_input = input()

    # 协商密钥
    if Client_input == '1':
        print('请输入目标客户端：')
        targetClientID = 'ID-' + input()
        RSA_message = str({'ID': ID_Client,
                           'TS': time.time().__trunc__()}).encode(ENCODING)
        DES_message = str({'Source': ID_Client,
                           'Target': targetClientID,
                           'TS': time.time().__trunc__()}).encode(ENCODING)
        RSA_Cipher = PKCS1_OAEP.new(Server_publicKey)
        RSA_message = RSA_Cipher.encrypt(RSA_message)
        DES_Cipher = DES.new(tmpKey.encode(ENCODING), DES.MODE_ECB)
        DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
        message = str({'Tag': 'CON', 'RSA': RSA_message, 'DES': DES_message}).encode(ENCODING)

        # 连接服务器
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
            Client_socket.connect((Sever_HOST, Sever_PORT))
            Client_socket.sendall(message)

            # 接收服务器发送的目标客户端密钥
            message = Client_socket.recv(BUF_SIZE)
            message = eval(unpad(DES_Cipher.decrypt(message), BLOCK_SIZE).decode(ENCODING))
            TargetPK = RSA.importKey(message['PK'].encode(ENCODING))
            # 生成与目标客户端通信的对称密钥
            KeyToTarget = (''.join(random.choice(letters) for i in range(8)))
            print(f'生成与目标客户端通信的对称密钥 {KeyToTarget}')
            Clients[targetClientID] = {'Key': KeyToTarget, 'PK': TargetPK}

            timeStamp = time.time().__trunc__()
            # 给RSA信息提取摘要
            RSA_abstract = SHA256.new((KeyToTarget + str(timeStamp)).encode(ENCODING))
            # 给摘要做签名
            signature = pkcs1_15.new(Client_privateKey).sign(RSA_abstract)

            RSA_message = str({'Key': KeyToTarget,
                               'TS': timeStamp}).encode(ENCODING)
            RSA_Cipher = PKCS1_OAEP.new(TargetPK)
            RSA_message = RSA_Cipher.encrypt(RSA_message)
            # 给目标客户端发送消息
            message = str({'Source': ID_Client,
                           'Target': targetClientID,
                           'Message': RSA_message,
                           'Sign': signature,
                           'TS': timeStamp}).encode(ENCODING)
            message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
            Client_socket.sendall(message)

            # 接收服务器回复的信息
            receivedMessage = Client_socket.recv(BUF_SIZE)
            receivedMessage = unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE)
            receivedMessage = eval(receivedMessage.decode(ENCODING))
            DES_message = receivedMessage['Mess']
            DES_Cipher = DES.new(KeyToTarget.encode(ENCODING), DES.MODE_ECB)
            DES_message = unpad(DES_Cipher.decrypt(DES_message), BLOCK_SIZE)
            DES_message = eval(DES_message.decode())
            print(f'从目标客户端回复消息中解密出的消息为{DES_message}')
            print('\n\n================================')
            print('密钥协商验证成功')
            print('================================\n\n')

    # 发送消息
    if Client_input == '2':
        print('请输入目标客户端：')
        targetClientID = 'ID-' + input()
        print('请输入要发送的消息：')
        messageToSend = input()

        timeStamp = time.time().__trunc__()
        signature = messageToSend + str(timeStamp)
        messageToSend = str({'Mess': messageToSend, 'TS': timeStamp}).encode(ENCODING)

        DES_Cipher = DES.new(Clients[targetClientID]['Key'].encode(ENCODING), DES.MODE_ECB)
        messageToSend = DES_Cipher.encrypt(pad(messageToSend, BLOCK_SIZE))

        RSA_abstract = SHA256.new(signature.encode(ENCODING))
        signature = pkcs1_15.new(Client_privateKey).sign(RSA_abstract)

        RSA_message = str({'ID': ID_Client, 'TS': timeStamp}).encode(ENCODING)
        RSA_Cipher = PKCS1_OAEP.new(Server_publicKey)
        RSA_message = RSA_Cipher.encrypt(RSA_message)

        DES_message = str({'Source': ID_Client,
                           'Target': targetClientID,
                           'Mess': messageToSend,
                           'Sign': signature,
                           'TS': time.time().__trunc__()}).encode(ENCODING)
        DES_Cipher = DES.new(tmpKey.encode(ENCODING), DES.MODE_ECB)
        DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))

        message = str({'Tag': 'MESS', 'RSA': RSA_message, 'DES': DES_message}).encode(ENCODING)

        # 连接服务器
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
            Client_socket.connect((Sever_HOST, Sever_PORT))
            Client_socket.sendall(message)

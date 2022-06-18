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
PORT = 40008
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
ID_Client = 'ID-' + input('请输入客户端ID:')

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

    print(f'读取客户端公钥、客户端私钥和服务器公钥')
    print(f'读取与服务器通信的对称密钥 {symmetricalKeyToServer}')
    input('按回车键连接服务器...')
    print('================================\n')

    # 连接服务器
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
        Client_socket.connect((Sever_HOST, Sever_PORT))
        # 发送客户端的ID
        RSA_message = str({'ID': ID_Client, 'TS': time.time().__trunc__()}).encode(ENCODING)
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
    with open(os.path.join(ID_Client, 'privateKey.pem'), 'wb') as f:
        f.write(Client_privateKey.export_key())
    with open(os.path.join(ID_Client, 'publicKey.pem'), 'wb') as f:
        f.write(Client_publicKey.export_key())

    # 选取和服务器通信的对称密钥
    symmetricalKeyToServer = (''.join(random.choice(letters) for i in range(8)))
    with open(os.path.join(ID_Client, 'symmetricalKey.pem'), 'wb') as f:
        f.write(symmetricalKeyToServer.encode(ENCODING))

    print(f'生成与服务器通信的对称密钥 {symmetricalKeyToServer}')
    input('按回车键连接服务器...')
    print('================================\n')

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
        print(f'获取服务器证书 {Server_Certificate}')
        print(f'获取服务器ID: {Server_ID}')
        print(f'获取服务器公钥')
        with open(os.path.join(ID_Client, 'ServerPublicKey.pem'), 'wb') as f:
            f.write(Server_publicKey.export_key())

        input('按回车键获取CA公钥和ID以验证服务器证书...')
        print('================================\n')

        print('\n================================')
        print(f'已向CA发送请求')
        print('================================\n')

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
        except:
            print('服务器证书验证失败')
            exit()

        input('按回车键开始注册...')
        print('================================\n')
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

        print('\n================================')
        print(f'已向服务器发送注册消息')
        print('================================\n')

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


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Client_socket:
    Client_socket.bind((HOST, PORT))
    print('\n================================')
    print(f'客户端正在 {HOST}:{PORT} 运行')
    print('================================\n')
    Client_socket.listen(1)
    while True:
        Server_socket, address = Client_socket.accept()
        print('\n================================')
        print(f'服务器 {address} 已连接')

        with Server_socket:
            receivedMessage = Server_socket.recv(BUF_SIZE).decode(ENCODING)
            print(f'从服务器{address}接收DES加密的信息')
            receivedMessage = eval(receivedMessage)
            DES_message = receivedMessage['DES']
            DES_Cipher = DES.new(tmpKey.encode(ENCODING), DES.MODE_ECB)
            DES_message = unpad(DES_Cipher.decrypt(DES_message), BLOCK_SIZE)
            DES_message = eval(DES_message.decode(ENCODING))

            if receivedMessage['Tag'] == 'CON':

                receivedSign = Server_socket.recv(BUF_SIZE)
                receivedSign = unpad(DES_Cipher.decrypt(receivedSign), BLOCK_SIZE).decode(ENCODING)
                signature = eval(receivedSign)['Sign']

                SourceClientID = DES_message['Source']
                SourceClientPK = DES_message['PK']
                print(f'获取源客户端ID{SourceClientID}和公钥')
                message = DES_message['Mess']
                RSA_Cihper = PKCS1_OAEP.new(Client_privateKey)
                message = eval(RSA_Cihper.decrypt(message).decode(ENCODING))
                SourceClientKey = message['Key']
                print(f'获取与源客户端通信的对称密钥{SourceClientKey}')
                timeStamp = message['TS']
                print(f'验证对称密钥{SourceClientKey}是否来自源客户端')

                try:
                    pkcs1_15.new(RSA.importKey(SourceClientPK.encode(ENCODING))).verify(
                        SHA256.new((SourceClientKey + str(timeStamp)).encode(ENCODING)),
                        signature
                    )
                    print('对称密钥验证成功')
                    Clients[SourceClientID] = {'Key': SourceClientKey, 'PK': SourceClientPK}
                except:
                    print('对称密钥验证失败')
                print('================================\n')

                input('按回车键向服务器和源客户端返回密钥协商信息...')

                # 回复给源服务器的加密信息
                message = str({'ID': ID_Client, 'TS': time.time().__trunc__()}).encode(ENCODING)
                DES_Cipher = DES.new(SourceClientKey.encode(ENCODING), DES.MODE_ECB)
                message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
                # 回复给服务器的加密信息
                DES_message = str({'Source': SourceClientID,
                                   'Target': ID_Client,
                                   'Mess': message,
                                   'TS': time.time().__trunc__()}).encode(ENCODING)
                DES_Cipher = DES.new(tmpKey.encode(ENCODING), DES.MODE_ECB)
                DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
                Server_socket.sendall(DES_message)

                print('\n================================')
                print(f'已向服务器和源客户端返回密钥协商信息')
                print('================================\n')

            elif receivedMessage['Tag'] == 'MESS':
                SourceClientID = DES_message['Source']
                message = DES_message['Mess']
                signature = DES_message['Sign']
                print(f'接收到从源客户端{SourceClientID}发送的消息（文件）')
                DES_Cipher = DES.new(Clients[SourceClientID]['Key'].encode(ENCODING), DES.MODE_ECB)
                message = eval(unpad(DES_Cipher.decrypt(message), BLOCK_SIZE).decode(ENCODING))
                receivedMessage = message['Mess']
                timeStamp = message['TS']
                print(f'消息（文件）解密为{receivedMessage}')

                SourceClientPK = Clients[SourceClientID]['PK']
                try:
                    pkcs1_15.new(RSA.importKey(SourceClientPK.encode(ENCODING))).verify(
                        SHA256.new((receivedMessage + str(timeStamp)).encode(ENCODING)),
                        signature
                    )
                    print('消息（文件）签名验证成功')
                    Clients[SourceClientID] = {'Key': SourceClientKey, 'PK': SourceClientPK}
                except:
                    print('消息（文件）签名验证失败')

                print('================================\n')


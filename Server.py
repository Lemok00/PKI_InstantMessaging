import socket
import time
import string
import random

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

input('按回车键开始程序...')

# 设置Server的网络配置
HOST = '127.0.0.1'
PORT = 40006
BUF_SIZE = 4096
ENCODING = 'utf-8'
BLOCK_SIZE = 32
ID_Server = 'ID-Server'
MAX_CONNECTIONS = 1

# CA的IP地址
CA_HOST = '127.0.0.1'
CA_PORT = 40005

# 生成Server的公钥和私钥
Server_keyPair = RSA.generate(2048)
Server_privateKey = Server_keyPair
Server_publicKey = Server_keyPair.public_key()

print('\n================================')
print(f'生成服务器公钥私钥对')
# print(f'服务器公钥为\n{Server_publicKey.export_key().decode(ENCODING)}')
# print(f'服务器私钥为\n{Server_privateKey.export_key().decode(ENCODING)}')

# 选取和CA通信的对称密钥
letters = string.ascii_lowercase
symmetricalKeyToCA = (''.join(random.choice(letters) for i in range(8)))
print(f'生成与CA通信的对称密钥{symmetricalKeyToCA}')

# 记录用户信息
Clients = {}

input('按回车键开始服务器认证过程...')
print('================================\n')

'''服务器认证过程'''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Server_socket:
    # 连接CA
    Server_socket.connect((CA_HOST, CA_PORT))
    CA_publicKey = RSA.importKey(Server_socket.recv(BUF_SIZE))
    RSA_Cipher = PKCS1_OAEP.new(CA_publicKey)
    # 发送需要认证的信息
    DES_Cipher = DES.new(symmetricalKeyToCA.encode(ENCODING), DES.MODE_ECB)
    RSA_Message = RSA_Cipher.encrypt(str(
        {'Key': symmetricalKeyToCA,
         'ID': ID_Server,
         'TS': time.time().__trunc__()}).encode(ENCODING))
    DES_Message = DES_Cipher.encrypt(pad(str(
        {'PK': Server_publicKey.export_key().decode(ENCODING)}).encode(ENCODING), BLOCK_SIZE))
    certificateMessage = {'RSA': RSA_Message, 'DES': DES_Message}
    certificateMessage = str(certificateMessage).encode(ENCODING)
    Server_socket.sendall(certificateMessage)

    print('\n================================')
    print(f'已向CA发送RSA加密的服务器认证信息')
    print('================================\n')

    # 接收证书
    receivedMessage = Server_socket.recv(BUF_SIZE)
    receivedMessage = eval(receivedMessage.decode(ENCODING))['DES']

    print('\n================================')
    print(f'从CA收到DES加密信息')
    decryptedMessage = eval(unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE).decode(ENCODING))
    print(f'信息解密为 {decryptedMessage}')
    # 验证证书
    CERTIFICATE = decryptedMessage['Certificate']
    try:
        pkcs1_15.new(CA_publicKey).verify(
            SHA256.new((ID_Server + decryptedMessage['ID_CA'] +
                        Server_publicKey.export_key().decode(ENCODING)).encode(ENCODING)),
            CERTIFICATE
        )
        print('证书验证成功')
    except:
        print('证书验证失败')
        exit()

input('按回车键开始运行服务器...')
print('================================\n')

'''服务器运行过程'''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Server_socket:
    Server_socket.bind((HOST, PORT))
    print('\n================================')
    print(f'服务器正在 {HOST}:{PORT} 运行')
    print('================================\n')
    Server_socket.listen(1)

    while True:
        Client_socket, address = Server_socket.accept()
        print('\n================================')
        print(f'客户端 {address} 已连接')

        with Client_socket:
            # 接受客户端发送的信息
            receivedMessage = Client_socket.recv(BUF_SIZE).decode(ENCODING)
            receivedMessage = eval(receivedMessage)

            # 新用户注册
            if receivedMessage['Tag'] == 'REG':

                print(f'从客户端{address}接收注册信息{receivedMessage}')

                input('按回车键向客户端发送服务器公钥和证书...')
                print('================================\n')
                # 给客户端发送证书和公钥
                message = str({'Certificate': CERTIFICATE,
                               'ID': ID_Server,
                               'PK': Server_publicKey.export_key().decode(ENCODING),
                               'TS': time.time().__trunc__()}).encode(ENCODING)
                Client_socket.sendall(message)

                print('\n================================')
                print(f'已向客户端{address}返回服务器公钥和证书')
                print('================================\n')

                # 等待用户发送注册信息
                receivedMessage = eval(Client_socket.recv(BUF_SIZE).decode(ENCODING))
                # 解密RSA信息
                receivedRSAMessage = receivedMessage['RSA']
                print('\n================================')
                print(f'从客户端{address}接收RSA加密信息')
                RSA_Cipher = PKCS1_OAEP.new(Server_privateKey)
                receivedRSAMessage = RSA_Cipher.decrypt(receivedRSAMessage).decode(ENCODING)
                print(f'解密后为{receivedRSAMessage}')
                receivedRSAMessage = eval(receivedRSAMessage)
                Client_ID = receivedRSAMessage['ID']
                Client_Key = receivedRSAMessage['Key']
                print(f'客户端{address}的ID为: {Client_ID}')
                print(f'获取与客户端{Client_ID}通信的对称密钥{Client_Key}')
                Client_IP = receivedRSAMessage['IP']
                Client_Port = receivedRSAMessage['Port']
                # 解密DES信息
                receivedDESMessage = receivedMessage['DES']
                print(f'从客户端{Client_ID}接收DES加密信息')
                DES_Cipher = DES.new(Client_Key.encode(ENCODING), DES.MODE_ECB)
                receivedDESMessage = unpad(DES_Cipher.decrypt(receivedDESMessage), BLOCK_SIZE).decode(ENCODING)
                print(f'解密后为{receivedDESMessage}')
                receivedDESMessage = eval(receivedDESMessage)
                Client_PK = receivedDESMessage['PK']
                print(f'获取客户端{Client_ID}的公钥')
                # 保存客户端信息
                Clients[Client_ID] = {'Key': Client_Key,
                                      'IP': Client_IP,
                                      'Port': Client_Port,
                                      'PK': Client_PK}
                # 生成临时DES密钥
                tmpKey = (''.join(random.choice(letters) for i in range(8)))
                Clients[Client_ID]['tmpKey'] = tmpKey
                print(f"生成与客户端{Client_ID}本次会话使用的临时密钥{tmpKey}")
                input('按回车键回复客户端注册结果...')
                print('================================\n')

                print('\n================================')
                print(f'已向客户端{Client_ID}返回注册结果')
                print('================================\n')

                # 回复给客户端注册结果
                message = str({'Key': tmpKey,
                               'ID': Client_ID,
                               'TS': time.time().__trunc__()}).encode(ENCODING)
                message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
                Client_socket.sendall(message)

            # 用户登陆
            elif receivedMessage['Tag'] == 'LOG':
                # 接受客户端发送的信息
                print(f'从客户端接收登陆信息')
                RSA_Message = receivedMessage['RSA']
                DES_Message = receivedMessage['DES']
                # 解密RSA信息
                RSA_Cipher = PKCS1_OAEP.new(Server_privateKey)
                RSA_Message = eval(RSA_Cipher.decrypt(RSA_Message).decode(ENCODING))
                Client_ID = RSA_Message['ID']
                print(f'从RSA加密信息中解密出客户端的ID: {Client_ID}')
                DES_Key = Clients[Client_ID]['Key']
                print(f'读取与客户端{Client_ID}通信的对称密钥{DES_Key}')
                # 解密DES信息
                DES_Cipher = DES.new(DES_Key.encode(ENCODING), DES.MODE_ECB)
                DES_Message = eval(unpad(DES_Cipher.decrypt(DES_Message), BLOCK_SIZE).decode(ENCODING))
                print(f"从DES加密信息中解密出客户端的ID: {DES_Message['ID']}")
                Clients[Client_ID]['IP'] = DES_Message['IP']
                Clients[Client_ID]['Port'] = DES_Message['Port']
                # 生成临时DES密钥
                tmpKey = (''.join(random.choice(letters) for i in range(8)))
                Clients[Client_ID]['tmpKey'] = tmpKey

                print(f"生成与客户端{Client_ID}本次会话使用临时密钥 {tmpKey}")
                input('按回车键向客户端返回登陆结果...')
                print('================================\n')

                # 生成回复信息
                message = str({'Key': tmpKey,
                               'ID': Client_ID,
                               'TS': time.time().__trunc__()}).encode(ENCODING)
                message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
                Client_socket.sendall(message)
                print('\n================================')
                print(f'已向客户端{Client_ID}返回登陆结果')
                print('================================\n')

            # 密钥协商
            elif receivedMessage['Tag'] == 'CON':
                # 接受客户端发送的信息
                print(f'从客户端接收密钥协商信息 {receivedMessage}')
                RSA_Message = receivedMessage['RSA']
                DES_Message = receivedMessage['DES']
                # 解密RSA信息
                RSA_Cipher = PKCS1_OAEP.new(Server_privateKey)
                RSA_Message = eval(RSA_Cipher.decrypt(RSA_Message).decode(ENCODING))
                SourceClientID = RSA_Message['ID']
                print(f'从RSA加密信息中解密出源客户端的ID{SourceClientID}')
                SourceDEStmpKey = Clients[SourceClientID]['tmpKey']
                print(f'读取与源客户端{SourceClientID}通信的临时对称密钥{SourceDEStmpKey}')
                # 解密DES信息
                DES_Cipher = DES.new(SourceDEStmpKey.encode(ENCODING), DES.MODE_ECB)
                DES_Message = eval(unpad(DES_Cipher.decrypt(DES_Message), BLOCK_SIZE).decode(ENCODING))
                TargetClientID = DES_Message['Target']
                print(f"从DES加密信息中解密出目标客户端的ID{TargetClientID}")
                TargetClientIP = Clients[TargetClientID]['IP']
                TargetClientPort = Clients[TargetClientID]['Port']
                TargetPK = Clients[TargetClientID]['PK']
                TargetDEStmpKey = Clients[TargetClientID]['tmpKey']
                # 将目标客户端公钥回复给源客户端
                print(f"将目标客户端公钥回复给源客户端:\n{TargetPK}")
                input('按回车键向源客户端返回DES加密的目标客户端公钥...')
                print('================================\n')

                message = str({'ID': SourceClientID, 'PK': TargetPK}).encode(ENCODING)
                message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
                Client_socket.sendall(message)

                print('\n================================')
                print(f'已向源客户端{Client_ID}返回DES加密的目标客户端公钥')
                print('================================\n')

                # 接收客户端发送的信息
                receivedMessage = Client_socket.recv(BUF_SIZE)
                receivedMessage = unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE).decode(ENCODING)
                receivedMessage = eval(receivedMessage)
                messageToTarget = receivedMessage['Message']

                print('\n================================')
                print(f"（窃听）源客户端发送给目标客户端的密钥协商信息为: {messageToTarget}")
                # 连接目标客户端
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Target_socket:
                    print(f"连接目标客户端{TargetClientID}, {(TargetClientIP, TargetClientPort)}")
                    print(f"将源客户端公钥发送给目标客户端:\n{Clients[SourceClientID]['PK']}")
                    input('按回车键向目标客户端发送DES加密的密钥协商信息...')
                    print('================================\n')

                    Target_socket.connect((TargetClientIP, TargetClientPort))
                    DES_message = str({'Source': SourceClientID,
                                       'Target': TargetClientID,
                                       'PK': Clients[SourceClientID]['PK'],
                                       'Mess': messageToTarget,
                                       'TS': time.time().__trunc__()}).encode(ENCODING)
                    DES_Cipher = DES.new(TargetDEStmpKey.encode(ENCODING), DES.MODE_ECB)
                    DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
                    message = str({'Tag': 'CON', 'DES': DES_message}).encode(ENCODING)
                    Target_socket.sendall(message)

                    DES_message = str({'Sign': receivedMessage['Sign'],
                                       'TS': time.time().__trunc__()}).encode(ENCODING)
                    DES_message = DES_Cipher.encrypt(pad(DES_message, BLOCK_SIZE))
                    Target_socket.sendall(DES_message)

                    print('\n================================')
                    print(f'已向目标客户端{TargetClientID}发送DES加密的密钥协商信息')
                    print('================================\n')

                    # 接收目标客户端回复的秘密信息
                    receivedMessage = Target_socket.recv(BUF_SIZE)
                    print('\n================================')
                    print(f'接收从目标客户端返回的密钥协商信息')
                    DES_Cipher = DES.new(TargetDEStmpKey.encode(ENCODING), DES.MODE_ECB)
                    receivedMessage = unpad(DES_Cipher.decrypt(receivedMessage), BLOCK_SIZE).decode(ENCODING)
                    receivedMessage = eval(receivedMessage)
                    print(f"（窃听）目标客户端返回给源客户端的信息为: {receivedMessage['Mess']}")
                    input('按回车键向源客户端返回密钥协商信息...')
                    print('================================\n')

                    message = str({'Mess': receivedMessage['Mess'],
                                   'TS': time.time().__trunc__()}).encode(ENCODING)
                    DES_Cipher = DES.new(SourceDEStmpKey.encode(ENCODING), DES.MODE_ECB)
                    message = DES_Cipher.encrypt(pad(message, BLOCK_SIZE))
                    Client_socket.sendall(message)

                    print('\n================================')
                    print(f'已向源客户端返回密钥协商信息')
                    print('================================\n')

            # 信息（文件）传递
            elif receivedMessage['Tag'] == 'MESS':
                # 接受客户端发送的信息
                print(f'从客户端接收消息（文件）传递信息')
                RSA_Message = receivedMessage['RSA']
                DES_Message = receivedMessage['DES']

                RSA_Cipher = PKCS1_OAEP.new(Server_privateKey)
                RSA_Message = RSA_Cipher.decrypt(RSA_Message).decode(ENCODING)
                SourceClientID = eval(RSA_Message)['ID']
                print(f'消息（文件）传递的源客户端为{SourceClientID}')

                DES_Cipher = DES.new(Clients[SourceClientID]['tmpKey'].encode(ENCODING), DES.MODE_ECB)
                DES_Message = eval(unpad(DES_Cipher.decrypt(DES_Message), BLOCK_SIZE).decode(ENCODING))
                print(f"（窃听）发送给目标客户端 {DES_Message['Target']} 的消息（文件）为 {DES_Message['Mess']}")

                TargetClientID = DES_Message['Target']
                DES_Message = str({'Source': DES_Message['Source'],
                                   'Target': DES_Message['Target'],
                                   'Mess': DES_Message['Mess'],
                                   'Sign': DES_Message['Sign']}).encode(ENCODING)
                DES_Cipher = DES.new(Clients[TargetClientID]['tmpKey'].encode(ENCODING), DES.MODE_ECB)
                DES_Message = DES_Cipher.encrypt(pad(DES_Message, BLOCK_SIZE))
                message = str({'Tag': "MESS", 'DES': DES_Message}).encode(ENCODING)

                print(f'使用DES加密服务器与目标客户端之间的通信')
                input('按回车键向目标客户端发送消息（文件）传递信息...')
                print('================================\n')

                # 连接目标客户端
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Target_socket:
                    Target_socket.connect((Clients[TargetClientID]['IP'], Clients[TargetClientID]['Port']))
                    Target_socket.sendall(message)

                print('\n================================')
                print(f'已向目标客户端发送消息（文件）传递信息')
                print('================================\n')

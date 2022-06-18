import socket
import time

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

input('按回车键开始程序...')

# 设置CA的网络配置
HOST = '127.0.0.1'
PORT = 40005
MAX_CONNECTIONS = 1
BUF_SIZE = 4096
ENCODING = 'utf-8'

BLOCK_SIZE = 32
ID_CA = 'ID-CA'

# 生成CA的公钥和私钥
CA_keyPair = RSA.generate(2048)
CA_privateKey = CA_keyPair
CA_publicKey = CA_keyPair.public_key()

# 等待服务器/客户端认证
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as CA_socket:
    CA_socket.bind((HOST, PORT))

    print('\n================================')
    print(f'CA正在 {HOST}:{PORT} 运行')
    print('================================\n')

    CA_socket.listen(MAX_CONNECTIONS)

    '''服务器证书发放'''
    # 服务器连接
    Server_socket, address = CA_socket.accept()

    print('\n================================')
    print(f'服务器{address}已连接')

    with Server_socket:
        # 发送CA的公钥
        Server_socket.sendall(CA_publicKey.export_key())
        # 接受服务器信息
        receivedData = Server_socket.recv(BUF_SIZE)
        receivedData = receivedData.decode(ENCODING)
        print(f'从服务器{address}接收RSA加密信息')

        # 解析信息为dict类型
        receivedData = eval(receivedData)
        # 解密信息
        RSA_chiper = PKCS1_OAEP.new(CA_privateKey)
        decryptedRSAData = eval(RSA_chiper.decrypt(receivedData['RSA']).decode(ENCODING))
        DES_Cipher = DES.new(decryptedRSAData['Key'].encode(ENCODING), DES.MODE_ECB)
        decryptedDESData = eval(unpad(DES_Cipher.decrypt(receivedData['DES']), BLOCK_SIZE).decode(ENCODING))
        decryptedReceivedData = {'RSA': decryptedRSAData, 'DES': decryptedDESData}
        print(f'信息解密为{decryptedReceivedData}')

        # 准备证书
        certificate = decryptedRSAData['ID'] + ID_CA + decryptedDESData['PK']
        certificateHash = SHA256.new(certificate.encode(ENCODING))
        print(f"获取服务器{address}的ID: {decryptedRSAData['ID']}")
        print(f"获取与服务器{decryptedRSAData['ID']}通信的对称密钥: {decryptedRSAData['Key']}")
        print(f"获取服务器{decryptedRSAData['ID']}的公钥")
        print(f'为服务器生成摘要')
        certificate = pkcs1_15.new(CA_privateKey).sign(certificateHash)
        print(f"将摘要签名为证书")
        input('按回车键向服务器发放证书...')
        print('================================\n')

        # 返回信息
        DES_Message = DES_Cipher.encrypt(pad(str(
            {'Certificate': certificate,
             'ID_Server': decryptedRSAData['ID'],
             'ID_CA': ID_CA,
             'TS': time.time().__trunc__()}).encode(ENCODING), BLOCK_SIZE))
        message = str({'DES': DES_Message}).encode(ENCODING)
        Server_socket.sendall(message)

        print('\n================================')
        print(f"已通过DES加密信息向服务器{decryptedRSAData['ID']}发放证书")
        print('================================\n')

    # 等待客户端连接
    while True:
        Client_socket, address = CA_socket.accept()

        print('\n================================')
        print(f'客户端{address}已连接')
        input('按回车键向客户端发送CA的ID和公钥')
        print('================================\n')
        with Client_socket:
            Client_socket.sendall(str({'ID': ID_CA,
                                       'PK': CA_publicKey.export_key().decode(ENCODING)}).encode(ENCODING))

        print('\n================================')
        print(f'已向客户端{address}发送CA的ID和公钥')
        print('================================\n')

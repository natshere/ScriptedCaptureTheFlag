#!/usr/bin/python

import argparse

# Todo: Add randomized encoded function for 'Poisoned Flags'

parser = argparse.ArgumentParser(description='Used to prove access and add points')
parser.add_argument('-u','--username', help='Include your username for adding points', required=True)
parser.add_argument('-m','--message', help='Include message to be displayed on scoreboard. Must be encapsulated by quotes'
                    , required=False)

def encrypt_RSA(message):

    key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4wtg/JTKQzd+xHp8IFyt
d74dZjJldI7L13J6rOWq2wo+stBgQBb0YNGg1TG70/U8sHfqVjIcqAksg4hCWY4s
QNNQl/Xupf/olzdKV9yrc8+QSYT51ddUbHRuX6CR55iW0pzIa3lA5IEfb3mlQX4T
iHUlUefH3bOWFIoQjSAw6E24fo9+umH7UqQKrhNvyRCheHue97/EWtaAvwpmDhSl
Xs3/RkOh0G1g8645W5XYS0z+YxNu2rvqClm3JfAzdr7pbX7tVv/5phQkll1cGUef
HByWElNKJqtFc3/Sua9rUOvFte1pKVETctv9wxaQe5eLPFLrAcNDQcg2DMh0iOYW
YwIDAQAB
-----END PUBLIC KEY-----"""

    from M2Crypto import RSA, BIO

    pubkey = str(key).encode('utf8')
    bio = BIO.MemoryBuffer(pubkey)
    rsa = RSA.load_pub_key_bio(bio)

    encrypted = rsa.public_encrypt(message, RSA.pkcs1_oaep_padding)

    return encrypted.encode('base64')

if __name__ == "__main__":

    import socket

    uuid = '16fd2706-8baf-433b-82eb-8c7fada847da'
    args = vars(parser.parse_args())
    HOST = ''   # Symbolic name meaning the local host
    PORT = 65535    # Arbitrary non-privileged port
    username = args['username']


    if not args['message']:
        message = '%s has modestly pwned a box.' % username
    else:
        message = args['message']

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,PORT))

    command = username + ',' + uuid + ',' + message

    encryptedCommand = encrypt_RSA(command)
    s.send(encryptedCommand)
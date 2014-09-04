__author__ = 'tom'

import uuid
#import argparse

#parser = argparse.ArgumentParser(description='Used to prove access and add points')

#args = vars(parser.parse_args())

#ToDo: Give option for venomous flag
#ToDo: Update flag database when creating flag/UUID
#ToDo: Add randomized encoded function for 'Poisoned Flags'
#ToDo: Add option to add points to UUID created
#ToDo: Add option to name flag
#ToDo: Add option to create just UUID

def createFlag(pub_key, flag_uuid):
    uuid_split = str(flag_uuid).split('-')
    script_head = """#!/usr/bin/python

import argparse

parser = argparse.ArgumentParser(description='Used to prove access and add points')
parser.add_argument('-u','--username', help='Include your username for adding points', required=True)
parser.add_argument('-m','--message', help='Include message to be displayed on scoreboard. Must be encapsulated by quotes'
                    , required=False)

def encrypt_RSA(message):"""

    script_end = '''
    key = \"\"\"{0}\"\"\"

    from M2Crypto import RSA, BIO

    pubkey = str(key).encode('utf8')
    bio = BIO.MemoryBuffer(pubkey)
    rsa = RSA.load_pub_key_bio(bio)

    encrypted = rsa.public_encrypt(message, RSA.pkcs1_oaep_padding)

    return encrypted.encode('base64')

if __name__ == "__main__":

    import socket

    uuid = \'{1}\'
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
'''
    script_part = script_end.format(pub_key, flag_uuid)
    full_script = script_head + script_part
    f = open(uuid_split[0] + '.py', 'w')

    f.write(full_script)
    f.close()

if __name__ == "__main__":
    public_key_loc = 'keys/pub.key'
    flagUUID = uuid.uuid4()
    pubKey = open(public_key_loc, "r").read()
    createFlag(pubKey, flagUUID)
__author__ = 'tom'

import uuid
import argparse
import sqlite3
import os
import logging

parser = argparse.ArgumentParser(description='Used to create flags')
parser.add_argument('-n', '--name', help='Enter name for flag', required=True)
parser.add_argument('-p', '--points', help='Enter how many points flag is worth', required=True)
parser.add_argument('-v', '--venomous', help='Enter if flag is venomous (1), or not (0)', default='0')

#ToDo: Add option to include ctfCollector IP address
#ToDo: Check if uuid exists, if exists create new uuid automatically
#ToDo: Check if name exists, if exists ask user for new name
#ToDo: Add randomized encoded function for 'Poisoned Flags'
#ToDo: Add option to create just UUID

def createFlag(flag_name, pub_key, flag_uuid):
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
    f = open(flag_name + '.py', 'w')

    f.write(full_script)
    f.close()

def update_uuid_db(flagname, newuuid, numpoints, venomous):
    if os.path.isfile(os.path.realpath('database/ctfCollector.db')):
        conn = sqlite3.connect('database/ctfCollector.db')
        logging.info("Attempted to connect to ctfCollector.db")
        c = conn.cursor()
        c.execute('''INSERT INTO flags VALUES (?,?,?,?)''', (flagname, newuuid, numpoints, venomous))
        conn.commit()
        logging.info("Commit INSERT INTO flags VALUES ({0}, {1}, {2}, {3})".format(flagname, newuuid,
                                                                                      numpoints, venomous))
        conn.close()
        logging.info("Closing connection to database")

if __name__ == "__main__":
    args = vars(parser.parse_args())
    public_key_loc = 'keys/pub.key'
    flagUUID = uuid.uuid4()
    pubKey = open(public_key_loc, "r").read()
    createFlag(args['name'], pubKey, flagUUID)
    update_uuid_db(args['name'], str(flagUUID), int(args['points']), args['venomous'])
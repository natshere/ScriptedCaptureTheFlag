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

def createFlag(flag_name, pub_key, flag_uuid):    # Used to create the flag, requires flag name, public key, and uuid
    # Had to split script into 2 sections due to using similar quotes
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
    script_part = script_end.format(pub_key, flag_uuid)    # Insert the variable public key and uuid (unique to each flag)
    full_script = script_head + script_part    # Tie string (script) together
    f = open(flag_name + '.py', 'w')    # Open script (named by user) for writing

    f.write(full_script)    # Write script to file
    f.close()    # Close the file

def update_uuid_db(flagname, newuuid, numpoints, venomous):     # Insert flag information into database
    if os.path.isfile(os.path.realpath('database/ctfCollector.db')):    # Make sure path exists
        conn = sqlite3.connect('database/ctfCollector.db')    # Set up connection to database
        logging.info("Connection setup for ctfCollector.db")    # Log the connection setup to informational
        c = conn.cursor()
        # Insert flag name, uuid, worth points, and whether or not it's venomous
        c.execute('''INSERT INTO flags VALUES (?,?,?,?)''', (flagname, newuuid, numpoints, venomous))
        conn.commit()    # Commit changes
        # Log the change
        logging.info("Commit INSERT INTO flags VALUES ({0}, {1}, {2}, {3})".format(flagname, newuuid,
                                                                                      numpoints, venomous))
        conn.close()    # Close the connection
        logging.info("Closing connection to database")    # Log the closure to informational
    else:
        print('There is a problem with the database. Delete and restart')    # Make some recommendations, this shouldn't happen

if __name__ == "__main__":
    args = vars(parser.parse_args())    # Assign arguments to args variable

    public_key_loc = 'keys/pub.key'    # Assign public key location to variable
    flagUUID = uuid.uuid4()    # Create new uuid and assign to variable
    pubKey = open(public_key_loc, "r").read()    # Feed the key to variable for writing
    createFlag(args['name'], pubKey, flagUUID)    # Create the new flag
    update_uuid_db(args['name'], str(flagUUID), int(args['points']), args['venomous'])    # Update the database with the information
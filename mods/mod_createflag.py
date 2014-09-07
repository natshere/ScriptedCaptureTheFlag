#!/usr/bin/python

def check_if_flagname_exists(flagname):    # Check if user has already submitted

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE flagname = ?)''', (flagname,))    # Check if user exists
    returnvalue = c.fetchone()
    return returnvalue[0]

def check_if_uuid_exists(createduuid):    # Check if user has already submitted

    import sqlite3

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = "''' + str(createduuid) + '''")''')    # Check if uuid exists
    returnvalue = c.fetchone()
    return returnvalue[0]

def createFlag(flag_name, pub_key, flag_uuid, ipaddress):    # Used to create the flag, requires flag name, public key, and uuid

    # Had to split script into 2 sections due to using similar quotes
    script_argparse = """#!/usr/bin/python

import argparse

parser = argparse.ArgumentParser(description='Used to prove access and add points')
parser.add_argument('-u','--username', help='Include your username for adding points', required=True)
parser.add_argument('-m','--message', help='Include message to be displayed on scoreboard. Must be encapsulated by quotes'
                    , required=False)

"""
    script_encryption = '''
def encrypt_RSA(message):

    key = \"\"\"{0}\"\"\"

    from M2Crypto import RSA, BIO

    pubkey = str(key).encode('utf8')
    bio = BIO.MemoryBuffer(pubkey)
    rsa = RSA.load_pub_key_bio(bio)

    encrypted = rsa.public_encrypt(message, RSA.pkcs1_oaep_padding)

    return encrypted.encode('base64')

'''
    script_main = '''
if __name__ == "__main__":

    import socket

    uuid = \'{0}\'
    args = vars(parser.parse_args())
    HOST = \'{1}\'   # Symbolic name meaning the local host
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
    server_ip = ipaddress
    script_encryption = script_encryption.format(pub_key)
    script_part = script_main.format(flag_uuid, server_ip)    # Insert the variable public key and uuid (unique to each flag)
    full_script = script_argparse + script_encryption + script_part    # Tie string (script) together
    f = open(flag_name + '.py', 'w')    # Open script (named by user) for writing

    f.write(full_script)    # Write script to file
    f.close()    # Close the file

def update_uuid_db(flagname, newuuid, numpoints, venomous):     # Insert flag information into database

    import os
    import logging
    import sqlite3

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

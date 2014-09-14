#!/usr/bin/python

import os
import logging

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def check_if_flagname_exists(flagname):    # Check if user has already submitted

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.inf(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.inf(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE flagname = ?)''', (flagname,))    # Check if user exists
    except Exception, e:
        logger.inf(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.inf(e)

    return returnvalue[0]

def check_if_uuid_exists(createduuid):    # Check if user has already submitted

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.inf(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.inf(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = "''' + str(createduuid) + '''")''')    # Check if uuid exists
    except Exception, e:
        logger.inf(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.inf(e)

    return returnvalue[0]

def createFlag(flag_name, pub_key, flag_uuid, ipaddress):    # Used to create the flag, requires flag name, public key, and uuid

    # Had to split script into 2 sections due to using similar quotes
    script_argparse = """#!/usr/bin/python

import argparse

parser = argparse.ArgumentParser(description='Used to prove access and add points')
parser.add_argument('-u','--username', help='Include your username for adding points', required=True)
parser.add_argument('-p', '--password', help='Enter password', required=True)
parser.add_argument('-m','--message', help='Include message to be displayed on scoreboard. Must be encapsulated by quotes'
                    , required=False)

"""
    script_encryption = '''
def encrypt_RSA(message):

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP

    key = \"\"\"{0}\"\"\"

    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = rsakey.encrypt(message)

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

    try:
        password = args['password']
    except Exception, e:
        logger.info(e)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,PORT))

    command = username + ',' + uuid + ',' + message + ',' + password

    encryptedCommand = encrypt_RSA(command)
    s.send(encryptedCommand)
'''

    try:
        script_encryption = script_encryption.format(pub_key)
    except Exception, e:
        logger.inf(e)

    try:
        script_part = script_main.format(flag_uuid, ipaddress)    # Insert the variable public key and uuid (unique to each flag)
    except Exception, e:
        logger.inf(e)

    try:
        full_script = script_argparse + script_encryption + script_part    # Tie string (script) together
    except Exception, e:
        logger.inf(e)

    try:
        f = open(flag_name + '.py', 'w')    # Open script (named by user) for writing
    except Exception, e:
        logger.inf(e)

    try:
        f.write(full_script)    # Write script to file
    except Exception, e:
        logger.inf(e)

    try:
        f.close()    # Close the file
    except Exception, e:
        logger.inf(e)

def update_uuid_db(flagname, newuuid, numpoints, venomous):     # Insert flag information into database

    import sqlite3

    try:
        if os.path.isfile(os.path.realpath('database/ctfCollector.db')):    # Make sure path exists

            try:
                conn = sqlite3.connect('database/ctfCollector.db')    # Set up connection to database
                logging.info("Connection setup for ctfCollector.db")    # Log the connection setup to informational
            except Exception, e:
                logger.inf(e)

            try:
                c = conn.cursor()
                # Insert flag name, uuid, worth points, and whether or not it's venomous
            except Exception, e:
                logger.inf(e)

            try:
                c.execute('''INSERT INTO flags VALUES (?,?,?,?)''', (flagname, newuuid, numpoints, venomous))
            except Exception, e:
                logger.inf(e)

            try:
                conn.commit()    # Commit changes
                logging.info("Commit INSERT INTO flags VALUES ({0}, {1}, {2}, {3})".format(flagname, newuuid, numpoints, venomous))
            except Exception, e:
                logger.inf(e)

            try:
                conn.close()    # Close the connection
                logging.info("Closing connection to database")    # Log the closure to informational
            except Exception, e:
                logger.inf(e)

        else:
            logger.info('There is a problem with the database. Delete and restart')
            print('There is a problem with the database. Delete and restart')    # Make some recommendations, this shouldn't happen
    except Exception, e:
        logger.inf(e)

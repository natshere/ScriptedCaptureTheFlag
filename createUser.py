__author__ = 'tom'

import argparse
import sqlite3
import logging
import os
import hashlib

database = 'ctfCollector.db'

parser = argparse.ArgumentParser(description='Used to create flags')
parser.add_argument('-u', '--user', help='Enter username', required=True)
parser.add_argument('-p', '--password', help='Enter password', required=True)

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def create_hash_passwd(password):
    # ToDo: Insert hashed password into user database
    # ToDo: Insert salt into salt database

    import hashlib
    import os

    salt = os.urandom(16)

    m = hashlib.md5()
    m.update(salt + password)
    salted_password = m.hexdigest()

    return salt,salted_password

try:
    if os.path.isfile(os.path.realpath('database/' + database)):    # Only do this if it does not exist

        initial_points = 0

        try:
            args = vars(parser.parse_args())    # Assign arguments to args variable
        except Exception, e:
            logger.inf(e)

        try:
            username = args['user']
        except Exception, e:
            logger.inf(e)

        try:
            confirm_password = raw_input('Please re-enter password')
        except Exception, e:
            logger.info(e)

        try:
            while confirm_password != args['password']:
                try:
                    confirm_password = raw_input('Password does not match. Please re-enter password')
                except Exception, e:
                    logger.info(e)
        except Exception, e:
            logger.info(e)

        try:
            salt_hash = create_hash_passwd(confirm_password)
            salt = salt_hash[0]
            hashed_password = salt_hash[1]
        except Exception, e:
            logger.info(e)

        try:
            conn = sqlite3.connect('database/' + database)    # Setup connection to database
            logger.info("Database open: {0}".format(database))    # Log to info what database was open
        except Exception, e:
            logger.info(e)

        try:
            # ToDo: Logic to make sure user doesn't already exist
            conn.execute('''INSERT INTO user_points(uname, tot_points) VALUES(?,?)''', (username, initial_points)) # UDJUST TO ADD USER
        except Exception, e:
            logger.info(e)

        try:
            # ToDo: Logic to make sure user doesn't already exist
            conn.execute('''INSERT INTO users(uname, password)''', (username, hashed_password))
        except Exception, e:
            logger.info(e)

        try:
            # ToDo: Logic to make sure user doesn't already exist
            conn.execute('''INSERT INTO users_salt(uname, salt)''', (username, salt))
        except Exception, e:
            logger.info(e)

    else:
        print ('Database does not exist. Please run setup.py')
        logger.info('Database does not exist. Please run setup.py')
        exit()
except Exception, e:
    logger.info(e)

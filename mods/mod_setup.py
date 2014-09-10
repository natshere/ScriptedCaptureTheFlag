#!/usr/bin/python

import logging
import os

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def setupDatabase(database):    # Set up sqlite database with appropriate tables and columns

    import logging
    import os
    import sqlite3

    logging.info("Using database: {0}".format(database))    # log to informational
    if not os.path.isfile(os.path.realpath('database/' + database)):    # Only do this if it does not exist
        conn = sqlite3.connect('database/' + database)    # Setup connection to database
        logging.info("Database open: {0}".format(database))    # Log to info what database was open

        # Create user_points table for tracking of users total points
        conn.execute('''CREATE TABLE user_points (uname VARCHAR(32) NOT NULL, tot_points INT);''')
        # Create user_flags table to track all flags found by user
        conn.execute('''CREATE TABLE user_flags (uname VARCHAR(32) NOT NULL, uuid VARCHAR(37));''')
        # Create user_messages table to track all messages by user
        conn.execute('''CREATE TABLE user_messages (uname VARCHAR(32) NOT NULL, message VARCHAR(255));''')
        # Create flags tables to track flags uuid, name, whether or not it's venomous and points
        conn.execute('''CREATE TABLE flags (flagname VARCHAR(32), uuid VARCHAR(37) NOT NULL, points INT NOT NULL, venomous BOOLEAN DEFAULT 0);''')
        # Create users table for storing of users passwords
        conn.execute('''CREATE TABLE users (uname VARCHAR(32) NOT NULL, password VARCHAR(32) NOT NULL);''')
        logging.info("tables created in {0}".format(database))    # Log to informational the completion of table creation

        conn.commit()    # Commit all changes
        logging.info("Commit Completed")    # Log to informational the completion
        conn.close()    # Close connection to database
        logging.info("Connection to database closed")    # Log ot informational the closure of connection

def generate_RSA(bits=2048):

    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA

    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")

    return private_key, public_key

def checkModules():    # Validate M2Crypto and base64 modules are installed

    import logging
    try:
        import M2Crypto
    except ImportError, e:
        logging.warning("M2Crypto module failed to import. Please install.")
        pass
    try:
        import base64
    except ImportError, e:
        logging.warning("base64 module failed to import. Please install.")
        pass
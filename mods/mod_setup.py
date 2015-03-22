#!/usr/bin/python

import logging
import os

current_directory = os.getcwd()
logger = logging.getLogger('CTFsetup')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def setupDatabase(database):    # Set up sqlite database with appropriate tables and columns

    import sqlite3

    logger.info("Using database: {0}".format(database))    # log to informational

    try:
        conn = sqlite3.connect('database/' + database)    # Setup connection to database
    except Exception, e:
        logger.info(e)
    try:
        # Create user_points table for tracking of users total points
        conn.execute('''CREATE TABLE user_points (uname VARCHAR(32) NOT NULL, tot_points INT);''')
    except Exception, e:
        logger.info(e)
    try:
        # Create user_flags table to track all flags found by user
        conn.execute('''CREATE TABLE user_flags (uname VARCHAR(32) NOT NULL, uuid VARCHAR(37));''')
    except Exception, e:
        logger.info(e)
    try:
        # Create user_messages table to track all messages by user
        conn.execute('''CREATE TABLE user_messages (uname VARCHAR(32) NOT NULL, message VARCHAR(255));''')
    except Exception, e:
        logger.info(e)
    try:
        # Create flags tables to track flags uuid, name, whether or not it's venomous and points
        conn.execute('''CREATE TABLE flags (flagname VARCHAR(32), uuid VARCHAR(37) NOT NULL, points INT NOT NULL, venomous BOOLEAN DEFAULT 0);''')
    except Exception, e:
        logger.info(e)
    try:
        # Create users table for storing of users passwords
        conn.execute('''CREATE TABLE users (uname VARCHAR(32) NOT NULL, password VARCHAR(33) NOT NULL, admin VARCHAR(5) NOT NULL);''')
    except Exception, e:
        logger.info(e)
    try:
        # Create users_salt table for storing of users salt
        conn.execute('''CREATE TABLE users_salt (uname VARCHAR(32) NOT NULL, salt VARCHAR(25) NOT NULL);''')
    except Exception, e:
        logger.info(e)

    logger.info("Tables created in {0}".format(database))    # Log to informational the completion of table creation

    try:
        conn.commit()    # Commit all changes
        logger.info("Commit Completed")    # Log to informational the completion
    except Exception, e:
        logger.info(e)

    try:
        conn.close()    # Close connection to database
        logger.info("Connection to database closed")    # Log ot informational the closure of connection
    except Exception, e:
        logger.info(e)

# def generate_RSA(bits=2048):
#     '''
#     Generate an RSA keypair with an exponent of 65537 in PEM format
#     param: bits The key length in bits
#     Return private key and public key
#     '''
#
#     from Crypto.PublicKey import RSA
#
#     try:
#         new_key = RSA.generate(bits, e=65537)
#     except Exception, e:
#         logger.info(e)
#
#     try:
#         public_key = new_key.publickey().exportKey("PEM")
#     except Exception, e:
#         logger.info(e)
#
#     try:
#         private_key = new_key.exportKey("PEM")
#     except Exception, e:
#         logger.info(e)
#
#     return private_key, public_key

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from M2Crypto import RSA, BIO
    new_key = RSA.gen_key(bits, 65537)
    memory = BIO.MemoryBuffer()
    new_key.save_key_bio(memory, cipher=None)
    private_key = memory.getvalue()
    new_key.save_pub_key_bio(memory)
    return private_key, memory.getvalue()

def checkModules():    # Validate M2Crypto and base64 modules are installed

    try:
        import M2Crypto
    except ImportError, e:
        logger.info(e)
        logger.warning("M2Crypto module failed to import. Please install.")
        print('M2Crypto module failed to import. Please install.')
        exit()
    try:
        import base64
    except ImportError, e:
        logger.info(e)
        logger.warning("base64 module failed to import. Please install.")
        print('base64 module failed to import. Please install.')
        exit()
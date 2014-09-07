#!/usr/bin/python

import sqlite3
import os
import argparse
import logging

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')

def logLevel():    # Used to set log levels based on argument
    if args['loglevel'] == 'info':    # Infomrational log level if loglevel argument == info
        logging.basicConfig(filename='log/setup.log', level=logging.INFO, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info('Log Level set to Informational')    # Insert initial log showing starting log level
    elif args['loglevel'] == 'debug':    # Debug log level if loglevel argument == debug
        logging.basicConfig(filename='log/setup.log', level=logging.DEBUG, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.debug('Log Level set to Debug')    # Insert initial log showing starting log level
    elif args['loglevel'] == 'warning':    # Warning log level if loglevel argument == warning
        logging.basicConfig(filename='log/setup.log', level=logging.WARNING, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.warning('Log Level set to Warning')    # Insert initial log showing starting log level

def setupDatabase(database):    # Set up sqlite database with appropriate tables and columns
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

if __name__ == "__main__":

    args = vars(parser.parse_args())    # Assign arguments to args array
    logLevel()    # Set log levels
    checkModules()    # Validate modules exist

    setupDatabase('ctfCollector.db')    # Setup the database
    encryption = generate_RSA()    # Generate public and private keys

    f = open('keys/priv.key', 'w')    # Write private key
    f.write(encryption[0])

    f = open('keys/pub.key', 'w')    # Write public key
    f.write(encryption[1])

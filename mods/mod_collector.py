#!/usr/bin/python

import logging
import os

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/ctfCollector.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def check_if_userflag_exists(uuid, username):    # Check if user has already submitted

    import sqlite3
    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM user_flags WHERE uname = ? and uuid = ?)''', (username, uuid,))    # Check if user exists
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("SELECT EXISTS FROM user_flag: {0}".format(e))

    return returnvalue[0]

def check_if_uuid_exists(uuid):    # Check if flag exists

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))


    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = ?)''', (uuid,))    # Check if user exists
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("SELECT EXISTS FROM flags: {0}".format(e))

    return returnvalue[0]

def check_if_user_exists_points(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM user_points WHERE uname = ?)''', (username,))    # Check if user exists
    except Exception, e:
        logger.info("SELECT EXISTS FROM user_points: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch results from SELECT: {0}".format(e))

    return returnvalue[0]

def checkdatabase(database):    # Validate the database exists in the correct directory. Recommend running setup.py otherwise

    try:
        if not os.path.isfile(os.path.realpath('database/' + database)):    # Check if database file in database/ does not exist
            logger.info('Database does not exist. Run setup first')
            print('Database does not exist. Run setup.py first')    # Print next steps if not
            exit()    # Exit script if database doesn't exist
    except Exception, e:
        logger.info("Check if database exists: {0}".format(e))


def decrypt_RSA(private_key_loc, package):

    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from base64 import b64decode

    try:
        key = open(private_key_loc, "r").read()
    except Exception, e:
        logger.info("Open private key for reading: {0}".format(e))

    try:
        rsakey = RSA.importKey(key)
    except Exception, e:
        logger.info("Call to RSA.importKey: {0}".format(e))

    try:
        rsakey = PKCS1_OAEP.new(rsakey)
    except Exception, e:
        logger.info("Call to PKCS1_OAEP: {0}".format(e))
    decrypted = ''
    try:
        decrypted = rsakey.decrypt(b64decode(package))
    except Exception, e:
        logger.info("Call to rsakey.decrypt: {0}".format(e))

    return decrypted

def update_user_flag(username, flag):    # Add flag to the user - used to allow only one time use of flags

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        logging.info("Connecting to ctfCollector.db setup")    # Log to informational
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_flags VALUES (?,?)''', (username, flag))
    except Exception, e:
        logger.info("INSERT INTO user_flags: {0}".format(e))

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info("Commit INSERT to database: {0}".format(e))

    try:
        conn.close()    # Close connection to sqlite database
        logging.info("Closing connection to database")    # Log to info
    except Exception, e:
        logger.info("Close connection to database: {0}".format(e))

def get_users_current_score(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        c.execute('''SELECT tot_points FROM user_points WHERE uname = ?''', (username,))    # Check if user exists
    except Exception, e:
        logger.info("SELECT tot_points FROM user_points: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch SELECT from database: {0}".format(e))

    try:
        c.close()
    except Exception, e:
        logger.info("Close connection to database: {0}".format(e))

    return returnvalue[0]

def get_flag_worth(uuid):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        c.execute('''SELECT points FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    except Exception, e:
        logger.info("SELECT points FROM flags: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch from SELECT: {0}".format(e))

    try:
        c.close()
    except Exception, e:
        logger.info("Close connection to database: {0}".format(e))

    return returnvalue[0]

def get_is_flag_venomous(uuid):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        c.execute('''SELECT venomous FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    except Exception, e:
        logger.info("SELECT venomous FROM flags: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch from SELECT: {0}".format(e))

    try:
        c.close()
    except Exception, e:
        logger.info("Close connection to database: {0}".format(e))

    return returnvalue[0]

def update_user_score(username, uuid):    # Update users score

    import sqlite3
    import mod_global as global_def

    try:
        if not check_if_user_exists_points(username):
            try:
                global_def.insert_new_user(username)
            except Exception, e:
                logger.info("Call to global_def.insert_new_user: {0}".format(e))
    except Exception, e:
        logger.info("Call to check_if_user_exists_points: {0}".format(e))

    try:
        points = get_users_current_score(username) # Get users current score for adding and updating
    except Exception, e:
        logger.info("Call to get_users_current_score: {0}".format(e))

    try:
        flag = get_flag_worth(uuid)
    except Exception, e:
        logger.info("Call to get_flag_worth: {0}".format(e))

    try:
        if not get_is_flag_venomous(uuid):    # Check if flag is not venomous
            try:
                new_points = int(points) + int(flag)    # Add if flag is not venomous
            except Exception, e:
                logger.info("Add points to user: {0}".format(e))
        else:
            try:
                new_points = int(points) - int(flag)    # Subtract if flag is venomous
            except Exception, e:
                logger.info("Subtract points from user: {0}".format(e))
    except Exception, e:
        logger.info("Call to get_is_flag_venomous: {0}".format(e))

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''UPDATE user_points SET tot_points=? WHERE uname=?''', (new_points, username))
    except Exception, e:
        logger.info("UPDATE user_points: {0}".format(e))

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info("Commit UPDATE: {0}".format(e))

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info("Close connection to database: {0}".format(e))

def user_message_update(username, message):    # Update user messages table

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_messages VALUES (?,?)''', (username, message))
    except Exception, e:
        logger.info("INSERT INTO user_messages: {0}".format(e))

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info("Commit INSERT: {0}".format(e))

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info("Close connection: {0}".format(e))

# def validate_passwd(password, salt, hashedpasswd):
#
#     import hashlib
#
#     m = hashlib.md5()
#     m.update(salt + password)
#     salted_password = m.hexdigest()
#
#     if hashedpasswd != salted_password:
#         print('Password does not match')
#     else:
#         print('Password matches')
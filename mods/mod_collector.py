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
        logger.info(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM user_flags WHERE uname = ? and uuid = ?)''', (username, uuid,))    # Check if user exists
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def check_if_uuid_exists(uuid):    # Check if flag exists

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info(e)


    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = ?)''', (uuid,))    # Check if user exists
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def check_if_user_exists(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM users WHERE uname = ?)''', (username,))    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def check_if_user_exists_points(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM user_points WHERE uname = ?)''', (username,))    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def checkdatabase(database):    # Validate the database exists in the correct directory. Recommend running setup.py otherwise

    try:
        if not os.path.isfile(os.path.realpath('database/' + database)):    # Check if database file in database/ does not exist
            logger.info('Database does not exist. Run setup first')
            print('Database does not exist. Run setup.py first')    # Print next steps if not
            exit()    # Exit script if database doesn't exist
    except Exception, e:
        logger.info(e)


# def decrypt_RSA(private_key_loc, package):
#     '''
#     param: public_key_loc Path to your private key
#     param: package String to be decrypted
#     return decrypted string
#     '''
#     from base64 import b64decode
#     from M2Crypto import BIO, RSA
#     print 'Working 1'
#     key = open(private_key_loc, "r").read()
#     print 'Working 2'
#     priv_key = BIO.MemoryBuffer(key.encode('utf8'))
#     print 'Working 3'
#     key = RSA.load_key_bio(priv_key)
#     print 'Working 4'
#     decrypted = key.private_decrypt(b64decode(package), RSA.pkcs1_oaep_padding)
#     print 'Working 5'
#     return decrypted


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
        logger.info(e)

    try:
        rsakey = RSA.importKey(key)
    except Exception, e:
        logger.info(e)

    try:
        rsakey = PKCS1_OAEP.new(rsakey)
    except Exception, e:
        logger.info(e)
    decrypted = ''
    try:
        decrypted = rsakey.decrypt(b64decode(package))
    except Exception, e:
        logger.info(e)

    return decrypted

def update_user_flag(username, flag):    # Add flag to the user - used to allow only one time use of flags

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        logging.info("Connecting to ctfCollector.db setup")    # Log to informational
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_flags VALUES (?,?)''', (username, flag))
    except Exception, e:
        logger.info(e)

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info(e)

    try:
        conn.close()    # Close connection to sqlite database
        logging.info("Closing connection to database")    # Log to info
    except Exception, e:
        logger.info(e)

def get_users_current_score(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT tot_points FROM user_points WHERE uname = ?''', (username,))    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    try:
        c.close()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def get_flag_worth(uuid):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT points FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    try:
        c.close()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def get_is_flag_venomous(uuid):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT venomous FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    try:
        c.close()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def update_user_score(username, uuid):    # Update users score

    import sqlite3
    import mod_global as global_def

    try:
        if not check_if_user_exists_points(username):
            try:
                global_def.insert_new_user(username)
            except Exception, e:
                logger.info(e)
    except Exception, e:
        logger.info(e)

    try:
        points = get_users_current_score(username) # Get users current score for adding and updating
    except Exception, e:
        logger.info(e)

    try:
        flag = get_flag_worth(uuid)
    except Exception, e:
        logger.info(e)

    try:
        if not get_is_flag_venomous(uuid):    # Check if flag is not venomous
            try:
                new_points = int(points) + int(flag)    # Add if flag is not venomous
            except Exception, e:
                logger.info(e)
        else:
            try:
                new_points = int(points) - int(flag)    # Subtract if flag is venomous
            except Exception, e:
                logger.info(e)
    except Exception, e:
        logger.info(e)

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''UPDATE user_points SET tot_points=? WHERE uname=?''', (new_points, username))
    except Exception, e:
        logger.info(e)

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info(e)

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info(e)

def user_message_update(username, message):    # Update user messages table

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_messages VALUES (?,?)''', (username, message))
    except Exception, e:
        logger.info(e)

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.info(e)

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info(e)

def validate_passwd(password, salt, hashedpasswd):
    # ToDo: pull salt from salt database
    # ToDo: pull hashed password from user database
    import hashlib

    m = hashlib.md5()
    m.update(salt + password)
    salted_password = m.hexdigest()

    if hashedpasswd != salted_password:
        print('Password does not match')
    else:
        print('Password matches')
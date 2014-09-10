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
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM users WHERE uname = ?)''', (username,))    # Check if user exists
    returnvalue = c.fetchone()
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
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def checkdatabase(database):    # Validate the database exists in the correct directory. Recommend running setup.py otherwise

    import os
    if not os.path.isfile(os.path.realpath('database/' + database)):    # Check if database file in database/ does not exist
        print('Run setup.py first')    # Print next steps if not
        exit()    # Exit script if database doesn't exist

def decrypt_RSA(private_key_loc, package):

    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from base64 import b64decode

    key = open(private_key_loc, "r").read()

    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted

def sanitize(table_name):    # On standby for the need to scrub sql input

    return ''.join( chr for chr in table_name if chr.isalnum() )    # Return string with only allow alphanumeric characters

def update_user_flag(username, flag):    # Add flag to the user - used to allow only one time use of flags

    import sqlite3
    import logging

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    logging.info("Connecting to ctfCollector.db setup")    # Log to informational
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''INSERT INTO user_flags VALUES (?,?)''', (username, flag))
    conn.commit()    # commit the changes to the database
    conn.close()    # Close connection to sqlite database
    logging.info("Closing connection to database")    # Log to info

def get_users_current_score(username):

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT tot_points FROM user_points WHERE uname = ?''', (username,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def get_flag_worth(uuid):

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT points FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def get_is_flag_venomous(uuid):

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT venomous FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def update_user_score(username, uuid):    # Update users score

    import sqlite3
    import mod_global as global_def

    if not check_if_user_exists_points(username):
        global_def.insert_new_user(username)

    points = get_users_current_score(username) # Get users current score for adding and updating
    flag = get_flag_worth(uuid)

    if not get_is_flag_venomous(uuid):    # Check if flag is not venomous
        new_points = int(points) + int(flag)    # Add if flag is not venomous
    else:
        new_points = int(points) - int(flag)    # Subtract if flag is venomous

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''UPDATE user_points SET tot_points=? WHERE uname=?''', (new_points, username))
    conn.commit()    # commit the changes to the database
    conn.close()    # Close connection to sqlite database

def user_message_update(username, message):    # Update user messages table

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''INSERT INTO user_messages VALUES (?,?)''', (username, message))
    conn.commit()    # commit the changes to the database
    conn.close()    # Close connection to sqlite database
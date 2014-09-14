#!/usr/bin/python

import logging
import os

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/global.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def sanitize(table_name):    # On standby for the need to scrub sql input

    try:
        clean_table_name = ''.join( chr for chr in table_name if chr.isalnum() )    # Return string with only allow alphanumeric characters
    except Exception, e:
        logger.info(e)

    return clean_table_name

def check_if_user_exists(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info(e)

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM users WHERE uname = "''' + sanitize(username) + '''")''')    # Check if user exists
    except Exception, e:
        logger.info(e)

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info(e)

    return returnvalue[0]

def insert_new_user(username):

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
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_points VALUES (?,?)''', (username, '0'))
    except Exception, e:
        logger.inf(e)

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.inf(e)

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.inf(e)

def get_user_password_hash(username):
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
        c.execute('''SELECT password FROM users WHERE uname="''' + sanitize(username) + '''"''')
    except Exception, e:
        logger.info(e)
    try:
        password_hash = c.fetchone()
    except Exception, e:
        logger.info(e)

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        if password_hash is not None and not isinstance(password_hash, list):
            return password_hash[0]
        else:
            return None
            logger.info('Password does not exist for user: %s' % username)
    except Exception, e:
        logger.info(e)

def get_user_salt(username):
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
        c.execute('''SELECT salt FROM users_salt WHERE uname="''' + sanitize(username) + '''"''')
    except Exception, e:
        logger.info(e)
    try:
        user_salt = c.fetchone()
    except Exception, e:
        logger.info(e)
    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info(e)

    try:
        if user_salt is not None and not isinstance(user_salt, list):
            return user_salt[0]
        else:
            return None
            logger.info('Salt does not exist for user: %s' % username)
    except Exception, e:
        logger.info(e)

def create_salt():

    salt = os.urandom(16)
    new_salt = salt.encode('base-64').rstrip('\n\r')

    return new_salt

def create_hash_passwd(password,salt):

    import hashlib

    m = hashlib.md5()
    m.update(salt + password)
    salted_password = m.hexdigest()

    return salted_password,salt

def validate_password(username, password):

    try:
        salt = get_user_salt(username)
    except Exception, e:
        logger.info(e)
    try:
        salted_password = create_hash_passwd(password,salt)
        salted_password = salted_password[0]
    except Exception, e:
        logger.info(e)

    try:
        hashed_passwd = get_user_password_hash(username)
    except Exception, e:
        logger.info(e)

    try:
        if hashed_passwd != salted_password:
            answer = False
            logger.info('Failed password attempted for username: %s. Password attempted: %s' % username, password)
        else:
            answer = True
            logger.info('Successful password attempt for username %s' % username)
    except Exception, e:
        logger.info(e)
    return answer
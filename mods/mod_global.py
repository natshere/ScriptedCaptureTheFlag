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
        logger.info("Call to join and chr.isalnum: {0}".format(e))

    return clean_table_name

def check_if_user_exists(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM users WHERE uname = "''' + sanitize(username) + '''")''')    # Check if user exists
    except Exception, e:
        logger.info("SELECT EXISTS: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch results of SELECT EXISTS: {0}".format(e))

    return returnvalue[0]

def insert_new_user(username):

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.inf("Setup conenction to database: {0}".format(e))
    try:
        c = conn.cursor()
    except Exception, e:
        logger.inf(e)
    try:
        # Insert into user_flags table the username and flag they have obtained
        c.execute('''INSERT INTO user_points VALUES (?,?)''', (username, '0'))
    except Exception, e:
        logger.inf("INSERT INTO user_points: {0}".format(e))

    try:
        conn.commit()    # commit the changes to the database
    except Exception, e:
        logger.inf("Commit changes to database: {0}".format(e))

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.inf("Clost connection to database: {0}".format(e))

def get_user_password_hash(username):
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
        c.execute('''SELECT password FROM users WHERE uname="''' + sanitize(username) + '''"''')
    except Exception, e:
        logger.info("SELECT password: {0}".format(e))
    try:
        password_hash = c.fetchone()
    except Exception, e:
        logger.info("Fetch results from SELECT: {0}".format(e))

    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info("Clost connection to database: {0}".format(e))

    try:
        if password_hash is not None and not isinstance(password_hash, list):
            return password_hash[0]
        else:
            return None
            logger.info('Password does not exist for user: %s' % username)
    except Exception, e:
        logger.info("Call to password_hash is not None and not isinstance(password_hash, list): {0}".format(e))

def get_user_salt(username):
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
        c.execute('''SELECT salt FROM users_salt WHERE uname="''' + sanitize(username) + '''"''')
    except Exception, e:
        logger.info("SELECT salt: {0}".format(e))
    try:
        user_salt = c.fetchone()
    except Exception, e:
        logger.info("Fetch results of SELECT: {0}".format(e))
    try:
        conn.close()    # Close connection to sqlite database
    except Exception, e:
        logger.info("Close connection to databse: {0}".format(e))

    try:
        if user_salt is not None and not isinstance(user_salt, list):
            return user_salt[0]
        else:
            return None
            logger.info('Salt does not exist for user: %s' % username)
    except Exception, e:
        logger.info("user_salt is not None and not isinstance(user_salt, list): {0}".format(e))

def create_salt():

    try:
        salt = os.urandom(16)
    except Exception, e:
        logger.info("Call os.random: {0}".format(e))

    try:
        new_salt = salt.encode('base-64').rstrip('\n\r')
    except Exception, e:
        logger.info("Call to encode and rstrip: {0}".format(e))

    return new_salt

def create_hash_passwd(password,salt):

    import hashlib

    try:
        m = hashlib.md5()
    except Exception, e:
        logger.info("Call to hashlib.md5: {0}".format(e))

    try:
        m.update(salt + password)
    except Exception, e:
        logger.info("Update with salt and password: {0}".format(e))

    try:
        salted_password = m.hexdigest()
    except Exception, e:
        logger.info("Call to hexdigest: {0}".format(e))

    return salted_password,salt

def validate_password(username, password):

    try:
        salt = get_user_salt(username)
    except Exception, e:
        logger.info("Call to get_user_salt: {0}".format(e))
    try:
        salted_password = create_hash_passwd(password,salt)
        salted_password = salted_password[0]
    except Exception, e:
        logger.info("Call to create_hash_passwd: {0}".format(e))

    try:
        hashed_passwd = get_user_password_hash(username)
    except Exception, e:
        logger.info("Call to get_user_password_hash: {0}".format(e))

    try:
        if hashed_passwd != salted_password:
            answer = False
            logger.info('Failed password attempted for username: %s. Password attempted: %s' % username, password)
        else:
            answer = True
            logger.info('Successful password attempt for username %s' % username)
    except Exception, e:
        logger.info("Validate hash_passwd and salted_password are the same: {0}".format(e))
    return answer
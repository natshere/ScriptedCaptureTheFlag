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
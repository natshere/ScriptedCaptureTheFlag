#!/usr/bin/python

import logging
import os
import sqlite3

current_directory = os.getcwd()
logger = logging.getLogger('CTFcreateUser')
hdlr = logging.FileHandler(current_directory + '/log/createUser.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def insert_user_points(username, database):

    initial_points = 0
    try:
        conn = sqlite3.connect('database/' + database)    # Setup connection to database
        logger.info("Database open: {0}".format(database))    # Log to info what database was open
    except Exception, e:
        logger.info("Creating conn: {0}".format(e))
    try:
        conn.execute('''INSERT INTO user_points(uname, tot_points) VALUES(?,?)''', (username, initial_points))
        logger.info("INSERT INTO user_points(uname, tot_points) VALUES({0},{1})".format(username, initial_points))
    except Exception, e:
        logger.info("Executing INSERT: {0}".format(e))
    try:
        conn.commit()    # Commit all changes
        logger.info("Commit Completed")    # Log to informational the completion
    except Exception, e:
        logger.info("Commiting change to database: {0}".format(e))
    try:
        conn.close()    # Close connection to database
        logger.info("Connection to database closed")    # Log ot informational the closure of connection
    except Exception, e:
        logger.info("Closing connection to database: {0}".format(e))

def insert_user_hash(username, hashed_password, database):

    try:
        conn = sqlite3.connect('database/' + database)    # Setup connection to database
        logger.info("Database open: {0}".format(database))    # Log to info what database was open
    except Exception, e:
        logger.info("Creating connection to database: {0}".format(e))
    try:
        conn.execute('''INSERT INTO users(uname, password) VALUES(?,?)''', (username, hashed_password))
        logger.info("INSERT INTO users(uname, password) VALUES({0}, {1})".format(username, hashed_password))
    except Exception, e:
        logger.info("Executing INSERT: {0}".format(e))
    try:
        conn.commit()    # Commit all changes
        logger.info("Commit Completed")    # Log to informational the completion
    except Exception, e:
        logger.info("Commiting to change to database: {0}".format(e))
    try:
        conn.close()    # Close connection to database
        logger.info("Connection to database closed")    # Log ot informational the closure of connection
    except Exception, e:
        logger.info("Closing connection to database: {0}".format(e))

def insert_user_salt(username, salt, database):

    try:
        conn = sqlite3.connect('database/' + database)    # Setup connection to database
        logger.info("Database open: {0}".format(database))    # Log to info what database was open
    except Exception, e:
        logger.info("Creating connection to database: {0}".format(e))
    try:
        conn.execute('''INSERT INTO users_salt(uname, salt) VALUES(?,?)''', (username, salt))
        logger.info("INSERT INTO users_salt(uname, salt) VALUES({0}, {1})".format(username, salt))
    except Exception, e:
        logger.info("Executing INSERT: {0}".format(e))
    try:
        conn.commit()    # Commit all changes
        logger.info("Commit Completed")    # Log to informational the completion
    except Exception, e:
        logger.info("Comming change to database: {0}".format(e))
    try:
        conn.close()    # Close connection to database
        logger.info("Connection to database closed")    # Log ot informational the closure of connection
    except Exception, e:
        logger.info("Closing connection to database: {0}".format(e))
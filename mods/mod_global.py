#!/usr/bin/python

def loglevel(level):    # Used to set log levels based on argument

    import logging
    if level == 'info':    # Infomrational log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.INFO, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info('Log Level set to Informational')
    elif level == 'debug':    # Debug log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.DEBUG, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.debug('Log Level set to Debug')
    elif level == 'warning':    # Warning log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.WARNING, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.warning('Log Level set to Warning')    # Insert initial log showing starting log level

def insert_new_user(username):

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''INSERT INTO user_points VALUES (?,?)''', (username, '0'))
    conn.commit()    # commit the changes to the database
    conn.close()    # Close connection to sqlite database
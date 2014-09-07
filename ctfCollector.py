#!/usr/bin/python

__author__ = 'tom'

import socket
import select
import logging
import argparse
import sqlite3
import os

#ToDo: Interact with user_messages table - update with new messages by users
#ToDo: Create logic for user to submit flag only once (Should be completed check_if_exists function)
#ToDo: Create function to validate flag exists (Should be completed check_if_uuid_exists function)
#ToDo: Create function to validate user exists (Should be completed check_if_usrflag_exists function)

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')

def check_if_usrflag_exists(username, uuid):    # Check if user has already submitted

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM user_flags WHERE uname = ? and uuid = ?)''', (username, uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    return returnvalue[0]

def check_if_uuid_exists(uuid):    # Check if flag exists

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = ?)''', (uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    return returnvalue[0]

def check_if_user_exists(username):

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT EXISTS(SELECT * FROM users WHERE uname = ?)''', (username,))    # Check if user exists
    returnvalue = c.fetchone()
    return returnvalue[0]

def loglevel():    # Used to set log levels based on argument

    if args['loglevel'] == 'info':    # Infomrational log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.INFO, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info('Log Level set to Informational')
    elif args['loglevel'] == 'debug':    # Debug log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.DEBUG, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.debug('Log Level set to Debug')
    elif args['loglevel'] == 'warning':    # Warning log level if loglevel argument == info
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.WARNING, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.warning('Log Level set to Warning')    # Insert initial log showing starting log level

def checkdatabase(database):    # Validate the database exists in the correct directory. Recommend running setup.py otherwise

    if not os.path.isfile(os.path.realpath('database/' + database)):    # Check if database file in database/ does not exist
        print('Run setup.py first')    # Print next steps if not
        exit()    # Exit script if database doesn't exist

def decrypt_RSA(private_key_loc, package):

    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from base64 import b64decode
    from M2Crypto import BIO, RSA

    key = open(private_key_loc, "r").read()    # Read private key to key variable for decryption
    priv_key = BIO.MemoryBuffer(key.encode('utf8'))    # Encode key with utf8
    key = RSA.load_key_bio(priv_key)    # Load the encoded private key
    decrypted = key.private_decrypt(b64decode(package), RSA.pkcs1_oaep_padding)    # Decrypt the 'package'

    return decrypted    # Return decrypted content

def sanitize(table_name):    # On standby for the need to scrub sql input
    return ''.join( chr for chr in table_name if chr.isalnum() )    # Return string with only allow alphanumeric characters

if __name__ == "__main__":

    args = vars(parser.parse_args())    # Pull arguments into args variable

    loglevel()    # Set log level
    checkdatabase('ctfCollector.db')    # Validate database exists in correct directory
    privateKey = 'keys/priv.key'    # Assign location of private key to privateKey variable

    CONNECTION_LIST = []  # list of socket clients
    RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
    PORT = 65535    # Set listening port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", PORT))    # Bind locally to appropriate port
    server_socket.listen(10)    # Listen and allow for 10 threads

    # Add server socket to the list of readable connections
    CONNECTION_LIST.append(server_socket)
    logging.info("Chat server started on port " + str(PORT))    # Log to info

def update_user_flag(username, flag):    # Add flag to the user - used to allow only one time use of flags
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    logging.info("Connecting to ctfCollector.db setup")    # Log to informational
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''INSERT INTO user_flags VALUES (?,?)''', (username, flag))
    conn.commit()    # commit the changes to the database
    # Log to informational the insert command
    logging.info("Commiting INSERT INTO user_flags VALUES (%s, %s)"
                 % username, flag)
    conn.close()    # Close connection to sqlite database
    logging.info("Closing connection to database")    # Log to info

def get_users_current_score(username):

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT tot_points FROM user_points WHERE uname = ?''', (username,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def get_flag_worth(uuid):

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT points FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def get_is_flag_venomous(uuid):

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()

    c.execute('''SELECT venomous FROM flags WHERE uuid = ?''', (uuid,))    # Check if user exists
    returnvalue = c.fetchone()
    c.close()
    return returnvalue[0]

def update_user_score(username, uuid):    # Update users score

    points = get_users_current_score(username) # Get users current score for adding and updating
    print "Points: " + str(points)
    flag = get_flag_worth(uuid)
    print "Flag: " + str(flag)

    if not get_is_flag_venomous(uuid):    # Check if flag is not venomous
        new_points = int(points) + int(flag)    # Add if flag is not venomous
    else:
        new_points = int(points) - int(flag)    # Subtract if flag is venomous

    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    #logging.info("Connecting to ctfCollector.db setup")    # Log to informational
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''UPDATE user_points SET tot_points=? WHERE uname=?''', (new_points, username))
    conn.commit()    # commit the changes to the database
    # Log to informational the insert command
    #logging.info("UPDATE user_points SET tot_points=%s WHERE uname=%s"
    #             % username, points)
    conn.close()    # Close connection to sqlite database
    #logging.info("Closing connection to database")    # Log to info

    while 1:
        # Get the list sockets which are ready to be read through select
        read_sockets, write_sockets, error_sockets = select.select(CONNECTION_LIST, [], [])

        for sock in read_sockets:

            # New connection
            if sock == server_socket:
                # Handle the case in which there is a new connection received through server_socket
                sockfd, addr = server_socket.accept()
                CONNECTION_LIST.append(sockfd)
                logging.info("Client %s %s connected" % addr)    # Log to info

            #Some incoming message from a client
            else:
                # Data received from client, process it
                try:
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    encryptedData = sock.recv(RECV_BUFFER)    # Receive the encrypted package
                    data = decrypt_RSA(privateKey, encryptedData)    # Decrypt and assign to data variable

                    if data:    # If data exists
                        logData = data.rstrip('\n\r')
                        logging.info("Client %s %s sent: " % addr + logData)    # Log to info
                        if ',' in logData:    # Validate proper string structure exists
                            username, flag, message  = data.split(",")    # Split up the string to variables for insert
                            if os.path.isfile(os.path.realpath('database/ctfCollector.db')):    # Validate database exists
                                if not check_if_usrflag_exists(flag, username):    # Check if user has already submitted flag
                                    if check_if_uuid_exists(flag):
                                        if check_if_user_exists(username):
                                            update_user_flag(username, flag)    # Update user_flag database
                                            update_user_score(username, flag)
                                        else:
                                            logging.warn("%s username doesn't exist" % username)
                                            print("%s username doesn't exists" % username)
                                    else:
                                        logging.warn("%s flag doesn't exist" % flag)
                                        print("%s flag doesn't exists" % flag)
                                else:
                                    logging.warn("%s submitted twice" % username)
                                    print("%s submitted twice" % username)    # ToDo: Find a way to give this back to the user
                            else:
                                logging.warning("No database available")    # Warn that database does not exist
                                print('Run setup.py first')    # Print next steps if not
                                exit()    # Exist script due to setup not being ran

                # client disconnected, so remove from socket list
                except:
                    logging.warning("Client %s %s is offline" % addr)    # Log to warn due to potential issue
                    sock.close()    # Close socket due to exception error
                    CONNECTION_LIST.remove(sock)    # Remove from list of sockets
                    continue    # Keep server listening

    server_socket.close()    # Should never close
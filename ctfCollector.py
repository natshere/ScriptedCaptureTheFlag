#!/usr/bin/python

__author__ = 'tom'

import socket, select
import logging
import argparse
import sqlite3
import os

#ToDo: Interact with user_points table - Logic to update scoring in user database
#ToDo: Interact with user_flags table - Update flags as user sends them
#ToDo: Interact with user_messages table - update with new messages by users
#ToDo: Interact with flags table - Check if flag is venomous and deduct set number of points
#ToDo: Create logic for user to submit flag only once

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')


def logLevel():
    if args['loglevel'] == 'info':
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.INFO, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info('Log Level set to Informational')
    elif args['loglevel'] == 'debug':
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.DEBUG, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.debug('Log Level set to Debug')
    elif args['loglevel'] == 'warning':
        logging.basicConfig(filename='log/ctfCollector.log', level=logging.WARNING, filemode='a', format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.warning('Log Level set to Warning')

def checkDatabase(database):

    if not os.path.isfile(os.path.realpath('database/' + database)):
        print('Run setup.py first')
        exit()

def decrypt_RSA(private_key_loc, package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from base64 import b64decode
    from M2Crypto import BIO, RSA

    key = open(private_key_loc, "r").read()
    priv_key = BIO.MemoryBuffer(key.encode('utf8'))
    key = RSA.load_key_bio(priv_key)
    decrypted = key.private_decrypt(b64decode(package), RSA.pkcs1_oaep_padding)

    return decrypted

if __name__ == "__main__":

    args = vars(parser.parse_args())

    logLevel()
    checkDatabase('ctfCollector.db')
    privateKey = 'keys/priv.key'

    CONNECTION_LIST = []  # list of socket clients
    RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
    PORT = 65535

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this has no effect, why ?
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", PORT))
    server_socket.listen(10)

    # Add server socket to the list of readable connections
    CONNECTION_LIST.append(server_socket)
    logging.info("Chat server started on port " + str(PORT))

    while 1:
        # Get the list sockets which are ready to be read through select
        read_sockets, write_sockets, error_sockets = select.select(CONNECTION_LIST, [], [])

        for sock in read_sockets:

            # New connection
            if sock == server_socket:
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, addr = server_socket.accept()
                CONNECTION_LIST.append(sockfd)
                logging.info("Client %s %s connected" % addr)

            #Some incoming message from a client
            else:
                # Data received from client, process it
                try:
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    encryptedData = sock.recv(RECV_BUFFER)
                    #print encryptedData
                    data = decrypt_RSA(privateKey, encryptedData)

                    if data:
                        logData = data.rstrip('\n\r')
                        logging.info("Client %s %s sent: " % addr + logData)
                        if '-' in logData:
                            username, message, flag = data.split(",")
                            if os.path.isfile(os.path.realpath('database/ctfCollector.db')):
                                conn = sqlite3.connect('database/ctfCollector.db')
                                logging.info("Attempted to connect to ctfCollector.db")
                                c = conn.cursor()
                                c.execute('''INSERT INTO ctfusers VALUES (?,?,?)''', (username, message, flag))
                                conn.commit()
                                logging.info("Commiting INSERT INTO ctfusers VALUES (%s, %s, %s)"
                                             % username, message, flag)
                                conn.close()
                                logging.info("Closing connection to database")
                            else:
                                logging.warning("No database available")
                                exit()

                # client disconnected, so remove from socket list
                except:
                    logging.warning("Client %s %s is offline" % addr)
                    sock.close()
                    CONNECTION_LIST.remove(sock)
                    continue

    server_socket.close()
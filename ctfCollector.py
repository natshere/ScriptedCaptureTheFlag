#!/usr/bin/python

__author__ = 'tom'

import socket
import select
import logging
import argparse
import os
import mods.mod_collector as collector_def

# ToDo: Find a way to give feedback to submitter of the flag
# ToDo: Require password for sending of flags (prevent other users removing points from others)

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')

if __name__ == "__main__":

    current_directory = os.getcwd()

    logger = logging.getLogger('ctfCollector')
    hdlr = logging.FileHandler(current_directory + '/log/ctfCollector.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

    privateKey = 'keys/priv.key'    # Assign location of private key to privateKey variable

    try:
        args = vars(parser.parse_args())    # Pull arguments into args variable
    except Exception, e:
        logger.info(e)

    try:
        collector_def.checkdatabase('ctfCollector.db')    # Validate database exists in correct directory
    except Exception, e:
        logger.info(e)


    CONNECTION_LIST = []  # list of socket clients
    RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
    PORT = 65535    # Set listening port

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", PORT))    # Bind locally to appropriate port
        server_socket.listen(10)    # Listen and allow for 10 threads
    except Exception, e:
        logger.info(e)

    try:
        # Add server socket to the list of readable connections
        CONNECTION_LIST.append(server_socket)
    except Exception, e:
        logger.info(e)

    while 1:
        try:
            # Get the list sockets which are ready to be read through select
            read_sockets, write_sockets, error_sockets = select.select(CONNECTION_LIST, [], [])
        except Exception, e:
            logger.info(e)

        for sock in read_sockets:
            # New connection
            if sock == server_socket:
                try:
                    # Handle the case in which there is a new connection received through server_socket
                    sockfd, addr = server_socket.accept()
                except Exception, e:
                    logger.info(e)

                try:
                    CONNECTION_LIST.append(sockfd)
                except Exception, e:
                    logger.info(e)
            #Some incoming message from a client
            else:
                # Data received from client, process it
                try:
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    try:
                        encryptedData = sock.recv(RECV_BUFFER).rstrip('\n\r')    # Receive the encrypted package
                    except Exception, e:
                        logger.info(e)

                    try:
                        data = collector_def.decrypt_RSA(privateKey, encryptedData)    # Decrypt and assign to data variable
                    except Exception, e:
                        logger.info(e)

                    if data:    # If data exists
                        try:
                            logData = data.rstrip('\n\r')
                            logger.info("Client %s %s sent: " % addr, logData)    # Log to info
                        except Exception, e:
                            logger.info(e)
                        if ',' in logData:    # Validate proper string structure exists
                            try:
                                username, flag, message  = data.split(",")    # Split up the string to variables for insert
                            except Exception, e:
                                logger.info(e)
                            if os.path.isfile(os.path.realpath(current_directory + '/database/ctfCollector.db')):    # Validate database exists
                                # Not sure why 'not collector_def.check_if_userflag_... works - used just if
                                try:
                                    user_flag_exists = collector_def.check_if_userflag_exists(flag, username)
                                except Exception, e:
                                    logger.info(e)
                                if user_flag_exists == 0:    # Check if user has already submitted flag
                                    try:
                                        uuid_exists = collector_def.check_if_uuid_exists(flag)
                                    except Exception, e:
                                        logger.info(e)
                                    if uuid_exists:
                                        try:
                                           user_exists = collector_def.check_if_user_exists(username)
                                        except Exception, e:
                                            logger.info(e)
                                        if user_exists:
                                            try:
                                                collector_def.update_user_flag(username, flag)    # Update user_flag database
                                            except Exception, e:
                                                logger.info(e)
                                            try:
                                                collector_def.update_user_score(username, flag)    # Update users score (venomous = subtract)
                                            except Exception, e:
                                                logger.info(e)
                                            try:
                                                collector_def.user_message_update(username, message)    # Update user messages table with message
                                            except Exception, e:
                                                logger.info(e)
                                        else:
                                            logger.info("%s username doesn't exist. Sent by %s." % username, addr)
                                    else:
                                        logger.info("%s flag doesn't exist. Sent by %s." % username, addr)
                                else:
                                    logger.info("%s username submitted more than once. Sent by %s." % username, addr)
                            else:
                                logger.info("No database available")    # Warn that database does not exist
                                print('Run setup.py first')    # Print next steps if not
                                exit()    # Exist script due to setup not being ran
                # client disconnected, so remove from socket list
                except Exception, e:
                    logger.info(e)
                    try:
                        sock.close()    # Close socket due to exception error
                        CONNECTION_LIST.remove(sock)    # Remove from list of sockets
                    except Exception, e:
                        logger.info(e)
                    continue    # Keep server listening
    server_socket.close()    # Should never close
#!/usr/bin/python

__author__ = 'tom'

import socket
import select
import logging
import argparse
import os
import mods.mod_collector as collector_def
import mods.mod_global as global_def

#ToDo: Create logic for user to submit flag only once (Should be completed check_if_exists function)
#ToDo: Create function to validate flag exists (Should be completed check_if_uuid_exists function)
#ToDo: Create function to validate user exists (Should be completed check_if_userflag_exists function)

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')

if __name__ == "__main__":

    args = vars(parser.parse_args())    # Pull arguments into args variable

    global_def.loglevel(args['loglevel'])    # Set log level
    collector_def.checkdatabase('ctfCollector.db')    # Validate database exists in correct directory
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
                    data = collector_def.decrypt_RSA(privateKey, encryptedData)    # Decrypt and assign to data variable

                    if data:    # If data exists
                        logData = data.rstrip('\n\r')
                        logging.info("Client %s %s sent: " % addr + logData)    # Log to info
                        #print logData
                        if ',' in logData:    # Validate proper string structure exists
                            username, flag, message  = data.split(",")    # Split up the string to variables for insert
                            if os.path.isfile(os.path.realpath('database/ctfCollector.db')):    # Validate database exists
                                # Not sure why 'not collector_def.check_if_userflag_... works - used just if
                                if collector_def.check_if_userflag_exists(flag, username) == 0:    # Check if user has already submitted flag
                                    if collector_def.check_if_uuid_exists(flag):
                                        if collector_def.check_if_user_exists(username):
                                            collector_def.update_user_flag(username, flag)    # Update user_flag database
                                            collector_def.update_user_score(username, flag)    # Update users score (venomous = subtract)
                                            collector_def.user_message_update(username, message)    # Update user messages table with message
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
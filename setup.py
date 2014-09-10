#!/usr/bin/python

import argparse
import mods.mod_global as global_def
import mods.mod_setup as setup_def
import logging
import os

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

if __name__ == "__main__":

    try:
        args = vars(parser.parse_args())    # Assign arguments to args array
    except Exception, e:
        logger.info(e)

    try:
        global_def.loglevel(args['loglevel'])    # Set log levels
    except Exception, e:
        logger.info(e)

    try:
        setup_def.checkModules()    # Validate modules exist
    except Exception, e:
        logger.info(e)

    try:
        setup_def.setupDatabase('ctfCollector.db')    # Setup the database
    except Exception, e:
        logger.info(e)

    try:
        encryption = setup_def.generate_RSA()    # Generate public and private keys
    except Exception, e:
        logger.info(e)

    try:
        f = open('keys/priv.key', 'w')    # Write private key
    except Exception, e:
        logger.info(e)

    try:
        f.write(encryption[0])
    except Exception, e:
        logger.info(e)

    try:
        f = open('keys/pub.key', 'w')    # Write public key
    except Exception, e:
        logger.info(e)

    try:
        f.write(encryption[1])
    except Exception, e:
        logger.info(e)

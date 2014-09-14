#!/usr/bin/python

import mods.mod_setup as setup_def
import logging
import os

# ToDo: If database exists ask to overwrite

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/setup.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

if __name__ == "__main__":

    try:
        setup_def.checkModules()    # Validate modules exist
    except Exception, e:
        logger.info("Call to setup_def.checkModules: {0}".format(e))

    try:
        setup_def.setupDatabase('ctfCollector.db')    # Setup the database
    except Exception, e:
        logger.info("Call to setup_def.setupDatabase: {0}".format(e))

    try:
        encryption = setup_def.generate_RSA()    # Generate public and private keys
    except Exception, e:
        logger.info("Call to setup_def.generate_RSA: {0}".format(e))

    try:
        f = open('keys/priv.key', 'w')    # Write private key
    except Exception, e:
        logger.info("Open priv.key for writing: {0}".format(e))

    try:
        f.write(encryption[0])
    except Exception, e:
        logger.info("Write the private key: {0}".format(e))

    try:
        f = open('keys/pub.key', 'w')    # Write public key
    except Exception, e:
        logger.info("Open pub.key for writing: {0}".format(e))

    try:
        f.write(encryption[1])
    except Exception, e:
        logger.info("Write the public key: {0}".format(e))
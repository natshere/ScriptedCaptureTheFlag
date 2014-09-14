__author__ = 'tom'

import argparse
import sqlite3
import logging
import os
import mods.mod_create_user as create_user_def
import mods.mod_global as global_def

database = 'ctfCollector.db'

parser = argparse.ArgumentParser(description='Used to create flags')
parser.add_argument('-u', '--user', help='Enter username', required=True)
parser.add_argument('-p', '--password', help='Enter password', required=True)

current_directory = os.getcwd()
logger = logging.getLogger('ctfCollector')
hdlr = logging.FileHandler(current_directory + '/log/createusers.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)


if __name__ == "__main__":
    database = 'ctfCollector.db'

    try:
        if os.path.isfile(os.path.realpath('database/' + database)):    # Only do this if it does not exist

            try:
                args = vars(parser.parse_args())    # Assign arguments to args variable
            except Exception, e:
                logger.inf(e)

            try:
                username = args['user']
            except Exception, e:
                logger.inf(e)

            try:
                confirm_password = raw_input('Please re-enter password: ')
            except Exception, e:
                logger.info(e)

            try:
                while confirm_password != args['password']:
                    try:
                        confirm_password = raw_input('Password does not match. Please re-enter password: ')
                    except Exception, e:
                        logger.info(e)
            except Exception, e:
                logger.info(e)

            try:
                salt = global_def.create_salt()
            except Exception, e:
                logger.info(e)
            try:
                salt_hash = global_def.create_hash_passwd(confirm_password,salt)
                salt = salt_hash[1]
                hashed_password = salt_hash[0]
            except Exception, e:
                logger.info(e)
            try:
                create_user_def.insert_user_points(username, database)
            except Exception, e:
                logger.info(e)
            try:
                create_user_def.insert_user_hash(username,hashed_password, database)
            except Exception, e:
                logger.info(e)
            try:
                create_user_def.insert_user_salt(username, salt, database)
            except Exception, e:
                logger.info(e)
        else:
            print ('Database does not exist. Please run setup.py')
            logger.info('Database does not exist. Please run setup.py')
            exit()
    except Exception, e:
        logger.info(e)

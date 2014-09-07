#!/usr/bin/python

import argparse
import mods.mod_global as global_def
import mods.mod_setup as setup_def

parser = argparse.ArgumentParser(description='Server listening for flags')
parser.add_argument('-l', '--loglevel', help='Logging level - followed by debug, info, or warning')



if __name__ == "__main__":

    args = vars(parser.parse_args())    # Assign arguments to args array
    global_def.loglevel(args['loglevel'])    # Set log levels
    setup_def.checkModules()    # Validate modules exist

    setup_def.setupDatabase('ctfCollector.db')    # Setup the database
    encryption = setup_def.generate_RSA()    # Generate public and private keys

    f = open('keys/priv.key', 'w')    # Write private key
    f.write(encryption[0])

    f = open('keys/pub.key', 'w')    # Write public key
    f.write(encryption[1])

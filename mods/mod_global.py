#!/usr/bin/python

def insert_new_user(username):

    import sqlite3
    conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
    c = conn.cursor()
    # Insert into user_flags table the username and flag they have obtained
    c.execute('''INSERT INTO user_points VALUES (?,?)''', (username, '0'))
    conn.commit()    # commit the changes to the database
    conn.close()    # Close connection to sqlite database
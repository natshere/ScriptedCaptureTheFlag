#!/usr/bin/python

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from os import curdir, sep
import ssl
import cgi
import sqlite3
import hashlib
import time, datetime
import Cookie
import uuid
import logging
import mods.mod_global as global_def
import mods.mod_create_user as create_user_def

PORT_NUMBER = 7665

# Handler for incoming web requests
class myHandler(BaseHTTPRequestHandler):

	def getCurrentScores(self):
		current_directory = os.getcwd()
		logger = logging.getLogger('ctfCollector')
		hdlr = logging.FileHandler(current_directory + '/log/ctfCollector.log')
		formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
		hdlr.setFormatter(formatter)
		logger.addHandler(hdlr)
		logger.setLevel(logging.INFO)
		try:
	        conn = sqlite3.connect('database/ctfCollector.db')    # Setup connection to sqlite database
	    except Exception, e:
	        logger.info("Setup connection to database: {0}".format(e))

	    try:
	        c = conn.cursor()
	    except Exception, e:
	        logger.info("Setup cursor: {0}".format(e))

	    try:
	        # Insert into user_flags table the username and flag they have obtained
	        c.execute('''SELECT * FROM user_points''')
	        points = c.fetchall()
	        if len(points) > 0:
	        	i = 1
	        	scores = '<h1>Top Scores</h1><table><tr><th>Rank</th><th>User</th><th>Score</th></tr>'
	        	for p in points:
	        		scores += '<tr><td>' + str(i) + '</td><td>' + str(p[0]) + '</td><td>' + str(p[1]) + '</td></tr>'
	        		i += 1
	        		if i == 10:
	        			break
	        	scores += '</table>'
	        	return scores
	        else:
	        	return '<p>No scores recorded yet....</p>'
	    except Exception, e:
	        logger.info("UPDATE user_points: {0}".format(e))

	def login(self, error_message=''):
		f = open('./login.html')
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		content = f.read()
		if error_message == '':
			content = content.replace('{0}', '')
		else:
			content = content.replace('{0}', error_message)
		self.wfile.write(content)
		f.close()
		return

	def admin(self, message=''):
		f = open('./admin.html')
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		content = f.read()
		if error_message == '':
			content = content.replace('{0}', '')
		else:
			content = content.replace('{0}', message)
		self.wfile.write(content)
		f.close()
		return

	def do_GET(self):
		if not self.path == 'background.png' and not self.path == 'updateScores' and not self.path == 'login.html':
			self.path = 'serverFiles/scores.html'
			mimetype='text/html'
			f = open(curdir + sep + self.path) 
			self.send_response(200)
			self.send_header('Content-type',mimetype)
			self.end_headers()
			contents = f.read()
			contents = contents.replace('&&&', self.getCurrentScores())
			self.wfile.write(contents)
			f.close()
			return

		elif self.path == 'updateScores':
			return self.getCurrentScores()
		
		elif self.path == 'login.html':
			self.login()
		# Available js, css, and images are hard-coded paths
		else:
			self.path = 'serverFiles/background.png'
			mimetype = 'image/png'
			f = open(curdir + sep + self.path) 
			self.send_response(200)
			self.send_header('Content-type',mimetype)
			self.end_headers()
			self.wfile.write(f.read())
			f.close()
			return


	def do_POST(self):
		if self.path=='/login':
			form = cgi.FieldStorage(
				fp=self.rfile, 
				headers=self.headers,
				environ={'REQUEST_METHOD':'POST',
		                 'CONTENT_TYPE':self.headers['Content-Type'],
			})
			if global_def.validate_password(form['username'].value, form['password'].value) and global_def.is_admin(form['username'].value):
				self.admin()
			else:
				self.login(error_message='Invalid login. Check your username and/or password')
			return

		elif self.path == '/admin':
			form = cgi.FieldStorage(
				fp=self.rfile, 
				headers=self.headers,
				environ={'REQUEST_METHOD':'POST',
		                 'CONTENT_TYPE':self.headers['Content-Type'],
			})
			if 'username' in form.keys():
				current_directory = os.getcwd()
				logger = logging.getLogger('CTFcreateUser')
				hdlr = logging.FileHandler(current_directory + '/log/createUser.log')
				formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
				hdlr.setFormatter(formatter)
				logger.addHandler(hdlr)
				logger.setLevel(logging.INFO)

    			try:
        			if os.path.isfile(os.path.realpath('database/ctfCollector.db')):
        				try:
                			username_available = global_def.check_if_user_exists(username)
				        except Exception, e:
				            logger.info("Call to global_def.check_if_user_exists: {0}".format(e))
				        if username_available != 0:
				        	self.admin(message='Error: Username already exists')
				        	return
				        else:
				        	try:
				                salt = global_def.create_salt()
				            except Exception, e:
				                logger.info("Call to global_def.create_salt: {0}".format(e))
				            try:
				                salt_hash = global_def.create_hash_passwd(confirm_password,salt)
				                salt = salt_hash[1]
				                hashed_password = salt_hash[0]
				            except Exception, e:
				                logger.info("Call to global_def.create_hash_passwd: {0}".format(e))
				            try:
				                create_user_def.insert_user_points(username, database)
				            except Exception, e:
				                logger.info("Call to create_user_def.insert_user_points: {0}".format(e))
				            try:
				                create_user_def.insert_user_hash(username,hashed_password, database)
				            except Exception, e:
				                logger.info("Call to create_user_def.insert_user_hash: {0}".format(e))
				            try:
				                create_user_def.insert_user_salt(username, salt, database)
				            except Exception, e:
				                logger.info("Call to create_user_def.insert_user_salt: {0}".format(e))

				    	self.admin(message='User created sucessfully')
				    else:
				    	print ('Database does not exist. Please run setup.py')
				        logger.info('Database does not exist. Please run setup.py')
				    return
			else:


			# process admin request
			return

		else:
			self.path = 'serverFiles/scores.html'
			mimetype='text/html'
			f = open(curdir + sep + self.path) 
			self.send_response(200)
			self.send_header('Content-type',mimetype)
			self.end_headers()
			contents = f.read()
			contents = contents.replace('&&&', self.getCurrentScores())
			self.wfile.write(contents)
			f.close()
			return

			
try:
	#Create a web server and define the handler to manage the
	#incoming request
	httpd = HTTPServer(('', 7665), myHandler)
	httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./certs/server.pem', server_side=True)
	print 'Serving HTTPS on port 7665'
	httpd.serve_forever()

except KeyboardInterrupt:
	print '^C received, shutting down the web server'
	httpd.socket.close()
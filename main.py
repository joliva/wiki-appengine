#!/usr/bin/env python

import cgi, re, os, logging, string
import hmac, random
from datetime import datetime

import webapp2, jinja2
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=False)

UNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
UPASS_RE = re.compile(r"^.{3,20}$")
UEMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

COOKIE_SALT = 'KISSMYGRITS'

def valid_username(username):
	return UNAME_RE.match(username)

def valid_password(password):
	return UPASS_RE.match(password)

def valid_email(email):
	return email == "" or UEMAIL_RE.match(email)

def make_salt():
	# salt will be a random six character string
	return ''.join([chr(random.randint(97,122)) for idx in xrange(6)])

def make_password_hash(password):
	if password:
		salt = make_salt()
		return hmac.new(salt, password).hexdigest() + ('|%s' % salt)
	else:
		return None

class WikiUsers(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

	@staticmethod
	def get_user(username):
		user = None
		if username:
			qry = "SELECT * FROM WikiUsers WHERE username = '%s'" % username
			#logging.info('query = %s', qry)
			user = db.GqlQuery(qry).get()
		return user

	@staticmethod
	def create_user(user):
		# assumes properties of user were previously validated
		if user:
			user = WikiUsers(**user)
			key = user.put()		

class WikiEntry(db.Model):
	name = db.StringProperty(required = True, indexed = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True, indexed = True)

class Handler(webapp2.RequestHandler):
	def update_cache(self, name, value):
		# store in cache
		logging.info('insert %s into cache', name)
		memcache.set(name, {'cached_time':datetime.now(), 'content':value})

	def store(self, name, content):
		# insert new wiki entry into datastore
		p = WikiEntry(name = name, content=content)
		key = p.put()

		# update cache
		self.update_cache(name, content)

	def retrieve(self, name, id=None):
		if id != None and id != '':
			value =  WikiEntry.get_by_id(int(id)).content
			return {'cached_time':datetime.now(), 'content':value}
		else:
			# attempt first to get page from cache
			value = memcache.get(name)

			if value:
				return value
			else:
				logging.info('%s is not in the cache', name)

				# attempt to retrieve from database
				query = "SELECT * FROM WikiEntry WHERE name='%s' ORDER BY created DESC LIMIT 1" % name

				entry = db.GqlQuery(query).get()

				if entry:
					self.update_cache(name, entry.content)
					value = memcache.get(name)
					return value
				else:
					logging.info('%s is not in the DB', name)
					return None

	def retrieve_all(self, name):
		# attempt to retrieve from database
		query = "SELECT * FROM WikiEntry WHERE name='%s' ORDER BY created DESC" % name
		entries = db.GqlQuery(query).fetch(100)

		return entries

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def create_cookie(self, value):
		# cookie format: value|salted hash
		if value:
			return '%s|' % value + hmac.new(COOKIE_SALT, value).hexdigest()
		else:
			return None

	def store_cookie(self, key, value):
		if key and value:
			self.response.set_cookie(key, value=self.create_cookie(value), path='/')

	def remove_cookie(self, key):
		if key:
			self.response.set_cookie(key, value='', path='/')
			#self.response.delete_cookie(key)

	def get_cookie(self, key):
		# cookie format: value|salted hash
		if key:
			hashed_value = self.request.cookies.get(key)

			if hashed_value:
				value, salted_hash = hashed_value.split('|')
				if hashed_value == ('%s|' % value) + hmac.new(COOKIE_SALT, value).hexdigest():
					return value
		return None

class Signup(Handler):
	def get(self):
		self.render('signup.html')

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		err_name=""
		err_pass=""
		err_vpass=""
		err_email=""
		err = False

		if not valid_username(username):
			err_name = "That's not a valid username."
			err = True

		if WikiUsers.get_user(username) != None:
			err_name = "That user already exists"
			err = True

		if not valid_password(password):
			password=""
			verify=""
			err_pass = "That's not a valid password."
			err = True
		elif verify != password:
			password=""
			verify=""
			err_vpass = "Your passwords didn't match."
			err = True

		if not valid_email(email):
			err_email = "That's not a valid email."
			err = True

		if err == True:
			args = {"username":username, "password":password, "verify":verify, "email":email, "err_name":err_name, "err_pass":err_pass, "err_vpass":err_vpass, "err_email":err_email}
			self.render('signup.html', **args)
		else:
			# save new user into DB
			user = {}
			user['username'] = username
			user['password_hash'] = make_password_hash(password)
			user['email'] = email
			WikiUsers.create_user(user)

			# save login session cookie
			self.store_cookie('username', username)

			self.redirect(FRONT_URL)

class Login(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		err = False

		if username and password:
			# validate login credentials
			user = WikiUsers.get_user(username)
			if user:
				# password hash: hmac.new(salt, password).hexdigest() + '|' + salt
				password_hash = user.password_hash.encode('ascii')
				logging.info('password_hash = %s', password_hash)
				hashval, salt = password_hash.split('|')
				logging.info('hashval = %s  salt=%s', hashval, salt)

				if hashval == hmac.new(salt, password).hexdigest():
					# save login session cookie
					self.store_cookie('username', username)
					self.redirect(FRONT_URL)
					return

		args = {"username":username, "password":password, "error":'Invalid Login'}
		self.render('login.html', **args)

class Logout(Handler):
	def get(self):
		self.remove_cookie('username')
		self.redirect(FRONT_URL)

class WikiPage(Handler): 
	def get(self, name):
		if name == '': name = '_front'

		logging.info('name=%s', name)

		id = self.request.get('id')

		# attempt to retrieve page from DB
		value = self.retrieve(name, id)

		if value == None:
			# redirect to an edit page to create the new entry
			logging.info('redirect to page to add new wiki topic: %s', BASE_EDIT + name)
			self.redirect(BASE_EDIT + name)
		else:
			# display the page
			now = datetime.now()
			delta_secs = (now - value['cached_time']).seconds

			if self.request.get('cause') == 'logoff':
				self.remove_cookie('username')
				self.redirect(BASE_URL + name)	# reload page

			# determine if user logged in to set header
			username = self.get_cookie('username')

			if username:
				edit_link=BASE_EDIT + name
				edit_status='edit'
				edit_user_sep=' | '
				hist_link=BASE_HIST + name
				hist_status='history'
				wiki_user='&lt%s&gt' % username
				login_link=BASE_URL + name + '?cause=logoff'
				login_status='logout'
				login_signup_sep=''
				signup_link=''
				signup_status=''
			else:
				edit_link=BASE_URL + name
				edit_status=''
				edit_user_sep=''
				hist_link=BASE_HIST + name
				hist_status='history'
				wiki_user=''
				login_link=BASE_URL + '/login'
				login_status='login'
				login_signup_sep=' | '
				signup_link=BASE_URL + '/signup'
				signup_status='signup'

			args = dict(topic=name,
						content=value['content'], 
						cache_time=delta_secs, 
						edit_link=edit_link,
						edit_status=edit_status,
						edit_user_sep=edit_user_sep,
						hist_link=hist_link,
						hist_status=hist_status,
						wiki_user=wiki_user,
						login_link=login_link,
						login_status=login_status,
						login_signup_sep=login_signup_sep,
						signup_link=signup_link,
						signup_status=signup_status)
			self.render('entry.html', **args)

class HistPage(Handler):
	def get(self, name):
			if self.request.get('cause') == 'logoff':
				self.remove_cookie('username')
				self.redirect(BASE_HIST + name)	# reload page

			# determine if user logged in to set header
			username = self.get_cookie('username')

			if username:
				edit_link=BASE_EDIT + name
				edit_status='edit'
				edit_user_sep=''
				wiki_user='&lt%s&gt' % username
				login_link=BASE_HIST + name + '?cause=logoff'
				login_status='logout'
				login_signup_sep=''
				signup_link=''
				signup_status=''
			else:
				edit_link=BASE_URL + name
				edit_status='view'
				edit_user_sep=''
				wiki_user=''
				login_link=BASE_URL + '/login'
				login_status='login'
				login_signup_sep=' | '
				signup_link=BASE_URL + '/signup'
				signup_status='signup'

			entries = self.retrieve_all(name)

			args = dict(topic=name,
						edit_link=edit_link,
						edit_status=edit_status,
						edit_user_sep=edit_user_sep,
						wiki_user=wiki_user,
						login_link=login_link,
						login_status=login_status,
						login_signup_sep=login_signup_sep,
						signup_link=signup_link,
						signup_status=signup_status,
						entries=entries)
			self.render('history.html', **args)

class EditPage(Handler):
	def get(self, name):
			if self.request.get('cause') == 'logoff':
				self.remove_cookie('username')
				self.redirect(BASE_URL + name)	# reload page

			# determine if user logged in to set header
			username = self.get_cookie('username')

			if username:
				edit_link=BASE_URL + name
				edit_status='view'
				edit_user_sep=''
				wiki_user='&lt%s&gt' % username
				login_link=BASE_URL + name + '?cause=logoff'
				login_status='logout'
				login_signup_sep=''
				signup_link=''
				signup_status=''

				id = self.request.get('id')

				# attempt to retrieve page from DB
				value = self.retrieve(name, id)

				if value:
					content = value['content']
				else:
					content = ''

				args = dict(topic=name, 
							content=content, 
							edit_link=edit_link,
							edit_status=edit_status,
							edit_user_sep=edit_user_sep,
							wiki_user=wiki_user,
							login_link=login_link,
							login_status=login_status,
							login_signup_sep=login_signup_sep,
							signup_link=signup_link,
							signup_status=signup_status)
				self.render('editentry.html', **args)
			else:
				edit_link=''
				edit_status=''
				edit_user_sep=''
				wiki_user=''
				login_link=BASE_URL + '/login'
				login_status='login'
				login_signup_sep=' | '
				signup_link=BASE_URL + '/signup'
				signup_status='signup'
				args = dict(topic=name, 
							msg='Not Authorized to create topic if not logged in.', 
							edit_link=edit_link,
							edit_status=edit_status,
							edit_user_sep=edit_user_sep,
							wiki_user=wiki_user,
							login_link=login_link,
							login_status=login_status,
							login_signup_sep=login_signup_sep,
							signup_link=signup_link,
							signup_status=signup_status)
				self.response.set_status(401)
				self.render('unauthorized.html', **args)

	def post(self, name):
		# validate field
		content = self.request.get('content')

		# save into datastore and cache
		self.store(name, content)

		# redirect to entry permalink
		self.redirect(BASE_URL + name)

class Flush(Handler):
	def get(self):
		memcache.flush_all()

BASE_URL = '/wiki'
FRONT_URL = BASE_URL + '/'
BASE_EDIT = BASE_URL + '/_edit'
BASE_HIST = BASE_URL + '/_history'

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

routes = [
	(BASE_URL + '/signup/?', Signup),
	(BASE_URL + '/login/?', Login),
	(BASE_URL + '/logout/?', Logout),
	(BASE_URL + '/flush/?', Flush),
	(BASE_EDIT + PAGE_RE + '/', EditPage),
	(BASE_EDIT + PAGE_RE, EditPage),
	(BASE_HIST + PAGE_RE + '/', HistPage),
	(BASE_HIST + PAGE_RE, HistPage),
	(BASE_URL + PAGE_RE + '/', WikiPage),
	(BASE_URL + PAGE_RE, WikiPage)
]

app = webapp2.WSGIApplication(routes, debug=True)


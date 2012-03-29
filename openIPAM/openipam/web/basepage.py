import time

import cherrypy
from openipam.utilities import error
from openipam.utilities.perms import Perms
from openipam.config import frontend

import openipam.web.resource.utils

import framework
splash = framework.Splash()

# Import the XMLRPC Library for consuming the webservices
import xmlrpclib

from resource.xmlrpcclient import CookieAuthXMLRPCSafeTransport

DEFAULT_HOSTS_LIMIT = 100
DEFAULT_DNS_RECORDS_LIMIT = 50

perms = frontend.perms

class BasePage(object):
	_cp_config = {'tools.cgitb.on': True}

	def redirect(self, path):
		openipam.web.resource.utils.redirect(path)
	def __init__(self):
		"""Class constructor to create global objects"""
		
		if (frontend.xmlrpc_ssl_enabled):
			# Remember the trailing slash! /
			self.__url = 'https://%s:%s/api/' % (frontend.xmlrpc_host, frontend.xmlrpc_port)
		else:
			# Remember the trailing slash! /
			self.__url = 'http://%s:%s/api/' % (frontend.xmlrpc_host, frontend.xmlrpc_port)
			
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("")
		
	def __do_logout(self):
		cherrypy.session.acquire_lock()
		try:
			cherrypy.lib.sessions.expire() 
			cherrypy.session.delete()	

			if hasattr(cherrypy.session, 'username'):
				raise error.FatalException("Still have session username ... this shouldn't ever happen ... please tell the openIPAM developers about this error and the conditions under which it happened.")
		finally:
			cherrypy.session.release_lock()
			try:
				self.webservice.logout()
			except:
				pass
	#-----------------------------------------------------------------
	def has_min_perms(self, perms):
		cherrypy.session.acquire_lock()
		try:
			return Perms(perms) & cherrypy.session['min_permissions'] == perms
		finally:
			cherrypy.session.release_lock()

	def check_session(self, logging_in=False):
		"""Session checking for user management"""
		cherrypy.session.acquire_lock()

		try:
			if not cherrypy.session.has_key('transport'):
				cherrypy.session['transport'] = CookieAuthXMLRPCSafeTransport( ssl=frontend.xmlrpc_ssl_enabled )

			self.webservice = xmlrpclib.ServerProxy(self.__url, transport=cherrypy.session['transport'], allow_none=True)

			have_username = cherrypy.session.has_key('username')
		finally:
			cherrypy.session.release_lock()


		# FIXME: there has to be a better way...
		if not logging_in and not self.webservice.have_session():
			self.__do_logout()
			self.redirect("/login/?expired=true")

		if not logging_in and not have_username:
			self.redirect("/login")
	
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, **kw):
		"""The home page."""
		cherrypy.session.acquire_lock()
		try:
			if cherrypy.session.has_key('transport'):
				self.redirect("/hosts/")
			self.redirect("/login")
		finally:
			cherrypy.session.release_lock()

	@cherrypy.expose
	def default(self, *args, **kw):
		"""Page for handling 404, page not found."""
		
		# Confirm user authentication
		self.check_session()
	
		maincontent = '''<h1>Page not found</h1>
						The page you were looking for could not be found.
						'''
		return self.__template.wrap(maincontent)
	
	@cherrypy.expose
	def denied(self, *args, **kw):
		"""Redirect here for pages the person doesn't have access to view."""
		
		# Confirm user authentication
		self.check_session()
	
		maincontent = '''<h1>Forbidden</h1>
						You do not have permission to access this page.
						'''
		return self.__template.wrap(maincontent)

	def logged_in(self):
		cherrypy.session.acquire_lock()
		try:
			return cherrypy.session.has_key('user') and cherrypy.session['user']['username']
		finally:
			cherrypy.session.release_lock()
		return False

	@cherrypy.expose
	def login(self, username=None, password=None, expired=None, failed=None, logged_out=None, ne=None, email=None, referer=None, **kw):
		'''The login page'''
		
		self.check_session(logging_in=True)
		
		if self.logged_in():
			# They're already logged in
			self.redirect("/hosts")

		if referer is None and cherrypy.request.headers.has_key('Referer'):
			referer = cherrypy.request.headers['Referer']
		
		if not username and not password:
			content = '''
				<div id="login"><h1><a href="/" title="Powered by openIPAM" onfocus="this.blur()">openIPAM</a></h1>
					<form name="login" action="/login" method="post">'''
			if referer is not None:
				content += """
						<input type="hidden" name="referer" value="%s"/>""" % referer
			if failed is not None:
				content += '''
						<p>Invalid credentials.</p>'''
			if expired is not None:
				content += '''
						<p>For your security, your session has expired.</p>'''
			if ne is not None:
				content += '''
						<p>Sorry, you have not yet been authorized to use this system.</p>'''
			if email is not None:
				content += '''
						%s''' % frontend.email_required_html
			content += '''
						<p>
						<p>
							<label>Username:<br />
							<input type="text" name="username" id="username" class="text" value="" size="20" /></label>
						</p>
						<p>
							<label>Password:<br />
							<input type="password" name="password" class="text" value="" size="20" /></label>
						</p>
						<p class="submit">
							<input type="submit" value="Login &raquo;" />
						</p>
					</form>
				</div>
			'''
#						<ul>
#							<li><a href="?action=lostpassword">Lost your password?</a></li>
#						</ul>
			return splash.wrap(content)
		else:
			# Do Authentication
			# validate username and password
			cherrypy.session.acquire_lock()
			try:
				info = self.webservice.login(username, password)
				
				# set session variables
				cherrypy.session['uid'] = info['uid']
				cherrypy.session['username'] = info['username']
				cherrypy.session['name'] = info['name']
				cherrypy.session['min_permissions'] = info['min_permissions']
				cherrypy.session['has_global_owner'] = ((Perms(info['min_permissions']) & perms.OWNER) == perms.OWNER)
				cherrypy.session['show_expired_hosts'] = True
				cherrypy.session['show_all_hosts'] = True
				cherrypy.session['show_all_records'] = False
				cherrypy.session['show_a_records'] = False
				cherrypy.session['show_cnames'] = False
				cherrypy.session['show_ns'] = False
				cherrypy.session['hosts_limit'] = DEFAULT_HOSTS_LIMIT
				cherrypy.session['dns_records_limit'] = DEFAULT_DNS_RECORDS_LIMIT

				# redirect to main page
				if referer is not None and 'login' not in referer:
					self.redirect(referer)
				self.redirect('/')
			except Exception, e:
				error_string = error.parse_webservice_fault(e)
				if error_string == "InvalidCredentials":
					raise cherrypy.InternalRedirect('/login?failed=true')
				elif error_string == "NoEmail":
					raise cherrypy.InternalRedirect('/login?email=required')
				else:
					raise
			finally:
				cherrypy.session.save() # releases lock, it would appear
		
		raise error.FatalException()
	
	@cherrypy.expose
	def logout(self, **kw):
		"""User logout function to clear session"""
		
		self.__do_logout()
		
		self.redirect('/login')	


import time

import cherrypy
from openipam.utilities import error
from openipam.utilities.perms import Perms
from openipam.config import frontend

import framework
splash = framework.Splash()

# Import the XMLRPC Library for consuming the webservices
import xmlrpclib

from resource.xmlrpcclient import CookieAuthXMLRPCSafeTransport

DEFAULT_HOSTS_LIMIT = 100
DEFAULT_DNS_RECORDS_LIMIT = 400

perms = frontend.perms

class BasePage(object):
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

		cherrypy.lib.sessions.expire() 
		cherrypy.session.delete()	

		if hasattr(cherrypy.session, 'username'):
			raise error.FatalException("Still have session username ... this shouldn't ever happen ... please tell the openIPAM developers about this error and the conditions under which it happened.")

		try:
			self.webservice.logout()
		except:
			pass
	#-----------------------------------------------------------------

	def check_session(self, logging_in=False):
		"""Session checking for user management"""
		
		if not cherrypy.session.has_key('transport'):
			cherrypy.session['transport'] = CookieAuthXMLRPCSafeTransport( ssl=frontend.xmlrpc_ssl_enabled )

		self.webservice = xmlrpclib.ServerProxy(self.__url, transport=cherrypy.session['transport'], allow_none=True)

		if not logging_in and not self.webservice.have_session():
			self.__do_logout()
			raise cherrypy.HTTPRedirect("/login/?expired=true")

		if not logging_in and hasattr(cherrypy, 'session') and not cherrypy.session.has_key('username'):
			raise cherrypy.HTTPRedirect("/login")
	
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, **kw):
		"""The home page."""
		if cherrypy.session.has_key('transport'):
			raise cherrypy.HTTPRedirect("/hosts")
		raise cherrypy.HTTPRedirect("/login")

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

	@cherrypy.expose
	def login(self, username=None, password=None, expired=None, failed=None, logged_out=None, ne=None, **kw):
		'''The login page'''
		
		self.check_session(logging_in=True)
		
		if hasattr(cherrypy, 'session') and cherrypy.session.has_key('username'):
			# They're already logged in
			raise cherrypy.HTTPRedirect("/hosts")
		
		if not username and not password:
			content = '''
				<div id="login"><h1><a href="/" title="Powered by openIPAM" onfocus="this.blur()">openIPAM</a></h1>
					<form name="login" action="/login" method="post">'''
			if failed is not None:
				content += '''
						<p>Invalid credentials.</p>'''
			if expired is not None:
				
				content += '''
						<p>For your security, your session has expired.</p>'''
			if ne is not None:
				content += '''
						<p>Sorry, you have not yet been authorized to use this system.</p>'''
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
			try:
				info = self.webservice.login(username, password)
				
				# set session variables
				cherrypy.session['uid'] = info['uid']
				cherrypy.session['username'] = info['username']
				cherrypy.session['name'] = info['name']
				cherrypy.session['min_permissions'] = info['min_permissions']
				cherrypy.session['has_global_owner'] = ((Perms(info['min_permissions']) & perms.OWNER) == perms.OWNER)
				cherrypy.session['show_expired_hosts'] = False
				cherrypy.session['show_all_hosts'] = False
				cherrypy.session['show_all_records'] = False
				cherrypy.session['show_a_records'] = False
				cherrypy.session['show_cnames'] = False
				cherrypy.session['show_ns'] = False
				cherrypy.session['hosts_limit'] = DEFAULT_HOSTS_LIMIT
				cherrypy.session['dns_records_limit'] = DEFAULT_DNS_RECORDS_LIMIT
				cherrypy.session.save()

				# redirect to main page
				raise cherrypy.HTTPRedirect('/')
			except Exception, e:
				if error.parse_webservice_fault(e) == "InvalidCredentials":
					raise cherrypy.InternalRedirect('/login?failed=true')
				else:
					raise
		
		raise error.FatalException()
	
	@cherrypy.expose
	def logout(self, **kw):
		"""User logout function to clear session"""
		
		self.__do_logout()
		
		raise cherrypy.HTTPRedirect('/login')	


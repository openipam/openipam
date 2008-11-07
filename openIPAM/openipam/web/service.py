import cherrypy
import types

from basepage import BasePage

import datetime
import time

import framework
from openipam.web.resource.submenu import submenu

from openipam.config import frontend
from openipam.utilities import validation

import re

anumbercheck = re.compile('A[0-9]{8}')

#-------------------------------------------------------------------------------
# This entire page is mostly a hack to be able to get the Service Desk
# to be able to add users into the system that exist in LDAP, but haven't
# logged into openIPAM yet.
#
# This may have a place in openIPAM proper, but for now it is here.
#-------------------------------------------------------------------------------

class Service(BasePage):
	'''The service class. This includes all pages that are /service/*'''

	def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("")
		
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, **kw):
		"""The user management page"""

		# Confirm user authentication
		self.check_session()
		
		# Make sure this person is in the Service Desk group in order to do anything on this page
		# FIXME: need to get db_service_group... from backend
		group = self.webservice.get_users( { 'uid' : cherrypy.session['uid'], 'gid' : frontend.db_service_group_id } )
		if not group:
			raise cherrypy.HTTPRedirect('/denied')

		text = []
		
		text.append("<h1>Service</h1>")
		
		if kw.has_key('submit_user'):
			# DOING USER THING
			try:
				self.__add_user(username=kw['username'])
				text.append('''<div class="message"><div>
					Done!
				</div></div>''')
			except Exception, e:
				if type(e.message) is types.ListType:
					text.append('''<div class="message"><div>
					<strong>The following error occured:</strong>
					<ul>
					''')
					for msg in e.message:
						text.append('<li>%s</li>' % msg)
					text.append('</ul></div></div>')
				else:
					raise e
		
		text.append("""
		
		<h3>Add user from LDAP:</h3>
		<p>Use this form to add an A-Number that exists in LDAP but does not yet exist in<br />openIPAM because they have not logged in.</p>
		
		<form action="" method="post">
			<input type="text" name="username" value="" />
			
			<input type="submit" class="button" name="submit_user" value="Add User" />
		</form>
		
		""")
			
		
		return self.__template.wrap(''.join(text))
	
	def __add_user(self, username): 
		"""
		Add a user to the DB if they exist in LDAP
		"""
		
		messages = []
		
		user = self.webservice.get_users( { 'username' : username, 'source' : 2 })
		
		if not user:
			# The user doesn't exist in our database, so add them
			try:
				self.webservice.verify_ldap_user( { 'username' : username } )
				self.webservice.add_user( {
					'username' : username,
					'source' : 2,
					# FIXME: we should leave this empty and let the DB set it properly
					'min_perms' : frontend.db_default_min_permissions
				})
			except:
				messages.append("The specified user does not exist in LDAP")
				raise Exception(messages)
		else:
			messages.append("The user already exists in openIPAM.")
			raise Exception(messages)
	
	
	

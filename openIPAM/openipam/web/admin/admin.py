import cherrypy

from openipam.web import framework
from openipam.web.basepage import BasePage
from openipam.web.resource.submenu import submenu
from openipam.config import frontend

perms = frontend.perms

class Admin(BasePage):
	'''The users class. This includes all pages that are /admin/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	def __init__(self):
		BasePage.__init__(self)
		# Object for wrapping HTML into the template
		self._template = framework.Basics("admin", javascript=("/scripts/admin.js", '/scripts/jquery/jquery.dimensions.js', '/scripts/jquery/jquery.levitip.js'))
		
	# FIXME: is this really necessary?
	def check_session(self, logging_in=False):
		"""
		Overwrite the BasePage's check_session function to make sure 
		that this user is an admin ...
		"""

		# Call the base session checker
		BasePage.check_session(self, logging_in)
		
		if not self.have_perms(perms.DEITY):
			raise cherrypy.InternalRedirect("/denied")

		
	
	def leftnav_manage(self, current=None):
		'''Returns the html for admin management in the leftnav
		@param current: a string of the current selection'''

		selected = None
		counter = 0

		actions = ('Users', 'Groups', 'DHCP Groups', 'DHCP Options', 'DNS Resource Record Types', 'Custom Host Attributes', 'System Settings')
		action_links = ('/admin/users', '/admin/groups', '/admin/dhcp/groups', '/admin/dhcp/options', '/admin/dns', '/admin/attr/host', '/admin/sys')
		
		# Run through our actions list and highlight the currently selected action
		for action in actions:
			if action == current:
				selected = counter
			counter += 1
		
		return submenu(actions, action_links, "Manage", selected)
	
	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self):
		"""The admin management page"""

		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage())
		
		maincontent = '''<h1>Administration</h1>'''
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------
	

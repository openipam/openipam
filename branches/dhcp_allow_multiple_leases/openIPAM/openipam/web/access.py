import cherrypy

from basepage import BasePage

import framework
from openipam.web.resource.submenu import submenu
from openipam.config import frontend
perms = frontend.perms

class Access(BasePage):
	'''The access class. This includes all pages that are /access/*'''

	def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("access")
		
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------

	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self):
		"""The user management page"""

		# Confirm user authentication
		self.check_session()
		
		domains_text = []
		networks_text = []
		hosts_text = []
		
		domains = self.webservice.get_domains( { 'additional_perms' : str(perms.ADD) } )
		if not domains:
			domains_text.append("<p>You do not have access to add hosts in any domains.</p>")
		else:
			domains_text.append("<p>You have access to add hosts in the following domains:</p>")
		
			rows = []

			# The template HTML for every item
			item_template = '''<tr class="info">
								<td>%(name)s</td>
								<td>%(description)s</td>
							</tr>
							'''
			
			# Go through the query and make the table HTML using the template
			for domain in domains:
				rows.append(item_template % (domain))
			
			# Combine all the parts into the table
			domains_text.append('''
					<table class="infoTable">
						<thead>
							<tr>
								<th>Name</th>
								<th>Description</th>
							</tr>
						</thead>
						<tbody> 
						%s
						</tbody>
					</table>
					''' % ''.join(rows))
			
		networks = self.webservice.get_networks( { 'additional_perms' : str(perms.ADD) } )
		if not networks:
			networks_text.append("<p>You do not have access to add static IP addresses to any networks.</p>")
		else:
			networks_text.append("<p>You have access to add static IP addresses to these networks:</p>")

			rows = []

			# The template HTML for every item
			item_template = '''<tr class="info">
								<td>%(network)s</td>
								<td>%(name)s</td>
								<td>%(gateway)s</td>
								<td>%(description)s</td>
							</tr>
							'''
			
			# Go through the query and make the table HTML using the template
			for network in networks:
				rows.append(item_template % (network))
			
			# Combine all the parts into the table
			networks_text.append('''
					<table class="infoTable">
						<thead>
							<tr>
								<th>Network (CIDR)</th>
								<th>Name</th>
								<th>Gateway</th>
								<th>Description</th>
							</tr>
						</thead>
						<tbody> 
						%s
						</tbody>
					</table>
					''' % ''.join(rows))
			
		maincontent = '''
	
		<h1>My Access</h1>
		%s
		
		<h2>Domains</h2>
		%s
		
		<h2>Networks</h2>
		%s
		
		''' % (frontend.my_access_text, ''.join(domains_text), ''.join(networks_text))
		
		return self.__template.wrap(maincontent)
	
	#-----------------------------------------------------------------


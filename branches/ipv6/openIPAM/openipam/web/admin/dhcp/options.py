import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu

class AdminDHCPOptions(Admin):
	'''The admin DHCP class. This includes all pages that are /admin/dhcp/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	#-----------------------------------------------------------------

	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self):
		'''The DHCP options management page'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("DHCP Options"))
		
		# The template HTML for every item
		item_template = '''<tr class="info">
							<td>%(id)s</td>
							<td>%(size)s</td>
							<td>%(name)s</td>
							<td>%(option)s</td>
							<td>%(comment)s</td>
						</tr>
						'''
		
		# Get the DHCP resource record options from the database
		dhcp_options = self.webservice.get_dhcp_options()

		# Go through the query and make the table HTML using the template
		dhcp_options_html = ''
		for dhcp_option in dhcp_options:
			dhcp_options_html += item_template % (dhcp_option)
		
		# Combine all the parts into the table
		info = '''
				<table class="infoTable">
					<thead>
						<tr>
							<th>&nbsp;</th>
							<th>Size</th>
							<th>Name</th>
							<th>Option Name</th>
							<th>Comment</th>
						</tr>
					</thead>
					<tbody> 
					''' + dhcp_options_html + '''
					</tbody>
				</table>
				'''
		
		maincontent = '''<h1>DHCP Resource Records</h1>''' + info
		
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------
import cherrypy

from openipam.web.basepage import BasePage

import framework
from resource.submenu import submenu

from openipam.config import frontend
perms = frontend.perms

class Networks(BasePage):
	'''
	The networks class. This includes all pages that are /networks/*
	'''
	
	def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("networks")
	
	#-----------------------------------------------------------------
	
	def check_session(self, logging_in=False):
		"""
		Overwrite the BasePage's check_session function to make sure 
		that this user is an admin ...
		"""

		# Call the base session checker
		BasePage.check_session(self, logging_in)
		
		if cherrypy.session['min_permissions'] != perms.DEITY:
			raise cherrypy.InternalRedirect("/denied")

	def search_form(self):
	   html = '''
	   <div style="float: right; width: 300px;">
		  <form name="search" class="search" method="get" action="/hosts">
				<div class="submit">
				    <input type="text" class="text" style="width: 200px" value="" />
				    <input type="submit" value="Search" />
				</div>
		  </form>
	   </div>
	   '''
	   
	   return html
    
	def leftnav_actions(self, current=None):
	   '''
	   Returns the html for actions in the leftnav
	   @param current: a string of the current action
	   '''
	   
	   selected = None
	   counter = 0

	   actions = ('Add Network',)
	   action_links = ('/networks/add',)
	   
	   # Run through our actions list and highlight the currently selected action
	   for action in actions:
		  if action == current:
			 selected = counter
		  counter += 1
	   
	   return submenu(actions, action_links, "Actions", selected)

	def network_form(self, action_string="Add", nid=0):
	   '''
	   The group form for adding and editing networks
	   @param action: the POST action URL
	   @param action_string: "Add" by default, should be "Update" otherwise
	   @param gid: If updating, the DB group id. Gid is 0 if new record
	   '''
	   
	   network = {}
	   network['network'] = ""
	   network['name'] = ""
	   network['gateway'] = ""
	   network['description'] = ""
	   
	   # Get the network info from the database if editing
	   if nid:
		  network = self.webservice.get_networks({ 'nid' : nid })[0]
	   
	   # TODO: add DHCP groups
	   
	   form = '''<form action="/networks/process_network" method="post" class="form">
			 <div id="element">
				<div id="label">Network (CIDR)*:</div>
				<div id="value"><input type="text" class="text" name="network" value="''' + network['network'] + '''" /></div>
			 </div>
			 <div id="element">
				<div id="label">Name:</div>
				<div id="value"><input type="text" class="text" name="name" value="''' + network['name'] + '''" /></div>
			 </div>
			 <div id="element">
				<div id="label">Gateway:</div>
				<div id="value"><input type="text" class="text" name="gateway" value="''' + network['gateway'] + '''" /></div>
			 </div>
			 <div id="element">
				<div id="label">Pool for Addresses:</div>
				<div id="value">
					<select name="pool">
						'''
	   pools = self.webservice.get_pools()
		
	   for pool in pools:
	   	   form += '<option value="%(id)s">%(name)s</option>' % pool
		
	   form += '''
					</select>
				</div>
			 </div>
			 <div id="element">
				<div id="label">Description:</div>
				<div id="value"><textarea class="text" name="description" style="width: 350px;">''' + network['description'] + '''</textarea></div>
			 </div>
			 
			 <input type="hidden" name="nid" value="''' + str(nid) + '''" />
			 
			 <!--
			 <div class="submit">
				<input type="submit" class="button" value="''' + action_string + ''' Network">
			 </div>
			 -->
			 
		  </form>'''
		  
	   return form
    
	#-----------------------------------------------------------------
    
	@cherrypy.expose
	def index(self):
	   """
	   The networks page
	   """
	   
	   # Confirm user authentication
	   self.check_session()
	   
	   leftnav = str(self.leftnav_actions())
	   
	   # The template HTML for every entry
	   item_template = '''<tr class="info">
					   <td>%(network)s</td>
					   <td>%(name)s</td>
					   <td>%(gateway)s</td>
					   <td>%(description)s</td>
					   <td class="actions">
						  <a href="/networks/edit/?nid=%(network)s">Edit</a> |
						  <a href="/networks/del/?nid=%(network)s">Delete</a>
					   </td>
				    </tr>
				    '''
	   
	   # Get the DNS resource record types from the database
	   networks = self.webservice.get_networks( { 'order_by' : 'network' })
	   
	   # Go through the query and make the table HTML using the template
	   networks_html = ''
	   for network in networks:
		  mapping = {
				   "network" : network['network'],
				   "name" : network['name'],
				   "gateway" : network['gateway'],
				   "description" : network['description']
				   }
		  networks_html += item_template % (mapping)
	   
	   # Combine all the parts into the table
	   info = '''
			 <table class="infoTable">
				<thead>
				    <tr>
					   <th width="25%">Network (CIDR)</th>
					   <th>Name</th>
					   <th>Gateway</th>
					   <th>Description</th>
					   <th class="actions" style="width: 15%">&nbsp;</th>
				    </tr>
				</thead>
				<tbody>
				''' + networks_html + '''
				</tbody>
			 </table>
			 '''
	   
	   maincontent = '''<h1>Networks</h1><div class="message">Under construction.</div>''' + info
	   
	   return self.__template.wrap(maincontent, leftnav)
    
	@cherrypy.expose
	def add(self):
	   '''The form to add a network'''
	   
	   # Confirm user authentication
	   self.check_session()
	   
	   leftnav = str(self.leftnav_actions("Add Network"))
	   
	   maincontent = '<h1>Add Network</h1><div class="message">Under construction.</div>%s' % self.network_form()
	   
	   return self.__template.wrap(maincontent, leftnav)
    
	@cherrypy.expose
	def edit(self, nid):
	   '''The form to edit a network'''
	   
	   # Confirm user authentication
	   self.check_session()
	   
	   leftnav = str(self.leftnav_actions())
	   
	   maincontent = '<h1>Edit Network</h1>' + self.network_form("Update", nid)
	   
	   return self.__template.wrap(maincontent, leftnav)
    
	@cherrypy.expose
	def process_network(self, **kw):
	   '''Process the group add or edit form and do the DB transactions
	   @param kw: a dictionary containing name, description and nid (nid=0 if adding new record)
	   '''

	   if int(kw['nid']) == 0:
		  # We're adding a new group
		  try:
			 args = {
				    'network' : kw['network'],
				    'name' : kw['name'],
				    'gateway' : kw['gateway'],
				    'description' : kw['description']
				    }
			 self.webservice.add_network(args)
		  except:
			 raise
			 raise Exception("Could not add network.")
	   else:
		  # We're updating a group
		  try:
			 args = {
				    'nid' : kw['nid'],
				    'network' : kw['network'],
				    'name' : kw['name'],
				    'gateway' : kw['gateway'],
				    'description' : kw['description']
				    }
			 self.webservice.edit_network(args)
		  except:
			 raise Exception("Could not update network.")
		  
	   raise cherrypy.InternalRedirect("/networks")
    

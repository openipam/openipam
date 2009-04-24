import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu
from openipam.utilities import misc

class AdminGroups(Admin):
	'''The admin groups class. This includes all pages that are /admin/groups/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	def leftnav_group_actions(self, current=None):
		'''Returns the html for admin actions in the leftnav
		@param current: a string of the current action'''

		selected = None
		counter = 0

		actions = ('Add Group', )
		action_links = ('/admin/groups/add', )
		
		# Run through our actions list and highlight the currently selected action
		for action in actions:
			if action == current:
				selected = counter
			counter += 1
			
		return submenu(actions, action_links, "Actions", selected)
	
	#-----------------------------------------------------------------

	def leftnav_view_actions(self, gid, current=None):
		'''Returns the html for admin actions in the leftnav
		@param current: a string of the current action'''

		selected = None
		counter = 0

		actions = ('Add User to Group', 'Add Domain to Group', 'Add Network to Group', 'Add Host to Group')
		action_links = ('/admin/groups/user/add/%s' % gid, '/admin/groups/domain/add/%s' % gid, '/admin/groups/network/add/%s' % gid, '/admin/groups/host/add/%s' % gid)
		
		# Run through our actions list and highlight the currently selected action
		for action in actions:
			if action == current:
				selected = counter
			counter += 1
			
		return submenu(actions, action_links, "Actions", selected)
	
	#-----------------------------------------------------------------
	
	def group_form(self, action_string="Add", gid=0):
		'''The group form for adding and editing groups
		@param action: the POST action URL
		@param action_string: "Add" by default, should be "Update" otherwise
		@param gid: If updating, the DB group id. Gid is 0 if new record'''
		
		values = {}
		values['name'] = ""
		values['description'] = ""
		values['action'] = action_string
		values['id'] = gid
		
		# Get the group info from the database if editing
		if gid != 0:
			values = self.webservice.get_groups({ 'gid' : gid })[0]
			values['action'] = action_string
			
		form = '''<form action="/admin/groups/process_group_form" method="post" class="form">
				<div id="element">
					<div id="label">Group name*:</div>
					<div id="value"><input type="text" class="text" name="name" value="%(name)s" /></div>
				</div>
				<div id="element">
					<div id="label">Description:</div>
					<div id="value"><textarea class="text" name="description" style="width: 350px;">%(description)s</textarea></div>
				</div>
				
				<input type="hidden" name="gid" value="%(id)s" />
				
				<div class="submit">
					<input type="submit" class="button" value="%(action)s Group">
				</div>
				
			</form>''' % values
			
		return form
	
	#-----------------------------------------------------------------
	
	def get_users_table(self, gid):
		'''Returns the table HTML
		@param gid: the database group id:'''
		
		text = []
		
		# Query the database
		users = self.webservice.get_users({ 'gid' : gid })
		permissions = self.webservice.get_permissions( { 'make_dictionary' : True })

		if not users:
			return "<p>This group does not contain any users.</p>"

		# The template HTML for every item
		item_template = '''<tr class="info" id="user%(id)s">
						
							<td>%(username)s</td>
							<td>%(min_permissions)s</td>
							<td>%(group_permissions)s</td>
							<td class="actions">
								<a href="javascript:;" id="delUser%(id)s" onclick="confirmUserRemove(%(id)s); return false;">Remove</a>
							</td>
						</tr>
						'''
		
		# Go through the query and make the table HTML using the template
		for user in users:
			user['gid'] = gid
			user['min_permissions'] = permissions[str(user['min_permissions'])]['name']
			user['group_permissions'] = permissions[str(user['permissions'])]['name']
			text.append(item_template % (user))
		
		# Combine all the parts into the table
		users_html = '''
				<table class="infoTable">
					<thead>
						<tr>
							<th width="25%%">Username</th>
							<th width="140px">Minimum Permissions</th>
							<th width="140px">Group Permissions</th>
							<th>&nbsp;</th>
						</tr>
					</thead>
					<tbody> 
					%s
					</tbody>
				</table>
				''' % ''.join(text)
		return users_html
	
	#-----------------------------------------------------------------
	
	def get_domains_table(self, gid):
		'''Returns the table HTML
		@param gid: the database group id:'''

		text = []
		
		# Query the database
		domains = self.webservice.get_domains({ 'gid' : gid })
		permissions = self.webservice.get_permissions()

		if not domains:
			return "<p>This group does not contain any domains.</p>"

		# The template HTML for every item
		item_template = '''<tr class="info" id="domain%(id)s">
							<td>%(name)s</td>
							<td>%(description)s</td>
							<td class="actions">
								<a href="javascript:;" id="delDomain%(id)s" onclick="confirmDomainRemove(%(id)s); return false;">Remove</a>
							</td>
						</tr>
						'''
		
		# Go through the query and make the table HTML using the template
		table_html = ''
		for domain in domains:
			domain['gid'] = gid
			text.append(item_template % (domain))
		
		# Combine all the parts into the table
		domains_html = '''
				<table class="infoTable">
					<thead>
						<tr>
							<th width="25%%">Name</th>
							<th>Description</th>
							<th>&nbsp;</th>
						</tr>
					</thead>
					<tbody> 
					%s
					</tbody>
				</table>
				''' % ''.join(text)
		return domains_html
	
	#-----------------------------------------------------------------
	
	def get_networks_table(self, gid):
		'''Returns the table HTML
		@param gid: the database group id:'''

		text = []
		
		# Query the database
		networks = self.webservice.get_networks({ 'gid' : gid })
		
		if not len(networks):
			return "<p>This group does not contain any networks.</p>"

		# The template HTML for every item
		item_template = '''<tr class="info" id="network%(clean_network)s">
							<td>%(network)s</td>
							<td>%(name)s</td>
							<td>%(gateway)s</td>
							<td class="actions">
								<a href="javascript:;" id="delNetwork%(clean_network)s" onclick="confirmNetworkRemove('%(clean_network)s'); return false;">Remove</a>
							</td>
						</tr>
						'''
		
		# Go through the query and make the table HTML using the template
		for network in networks:
			network['gid'] = gid
			network['clean_network'] = misc.fix_cidr_network(network['network'])
			text.append(item_template % (network))
		
		# Combine all the parts into the table
		networks_html = '''
				<table class="infoTable">
					<thead>
						<tr>
							<th width="25%%">Network</th>
							<th>Name</th>
							<th>Gateway</th>
							<th>&nbsp;</th>
						</tr>
					</thead>
					<tbody> 
						%s
					</tbody>
				</table>
				''' % ''.join(text)
		return networks_html

	#-----------------------------------------------------------------
	
	def get_hosts_table(self, gid):
		'''Returns the table HTML
		@param gid: the database group id:'''
		
		text = []
		
		# Query the database
		hosts= self.webservice.get_hosts( { 'gid' : gid } )
		
		if not hosts:
			return "<p>This group does not contain any hosts.</p>"

		# The template HTML for every item
		item_template = '''<tr class="info" id="host%(clean_mac)s">
							<td>%(hostname)s</td>
							<td>%(mac)s</td>
							<td class="actions">
								<a href="javascript:;" id="delHost%(clean_mac)s" onclick="confirmHostRemove('%(clean_mac)s'); return false;">Remove</a>
							</td>
						</tr>
						'''
		
		# Go through the query and make the table HTML using the template
		for host in hosts:
			host['gid'] = gid
			host['clean_mac'] = misc.fix_mac(host['mac'])
			text.append(item_template % (host))
		
		# Combine all the parts into the table
		hosts_html = '''
				<table class="infoTable">
					<thead>
						<tr>
							<th width="25%%">Hostname</th>
							<th>Ethernet Address</th>
							<th>&nbsp;</th>
						</tr>
					</thead>
					<tbody> 
					%s
					</tbody>
				</table>
				''' % ''.join(text)
		return hosts_html
	
	#-----------------------------------------------------------------
	
	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, **kw):
		'''The groups management page'''
		
		# Confirm user authentication
		self.check_session()
		
		text = []
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_group_actions())
		
		# The template HTML for every entry
		item_template = '''<tr class="info" id="group%(id)s">
							<td><a href="/admin/groups/view/?gid=%(id)s">%(name)s</a></td>
							<td>%(description)s</td>
							<td class="actions">
								<a href="/admin/groups/edit/?gid=%(id)s">Edit</a> |
								<a href="/admin/groups/delete/?gid=%(id)s" id="del%(id)s" onclick="delGroupConfirm(%(id)s); return false;">Delete</a> |
								<a href="/admin/groups/view/?gid=%(id)s">Members</a>
							</td>
						</tr>
						'''
		
		# Get the DNS resource record types from the database
		args = {}
		if not kw.has_key('showug'):
			args = { 'ignore_usergroups' : True }
		
		groups = self.webservice.get_groups( args )

		# Go through the query and make the table HTML using the template
		for group in groups:
			text.append( item_template % (group) )
			
		groups_html = ''.join(text)
		
		text = []
		
		# Combine all the parts into the table
		text.append('<div style="float:right">')
		if kw.has_key('showug'):
			text.append('<a href="/admin/groups/">Hide default user groups</a></div>')
		else:
			text.append('<a href="/admin/groups/?showug=True">Show default user groups</a></div>')
		
		text.append('<h1>Groups</h1>')
			
		if not groups:
			text.append('No groups found.')
		else:
			text.append('''
					<table class="infoTable">
						<thead>
							<tr>
								<th width="25%%">Group Name</th>
								<th>Description</th>
								<th class="actions">&nbsp;</th>
							</tr>
						</thead>
						<tbody>
							%s
						</tbody>
					</table>
					''' % groups_html)
		
		return self._template.wrap(''.join(text), leftnav)
	
	#-----------------------------------------------------------------

	@cherrypy.expose
	def add(self):
		'''The form to add a group'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_group_actions("Add Group"))
		
		maincontent = '<h1>Add Group</h1>' + self.group_form()
		
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------

	@cherrypy.expose
	def edit(self, gid):
		'''The form to edit a group'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_group_actions())
		
		maincontent = '<h1>Edit Group</h1>' + self.group_form("Update", gid)
		
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------

	@cherrypy.expose
	def delete(self, gid):
		'''Delete a group'''
		
		# Confirm user authentication
		self.check_session()
		
		self.webservice.del_group(gid)
		
		raise cherrypy.InternalRedirect("/admin/groups")
	
	#-----------------------------------------------------------------

	@cherrypy.expose
	def process_group_form(self, **kw):
		'''Process the group add or edit form and do the DB transactions
		@param kw: a dictionary containing name, description and gid (gid=0 if adding new record)
		'''
		
		# Confirm user authentication
		self.check_session()

		if int(kw['gid']) == 0:
			# We're adding a new group
			self.webservice.add_group({ 'name' : kw['name'], 'description' : kw['description']})
		else:
			# We're updating a group
			self.webservice.edit_group( { 'gid' : kw['gid'], 'name' : kw['name'], 'description' : kw['description']})
			
		raise cherrypy.InternalRedirect("/admin/groups")
	
	#-----------------------------------------------------------------
		
	@cherrypy.expose
	def view(self, gid):
		'''View the members and permissions of a group
		@param gid: the group id'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))
		
		# Query the database
		group = self.webservice.get_groups({ 'gid' : gid })[0]
		
		# Generate all the tables for this group's members
		maincontent = '<h1>' + group['name'] + '</h1><input type="hidden" id="gid" value="%s" />' % gid
		maincontent += '<h2>Users</h2>' + self.get_users_table(gid)
		maincontent += '<h2>Domains</h2>' + self.get_domains_table(gid)
		maincontent += '<h2>Networks</h2>' + self.get_networks_table(gid)
		maincontent += '<h2>Hosts</h2>' + self.get_hosts_table(gid)
		
		return self._template.wrap(maincontent, leftnav)
		
	#-----------------------------------------------------------------

	@cherrypy.expose
	def permissions(self, gid, did=None, nid=None, hid=None):
		'''Edit the permissions of a domain, network, or host in a group
		@param did: the database domain id
		@param nid: the database network id
		@param hid: the database host id
		@param gid: the database group id'''
		
		# Confirm user authentication
		self.check_session()
		
		if (did and nid) or (did and hid) or (nid and hid):
			raise Exception("Permissions can only be changed on one item type.")
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))

	#-----------------------------------------------------------------
		
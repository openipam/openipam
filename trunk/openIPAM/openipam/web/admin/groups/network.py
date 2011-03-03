import cherrypy
import re

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin
from openipam.web.admin.groups.groups import AdminGroups
from openipam.web.resource.submenu import submenu
from openipam.utilities import error, misc

class AdminGroupsNetwork(AdminGroups):
	'''All pages that are /admin/groups/network/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	def __init__(self):
		Admin.__init__(self)
		
	#-----------------------------------------------------------------

	def get_results_table(self, search, gid):
		'''Returns the table of search results'''
		
		rows = []
		
		networks = ''
		if len(search):
			try:
				networks = self.webservice.get_networks({ 'network' : search, 'exact': False })
			except Exception, e:
				err = error.parse_webservice_fault(e)
				if err == 'InvalidCIDRNetwork':
					return '<div class="message"><div>Invalid network specified. Please search using a full CIDR network descriptor.</div></div>'
				else:
					raise
			used_networks_temp = self.webservice.get_networks({ 'gid' : gid })
			
			# Put all used network names into a list for comparison
			used_networks = []
			for network in used_networks_temp:
				used_networks.append(network['network'])
			
		if not networks:
			return '<p class="noResults">No networks found.</p>'
		else:
			# The template HTML for every entry
			# If you change the <span id="add#"> below, be sure to update the regex in the table compliation below
			item_template = '''<tr class="info" id="network%(id)s">
								<td>%(network)s</td>
								<td>%(name)s</td>
								<td>%(gateway)s</td>
								<td class="actions">
									<span id="add%(id)s">
										<a href="javascript:;" id="addLink%(id)s" onclick="addNetworkToGroup('%(id)s'); return false;">Add to group</a>
									</span>
								</td>
							</tr>
							'''
			
			# Go through the query and make the table HTML using the template
			for item in networks:
				item['id'] = misc.fix_cidr_network(item['network'])
				
				if item['network'] in used_networks:
					# This network already belongs to this group, so don't allow the user to select it (ie. remove the span containing the links)
					# FIXME: this regex could be better ... 
					regex = re.compile('(<span).*?(<\\/span>)', re.IGNORECASE|re.DOTALL)
					rows.append(regex.sub('Already in group', (item_template % (item))))
				else:
					# This network doesn't belong to this group yet, so keep all the normal links
					rows.append(item_template % (item))
			
			# Combine all the parts into the table
			info = '''<input type="hidden" id="gid" value="%s" />
					<table class="infoTable">
						<thead>
							<tr>
								<th width="25%%">Network</th>
								<th>Name</th>
								<th>Gateway</th>
								<th class="actions">&nbsp;</th>
							</tr>
						</thead>
						<tbody>
						%s
						</tbody>
					</table>
					''' % (gid, ''.join(rows))
					
			return info

	#-----------------------------------------------------------------
	
	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def add(self, gid, search='', nid=None):
		'''The form for adding a network to a group'''
		
		# Confirm user authentication
		self.check_session()
		
		
		# If given a network, show the add_network form
		if nid:
			return self.add_network(nid, gid)
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add Network to Group"))
		
		# Query the database
		group = self.webservice.get_groups({ 'gid' : gid })[0]
		values = group
		values['search'] = search
		
		maincontent = '''<h1>Add Network to Group: <a href="/admin/groups/view/%(id)s">%(name)s</a></h1>
					<form action="/admin/groups/network/add/%(id)s" method="get" class="form">
						<div id="element">
							<div id="label">Find network:</div>
							<div id="value"><input type="text" id="search" class="text" name="search" value="%(search)s"/><input type="submit" class="button" value="Search"></div>
						</div>
					</form>
					''' % values
		if search:
			maincontent += self.get_results_table(search, gid)
			
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def add_network(self, nid, gid):
#		'''Display the form for adding a network to a group (for JavaScript degradation)'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add Network to Group"))
#		
#		# Query the database
#		network = self.webservice.get_networks({ 'nid' : nid })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		(permission_types, permission_ids) = self.webservice.get_permission_types()
#		
#		maincontent = '<h1>Add Network to Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/network/add_network_post/?nid=''' + str(nid) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">Network:</div>
#					<div id="value">''' + network['name'] + '''</div>
#					<div id="label">Permissions:</div>
#					<div id="value">
#						 <select class="text" name="pid">'''
#		
#		for id in permission_ids:
#			maincontent += '<option value="%s">%s</option>' % (permission_types[id]['id'], permission_types[id]['name'])
#			 
#		maincontent +=	 '''
#						 </select>
#					</div>
#
#					<div class="submit">
#						<input type="submit" class="button" value="Add Network to Group">
#					</div>
#					
#				</div>
#			</form>
#			'''
#		
#		return self._template.wrap(maincontent, leftnav)
#	
#	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def add_network_post(self, nid, gid, pid):
#		'''Add the given network to the group and redirect (for JavaScript degradation)
#		@param nid: the database network ID
#		@param gid: the database group ID
#		@param search: a search query string'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.add_network_to_group(nid, gid, pid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#	
#	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def delete(self, nid, gid):
#		'''Remove a network from a group
#		@param nid: the database network ID
#		@param gid: the database group ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.del_network_from_group(nid, gid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#		
#	#-----------------------------------------------------------------
#	
#	@cherrypy.expose
#	def permissions(self, gid, nid):
#		'''Edit permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param nid: the database network ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))
#		
#		# Query the database
#		network = self.webservice.get_networks({ 'nid' : nid })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		(permission_types, permission_ids) = self.webservice.get_permission_types()
#		
#		maincontent = '<h1>Edit Network in Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/network/permissions_post/?nid=''' + str(nid) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">Network:</div>
#					<div id="value">''' + network['name'] + '''</div>
#					<div id="label">Permissions:</div>
#					<div id="value">
#						 <select class="text" name="pid">'''
#		
#		for id in permission_ids:
#			maincontent += '<option value="%s">%s</option>' % (permission_types[id]['id'], permission_types[id]['name'])
#			 
#		maincontent +=	 '''
#						 </select>
#					</div>
#
#					<div class="submit">
#						<input type="submit" class="button" value="Update Permissions">
#					</div>
#					
#				</div>
#			</form>
#			'''
#		
#		return self._template.wrap(maincontent, leftnav)
#		
#	#-----------------------------------------------------------------
#	
#	@cherrypy.expose
#	def permissions_post(self, gid, nid, pid):
#		'''The form has been POSTed. Update the permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param nid: the database network ID
#		@param pid: the database permission ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.set_permissions(gid, pid, nid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#	

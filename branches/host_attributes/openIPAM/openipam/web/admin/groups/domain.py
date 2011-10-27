import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin
from openipam.web.admin.groups.groups import AdminGroups
from openipam.web.resource.submenu import submenu

import re

class AdminGroupsDomain(AdminGroups):
	'''All pages that are /admin/groups/domain/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	def __init__(self):
		Admin.__init__(self)
		
	#-----------------------------------------------------------------

	def get_results_table(self, search, gid):
		'''Returns the table of search results'''
		
		rows = []
		domains = ''
		
		if len(search):
			domains = self.webservice.get_domains({ 'name' : '%%%s%%' % search })
			used_domains_temp = self.webservice.get_domains({ 'gid' : gid })
			
			# Put all used domain names into a list for comparison
			used_domains = []
			for domain in used_domains_temp:
				used_domains.append(domain['name'])
			
		if not domains:
			return '<p class="noResults">No domains found.</p>'
		else:
			# The jQuery to make an Ajax request for adding to a group
			jquery = '''<script type="text/javascript">


						</script>
						'''
			
			# The template HTML for every entry
			# If you change the <span id="add#"> below, be sure to update the regex in the table compliation below
			item_template = '''<tr class="info" id="domain%(id)s">
								<td>%(name)s</td>
								<td>%(description)s</td>
								<td class="actions">
									<span id="add%(id)s">
										<a href="javascript:;" id="addLink%(id)s" onclick="addDomainToGroup(%(id)s); return false;">Add to group</a>
									</span>
								</td>
							</tr>
							'''
			
			# Go through the query and make the table HTML using the template
			for item in domains:
				if item['name'] in used_domains:
					# This domain already belongs to this group, so don't allow the user to select it (ie. remove the span containing the links)
					# FIXME: this regex could be better ... 
					regex = re.compile('(<span).*?(<\\/span>)', re.IGNORECASE|re.DOTALL)
					
					rows.append(regex.sub('Already in group', (item_template % (item))))
				else:
					# This domain doesn't belong to this group yet, so keep all the normal links
					rows.append(item_template % (item))
			
			# Combine all the parts into the table
			info = '''<input type="hidden" id="gid" value="%s" />
					<table class="infoTable">
						<thead>
							<tr>
								<th width="25%%">Domain Name</th>
								<th>Description</th>
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
	def add(self, gid, search='', did=None):
		'''The form for adding a domain to a group'''
		
		# Confirm user authentication
		self.check_session()
		
		# If given a domain, show the add_domain form
		if did:
			return self.add_domain(did, gid)
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add Domain to Group"))
		
		# Query the database
		group = self.webservice.get_groups({ 'gid' : gid })[0]
		values = group
		values['search'] = search
		
		maincontent = '''<h1>Add Domain to Group: <a href="/admin/groups/view/%(id)s">%(name)s</a></h1>
					<form action="/admin/groups/domain/add/%(id)s" method="get" class="form">
						<div id="element">
							<div id="label">Find domain:</div>
							<div id="value"><input type="text" id="search" class="text" name="search" value="%(search)s"/><input type="submit" class="button" value="Search"></div>
						</div>
					</form>
					''' % values
		
		if search:
			maincontent += self.get_results_table(search, gid)
			
		return self._template.wrap(maincontent, leftnav)
	
#	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def add_domain(self, did, gid):
#		'''Display the form for adding a domain to a group (for JavaScript degradation)'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add Domain to Group"))
#		
#		# Query the database
#		domain = self.webservice.get_domains({ 'did' : did })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		(permission_types, permission_ids) = self.webservice.get_permission_types()
#		
#		maincontent = '<h1>Add Domain to Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/domain/add_domain_post/?did=''' + str(did) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">Domain:</div>
#					<div id="value">''' + domain['name'] + '''</div>
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
#						<input type="submit" class="button" value="Add Domain to Group">
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
#	def add_domain_post(self, did, gid, pid):
#		'''Add the given domain to the group and redirect (for JavaScript degradation)
#		@param did: the database domain ID
#		@param gid: the database group ID
#		@param search: a search query string'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.add_domain_to_group(did, gid, pid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#	
#	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def delete(self, did, gid):
#		'''Remove a domain from a group
#		@param did: the database domain ID
#		@param gid: the database group ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.del_domain_from_group(did, gid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#		
#	#-----------------------------------------------------------------
#	
#	@cherrypy.expose
#	def permissions(self, gid, did):
#		'''Edit permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param did: the database domain ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))
#		
#		# Query the database
#		domain = self.webservice.get_domains({ 'did' : did })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		(permission_types, permission_ids) = self.webservice.get_permission_types()
#		
#		maincontent = '<h1>Edit Domain in Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/domain/permissions_post/?did=''' + str(did) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">Domain:</div>
#					<div id="value">''' + domain['name'] + '''</div>
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
#	def permissions_post(self, gid, did, pid):
#		'''The form has been POSTed. Update the permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param did: the database domain ID
#		@param pid: the database permission ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.set_permissions(gid, pid, did)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
	

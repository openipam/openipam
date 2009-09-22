import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin
from openipam.web.admin.groups.groups import AdminGroups

from openipam.web.resource.submenu import submenu
from openipam.config import frontend
import re

class AdminGroupsUser(AdminGroups):
	'''All pages that are /admin/groups/user/*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	def __init__(self):
		Admin.__init__(self)
		
	#-----------------------------------------------------------------

	def get_results_table(self, search, gid):
		'''Returns the table of search results'''
		
		users = ''
		rows = []
		
		if len(search):
			users = self.webservice.get_users({ 'username' : '%%%s%%' % search })
			used_users_temp = self.webservice.get_users({ 'gid' : gid, 'username' : '%%%s%%' % search })
			
			# Put all used user names into a list for comparison
			used_users = []
			for user in used_users_temp:
				used_users.append(user['username'])
			
		if not users:
			return '<p class="noResults">No users found.</p>'
		else:
			permissions = self.webservice.get_permissions()
			
			# The template HTML for every entry
			# If you change the <span id="add#"> below, be sure to update the regex in the table compliation below
			item_template = '''<tr class="info" id="user%(id)s">
								<td>%(username)s</td>
								<td class="actions">
									<span id="add%(id)s">
										<a href="javascript:;" id="addLink%(id)s" onclick="addUserToGroup(%(id)s, '%(permission_id)s'); return false;">Add to group</a>
										with <a href="javascript:;" name="%(id)s" class="permissionsChange">%(permission_name)s</a> permissions
									</span>
			 	   	   	   	   	   <div id="overlayPicker">
										<ul>
											'''
			for permission in permissions:
				item_template +=	'			<li><a href="javascript:;" onclick="changePermissions(%%(id)s, \'%(name)s\', \'%(id)s\');">%(name)s</a></li>' % { 'id' : permission['id'], 'name' : permission['name'] }
				
			item_template += '''			</ul>
									</div>
								</td>
							</tr>
							'''
			
			# Go through the query and make the table HTML using the template
			for permission in permissions:
				# FIXME: why is this needed?  can we get it from the backend?
				if permission['id'] == frontend.db_default_group_permissions:
					perm = permission
				
			for item in users:
				item['gid'] = gid
				item['permission_name'] = perm['name']
				item['permission_id'] = perm['id']
				
				if item['username'] in used_users:
					# This user already belongs to this group, so don't allow the user to select it (ie. remove the span containing the links)
					# FIXME: this regex could be better ... 
					regex = re.compile('(<span).*?(<\\/span>)', re.IGNORECASE|re.DOTALL)
					rows.append(regex.sub('Already in group', (item_template % (item))))
				else:
					# This user doesn't belong to this group yet, so keep all the normal links
					
					# FIXME: allow users to be added to a group with different than default ADD permissions
					rows.append(item_template % (item))
			
			# Combine all the parts into the table
			text = '''<input type="hidden" id="gid" value="%s" />
			
					<table class="infoTable">
						<thead>
							<tr>
								<th width="25%%">Username</th>
								<th class="actions">&nbsp;</th>
							</tr>
						</thead>
						<tbody>
						%s
						</tbody>
					</table>
					''' % (gid, ''.join(rows))
			
			return text

	#-----------------------------------------------------------------
	
	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def add(self, gid, search='', uid=None):
		'''The form for adding a user to a group'''
		
		# Confirm user authentication
		self.check_session()
		
		text = []
		
		# If given a user, show the add_user form
		if uid:
			return self.add_user(uid, gid)
		
		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add User to Group"))
		
		# Query the database
		group = self.webservice.get_groups({ 'gid' : gid })[0]
		values = group
		values['search'] = search
		
		text.append('''<h1>Add User to Group: <a href="/admin/groups/view/%(id)s">%(name)s</a></h1>
					<form action="/admin/groups/user/add/%(id)s" method="get" class="form">
						<div id="element">
							<div id="label">Find user:</div>
							<div id="value"><input type="text" id="search" class="text" name="search" value="%(search)s"/><input type="submit" class="button" value="Search"></div>
						</div>
					</form>
					''' % values)
		
		if search:
			text.append(self.get_results_table(search, gid))
			
		return self._template.wrap(''.join(text), leftnav)
	
	#-----------------------------------------------------------------

#	@cherrypy.expose
#	def add_user(self, uid, gid):
#		'''Display the form for adding a user to a group (for JavaScript degradation)'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add User to Group"))
#		
#		# Query the database
#		user = self.webservice.get_users({ 'uid' : uid })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		permissions = self.webservice.get_permissions()
#		
#		maincontent = '<h1>Add User to Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/user/add_user_post/?uid=''' + str(uid) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">User:</div>
#					<div id="value">''' + user['name'] + '''</div>
#					<div id="label">Group Permissions:</div>
#					<div id="value">
#						 <select class="text" name="pid">'''
#		
#		for perm in permissions:
#			maincontent += '<option value="%s">%s</option>' % (permissions[id]['id'], permission_types[id]['name'])
#			 
#		maincontent +=	 '''
#						 </select>
#					</div>
#
#					<div class="submit">
#						<input type="submit" class="button" value="Add User to Group">
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
#	def add_user(self, uid, gid, pid):
#		'''Add the given user to the group and redirect (for JavaScript degradation)
#		@param uid: the database user ID
#		@param gid: the database group ID
#		@param search: a search query string'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.add_user_to_group(uid, gid, pid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#	
#	#-----------------------------------------------------------------
#
#	@cherrypy.expose
#	def delete(self, uid, gid):
#		'''Remove a user from a group
#		@param uid: the database user ID
#		@param gid: the database group ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.del_user_from_group(uid, gid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#		
#	#-----------------------------------------------------------------
#	
#	@cherrypy.expose
#	def permissions(self, gid, uid):
#		'''Edit permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param uid: the database user ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))
#		
#		# Query the database
#		user = self.webservice.get_users({ 'uid' : uid })[0]
#		group = self.webservice.get_groups({ 'gid' : gid })[0]
#		permissions = self.webservice.get_permission_types()
#		
#		maincontent = '<h1>Edit User in Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
#				'''
#			<form action="/admin/groups/user/permissions_post/?uid=''' + str(uid) + \
#			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
#				<div id="element">
#					<div id="label">User:</div>
#					<div id="value">''' + user['name'] + '''</div>
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
#	def permissions_post(self, gid, uid, pid):
#		'''The form has been POSTed. Update the permissions for a group member (for JavaScript degradation)
#		@param gid: the database group ID
#		@param uid: the database user ID
#		@param pid: the database permission ID'''
#		
#		# Confirm user authentication
#		self.check_session()
#		
#		self.webservice.set_permissions(gid, pid, uid)
#		
#		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
	

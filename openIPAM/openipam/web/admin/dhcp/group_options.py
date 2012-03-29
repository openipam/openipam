import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.dhcp.groups import AdminDHCPGroups

from openipam.web.resource.submenu import submenu

class AdminDHCPGroupOptions(AdminDHCPGroups):
	'''The admin DHCP class. This includes all pages that are /admin/dhcp/group/#*'''
	
	#-----------------------------------------------------------------
	#					  PUBLISHED FUNCTIONS
	#-----------------------------------------------------------------
	
	def __init__(self):
		AdminDHCPGroups.__init__(self)
	
	#-----------------------------------------------------------------

	def leftnav_option_actions(self, gid, current=None):
		'''Returns the html for admin actions in the leftnav
		@param current: a string of the current action'''

		selected = None
		counter = 0

		actions = ('Add DHCP Option to Group', )
		action_links = ('/admin/dhcp/groups/options/add/'+gid,)
		
		# Run through our actions list and highlight the currently selected action
		for action in actions:
			if action == current:
				selected = counter
			counter += 1
			
		return submenu(actions, action_links, "Actions", selected)

	#-----------------------------------------------------------------
	
	def get_options_table(self, gid):
		'''Returns the table HTML
		@param gid: the database group id:'''
		
		# Query the database
		(options, relations) = self.webservice.get_dhcp_options({ 'gid' : gid })

		if not len(options):
			return "<p>This group does not contain any DHCP options.</p>"

		# The jQuery to make an Ajax request for delete
		jquery = '''<script type="text/javascript">
						function confirmOptionRemove( rid ){
							$("#delOption" + rid)
								.after('<span id="confirm'+rid+'">Are you sure? <a href="" onclick="removeOption('+rid+', '''+str(gid)+'''); return false;">Yes</a> / <a href="" onclick="restoreOptionRemove('+rid+'); return false;">No</a></span>')
								.hide(); 
						};
						
						function restoreOptionRemove( rid ) {
							$("#option"+rid+" #confirm"+rid).remove();
							$("#delOption"+rid).show();
						};
						
						function removeOption( rid ){
							$.ajax({
								type: "GET",
								url: "/ajax/ajax_del_dhcp_option_from_group/?oid="+rid+"&gid='''+str(gid)+'''",
								success: function() {
										$("#option" + rid).remove();
									}
							});
						};
					</script>
					'''

		# The template HTML for every item
		item_template = '''<tr class="info" id="option%(rid)s">
							<td>%(name)s</td>
							<td>%(option)s</td>
							<td>%(value)s</td>
							<td class="actions">
								<a href="/admin/dhcp/groups/options/edit/?rid=%(rid)s&gid=''' + str(gid) + '''">Edit</a> | 
								<a href="/admin/dhcp/groups/options/remove/?rid=%(rid)s&gid=''' + str(gid) + '''" id="delOption%(rid)s" onclick="confirmOptionRemove(%(rid)s); return false;">Remove</a>
							</td>
						</tr>
						'''
		
		# Go through the query and make the table HTML using the template
		table_html = ''
		for i in range(0, len(options)):
			item = {
				'rid' : relations[i]['id'],
				'name' : options[i]['name'],
				'option' : options[i]['option'],
				'value' : relations[i]['value']
				}
			table_html += item_template % (item)
		table_html += jquery
		
		# Combine all the parts into the table
		options_html = '''
				<table class="infoTable" id="option%(id)s">
					<thead>
						<tr>
							<th style="width: 15%">Name</th>
							<th>Option Name</th>
							<th>Value</th>
							<th width="20%">&nbsp;</th>
						</tr>
					</thead>
					<tbody> 
					''' + table_html + '''
					</tbody>
				</table>
				'''
		return options_html
	
	#-----------------------------------------------------------------
		
	def option_form(self, gid, action_string="Add", rid=0):
		'''The group form for adding and editing DHCP options within a group
		@param action: the POST action URL
		@param action_string: "Add" by default, should be "Update" otherwise
		@param gid: If updating, the DB group id. gid is 0 if new record
		@param rid: If updating, the DB relation id (NOT the option's ID, because gid+oid is not unique in this table).'''
		
		option = {}
		option['name'] = ""
		option['option'] = ""
		option['value'] = ""
		
		options = self.webservice.get_dhcp_options()
		
		# Get the group info from the database if editing
		if rid:
			option = self.webservice.get_dhcp_group_options({ 'gid' : gid, 'rid' : rid })[0]
			
		form = '''<form action="/admin/dhcp/groups/options/process_option_form" method="post" class="form">
				<div id="element">
					<div id="label">DHCP option:</div>
					<div id="value">
						<select name="oid">
						'''
		# TODO: sort the options before displaying
		for anOption in options:
			# Awesomeness ... if you're trying to comprehend this, it's like faith ... sometimes you just have to jump
			form += '<option value="' + str(anOption['id']) + '"'+((option['oid'] == anOption['id']) and ' selected=""' or "",)[0]+'>' + anOption['name'] + '</option>' 
					
		form +=   '''</select>
					</div>
				</div>
				<div id="element">
					<div id="label">Value:</div>
					<div id="value"><input class="text" name="value" value="''' + option['value'] + '''" /></div>
				</div>
				
				<input type="hidden" name="gid" value="''' + str(gid) + '''" />
				<input type="hidden" name="rid" value="''' + str(rid) + '''" />
				
				<div class="submit">
					<input type="submit" class="button" value="''' + action_string + ''' Group">
				</div>
				
			</form>'''
			
		return form
	
	#-----------------------------------------------------------------

	#-----------------------------------------------------------------
	#						EXPOSED FUNCTIONS
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, gid):
		'''The DHCP options management page for a specific option in a group'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("DHCP Groups")) + str(self.leftnav_option_actions(gid))
		group = self.webservice.get_dhcp_groups({ 'gid' : gid })[0]
		
		maincontent = '<h1>' + group['name'] + ' DHCP Options</h1>' + self.get_options_table(gid)
		
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def add(self, gid=None):
		'''The form to add an option to a group'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("DHCP Groups")) + str(self.leftnav_option_actions(gid, 'Add DHCP Option to Group'))
		
		maincontent = '<h1>Add DHCP Option to Group</h1>' + self.option_form(gid=gid)
		
		return self._template.wrap(maincontent, leftnav)
		
	#-----------------------------------------------------------------

	@cherrypy.expose
	def process_option_form(self, oid, gid, value, rid=0):
		'''Add the given option & value to the group and redirect
		@param gid: the database option ID
		@param oid: the database group ID
		@param value: the DHCP option value
		@param rid: the database relation ID (0 if adding new relation)'''
		
		# Confirm user authentication
		self.check_session()
		
		if rid:
			self.webservice.edit_dhcp_option_in_group({ 'rid' : rid, 'oid' : oid, 'value' : value })
		else:
			self.webservice.add_dhcp_option_to_group({ 'oid' : oid, 'gid' : gid, 'value' : value })
		
		self.redirect("/admin/dhcp/groups/options/?gid="+str(gid))
	
	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def delete(self, gid):
		'''Delete a DHCP option from a group'''
		
		# Confirm user authentication
		self.check_session()
		
		self.webservice.del_dhcp_option_from_group(gid)
		
		raise cherrypy.InternalRedirect("/admin/dhcp/groups/options/?gid="+str(gid))
	
	#-----------------------------------------------------------------

	@cherrypy.expose
	def edit(self, rid, gid):
		'''The form to edit an option in group'''
		
		# Confirm user authentication
		self.check_session()
		
		leftnav = str(self.leftnav_manage("DHCP Groups")) + str(self.leftnav_group_actions())
		
		maincontent = '<h1>Edit Option in Group</h1>' + self.option_form(gid, "Update", rid)
		
		return self._template.wrap(maincontent, leftnav)
	
	#-----------------------------------------------------------------













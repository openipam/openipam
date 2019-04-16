import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu
from openipam.utilities import misc


class AdminDHCPGroups(Admin):
    """The admin groups class. This includes all pages that are /admin/dhcp/groups/*"""

    # -----------------------------------------------------------------
    # 					  PUBLISHED FUNCTIONS
    # -----------------------------------------------------------------

    def leftnav_group_actions(self, current=None):
        """Returns the html for admin actions in the leftnav
		@param current: a string of the current action"""

        selected = None
        counter = 0

        actions = ("Add DHCP Group",)
        action_links = ("/admin/dhcp/groups/add",)

        # Run through our actions list and highlight the currently selected action
        for action in actions:
            if action == current:
                selected = counter
            counter += 1

        return submenu(actions, action_links, "Actions", selected)

        # -----------------------------------------------------------------

    def group_form(self, action_string="Add", gid=0):
        """The group form for adding and editing groups
		@param action: the POST action URL
		@param action_string: "Add" by default, should be "Update" otherwise
		@param gid: If updating, the DB group id. Gid is 0 if new record"""

        group = {}
        group["name"] = ""
        group["description"] = ""

        # Get the group info from the database if editing
        if gid != 0:
            group = self.webservice.get_dhcp_groups({"gid": gid})[0]

        form = (
            '''<form action="/admin/dhcp/groups/process_group_form" method="post" class="form">
				<div id="element">
					<div id="label">DHCP group name*:</div>
					<div id="value"><input type="text" class="text" name="name" value="'''
            + group["name"]
            + """" /></div>
				</div>
				<div id="element">
					<div id="label">Description:</div>
					<div id="value"><textarea class="text" name="description" style="width: 350px;">"""
            + group["description"]
            + '''</textarea></div>
				</div>
				
				<input type="hidden" name="gid" value="'''
            + str(gid)
            + '''" />
				
				<div class="submit">
					<input type="submit" class="button" value="'''
            + action_string
            + """ Group">
				</div>
				
			</form>"""
        )

        return form

        # -----------------------------------------------------------------

        # -----------------------------------------------------------------
        # 						EXPOSED FUNCTIONS
        # -----------------------------------------------------------------

    @cherrypy.expose
    def index(self):
        """The groups management page"""

        # Confirm user authentication
        self.check_session()

        leftnav = str(self.leftnav_manage("DHCP Groups")) + str(
            self.leftnav_group_actions()
        )

        # The jQuery to make an Ajax request for delete
        jquery = """<script type="text/javascript">
						function delGroupConfirm( gid ){
							$("#del" + gid)
								.after('<span id="confirm'+gid+'">Are you sure? <a href="javascript:;" onclick="delGroup('+gid+'); return false;">Yes</a> / <a href="javascript:;" onclick="restoreDelGroup('+gid+');">No</a></span>')
								.hide(); 
						};
						
						function restoreDelGroup( gid ) {
							$("#confirm"+gid).remove();
							$("#del"+gid).show();
						};
						
						function delGroup( gid ){
							$.ajax({
								type: "GET",
								url: "/ajax/ajax_del_dhcp_group/?gid="+gid,
								success: function() {
										$("#group" + gid).remove();
									}
							});
						};
					</script>
					"""

        # The template HTML for every entry
        item_template = """<tr class="info" id="group%(id)s">
							<td>%(name)s</td>
							<td>%(description)s</td>
							<td class="actions">
								<a href="/admin/dhcp/groups/edit/?gid=%(id)s">Edit</a> |
								<a href="/admin/dhcp/groups/delete/?gid=%(id)s" id="del%(id)s" onclick="delGroupConfirm(%(id)s); return false;">Delete</a> |
								<a href="/admin/dhcp/groups/options/?gid=%(id)s">Options</a>
							</td>
						</tr>
						"""

        # Get the DNS resource record types from the database
        groups = self.webservice.get_dhcp_groups({"limit": 20})

        # Go through the query and make the table HTML using the template
        groups_html = ""
        for group in groups:
            mapping = {
                "id": group["id"],
                "name": group["name"],
                "description": group["description"],
            }
            groups_html += item_template % (mapping)

            # Combine all the parts into the table
        info = (
            """
				<table class="infoTable">
					<thead>
						<tr>
							<th width="25%">Group Name</th>
							<th>Description</th>
							<th class="actions">&nbsp;</th>
						</tr>
					</thead>
					<tbody>
					"""
            + groups_html
            + """
					</tbody>
				</table>
				"""
        )

        maincontent = """<h1>DHCP Groups</h1>""" + info + jquery

        return self._template.wrap(maincontent, leftnav)

        # -----------------------------------------------------------------

    @cherrypy.expose
    def add(self, gid=None):
        """The form to add a group"""

        # Confirm user authentication
        self.check_session()

        leftnav = str(self.leftnav_manage("DHCP Groups")) + str(
            self.leftnav_group_actions("Add Group")
        )

        maincontent = "<h1>Add Group</h1>" + self.group_form()

        return self._template.wrap(maincontent, leftnav)

        # -----------------------------------------------------------------

    @cherrypy.expose
    def delete(self, gid):
        """Delete a DHCP group"""

        # Confirm user authentication
        self.check_session()

        self.webservice.del_dhcp_group(gid)

        raise cherrypy.InternalRedirect("/admin/dhcp/groups")

        # -----------------------------------------------------------------

    @cherrypy.expose
    def edit(self, gid):
        """The form to edit a group"""

        # Confirm user authentication
        self.check_session()

        leftnav = str(self.leftnav_manage("DHCP Groups")) + str(
            self.leftnav_group_actions()
        )

        maincontent = "<h1>Edit Group</h1>" + self.group_form("Update", gid)

        return self._template.wrap(maincontent, leftnav)

        # -----------------------------------------------------------------

    @cherrypy.expose
    def process_group_form(self, **kw):
        """Process the group add or edit form and do the DB transactions
		@param kw: a dictionary containing name, description and gid (gid=0 if adding new record)
		"""

        # Confirm user authentication
        self.check_session()

        if int(kw["gid"]) == 0:
            # We're adding a new group
            try:
                self.webservice.add_dhcp_group(
                    {"name": kw["name"], "description": kw["description"]}
                )
            except Exception as detail:
                raise Exception("Could not add group\n" + str(detail))
        else:
            # We're updating a group
            try:
                self.webservice.edit_dhcp_group(
                    {
                        "gid": kw["gid"],
                        "name": kw["name"],
                        "description": kw["description"],
                    }
                )
            except:
                raise Exception("Could not update group.")

        raise cherrypy.InternalRedirect("/admin/dhcp/groups")

        # -----------------------------------------------------------------

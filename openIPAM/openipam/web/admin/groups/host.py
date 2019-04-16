import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin
from openipam.web.admin.groups.groups import AdminGroups

from openipam.web.resource.submenu import submenu
from openipam.utilities import misc

import re


class AdminGroupsHost(AdminGroups):
    """All pages that are /admin/groups/host/*"""

    # -----------------------------------------------------------------
    # 					  PUBLISHED FUNCTIONS
    # -----------------------------------------------------------------

    def __init__(self):
        Admin.__init__(self)

        # -----------------------------------------------------------------

    def get_results_table(self, search, gid):
        """Returns the table of search results"""

        hosts = ""
        rows = []
        HOSTS_LIMIT = 250

        if len(search):
            hosts = self.webservice.get_hosts(
                {"hostname": "%%%s%%" % search, "limit": HOSTS_LIMIT}
            )
            used_hosts_temp = self.webservice.get_hosts({"gid": gid})

            # Put all used host names into a list for comparison
            used_hosts = []
            for host in used_hosts_temp:
                used_hosts.append(host["hostname"])

        if not hosts:
            return '<p class="noResults">No hosts found.</p>'
        else:
            # The template HTML for every entry
            # If you change the <span id="add#"> below, be sure to update the regex in the table compliation below
            item_template = """<tr class="info" id="host%(clean_mac)s">
								<td>%(hostname)s</td>
								<td>%(mac)s</td>
								<td class="actions">
									<span id="add%(clean_mac)s">
										<a href="javascript:;" id="addLink%(clean_mac)s" onclick="addHostToGroup('%(clean_mac)s'); return false;">Add to group</a>
									</span>
								</td>
							</tr>
							"""

            # Go through the query and make the table HTML using the template
            table_html = ""
            for host in hosts:
                host["clean_mac"] = misc.fix_mac(host["mac"])
                host["gid"] = gid

                if host["hostname"] in used_hosts:
                    # This host already belongs to this group, so don't allow the user to select it (ie. remove the span containing the links)
                    # FIXME: this regex could be better ...
                    regex = re.compile(
                        "(<span).*?(<\\/span>)", re.IGNORECASE | re.DOTALL
                    )
                    rows.append(regex.sub("Already in group", (item_template % host)))
                else:
                    # This host doesn't belong to this group yet, so keep all the normal links
                    rows.append(item_template % (host))

            limit = ""
            if len(hosts) == HOSTS_LIMIT:
                limit = (
                    '<div class="message"><div>Search results truncated to %s results. Try making your search more specific.</div></div>'
                    % HOSTS_LIMIT
                )

                # Combine all the parts into the table
            info = """%s
					<input type="hidden" id="gid" value="%s" />
					<table class="infoTable">
						<thead>
							<tr>
								<th width="25%%">Hostname</th>
								<th>Ethernet Address</th>
								<th class="actions">&nbsp;</th>
							</tr>
						</thead>
						<tbody>
						%s
						</tbody>
					</table>
					%s
					""" % (
                limit,
                gid,
                "".join(rows),
                limit,
            )

            return info

            # -----------------------------------------------------------------

            # -----------------------------------------------------------------
            # 						EXPOSED FUNCTIONS
            # -----------------------------------------------------------------

    @cherrypy.expose
    def add(self, gid, search="", mac=None):
        """The form for adding a host to a group"""

        # Confirm user authentication
        self.check_session()

        # If given a host, show the add_host form
        if mac:
            return self.add_host(mac, gid)

        leftnav = str(self.leftnav_manage("Groups")) + str(
            self.leftnav_view_actions(gid, "Add Host to Group")
        )

        # Query the database
        group = self.webservice.get_groups({"gid": gid})[0]

        back_to_group = ""

        maincontent = (
            '<h1>Add Host to Group: <a href="/admin/groups/view/'
            + gid
            + '">'
            + group["name"]
            + "</a></h1>"
            + """
					<form action="/admin/groups/host/add/"""
            + gid
            + '''" method="get" class="form">
						<div id="element">
							<div id="label">Find host:</div>
							<div id="value"><input type="text" id="search" class="text" name="search" value="'''
            + search
            + """"/><input type="submit" class="button" value="Search"></div>
						</div>
					</form>
					"""
        )

        if len(search):
            maincontent += self.get_results_table(search, gid)

        return self._template.wrap(maincontent, leftnav)


# 	#-----------------------------------------------------------------
#
# 	@cherrypy.expose
# 	def add_host(self, mac, gid):
# 		'''Display the form for adding a host to a group (for JavaScript degradation)'''
#
# 		# Confirm user authentication
# 		self.check_session()
#
# 		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid, "Add Host to Group"))
#
# 		# Query the database
# 		(host, a_record) = self.webservice.get_hosts({ 'mac' : mac })
# 		host = host[0]
#
# 		group = self.webservice.get_groups({ 'gid' : gid })[0]
# 		(permission_types, permission_ids) = self.webservice.get_permission_types()
#
# 		maincontent = '<h1>Add Host to Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
# 				'''
# 			<form action="/admin/groups/host/add_host_post/?mac=''' + str(mac) + \
# 			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
# 				<div id="element">
# 					<div id="label">Hostname:</div>
# 					<div id="value">''' + host['hostname'] + '''</div>
# 					<div id="label">Ethernet Address:</div>
# 					<div id="value">''' + host['mac'] + '''</div>
# 					<div id="label">Permissions:</div>
# 					<div id="value">
# 						 <select class="text" name="pid">'''
#
# 		for id in permission_ids:
# 			maincontent += '<option value="%s">%s</option>' % (permission_types[id]['id'], permission_types[id]['name'])
#
# 		maincontent +=	 '''
# 						 </select>
# 					</div>
#
# 					<div class="submit">
# 						<input type="submit" class="button" value="Add Host to Group">
# 					</div>
#
# 				</div>
# 			</form>
# 			'''
#
# 		return self._template.wrap(maincontent, leftnav)
#
# 	#-----------------------------------------------------------------
#
# 	@cherrypy.expose
# 	def add_host_post(self, mac, gid, pid):
# 		'''Add the given host to the group and redirect (for JavaScript degradation)
# 		@param mac: the database host ID
# 		@param gid: the database group ID
# 		@param search: a search query string'''
#
# 		# Confirm user authentication
# 		self.check_session()
#
# 		self.webservice.add_host_to_group(mac, gid, pid)
#
# 		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#
# 	#-----------------------------------------------------------------
#
# 	@cherrypy.expose
# 	def delete(self, mac, gid):
# 		'''Remove a host from a group
# 		@param mac: the database host ID
# 		@param gid: the database group ID'''
#
# 		# Confirm user authentication
# 		self.check_session()
#
# 		self.webservice.del_host_from_group(mac, gid)
#
# 		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))
#
# 	#-----------------------------------------------------------------
#
# 	@cherrypy.expose
# 	def permissions(self, gid, mac):
# 		'''Edit permissions for a group member (for JavaScript degradation)
# 		@param gid: the database group ID
# 		@param mac: the database host ID'''
#
# 		# Confirm user authentication
# 		self.check_session()
#
# 		leftnav = str(self.leftnav_manage("Groups")) + str(self.leftnav_view_actions(gid))
#
# 		# Query the database
# 		host = self.webservice.get_hosts({ 'mac' : mac })[0]
# 		group = self.webservice.get_groups({ 'gid' : gid })[0]
# 		(permission_types, permission_ids) = self.webservice.get_permission_types()
#
# 		maincontent = '<h1>Edit Host in Group: <a href="/admin/groups/view/'+gid+'">' + group['name'] + '</a></h1>' + \
# 				'''
# 			<form action="/admin/groups/host/permissions_post/?mac=''' + str(mac) + \
# 			 	   	   	   	   	   	   	   	   	   	   '''&gid=''' + str(gid) + '''" method="post" class="form">
# 				<div id="element">
# 					<div id="label">Host:</div>
# 					<div id="value">''' + host['name'] + '''</div>
# 					<div id="label">Permissions:</div>
# 					<div id="value">
# 						 <select class="text" name="pid">'''
#
# 		for id in permission_ids:
# 			maincontent += '<option value="%s">%s</option>' % (permission_types[id]['id'], permission_types[id]['name'])
#
# 		maincontent +=	 '''
# 						 </select>
# 					</div>
#
# 					<div class="submit">
# 						<input type="submit" class="button" value="Update Permissions">
# 					</div>
#
# 				</div>
# 			</form>
# 			'''
#
# 		return self._template.wrap(maincontent, leftnav)
#
# 	#-----------------------------------------------------------------
#
# 	@cherrypy.expose
# 	def permissions_post(self, gid, mac, pid):
# 		'''The form has been POSTed. Update the permissions for a group member (for JavaScript degradation)
# 		@param gid: the database group ID
# 		@param mac: the database host ID
# 		@param pid: the database permission ID'''
#
# 		# Confirm user authentication
# 		self.check_session()
#
# 		self.webservice.set_permissions(gid, pid, mac)
#
# 		raise cherrypy.HTTPRedirect("/admin/groups/view/"+str(gid))

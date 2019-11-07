import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin


class AdminUsers(Admin):
    """The admin users class. This includes all pages that are /admin/users/*"""

    # -----------------------------------------------------------------
    # 					  PUBLISHED FUNCTIONS
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # 						EXPOSED FUNCTIONS
    # -----------------------------------------------------------------

    @cherrypy.expose
    def index(self):
        """The user management page"""

        # Confirm user authentication
        self.check_session()

        rows = []

        leftnav = str(self.leftnav_manage("Users"))

        # The template HTML for every item
        item_template = """<tr class="info">
							<td>%(username)s</td>
							<td>%(source)s</td>
							<td>%(min_permissions)s</td>
						</tr>
						"""

        # Get the users from the database
        users = self.webservice.get_users()

        # Go through the query and make the table HTML using the template
        for user in users:
            rows.append(item_template % (user))

            # Combine all the parts into the table
        info = """<h1>Users</h1>
				<table class="infoTable">
					<thead>
						<tr>
							<th>Username</th>
							<th>Authentication Source</th>
							<th>Minimum Permissions</th>
						</tr>
					</thead>
					<tbody> 
					%s
					</tbody>
				</table>
				""" % "".join(
            rows
        )

        return self._template.wrap(info, leftnav)

        # -----------------------------------------------------------------

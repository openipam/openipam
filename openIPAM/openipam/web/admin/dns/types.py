import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu


class AdminDNSTypes(Admin):
    """The admin DNS class. This includes all pages that are /admin/dns/*"""

    # -----------------------------------------------------------------

    @cherrypy.expose
    def index(self):
        """The DNS resource records management page"""

        # Confirm user authentication
        self.check_session()

        leftnav = str(self.leftnav_manage("DNS Resource Record Types"))

        # The template HTML for every item
        item_template = """<tr class="info">
							<td>%(id)s</td>
							<td>%(name)s</td>
							<td>%(description)s</td>
						</tr>
						"""

        # Get the DNS resource record types from the database
        dns_types = self.webservice.get_dns_types()

        # Go through the query and make the table HTML using the template
        dns_types_html = ""
        for dns_type in dns_types:
            dns_types_html += item_template % (dns_type)

            # Combine all the parts into the table
        info = (
            """
				<table class="infoTable">
					<thead>
						<tr>
							<th>&nbsp;</th>
							<th>Resource Record Type</th>
							<th>Description</th>
						</tr>
					</thead>
					<tbody> 
					"""
            + dns_types_html
            + """
					</tbody>
				</table>
				"""
        )

        maincontent = """<h1>DNS Resource Records</h1>""" + info

        return self._template.wrap(maincontent, leftnav)

        # -----------------------------------------------------------------

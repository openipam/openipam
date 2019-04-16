import cherrypy

from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu

from openipam.utilities import misc


class AdminHostAttributes(Admin):
    """The custom host attributes class. This includes all pages that are /admin/attr/host/*"""

    # -----------------------------------------------------------------

    @cherrypy.expose
    def index(self):
        """The custom host attributes management page"""

        # Confirm user authentication
        self.check_session()

        text = '<h1>Custom Host Attributes</h1><div class="message">Under construction.</div>'
        return self._template.wrap(
            text, str(self.leftnav_manage("Custom Host Attributes"))
        )

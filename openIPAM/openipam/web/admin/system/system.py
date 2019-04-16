import cherrypy

from openipam.web.basepage import BasePage
from openipam.web.admin.admin import Admin

from openipam.web.resource.submenu import submenu


class AdminSystem(Admin):
    """The admin system settings class. This includes all pages that are /admin/sys/*"""

    # -----------------------------------------------------------------
    # 					  PUBLISHED FUNCTIONS
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # 						EXPOSED FUNCTIONS
    # -----------------------------------------------------------------

    @cherrypy.expose
    def index(self):
        """The settings management page"""

        # Confirm user authentication
        self.check_session()

        leftnav = str(self.leftnav_manage("System Settings"))
        text = '<h1>System Settings</h1><div class="message">Under construction</div>'
        return self._template.wrap(text, str(self.leftnav_manage("System Settings")))

        # TODO: make sure to add checkbox for host change digest emails

        # -----------------------------------------------------------------

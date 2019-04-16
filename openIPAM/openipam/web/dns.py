from .basepage import BasePage
from openipam.web.resource.submenu import submenu, OptionsSubmenu
from openipam.utilities import misc, error, validation
from openipam.utilities.perms import Perms
from openipam.web.resource.utils import redirect_to_referer
from openipam.config import frontend

import types

import cherrypy
from . import framework
from .resource.submenu import submenu


class DNS(BasePage):
    """
	The DNS class. This includes all pages that are /dns/*
	"""

    def __init__(self):
        BasePage.__init__(self)

        # Object for wrapping HTML into the template
        self.__template = framework.Basics(
            "dns",
            javascript=(
                "/scripts/jquery/ui/jquery-ui-personalized.min.js",
                "/scripts/dns.js",
                "/scripts/json2.js",
            ),
        )

        # ------------------------  Private Functions  ------------------------

    def leftnav_options(self):
        """
		Returns the html for the leftnav options on the Manage DNS tab
		"""

        # options = ('Show A records', 'Show CNAMEs')
        # options_links = ('/dns/?show_a_records', '/dns/?show_cnames')

        options = ()
        options_links = ()
        selected = ()

        return OptionsSubmenu(
            values=options, links=options_links, title="Options", selected=selected
        )

    def get_leftnav(self, action="", show_options=True):
        return "%s" % (self.leftnav_options() if show_options else "")

    def get_dns(self, name=None, address=None, content=None, mac=None, limit=None):
        """
		
		"""

        if not limit and frontend.default_dns_records_limit:
            limit = frontend.default_dns_records_limit

            # Replace any wildcard stars with DB capable wildcards
        if type(name) == bytes:
            name = name.replace("*", "%")
        if type(content) == bytes:
            content = content.replace("*", "%")

            # Initialization
        values = {
            "name": name,
            "address": address,
            "content": content,
            "order_by": "tid, name",
            "mac": mac,
        }

        if limit:
            values["limit"] = limit

            # call webservice to get values
        dns_records = self.webservice.get_dns_records(values)

        # get permissions
        permissions = self.webservice.find_permissions_for_dns_records(
            {"records": dns_records}
        )

        # Translates type id into name
        dns_types = self.webservice.get_dns_types({"make_dictionary": True})

        for record in dns_records:
            # dns_types = { '2' : { name : 'NS' },  }
            record["type"] = dns_types[str(record["tid"])]["name"]
            record["has_modify_perm"] = (
                Perms(permissions[0][str(record["id"])]) & frontend.perms.MODIFY
            ) == frontend.perms.MODIFY
            record["has_delete_perm"] = (
                Perms(permissions[0][str(record["id"])]) & frontend.perms.DELETE
            ) == frontend.perms.DELETE

            # don't filter
        return dns_records

        # ------------------------  Public Functions  ------------------------

    @cherrypy.expose
    def index(self, success=False, **kw):
        """
		The DNS management page
		"""

        # Confirm user authentication
        self.check_session()

        values = {}
        values["show_search_here"] = True
        values["title"] = "DNS Search Results"
        if success:
            values["global_success"] = "Records Updated Successfully!"
        values["dns_types_dropdown"] = self.webservice.get_dns_types(
            {"only_useable": True, "order_by": "name"}
        )

        return self.__template.wrap(
            leftcontent=self.get_leftnav(),
            filename="%s/templates/dns.tmpl" % frontend.static_dir,
            values=values,
        )

    @cherrypy.expose
    def search(
        self,
        q=None,
        mac=None,
        name=None,
        address=None,
        content=None,
        success=False,
        **kw
    ):
        """
		The search page where the search form POSTs
		"""

        # Confirm user authentication
        self.check_session()

        # Initialization
        values = {}

        name_or_content = None

        if not (q or mac or name or content):
            raise cherrypy.InternalRedirect("/dns")

        if success:
            values["global_success"] = "Records Updated Successfully!"

        def startswith(s, m):
            l = len(m)
            if s[:l] == m:
                return True
            return False

        def strip(s, m):
            return s[len(m) :]

        if q:
            # Strip the query string and make sure it's a string
            q = str(q).strip().split("|")
            for i in q:
                if startswith(i, "name:"):
                    name = strip(i, "name:")
                elif startswith(i, "mac:"):
                    mac = strip(i, "mac:")
                elif startswith(i, "content:"):
                    content = strip(i, "content:")
                elif startswith(i, "address:"):
                    address = strip(i, "address:")
                elif startswith(i, "addr:"):
                    address = strip(i, "addr:")
                elif startswith(i, "ip:"):
                    address = strip(i, "ip:")
                else:
                    name_or_content = i

        query_string = []
        if name:
            query_string.append("name:%s" % name)
        if mac:
            query_string.append("mac:%s" % name)
        if address:
            query_string.append("address:%s" % name)
        if content:
            query_string.append("content:%s" % name)
        if name_or_content:
            query_string.append("%s" % name)

        values["query_string"] = "|".join(query_string)
        values["dns_types_dropdown"] = self.webservice.get_dns_types(
            {"only_useable": True, "order_by": "name"}
        )

        # Search by MAC if query is a MAC address

        if name_or_content and (name or content):
            raise Exception(
                "Cannot specify name or content with generic string matching."
            )

        if name_or_content:
            values["dns"] = self.get_dns(mac=mac, address=address, name=name_or_content)
            values["dns"] += self.get_dns(
                mac=mac, address=address, content=name_or_content
            )
        else:
            values["dns"] = self.get_dns(
                mac=mac, address=address, name=name, content=content
            )

        return self.__template.wrap(
            leftcontent=self.get_leftnav(),
            filename="%s/templates/dns.tmpl" % frontend.static_dir,
            values=values,
        )

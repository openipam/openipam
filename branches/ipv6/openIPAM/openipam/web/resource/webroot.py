
def get_web_root():
	# Import the classes for CherryPy mappings
	from openipam.web.basepage import BasePage
	from openipam.web.hosts import Hosts
	from openipam.web.networks import Networks
	from openipam.web.dns import DNS
	from openipam.web.access import Access
	from openipam.web.ajax import AjaxTransport
	from openipam.web.service import Service
	from openipam.web.admin.admin import Admin
	from openipam.web.admin.attributes.host import AdminHostAttributes
	from openipam.web.admin.dhcp.groups import AdminDHCPGroups
	from openipam.web.admin.dhcp.group_options import AdminDHCPGroupOptions
	from openipam.web.admin.dhcp.options import AdminDHCPOptions
	from openipam.web.admin.dns.types import AdminDNSTypes
	from openipam.web.admin.groups.groups import AdminGroups
	from openipam.web.admin.groups.user import AdminGroupsUser
	from openipam.web.admin.groups.domain import AdminGroupsDomain
	from openipam.web.admin.groups.network import AdminGroupsNetwork
	from openipam.web.admin.groups.host import AdminGroupsHost
	from openipam.web.admin.system.system import AdminSystem
	from openipam.web.admin.users.users import AdminUsers
	
	# Set up the object mappings for CherryPy
	root = BasePage()
	root.hosts = Hosts()
	root.networks = Networks()
	root.dns = DNS()
	root.dhcp = BasePage()
	root.access = Access()
	root.ajax = AjaxTransport()
	root.service = Service()
	root.admin = Admin()
	root.admin.users = AdminUsers()
	root.admin.groups = AdminGroups()
	root.admin.groups.user = AdminGroupsUser()
	root.admin.groups.domain = AdminGroupsDomain()
	root.admin.groups.network = AdminGroupsNetwork()
	root.admin.groups.host = AdminGroupsHost()
	root.admin.dns = AdminDNSTypes()
	root.admin.dhcp = BasePage()
	root.admin.dhcp.groups = AdminDHCPGroups()
	root.admin.dhcp.groups.options = AdminDHCPGroupOptions()
	root.admin.dhcp.options = AdminDHCPOptions()
	root.admin.attr = BasePage()
	root.admin.attr.host = AdminHostAttributes()
	root.admin.sys = AdminSystem()
	
	return root
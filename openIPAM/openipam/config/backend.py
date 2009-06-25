import IPy

# SSL
ssl_enabled = False
ssl_cert = None
ssl_key = None

# NETWORK BINDINGS
bind_port = 8080         # Port the backend will listen on.
bind_host = '127.0.0.1'  # Address the backend will bind to. If you use anything but 127.0.0.1, we strongly recommend enabling SSL.

# DATABASE
db_host = None
db_port = 5432
db_database = "openipam"
db_username = "openipam"
db_password = None
db_show_sql = False
db_connect_args = { 'sslmode' : 'require' }

# SESSIONS
session_storage = "file"
session_dir = "/var/lib/openipam/sessions/backend"
session_timeout = 60	# Minutes

# PROXY SETTINGS
proxied = False # Are requests coming through a proxy?
proxy_base = None
proxy_client_ip_header = None

# LOGGING
log_dir = "/var/log/openipam/backend"
log_access = None
log_error = None
log_stdout = None
log_stderr = None
 
# SYSTEM CONFIGURATION

# Enable or disable the use of dynamic IP addresses
allow_dynamic_ip = True

# If someone doesn't have minimum ADMIN rights, can they create a new host under someone else's name? 
allow_non_admin_host_transfer = False

# Default time to live for normal resource records and for dynamic registrations
default_ttl = 86400

# An index into an IP network object ... ie. -2 on a /24 is .254 ... 1 is .1, etc.
default_gateway_address_index = -2

# FIXME: use names here
db_default_min_permissions = '00000100'

# FIXME: eliminate the need for these
db_default_pool_id = 1
db_default_group_id = 1
db_default_guest_group_id = 2
db_service_group_id = 3

# WRITEME
pool_map = []

assignable_pools = [] # pools to be treated as free addresses

# When adding a user to a group, what will host_permissions default to?
default_host_permissions	= '00001111'

def get_pool_id(address):
	"""
	Take an address and return a pool ID ...
	
	This should contain your mapping for pools so that an address, when released
	from being static can be placed into the correct pool.
	"""
	
	for pool, network in pool_map:
		if address in network:
			return pool
		
	return None

func_get_pool_id = get_pool_id

auth_user = 'auth'
guest_user = 'guest'

from openipam_config.backend import *

if log_access is None: log_access = '%s/access' % log_dir
if log_error is None: log_error = '%s/error' % log_dir
if log_stdout is None: log_stdout = '%s/stdout' % log_dir
if log_stderr is None: log_stderr = '%s/stderr' % log_dir




# SSL
ssl_enabled = True
ssl_cert = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key = '/etc/ssl/private/ssl-cert-snakeoil.key'

# NETWORK BINDINGS
bind_port = 8443        # Port the frontend will listen on
bind_host = '0.0.0.0'   # Address the frontend will bind to

# WEBSERVICE
# The host and port settings of the backend webservice
xmlrpc_ssl_enabled = False
xmlrpc_port = 8080
xmlrpc_host = '127.0.0.1'

# WEB STATIC FILES (CSS, JavaScript, images, etc.)
static_dir='/usr/local/openipam/openIPAM/openipam/web/media'
#styles_dir = None
#scripts_dir = None
#images_dir = None

# SESSIONS
session_storage = "file"
session_dir = "/var/lib/openipam/sessions/frontend"
session_timeout = 60	# Minutes

# PROXY SETTINGS
proxied = False # Are requests coming through a proxy?
#proxy_base = 'https://base.url'
#proxy_client_ip_header = 'Client-IP'

# Placed underneath the header on the My Access tab ... good for describing your procedures for obtaining more access
my_access_text = "<p>If you need additional access, please contact your local network administrator.</p>"
email_required_html = "<p>Your user does not have an email address set, please contact your local network administrator.</p>"

# LOGGING
log_dir = "/var/log/openipam/web"
#log_access = None
#log_error = None
#log_stdout = None
#log_stderr = None

# GROUPS
# Permissions selected by default when adding users to groups 
# FIXME: make this 'ADD' instead of permission bits, and rename this to be more intuitive
db_default_group_permissions = '00000010'

enable_gul = False

default_dns_records_limit = 100


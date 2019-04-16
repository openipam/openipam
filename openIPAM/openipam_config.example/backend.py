import openipam.iptypes

# IPv6 support
allow_ipv6 = False

# SSL
ssl_enabled = False
ssl_cert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
ssl_key = "/etc/ssl/private/ssl-cert-snakeoil.key"

# NETWORK BINDINGS
bind_port = 8080  # Port the backend will listen on.
bind_host = (
    "127.0.0.1"
)  # Address the backend will bind to. If you use anything but 127.0.0.1, we strongly recommend enabling SSL.

# For some of our cron jobs
smtp_host = "127.0.0.1"
digest_dest = "openipam@localhost"
digest_from = "noreply@localhost"
bounce_addr = None
expiration_from = "openipam@localhost"
expiration_reply_to = None

# DATABASE
db_host = "127.0.0.1"  # An IP or hostname of your PostgreSQL server
# db_port = 5432
db_database = "openipam"
db_username = "openipam"
db_password = "something_better_than_this"
db_show_sql = False  # setting this to True will cause _huge_ log files
db_connect_args = {"sslmode": "require"}

# You can create a file called db_priv.py that contains the above DB settings.
# This allows us to have strict permissions on the file containing a password
try:
    from db_priv import *
except:
    pass

# SESSIONS
session_storage = "file"
session_dir = "/var/lib/openipam/sessions/backend"
session_timeout = 60  # Minutes

# PROXY SETTINGS
proxied = False  # Are requests coming through a proxy?
# proxy_base = 'https://base.url'
# proxy_client_ip_header = 'Client-IP'

# LOGGING
log_dir = "/var/log/openipam/backend"
# log_access = None
# log_error = None
# log_stdout = None
# log_stderr = None

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
db_default_min_permissions = "00000100"

# FIXME: eliminate the need for these
db_default_pool_id = 1
db_default_group_id = 1
db_default_guest_group_id = 2
db_service_group_id = 3

enable_gul = False

# WRITEME
pool_map = [
    (1, openipam.iptypes.IP("192.168.0.0/16")),
    (2, openipam.iptypes.IP("172.16.0.0/16")),
]

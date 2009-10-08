# Django settings for openipam project.

try: from local_settings import *
except ImportError:	raise Exception("Could not import local_settings. Please copy local_settings.py.example to local_settings.py and customize.")

DEBUG = locals().pop('DEBUG', True)
TEMPLATE_DEBUG = DEBUG

ADMINS = locals().pop('ADMINS', (
    # ('Your Name', 'your_email@domain.com'),
))

MANAGERS = ADMINS

#DATABASE_ENGINE = ''           # 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
#DATABASE_NAME = ''             # Or path to database file if using sqlite3.
#DATABASE_USER = ''             # Not used with sqlite3.
#DATABASE_PASSWORD = ''         # Not used with sqlite3.
#DATABASE_HOST = ''             # Set to empty string for localhost. Not used with sqlite3.
#DATABASE_PORT = ''             # Set to empty string for default. Not used with sqlite3.

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = locals().pop('TIME_ZONE', 'America/Denver')

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = locals().pop('MEDIA_ROOT', '%s/static/' % BASE_DIR)

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = locals().pop('MEDIA_URL', '/static/')

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = locals().pop('ADMIN_MEDIA_PREFIX', '/media/')

# Make this unique, and don't share it with anybody.
SECRET_KEY = locals().pop('SECRET_KEY')

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'openipam.middleware.WebserviceMiddleware',
    'openipam.middleware.PermissionsMiddleware',
#    'django.contrib.auth.middleware.AuthenticationMiddleware',
)

ROOT_URLCONF = 'openipam.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    '%s/openipam/glue/templates/' % BASE_DIR,
)

INSTALLED_APPS = (
    #'django.contrib.auth',
    #'django.contrib.contenttypes',
    'django.contrib.sessions',
    #'django.contrib.sites',
    'hosts',
    'networks',
    'domains',
    'admin',
)

try: __import__("django_extensions")
except ImportError: pass
else: INSTALLED_APPS += ("django_extensions",)

# The settings of the backend webservice
WEBSERVICE_SSL_ENABLED = False
WEBSERVICE_PORT = 8080
WEBSERVICE_HOST = '127.0.0.1'

FORCE_ALL_SSL = True

LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'

SESSION_ENGINE = 'django.contrib.sessions.backends.file'

# proxy settings?
# perms handling?
# session handling?
# ssl handling?

#from openipam.utilities.perms import Perms

# SSL
#ssl_enabled = True
#ssl_cert = None
#ssl_key = None

#ssl_enabled = True
#ssl_cert = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
#ssl_key = '/etc/ssl/private/ssl-cert-snakeoil.key'

# NETWORK BINDINGS
#bind_port = 8443        # Port the frontend will listen on
#bind_host = '0.0.0.0'   # Address the frontend will bind to



# WEB STATIC FILES (CSS, JavaScript, images, etc.)
#static_dir='/usr/local/openipam/openIPAM/openipam/web'
#styles_dir = None
#scripts_dir = None
#images_dir = None

# SESSIONS
#session_storage = "file"
#session_dir = "/var/lib/openipam/sessions/web"
#session_timeout = 60
#
## PROXY SETTINGS
#proxied = False # Are requests coming through a proxy?
#proxy_base = 'https://base.url'
#proxy_client_ip_header = 'Client-IP'

# Placed underneath the header on the My Access tab ... good for describing your procedures for obtaining more access
#my_access_text = "<p>If you need additional access, please contact your local network administrator.</p>"
#email_required_html = "<p>Your user does not have an email address set, please contact your local network administrator.</p>"

# LOGGING
#log_dir = "/var/log/openipam/web"
#log_access = None
#log_error = None
#log_stdout = None
#log_stderr = None

# GROUPS
# Permissions selected by default when adding users to groups 
# FIXME: make this 'ADD' instead of permission bits, and rename this to be more intuitive
#db_default_group_permissions = '00000010'

# FIXME: these should come from the backend
#allow_dynamic_ip = True
#db_service_group_id = 3

# FIXME: make this come from the DB
#class PermObj( object ):
#	pass
#perms = PermObj()
#perms.ADD=Perms('00000010')
#perms.READ=Perms('00000100')
#perms.DELETE=Perms('00001000')
#perms.ADMIN=Perms('00000001')
#perms.MODIFY=Perms('00001110')
#perms.OWNER=Perms('00001111')
#perms.DEITY=Perms('11111111')

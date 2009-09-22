import os

DEBUG = True

# The base installation directory of openIPAM (including trailing slash)
#BASE_DIR = '/usr/local/openipam/web/'
BASE_DIR = os.sep.join(__file__.split(os.sep)[:-2])

ADMINS = (
	('Mike Fotes', 'mike.fotes@usu.edu'),
)

# Make this a really long unique string, and don't share it with anybody.
SECRET_KEY = 'o8t(cn8$f2h6siif7y4k5=%f4%6ab2*x1y==sx7t6dvx2@t+9d'

#TIME_ZONE = 'American/Denver'

# Enable error emails
EMAIL_HOST = 'mail.usu.edu'
DEFAULT_FROM_EMAIL = 'noreply@usu.edu'
SERVER_EMAIL = 'noreply@usu.edu'
EMAIL_SUBJECT_PREFIX = '[openIPAM] '

# On production, force all pages to be served over SSL
FORCE_ALL_SSL = True
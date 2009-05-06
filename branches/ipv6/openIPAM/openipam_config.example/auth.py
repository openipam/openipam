
# LDAP 
ldap_enabled = False
#ldap_filter = '(&(sAMAccountName=%s)(|(memberof=cn=somegrp,ou=someou,dc=some,dc=ldap,dc=server)(memberof=cn=othergrp,ou=someou,dc=some,dc=ldap,dc=server)))'
#ldap_base ='ou=someou,dc=some,dc=ldap,dc=server'
#ldap_alias_base = 'ou=alias,dc=some,dc=ldap,dc=server'
#ldap_user_format = '%s@some.ldap.server'
#ldap_uri = 'ldaps://some.ldap.server:636'
#ldap_binddn = 'ro_ldap_user@some.ldap.server'
#ldap_bindpw = 'some_ldap_password'
#ldap_username_attribute = 'sAMAccountName'
#ldap_mail_attribute = 'mail'
#ldap_realname_attribute = 'displayName'

# You can create a file called ldap_priv.py that contains the above LDAP settings.
# This allows us to have strict permissions on the file containing a password.
try:	from ldap_priv import *;
except: pass

# Automatically create users in openIPAM that authenticate via LDAP
ldap_auto_create = True

# Require that a user has their email address set in LDAP to use openIPAM
ldap_require_email = False

# INTERNAL AUTHENTICATION
internal_enabled = True
# This can be one of: ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
# Changing it will break all existing passwords in the DB
internal_hash = 'sha512'

# GUESTS
guests_enabled = True # FIXME: not checked anywhere yet

# If enabled, one guest ticket can be used by an unlimited number of people
guests_multi_use_tickets = True

# The format for all guest hostnames. The %s will be replaced with an available number
guests_hostname_format = 'g-%s.guests.example.com'

# WRITEME
types = None


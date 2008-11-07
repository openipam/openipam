
# LDAP
ldap_enabled = False    	    	    	    	    	    	    	
ldap_filter = None
ldap_base = None
ldap_alias_base = None
ldap_user_format = None
ldap_uri = None
ldap_binddn = None
ldap_bindpw = None
ldap_debug_level = 0
ldap_username_attribute = 'sAMAccountName'
ldap_mail_attribute = 'mail'
ldap_realname_attribute = 'displayName'

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

from openipam_config.auth import *

from openipam.backend.db import interface

dbi = interface.DBAuthInterface()

class AuthSources( object ):
	def __init__( self, sources ):
		for i in sources:
			setattr(self, i['name'], i['id'])

sources = AuthSources( dbi.get_auth_sources() )


from openipam.config import auth
from openipam.auth import interfaces

if auth.types:
	types=auth.types
else:
	# FIXME
	types = []
	if internal_enabled:
		types.append( InternalAuthInterface() )
	if ldap_enabled:
		types.append( openipam.auth.interfaces.LDAPInterface() )


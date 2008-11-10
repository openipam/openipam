from openipam.config import auth
import openipam.backend.auth.interfaces

if auth.interfaces:
	interfaces = auth.interfaces
else:
	# FIXME
	interfaces = []
	
	if auth.internal_enabled:
		interfaces.append( openipam.backend.auth.interfaces.InternalAuthInterface() )
		
	if auth.ldap_enabled:
		interfaces.append( openipam.backend.auth.interfaces.LDAPInterface() )
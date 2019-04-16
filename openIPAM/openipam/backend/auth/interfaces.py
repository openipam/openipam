import ldap
import _thread

from openipam.config import auth
from openipam.config import backend
from .internal import hash_password
from openipam.utilities import error

class BaseAuthInterface:
	def verify( self, username ):
		'''
		Given a username, determine whether a user exists by username in this auth source
		@raise error.NotUser: raise when the user doesn't exist for this auth source
		@return: nothing ... if no error is thrown, the user exists in this auth source
		'''
		raise error.NotImplemented('Interface did not implement verify_user')
	def authenticate( self, username, password ):
		'''
		Check to see that the password is correct for this user in this auth source
		@raise error.InvalidCredentials: will be raised if the credentials are wrong
		@return: a user object 
		'''
		raise error.NotImplemented('Interface did not implement check_pass')
	def create_user( self, username, password, name, email ):
		raise error.NotImplemented('Interface did not implement create_user')
	def update_password( self, username, password, old_password=None ):
		raise error.NotImplemented('Interface did not implement create_user')

class User( object ):
	"""
	A user object
	"""
	def __init__( self, uid, username, name, source, min_perms, email ):
		"""
		Constructor ... set the base attributes for this object
		What will every user have?
		"""
		self.uid = uid
		self.username = username
		self.name = name
		self.auth_source =  source
		self.min_permissions = min_perms
		self.email = email
		
class InternalAuthInterface(BaseAuthInterface):
	"""
	An internal auth object for authenticating users
	"""
	def _search_internal( self, username ):
		"""
		Search internal authentication for this username and return info about them
		
		@raise error.NotUnique: if more than one user is found, this shouldn't happen
		@raise error.NotUser: if the user doesn't exist in this auth source
		@return: information related to this user
		"""
		# Get the user's information
		user = auth.dbi.get_users(username=username, source=auth.sources.INTERNAL)
		
		if not user:
			raise error.NotUser()
		if len(user) > 1:
			raise error.NotUnique()
		
		user = user[0]
		
		internal_auth_info = auth.dbi.get_internal_auth(uid=user['id'])
		
		if not internal_auth_info:
			raise error.NotUser("User does not exist in internal authentication source.")
		
		return user, internal_auth_info[0]
		
	def __verify(self, username, password=False):
		
		(user, internal_auth_info) = self._search_internal(username)
		
		if password != False:
			# Hash the user's password for comparison
			hash = hash_password(password)
			
			# Compare the retrieved hashed password to the hashed password we were given
			if internal_auth_info['hash'] != hash:
				# "Invalid password: %s" % password
				# ;)
				raise error.InvalidCredentials("Invalid password for user: %s" % username)
		
		return User(uid=user['id'], username=user['username'], name=internal_auth_info['name'], source=auth.sources.INTERNAL, min_perms=user['min_permissions'], email=internal_auth_info['email'])

	def verify(self, username):
		'''
		Given a username, determine whether that user exists in this auth source
		@return: nothing ... if no error is thrown, the user exists
		@raise error.NotUser: raised when the user doesn't exist for this auth source
		'''
		if not username:
			raise error.InvalidCredentials("Username not supplied")
		return self.__verify(username)
		
	def authenticate( self, username, password ):
		'''
		Check to see that the password is correct for this user in this auth source
		
		@param username: the user's username
		@param password: the user's unhashed password
		
		@raise error.InvalidCredentials: will be raised if the credentials are wrong 
		@return: a user object 
		'''
		if not password:
			raise error.InvalidCredentials("Password not supplied")
		
		# Authentication successful
		return self.__verify(username, password)

	def create_user( self, username, password, name, email ):
		# FIXME: Make sure permissions are handled properly anywhere this gets called!
		return auth.dbi.create_internal_user( username=username, name=name, email=email, hash=hash_password(password) )
	
	def update_password( self, username, password, old_password=None ):
		# FIXME: Make sure permissions are handled properly anywhere this gets called!
		# (ask for old password, etc)
		if old_password is not None:
			authenticate(username, old_password)
		user = self.verify(username)
		return auth.dbi.change_internal_password( id=user.uid, hash=hash_password(password) )
		
class LockingWrapper(object):
	"""Wrapper to try to make ldap object more thread-safe"""
	def __init__( self, obj ):
		# Make a lock
		# store the object
		self.obj_lock = _thread.allocate_lock()
		self.obj = obj
		self.obj_fcn = None
	def __getattr__( self, name ):
		obj_fcn = getattr( self.obj, name )
		# lock
		self.obj_lock.acquire()
		# set fcn
		self.obj_fcn = obj_fcn
		return self.__do_call_unlock
	def __do_call_unlock( self, *args, **kw ):
		# call fcn
		try:
			ret = self.obj_fcn( *args, **kw )
		finally:
			# unlock
			self.obj_fcn = None
			self.obj_lock.release()
		return ret

class LDAPInterface(BaseAuthInterface):
	'''
	Class used to interact with LDAP.
	'''
	def __init__( self ):
		self.__basedn = auth.ldap_base
		self.__user_fmt = auth.ldap_user_format
		self.__uri = auth.ldap_uri
		self.__binddn = auth.ldap_binddn
		self.__bindpw = auth.ldap_bindpw
		self.__username_attribute = auth.ldap_username_attribute # 'sAMAccountName'
		self.__mail_attribute = auth.ldap_mail_attribute # 'mail'
		self.__name_attribute = auth.ldap_realname_attribute # 'displayName'
		self.__timeout = auth.ldap_timeout
		self.__scope = ldap.SCOPE_SUBTREE
		self.__filter = auth.ldap_filter
		self.__debuglevel = auth.ldap_debug_level
		#self.__bind_type = ldap.AUTH_SIMPLE
		self.__connect()
		
	def __del__( self ):
		if hasattr(self, '__conn') and self.__conn:
			self.__conn.unbind_s()
			
	def __bind_as( self, username, password ):
		'''
		Attempt to bind with the given credentials.
		@param username: username to use for bind
		@param password: password to use for bind
		'''
		if not password: # If an empty password is given, LDAP binds anonymously...bad
			raise Exception( "No password supplied!" )
		
		result = self._search_ldap( username )
		try:
			self.__conn.simple_bind_s( result['dn'], password )
		except:
			del self.__conn
			self.__connect()
			raise
			
		# Unbind the bound user
		self.__conn.unbind_s()
		
		return result
	
	def _query( self, basedn=None, scope=ldap.SCOPE_SUBTREE, filter=None, attrs=None ):
		result = self.__conn.search_st( basedn, scope, filter, attrs )
		return result
	
	def __connect( self ):
		'''
		Connect to the URI in __init__, etc.
		'''
		
		# If trace_level is set to 1, passwords and other info will be output to stdout ...
		# don't do this unless you REALLY want to...which, if you do, I'd like to talk to you sometime
		self.__conn = LockingWrapper( obj = ldap.initialize( self.__uri, trace_level=0 ) )
		
		ldap.set_option( ldap.OPT_DEBUG_LEVEL, self.__debuglevel )
		#ldap.set_option( ldap.OPT_NETWORK_TIMEOUT, self.__timeout)
		self.__conn.set_option( ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3 )
		self.__conn.set_option( ldap.OPT_REFERRALS, 0 )
		self.__conn.set_option( ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND )

		# Die!!
		#self.__conn.timelimit = self.__timeout
		#self.__conn.timeout = self.__timeout
		#self.__conn.network_timeout = self.__timeout

		#if auth.ldap_tls_cacertfile:
		#	self.__conn.set_option( ldap.OPT_X_TLS_CACERTFILE, local_config['ldap_tls_cacertfile'])
		#if auth.ldap_tls_cacertdir:
		#	self.__conn.set_option( ldap.OPT_X_TLS_CACERTDIR, local_config['ldap_tls_cacertdir'])
		#self.__conn.set_option( ldap.OPT_X_SASL_SECPROPS, 'maxssf=0' )
		# FIXME: this should probably be in a try/except
		#self.__conn.bind_s( self.__binddn, self.__bindpw,
		#		self.__bind_type )
		self.__conn.simple_bind_s( self.__binddn, self.__bindpw )
		
	def _search_ldap(self, username ):
		"""
		Search LDAP for this username and return info about them
		
		@raise error.NotUnique: if more than one user is found, this shouldn't happen
		@raise error.NotUser: if the user doesn't exist in this auth source
		@return: information from LDAP related to this user
		"""

		try:
			self.__conn.simple_bind_s( self.__binddn, self.__bindpw )
		except ldap.LDAPError:
			del self.__conn
			self.__connect()
			
		result = self.__conn.search_st(self.__basedn, self.__scope, self.__filter % username,
				[self.__username_attribute,self.__mail_attribute,self.__name_attribute])

		if len(result) == 1:
			# We found the user
			username = result[0][1][self.__username_attribute][0]
			display_name = result[0][1][self.__name_attribute][0]
			try:
				mail = result[0][1][self.__mail_attribute][0]
			except:
				if auth.ldap_require_email:
					raise error.NoEmail()
				else:
					mail = ''
			dn = result[0][0]
			
			# We're done, we have the information
			return { 'username': username,
					'name': display_name,
					'email': mail,
					'dn': dn
					}
		elif result:
			raise error.NotUnique()
		else:
			raise error.NotUser("User does not exist in the LDAP auth source.")
		
	def __verify( self, username, password=(False,) ):
		'''
		Check to see that the password is correct for this user in this auth source
		@raise error.InvalidCredentials: will be raised if the credentials are wrong 
		@return: a user object 
		'''
		
		
		if password != (False,):
			# Bind as this user, dies if unsuccessful
			ldap_user = self.__bind_as( username, password )
		else:
			ldap_user = self._search_ldap( username )
		
		if 'email' not in ldap_user or ('email' in ldap_user and not ldap_user['email'].strip()):
			if auth.ldap_require_email:
				raise error.NoEmail()
			else:
				ldap_user['email'] = ''
		
		# Successful bind, continue to authenticate
		our_user = auth.dbi.get_users(username=ldap_user['username'], source=auth.sources.LDAP)
		
		if not len(our_user) and auth.ldap_auto_create:
			# The user doesn't exist in our database, so add them
			auth.dbi.add_user( username=ldap_user['username'], source=auth.sources.LDAP )
			
			# Re-get the user row
			our_user = auth.dbi.get_users(username=ldap_user['username'], source=auth.sources.LDAP)
			
			if not our_user:
				raise error.InsertFailed("New user from LDAP could not be inserted into the database")
		elif len(our_user) > 1:
			raise error.NotUnique(str(our_user))
		
		our_user = our_user[0]
		
		return User(uid=our_user['id'], username=our_user['username'], name=ldap_user['name'], source=auth.sources.LDAP, min_perms=our_user['min_permissions'], email=ldap_user['email'] )
			
	def verify( self, username ):
		'''
		Given a username, determine whether a user exists by username in this auth source
		@raise error.NotUser: raise when the user doesn't exist for this auth source
		@return: nothing ... if no error is thrown, the user exists in this auth source
		'''
		return self.__verify(username)
		

	def authenticate( self, username, password ):
		if not password:
			raise error.InvalidCredentials("Password not supplied")
		return self.__verify( username, password )
		

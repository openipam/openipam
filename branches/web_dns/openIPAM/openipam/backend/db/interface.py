'''
The main openIPAM database interface. This is where the magic happens.

CODING STANDARDS FOR DATABASE LAYER:
- Follow openIPAM coding conventions: see http://code.google.com/p/openipam/wiki/CodingConventions
- Always use full arguments for all functions and never use **kw because things should intentionally
break if the webservice layer or DHCP server is not invoking methods correctly.
Example:
	def get_dhcp_group_options(self, gid=None, rid=None):
		...

- Use SQLAlchemy query building conventions (don't do it all at once, build the query).
- Use SQLAlchemy Expression Language fully, never use hybrid or full text queries.
- We do not use any part of SQLAlchemy's Object Relational Mapper (ORM)
- Never use a list or a dictionary as a default argument. See http://code.google.com/p/openipam/wiki/CodingConventions#Functions

'''

import random
random.seed()

import types
import string
import time
import datetime

import sqlalchemy
import obj
import IPy
import re
import thread

from openipam.utilities import error
from openipam.utilities import validation
from openipam.utilities.perms import Perms
from openipam.config import backend

from sqlalchemy.sql import select, and_, or_, not_, join, outerjoin, subquery, text, union

import openipam.utilities.perms

my_conn = obj.engine.connect()
query= select([obj.permissions.c.id,obj.permissions.c.name])
try:
	result = my_conn.execute(query).fetchall()
	my_conn.close()
except:
	my_conn.close()
	raise
perms = openipam.utilities.perms.PermsList( result )
del result
del my_conn
del query

# Make sure that the installed version of SQLAlchemy is up-to-date

SQLALCHEMY_MAJOR = 0
SQLALCHEMY_MINOR = 4
SQLALCHEMY_PATCH = 5

(minor, patch) = sqlalchemy.__version__.split('.')[1:]

if minor < SQLALCHEMY_MINOR:
	raise error.LibraryError("SQLAlchemy version %s.%s.%s or above is required" % (SQLALCHEMY_MAJOR, SQLALCHEMY_MINOR, SQLALCHEMY_PATCH))
if patch < SQLALCHEMY_PATCH and minor < SQLALCHEMY_MINOR:
	raise error.LibraryError("SQLAlchemy version %s.%s.%s or above is required"  % (SQLALCHEMY_MAJOR, SQLALCHEMY_MINOR, SQLALCHEMY_PATCH))

addresses_re = re.compile('[0-9., ]+')
def is_addresses(val):
	return bool( addresses_re.match(val) )

class DBBaseInterface(object):
	'''
	The base database interface components
	
	The base interface only does SELECTs (getters), all setters (INSERTs, UPDATEs, DELETEs)
	happen in the DBInterface class.
	'''
	def __init__( self ):
		self.__function_lock = thread.allocate_lock()

	def __del__( self ):
		self._rollback()
	
	def has_min_perms( self, permission ):
		return permission & self._min_perms == permission

	def require_perms( self, permission, error_str=None ):
		if not error_str:
			error_str = "Insufficient Permissions"
		if permission & self._min_perms != permission:
			raise error.InsufficientPermissions( error_str )

	def _create_conn( self ):
		return obj.engine.connect()

	def _begin_transaction( self ):
		"""
		Create a transactional connection and begin the transaction
		"""

		# FIXME: this is not thread-safe
		
		# If we already have a connection, don't create another one
		# This should make nested transactions work properly
		# See: http://www.sqlalchemy.org/docs/05/dbengine.html#dbengine_transactions
		if not hasattr(self, '_conn'):
			# Initial creation of connection and transaction stack
			self._conn = self._create_conn()
			self._trans_stack = [self._conn.begin(),]
		else:
			# We already have a connection, so we're already in a transaction
			# Add the next transaction object to the transaction stack
			self._trans_stack.append(self._conn.begin())
		
	def _commit( self ):
		"""
		Commits the current connection and closes the connection to return it to the pool.
		"""
		
		# Pop the transaction object from the stack and commit it
		self._trans_stack.pop().commit()
		
		if not self._trans_stack:
			# We've committed the root transaction object, we're done! 
			self._conn.close()
		
			del self._conn
			del self._trans_stack
	
	def _rollback( self ):
		"""
		Rollback the transactional connection.
		"""

		# Make sure that the objects exist on self before rolling back.
		# This is done for nested transactions where an inner transaction may
		# call this function and already kill the objects, but the outer transaction
		# will then also call this function
		if hasattr(self, '_trans_stack'):
			for trans in self._trans_stack:
				trans.rollback()
			del self._trans_stack
		
		if hasattr(self, '_conn'):
			self._conn.close()
			del self._conn
	
	def __getattr__(self, name):
		"""
		On missing method
		"""
		if name[:4] == 'get_':
			self.__function_lock.acquire()
			try:
				self.function = getattr( self, '_%s' % name )
				return self._execute_get
			except:
				self.__function_lock.release()
				raise
		raise AttributeError(name)
		
	def _execute_get( self, *args, **kw ):
		"""
		Called by __getattr__, unconditionally executes self.function (set in __getattr__)
		with the given arguments and executes the query.
		
		@return: result of query
		"""
		if not self.__function_lock.locked():
			raise error.FatalException("Somehow, I don't have my __function_lock.  This is very bad.")
		try:
			function = self.function
			del self.function
			self.__function_lock.release()
		except:
			self.__function_lock.release()
			raise
		page = None
		if kw.has_key('page'):
			page = kw['page']
			del kw['page']
		
		limit = None
		if kw.has_key('limit'):
			limit = kw['limit']
			del kw['limit']
			
		order_by = None
		if kw.has_key('order_by'):
			order_by = kw['order_by']
			del kw['order_by']
		
		query = function( *args, **kw )

		# Apply given ORDER BY, OFFSET and LIMIT statements
		if order_by:
			query = query.order_by(order_by)
		if page and limit:
			query = self.__do_page( query=query, page=page, limit=limit)
		elif limit:
			query = query.limit(limit)
		
		query = self._execute( query )
		return query

	def _execute(self, query):
		if hasattr(self, '_conn') and hasattr(self, '_trans_stack'):
			# We're doing transactional stuff, probably because of DBInterface.
			# Use the transactional connection to keep a consistent view of the DB
			result = self._conn.execute(query).fetchall()
		else:
			# No connection exists, just call execute on the connection itself
			my_conn = self._create_conn()
			try:
				result = my_conn.execute(query).fetchall()
				my_conn.close()
			except:
				my_conn.close()
				raise
			
		return result
	
	def __do_page( self, query, page, limit ):
		"""
		Set the offset and limit on a query based on self.__limit and the specified
		page (zero-based index).
		@param query: An sqlalchemy selectable
		@param page: A zero-based index to the desired 'page'
		@param limit: An integer limit to the query
		@return: An sqlalchemy selectable with OFFSET and LIMIT set appropriately.
		"""
		if limit:
			return query.offset( int(page) * int(limit) ).limit(limit)
		else:
			return query
		
	def _is_user_in_group(self, gid):
		"""
		Check to see if the user is in a group to make sure they have permission
		"""
		
		if self.get_users( uid=self._uid, gid=gid ):
			return True
		return False
	
	def _require_perms_on_host(self, permission, mac, error_msg=None):
		"""
		Many functions need to simply make sure that the user has a certain access over a host
		This function does that.
		
		@raise: error.InsufficientPermission if they don't have perms over mac
		@return: None if they have permission 
		"""
		
		if not self.has_min_perms(permission):
			host_perms = obj.perm_query( self._uid, self._min_perms, hosts = True, required_perms = permission )
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = permission )
			
			# Find all hosts where the user has access via networks_to_groups
			net_perms = net_perms.join(obj.addresses, and_(net_perms.c.nid == obj.addresses.c.network, obj.addresses.c.mac==mac))
			
			# Find all hosts where the user has access via hosts_to_groups
			host_perms = host_perms.join(obj.hosts, and_(host_perms.c.mac==obj.hosts.c.mac, obj.hosts.c.mac==mac))
			
			net_hosts = select([obj.addresses.c.mac], from_obj=net_perms)
			group_hosts = select([obj.hosts.c.mac], from_obj=host_perms)
			
			# Execute the queries
			net_hosts = self._execute(net_hosts)
			group_hosts = self._execute(group_hosts)
			
			# If anything exists, we allow this to continue because the user has permissions
			# over that host either via a host group or a network
			# If empty, raise exception
			if not group_hosts and not net_hosts:
				raise error.InsufficientPermissions(error_msg)
			
	def find_owners_of_host(self, mac, get_users=False):
		"""
		Find groups or users who have OWNER over this host
		where their permissions over a group that contains that host is OWNER
		
		@param get_users: whether to go futher than group names and get usernames
		@return: either groups owners or, if get_users=True, usernames
		"""
		
		self.require_perms(perms.READ)
		
		# Groups --> Hosts to Groups
		fromobject = obj.groups.join(obj.hosts_to_groups, and_(obj.hosts_to_groups.c.gid == obj.groups.c.id, obj.hosts_to_groups.c.mac == mac))
		
		# Make sure to OR users_to_groups.host_permissions after finding the user's group permissions
		# Hosts to Groups --> Users to Groups
		fromobject = fromobject.join(obj.users_to_groups, and_(obj.users_to_groups.c.gid == obj.hosts_to_groups.c.gid,
												obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(perms.OWNER)) == str(perms.OWNER)))
		
		if get_users:
			# Users to Groups --> Users
			fromobject = fromobject.join(obj.users, obj.users.c.id == obj.users_to_groups.c.uid)
		
		if get_users:
			query = select([obj.users], from_obj=fromobject, distinct=True)
		else:
			query = select([obj.groups], from_obj=fromobject, distinct=True)
		
		return self._execute(query)
	
	def find_mac_from_lease(self, ip):
		"""
		Get a MAC address back from an IP address lease
		
		@param ip: if specified, return the lease associated with this IP addresses
		@return: mac address or None
		"""
		
		self.require_perms(perms.READ)
		
		query = select([obj.leases.c.mac], obj.leases.c.address==ip)
		
		# This is a special function, not a _get so we have to execute on our own
		return self._execute(query)
	
	def find_expiring_hosts(self):
		"""
		Returns all of the hosts that will be expiring from now up until interval
		"""
		
		self.require_perms(perms.DEITY)
		
		from_object = obj.hosts.join(obj.notifications_to_hosts, obj.notifications_to_hosts.c.mac==obj.hosts.c.mac)
		from_object = from_object.join(obj.notifications, obj.notifications.c.id==obj.notifications_to_hosts.c.nid)
		from_object = from_object.join(obj.hosts_to_groups, obj.hosts_to_groups.c.mac==obj.notifications_to_hosts.c.mac)
		from_object = from_object.join(obj.users_to_groups, obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid)
		from_object = from_object.join(obj.users, obj.users_to_groups.c.uid==obj.users.c.id)
		
		query = select([obj.hosts, obj.notifications_to_hosts.c.id, obj.notifications.c.notification, obj.users.c.username], from_obj=from_object)
		
		# Don't add this to the join above, things get funky
		query = query.where((obj.hosts.c.expires - obj.notifications.c.notification) <= sqlalchemy.sql.func.now())
		
		return self._execute(query)
	
	def _finalize_whereclause(self, whereclause):
		"""
		Accepts an iterable of criterion and creates a SQLAlchemy-ready whereclause
		
		@param whereclause: a list of criterion that will be AND'd together
		"""
		
		if len(whereclause) == 1:
			# We only have one whereclause clause, don't AND anything
			final_whereclause = whereclause[0]
		elif len(whereclause) > 1:
			# More than one whereclause, AND them all together
			final_whereclause = and_(whereclause.pop(), whereclause.pop()) 
			while whereclause:
				final_whereclause = and_(final_whereclause, whereclause.pop())
		else:
			raise error.RequiredArgument("_finalize_whereclause needs a list of criterion")
				
		return final_whereclause
	
	def _get_host_attributes( self ):
		"""Get host attributes
		@param filter: keyword args on which to filter"""
		pass
		
	def _get_host_attribute_values( self, aid ):
		"""Returns all values for a host attribute
		@param aid: the database attribute ID"""
		pass

	def _get_attribute_to_host( self ):
		"""attribute_to_host"""
		# Write later
#		if self._min_perms & perms.READ is perms.READ:
#			relation = select( [obj.attributes_to_hosts] )
#			if mac:
#				relation = relation.where(obj.hosts_to_groups.c.mac == mac)
#			elif gid:
#				relation = relation.where(obj.hosts_to_groups.c.gid == gid)
#		else:
			# TODO: v2: write getting a HTG relation for user's without at least READ permissions
		pass
	
	def _get_addresses(self, address=None, network=None, mac=None, pool=None):
		"""
		Return rows from the addresses table
		
		@param address: an IP address
		@param mac: a MAC address
		@param pool: a pool ID
		@return: rows from the addresses table, filtered by the above parameters
		"""
		
		self.require_perms(perms.READ)
		
		if not address and not mac and not pool:
			self.require_perms(perms.OWNER)
		
		if (address and mac) or (address and pool):
			raise error.RequiredArgument("Address was specified in addition to mac or pool")
		
		query = select( [obj.addresses] )
		
		if address:
			query = query.where(obj.addresses.c.address == address)
		if mac:
			query = query.where(obj.addresses.c.mac == mac)
		if pool:
			query = query.where(obj.addresses.c.pool == pool)
		if network:
			query = query.where(obj.addresses.c.address.op('<<')(network))
			
		return query
		
	
	def _get_host_attribute_value( self ):
		"""attribute_value"""
		pass
	
	def _get_auth_sources( self ):
		"""auth_source"""
		self.require_perms( perms.DEITY )
		query = select([obj.auth_sources,])
		return query
	
	def _get_dhcp_options( self, gid=None, id=None ):
		"""
		Get valid DHCP option types
		
		@param gid: if specified, return option types related to this group id
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		whereclause = None
		
		fromobject = obj.dhcp_options
		
		if gid:
			fromobject = fromobject.join(obj.dhcp_groups.c.id == gid)
		
		if id:
			whereclause = obj.dhcp_options.c.id == id

		query = select([obj.dhcp_options], from_obj=fromobject)

		if whereclause:
			query = query.where(whereclause)

		return query
		
	
	def _get_dhcp_group_options(self, gid=None, rid=None):
		"""
		Get all (or filtered) DHCPOptionToGroup relations
		"""
		pass
	
	def _get_dhcp_groups( self, id=None ):
		"""
		Get DHCP groups, optionally filtered
		@param id: a DHCP group ID, if only one needs to be returned
		"""
		query = select([obj.dhcp_groups])
		
		if id:
			query = query.where(obj.dhcp_groups.c.id == id)

		return query
	
	def _get_dns_records( self, tid=None, id=None, name=None, content=None, mac=None, changed=None, address=None ):
		"""
		Get DNS Records
		
		@param tid: a database DNS record type ID
		@param name: the name of this DNS record for filtering
		@param content: the content field
		@param mac: filter on a mac address
		@param changed: if given, will return the DNS records changed after this datetime.
		@param address: return the A or AAAA record for this IP address
		
		@return: filtered DNS records
		"""
		# A: A record -> IP -> mac
		# CNAME: content=A record name -> IP -> mac,
		# MX: name = A record -> ip -> mac
		# SRV: content = '% <A record name>' -> IP -> mac
		# PTR: name = A record ip_content reverse
		
		self.require_perms( perms.READ )
		columns = [obj.dns_records]
		
		whereclause = []
		
		if id:
			if type(id) is types.IntType:
				whereclause.append( obj.dns_records.c.id == id )
			elif type(id) is types.TupleType or type(id) is types.ListType:
				whereclause.append( obj.dns_records.c.id.in_(id) )
		if address:
			whereclause.append( obj.dns_records.c.ip_content == address )
		if tid:
			whereclause.append( obj.dns_records.c.tid == tid )
		if name:
			name = name.lower()
			if '%' in name:
				# Use a LIKE condition
				whereclause.append( obj.dns_records.c.name.like( name ) )
			else:
				# name = 'exact string'
				whereclause.append( obj.dns_records.c.name == name )
				
		if content:
			# FIXME: is there a better way to do this?
			if validation.is_ip(content): 
				whereclause.append( obj.dns_records.c.ip_content == content  )
			else:
				if '%' in content:
					# Use a LIKE condition
					whereclause.append( obj.dns_records.c.text_content.like( content ) )
				else:
					# content = 'exact string' OR content like '% exact string'
					whereclause.append( or_(obj.dns_records.c.text_content == content, obj.dns_records.c.text_content.like( '%% %s' % content )  ) )
		if changed:
			whereclause.append( obj.dns_records.c.changed >= changed )
		
		if whereclause:
			whereclause = self._finalize_whereclause( whereclause )

		if mac:
			a_records = obj.dns_records.join( obj.addresses, and_(obj.addresses.c.address == obj.dns_records.c.ip_content, obj.addresses.c.mac == mac ) )
			
			a_records_select = select( columns, from_obj = a_records)
			if whereclause:
				a_records_select = a_records_select.where( whereclause )
			
			a_records_result = self._execute(a_records_select)
			
			ptr_names = []
			for rr in a_records_result:
				ptr_names.append(IPy.IP(rr['ip_content']).reverseName()[:-1])
				
			ptr_records =  select( columns ).where(obj.dns_records.c.name.in_(ptr_names))
			if whereclause:
				ptr_records = ptr_records.where( whereclause )
			
			# The universe of all DNS records where the name is the A record's name
			same_name_records = obj.dns_records.join( a_records_select.alias('a_records'), obj.dns_records.c.name==a_records_select.alias('a_records').c.name)
			
			# The universe of all DNS records where the text_content is the A record's name
			content_is_name_records = obj.dns_records.join( a_records_select.alias('a_records'), obj.dns_records.c.text_content==a_records_select.alias('a_records').c.name)
			
			# The universe of all DNS records where the text_content is like '% <the A record's name>'
			# like_name_records = obj.dns_records.join( a_records_select.alias('a_records'), obj.dns_records.c.name.like('_%%._%%.%s' % a_records_select.alias('a_records').c.name))

			# Find all records where the name is the same as any A record we found
			same_name_select = select( columns, from_obj=same_name_records)
			if whereclause:
				same_name_select = same_name_select.where( whereclause )
				
			# Find all records where the text_content is the same as any A record we found
			content_is_name_select = select( columns, from_obj=content_is_name_records)
			if whereclause:
				content_is_name_select = content_is_name_select.where( whereclause )

			# Select, and filter to just SRV records
			# srv_records = select( columns, from_obj=like_name_records).where(obj.dns_records.c.tid == 33)
			# if whereclause:
			#	srv_records = srv_records.where( whereclause )

			query = union( a_records_select, same_name_select, content_is_name_select, ptr_records ) #, srv_records )
		else:
			from_object = obj.dns_records
			query = select( [obj.dns_records], from_obj = from_object )

			if whereclause:
				query = query.where( whereclause )
			else:
				self.require_perms( perms.DEITY, "You're trying to retrieve all DNS records ... why?" )

		return query
	
	def _get_dns_types( self, only_useable=False ):
		"""
		Returns all DNS resource record types
		"""
		
		query = select([obj.dns_types])
		
		if only_useable:
			query = query.where( and_(not_(obj.dns_types.c.min_permissions == '00000000'), obj.dns_types.c.min_permissions.op('&')(str(self._min_perms)) == obj.dns_types.c.min_permissions))

		return query

	def _get_dns_views( self ):
		"""Return a list of all DNS views"""
		pass
	
	def _get_domains( self, did=None, name=None, contains=None, gid=None, additional_perms='00000000', columns=None, show_reverse=True ):
		"""
		Return a filtered list of domains
		Search through domains by passing a percent sign (%) in the name param
		
		@param did: return only one domain of this ID
		@param name: return only one domain of this name
		@param gid: return only the domains in this group ID
		@param contains: return the most specific domain containing this name
		@param additional_perms: require these additional permissions also
		@param show_reverse: whether or not to show reverse lookup (in-addr.arpa) domains 
		"""
		# require read permissions over associated domains
		required_perms = perms.READ
			
		if additional_perms:
			required_perms = required_perms | additional_perms
			
		# Permissions may be a little bit screwy...again
		if self.has_min_perms(required_perms): 
			query = obj.domains
			if gid:
				query = query.join(obj.domains_to_groups, and_(obj.domains.c.id == obj.domains_to_groups.c.did, obj.domains_to_groups.c.gid==gid))
		else:
			domain_perms = obj.perm_query( self._uid, self._min_perms, domains = True, gid=gid, required_perms = required_perms )
			query = domain_perms.join(obj.domains, obj.domains.c.id == domain_perms.c.did )
		
		if not columns:
			columns = [obj.domains]
		
		query = select(columns, from_obj=query )
		
		if did:
			query = query.where(obj.domains.c.id == did)
		if name:
			if '%' in name:
				query = query.where(obj.domains.c.name.like(name))
			else:
				query = query.where(obj.domains.c.name==name)
		if contains:
			domains = []
			
			if type(contains) is types.ListType or type(contains) is types.TupleType:
				# We have been given a list of names (whether hostnames or domain names),
				# return a list of only the first-level containing domains for every name.
				# ie ... this does NOT do the normal functionality of returning all containing
				# domains, just the first-level for each

				for record in contains:
					# If record is "test.place.example.com", we will append "place.example.com" to the list of domains
					domains.append('.'.join( record.split('.')[1:] ))
					
				# If record is "example.com", we need to include that also because it could be a domain
				# So, just include all the original record names
				domains += contains
			else:
				# Find all of the containing domains for this single hostname
				names = contains.split('.')
				while names:
					domains.append('.'.join(names))
					del names[0]
					
			# Apply our search list to the query
			query = query.where(obj.domains.c.name.in_(domains))
		
			# Awesome...order by descending on the length of domain names.
			# Gives the most specific domains first, followed by the rest.
			query = query.order_by(sqlalchemy.sql.func.length(obj.domains.c.name).desc())
		if not show_reverse:
			query = query.where(not_(obj.domains.c.name.like('%.in-addr.arpa')))
		
		return query
	
	def _get_expiration_types( self ):
		"""
		Return expiration types that this user can access
		"""
		
		query = select( [obj.expiration_types.c.id, obj.expiration_types.c.expiration], obj.expiration_types.c.min_permissions <= str(self._min_perms) )
		
		return query
	
	def _get_guest_tickets(self, ticket=None, uid=None):
		"""
		Get guest tickets
		
		@param ticket: get the information related to this ticket name
		@param uid: only get tickets tied to this user ID
		@return: rows from the guest_tickets table
		"""
		
		if (not ticket and not uid):
			raise error.RequiredArgument("Must specify at least one of name or uid to get guest tickets")
		
		query = select( [obj.guest_tickets] )
		
		if ticket:
			query = query.where(obj.guest_tickets.c.ticket == ticket)
			
		if uid:
			if self._uid != uid and not self.has_min_perms(perms.DEITY):
				# I'm not a DEITY and I'm trying to get someone else's tickets
				raise error.InsufficientPermissions()
			
			query = query.where(obj.guest_tickets.c.uid == uid) 
			
		return query
			
	def _get_groups( self, gid=None, name=None, ignore_usergroups=False, uid=None, additional_perms=None):
		"""
		Return groups
		
		@param gid: return a single group of this database ID
		@param name: return a single group of this name
		@param ignore_usergroups: a boolean, if true no groups prepended with 'user_' will be returned
		@param uid: a user's database ID, returns a user's groups, optionally filtered by permissions in that group
		@param additional_perms: return groups where the users_to_groups.permissions meet these additional permission requirements
		"""
		
		# require read permissions over associated groups
		self.require_perms(perms.READ)
		
		if gid and name:
			raise error.RequiredArgument("Specify exactly one of gid or name")
		if (gid or name or ignore_usergroups) and (uid or additional_perms):
			raise error.RequiredArgument("If uid or additional_perms is specified, you cannot filter by gid, name, or use ignore_usergroups.")
		
		if uid:
			if additional_perms is None:
				additional_perms = '00000000'
				
			fromobj = obj.groups.join(obj.users_to_groups, and_(and_(obj.groups.c.id==obj.users_to_groups.c.gid, obj.users_to_groups.c.uid == uid), 
												obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(additional_perms)) == str(additional_perms)))
		else:
			fromobj = obj.groups
		
		query = select( [obj.groups], from_obj=fromobj )
		
		if gid:
			query = query.where(obj.groups.c.id == gid)
		if name:
			query = query.where(obj.groups.c.name == name)
		if ignore_usergroups:
			query = query.where(not_(obj.groups.c.name.like('user_%')))
			
		return query
	
	def _get_hosts( self, mac=None, hostname=None, ip=None, network=None, uid=None, username=None, gid=None, columns=None, additional_perms=None, show_expired=True, show_active=True, only_dynamics=False, only_statics=False, funky_ordering=False ):
		"""
		Get hosts and DNS records from the DB
		@param mac: return a list containing the host with this mac
		@param hostname: hostname (allowing wildcards) on which to filter
		@param ip: return host associated (statically) with this IP
		@param network: network on which to filter
		@param username: a username on which to filter
		@param gid: return only the hosts in this group ID
		@param columns: list of columns to select. defaults to [obj.hosts]
		@param additional_perms: return hosts that meet these additional permission requirements
		@param show_expired: default true, will show all hosts that have expired before now. If false, will only show non-expired hosts.
		@param show_active: default true, will show all hosts that are active now. If false, will not show non-expired hosts.
		@param only_dynamics: only return dynamic addresses 
		@param only_statics: only return statics addresses
		@param funky_ordering: if on, hosts are ordered by hostname length ... fixes problems with guest registrations
		"""

		# require read permissions over hosts
		required_perms = perms.READ
		
		if additional_perms != None:
			required_perms = required_perms | additional_perms
		
		# Extremely important to have this ... BAD bad things happen if hostnames are ever mixed-case
		if hostname != None:
			# Make sure the hostname is always lower case
			if type(hostname) is types.ListType or type(hostname) is types.TupleType:
				hostname = [name.lower() for name in hostname]
			else:
				hostname = hostname.lower()
		
		if (only_dynamics and only_statics):
			raise error.RequiredArgument("Cannot specify both only_dynamics and only_statics")
		
		if not columns:
			columns = [obj.hosts]

		if funky_ordering:
			columns.append(sqlalchemy.sql.func.length(obj.hosts.c.hostname).label('len'))
			
		# If username was passed in, get the uid
		if username:
			user = self.get_users(username=username)
			if not user:
				raise error.NotUser("No user found named %s" % username)
			uid = user[0]['id']
			
		# Filter and make the whereclause
		
		whereclause = []
		
		# Apply all the filtering that was specified
		if ip != None:
			# This allows us to search on IP addresses that are dynamically assigned
			lease = self.get_leases(address=ip, show_expired=False)
			if lease:
				mac = lease[0]['mac']
				ip = None
			else: 
				whereclause.append(obj.addresses.c.address==ip)
		if only_statics:
			whereclause.append(obj.addresses.c.mac == obj.hosts.c.mac)
		if mac != None:
			whereclause.append(obj.hosts.c.mac==mac)
		if hostname != None:
			if type(hostname) is types.ListType or type(hostname) is types.TupleType:
				whereclause.append(obj.hosts.c.hostname.in_( hostname ))
			elif '%' in hostname:
				whereclause.append(obj.hosts.c.hostname.like( hostname ))
			else:
				whereclause.append(obj.hosts.c.hostname == hostname)
		if network != None:
			whereclause.append(obj.addresses.c.address.op('<<')(network))
		if not show_expired:
			whereclause.append(obj.hosts.c.expires >= sqlalchemy.sql.func.now())
		if not show_active:
			whereclause.append(obj.hosts.c.expires < sqlalchemy.sql.func.now())

		# Finalize the WHERE clause
		if whereclause:
			whereclause = self._finalize_whereclause( whereclause )
		
		# Check permissions and generate the query
		if self.has_min_perms( required_perms ):
			hosts = obj.hosts.outerjoin(obj.addresses, obj.hosts.c.mac==obj.addresses.c.mac)
			
			if gid:
				hosts = hosts.join(obj.hosts_to_groups, and_(obj.hosts.c.mac == obj.hosts_to_groups.c.mac, obj.hosts_to_groups.c.gid==gid))
			if only_dynamics:
				hosts = hosts.join(obj.hosts_to_pools, obj.hosts_to_pools.c.mac == obj.hosts.c.mac)
			if uid:
				hosts = hosts.join(obj.hosts_to_groups, obj.hosts.c.mac == obj.hosts_to_groups.c.mac)
				# Make sure to bitwise OR users_to_groups.host_permissions after finding the user's group permissions
				hosts = hosts.join(obj.users_to_groups, and_(obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid,
									and_(obj.users_to_groups.c.uid == uid,
									obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(perms.OWNER)) == str(perms.OWNER))))
			
			# Create the selectable	
			hosts = select( columns, from_obj=hosts, distinct=True )
			if whereclause:
				hosts = hosts.where( whereclause )
	
			# Funky ordering to order by length ... fixes problems with guest registrations
			# because, technically, 11 in ASCII is before 9 in ASCII ... think about it 	
			if funky_ordering:
				hosts = hosts.order_by('len DESC').order_by(obj.hosts.c.hostname.desc())
			
			return hosts
		else:
			# Get our permissions over hosts
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = required_perms )
			
			# Get our permissions over networks
			host_perms = obj.perm_query( self._uid, self._min_perms, hosts = True, required_perms = required_perms )

			# Find
			net_hosts = net_perms.join( obj.networks, obj.networks.c.network == net_perms.c.nid )
			net_hosts = net_hosts.join( obj.addresses, obj.networks.c.network == obj.addresses.c.network )
			net_hosts = net_hosts.join( obj.hosts, obj.hosts.c.mac == obj.addresses.c.mac )
			direct_hosts = host_perms.join( obj.hosts, obj.hosts.c.mac == host_perms.c.mac )

			if gid:
				net_hosts = net_hosts.join(obj.hosts_to_groups, and_(obj.hosts.c.mac == obj.hosts_to_groups.c.mac, obj.hosts_to_groups.c.gid==gid))
				direct_hosts = direct_hosts.join(obj.hosts_to_groups, and_(obj.hosts.c.mac == obj.hosts_to_groups.c.mac, obj.hosts_to_groups.c.gid==gid))
			if only_dynamics:
				net_hosts = net_hosts.join(obj.hosts_to_pools, obj.hosts_to_pools.c.mac == obj.hosts.c.mac)
				direct_hosts = direct_hosts.join(obj.hosts_to_pools, obj.hosts_to_pools.c.mac == obj.hosts.c.mac)
			if uid:
				net_hosts = net_hosts.join(obj.hosts_to_groups, obj.hosts.c.mac == obj.hosts_to_groups.c.mac)
				direct_hosts = direct_hosts.join(obj.hosts_to_groups, obj.hosts.c.mac == obj.hosts_to_groups.c.mac)
				
				net_hosts = net_hosts.join(obj.users_to_groups, and_(obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid, obj.users_to_groups.c.uid == uid))
				direct_hosts = direct_hosts.join(obj.users_to_groups, and_(obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid, obj.users_to_groups.c.uid == uid))
			
			# Create the selectables
			net_select = select( columns, from_obj=net_hosts, distinct=True )
			host_select = select( columns, from_obj=direct_hosts, distinct=True )
			
			if whereclause:
				net_select = net_select.where( whereclause )
				host_select = host_select.where( whereclause )
				
			accessible_hosts = net_select.union( host_select )

			return accessible_hosts
		
	def _find_permissions_for_objects(self, objects, primary_table, primary_key, bridge_table, foreign_key, alternate_perms_key=None ):
		'''
		Returns a dictionary of { object's primary key : permissions bitstring } 
		for this user's overall permissions on the objects
		
		@param objects: A list of dictionaries of objects to find permissions for, usually hosts or
		domains, or a list of primary key values
		@param primary_table: A SQLAlchemy table object, usually obj.some_table
		@param primary_key: A SQLAlchemy column object, usually obj.some_table.c.id
		@param bridge_table: A SQLAlchemy table object, usually obj.something_to_groups 
		@param foreign_key: A SQLAlchemy column object, usually obj.something_to_groups.c.xid
		@param alternate_perms_key: A SQLAlchemy column object, usually obj.some_table.c.some_name, that
		will be used as the key for the returned permissions object. If not specified, the
		primary_key's name is used. This better be a unique column or bad things may happen.
		'''
		
		primary_key_name = primary_key.name
		
		# Create a list of primary key IDs
		
		if objects and (type(objects[0]) is types.DictionaryType or type(objects[0] is sqlalchemy.engine.base.RowProxy)):
			objects_list = [object[primary_key_name] for object in objects]
		else:
			objects_list = objects
			
		if not objects_list:
			return [{}]
		
		# Query for the objects, LEFT joining permissions
		fromobj = (bridge_table.join( primary_table, and_(foreign_key==primary_key, primary_key.in_(objects_list) ) )
			.outerjoin(obj.users_to_groups, and_(obj.users_to_groups.c.gid==bridge_table.c.gid, obj.users_to_groups.c.uid == self._uid)))
		
		columns = [primary_key, obj.users_to_groups.c.permissions, obj.users_to_groups.c.host_permissions]
		
		if alternate_perms_key:
			columns += [alternate_perms_key]
		
		query = select(columns, from_obj=fromobj)
		
		results = self._execute(query)
		
		permissions = {}
		
		# If the alternate_perms_key is specified, use that for our permissions object
		perms_key_name = alternate_perms_key.name if alternate_perms_key else primary_key_name
		
		# Initialize the permissions dictionary with my min_perms for every element
		for row in results:
			permissions[row[perms_key_name]] = str(self._min_perms)
		
		# This section inherently takes care of having permissions to an object via multiple groups
		# ie. A host can be in multiple groups and the final permissions you have over that host
		# is a bitwise OR of ALL of those permission sets (and your min_permissions)
		for row in results:
			# Because we LEFT JOINed, row['permissions'] will be NULL if we don't have group access over this object 
			if row['permissions']:
				permissions[row[perms_key_name]] = str((Perms(permissions[row[perms_key_name]]) | row['permissions']) | row['host_permissions'])
			else:
				permissions[row[perms_key_name]] = str(self._min_perms)
			
		return [permissions]
	
	def find_permissions_for_hosts(self, hosts, alternate_perms_key=None):
		'''
		Returns a dictionary of { MAC (or alternate_perms_key) : permissions bitstring } 
		for this user's overall permissions on the each host
		
		@param host: a list of dictionaries of hosts (or a list of MACs).
		The dictionary must have 'mac' key, all others keys are not used
		'''
		
		return self._find_permissions_for_objects(objects=hosts, primary_table=obj.hosts, primary_key=obj.hosts.c.mac, bridge_table=obj.hosts_to_groups, foreign_key=obj.hosts_to_groups.c.mac, alternate_perms_key=alternate_perms_key)
	
	def find_permissions_for_domains(self, domains, alternate_perms_key=None):
		'''
		Returns a dictionary of { domain ID : permissions bitstring } 
		for this user's overall permissions on the each domain
		
		@param domains: a list of dictionaries of domains (or a list of domain IDs).
		The dictionary must have 'id' key, all others keys are not used
		'''
		
		return self._find_permissions_for_objects(objects=domains, primary_table=obj.domains, primary_key=obj.domains.c.id, bridge_table=obj.domains_to_groups, foreign_key=obj.domains_to_groups.c.did, alternate_perms_key=alternate_perms_key)
	
	def find_permissions_for_dns_records(self, records):
		'''
		Returns a dictionary of { DNS record ID : permissions bitstring } 
		for this user's overall permissions on the DNS records
		
		@param records: a list of dictionaries of DNS records, or a list of DNS record names
		'''
		
		print '&&&'
		print records
		
		if not records:
			return {}
		
		if isinstance(records[0], dict):
			# Create a list of names, get the hosts who have those names, then get the permissions for those hosts
			names = [row['name'] for row in records]
		elif isinstance(records[0], str):
			names = records
		else:
			raise error.NotImplemented("Please supply list of dictionaries or a list of strings. Type given: %s" % type(records[0]))

		hosts = self.get_hosts( hostname=names )
		
		host_perms = self.find_permissions_for_hosts( hosts, alternate_perms_key=obj.hosts.c.hostname )
		
		host_perms = host_perms[0] if host_perms else {}

		# Get the domains who have those names, then get the permissions for those domains
		domains = self.get_domains( contains=names )
		domain_perms = self.find_permissions_for_domains( domains )
		
		domain_perms = domain_perms[0] if domain_perms else {}
		
		# Get the DNS types so that we can clear permissions to default if they can't read the type
		dns_types = self.get_dns_types( only_useable=True )
		dns_type_perms = {}
		# Have [ { 'id' : 0, 'name' : 'blah' }, ... ]
		for type in dns_types:
			dns_type_perms[type['id']] = type
		# Now have { 0 : { ... dns dict ... }, 12 : { ... dns dict ... } ... }
		
		permissions = {}
		
		# Initialize the permissions dictionary with my min_perms to GUARANTEE a result for every record input
		for rr in records:
			permissions[rr['id']] = str(self._min_perms)
		
		# Turn the domain_perms from { domain ID : permissions } into { name : permissions } so that we can do O(1) lookups
		domain_name_perms = {}
		for id in domain_perms:
			# Hmm ... can we do this better than O(n^2)? probably...
			
			# Search through the hosts for this ID and, when found, take the name and
			# add that to domain_name_perms with the ID's original permissions
			for domain in domains:
				if domain['id'] == id:
					# We found the correct row, strip the name out and add it to the domain_name_perms dictionary
					domain_name_perms[domain['name']] = domain_perms[id]
					break
				
		for rr in records:
			# For every record that was a host, add that permission set to the final result
			
			if host_perms.has_key(rr['name']):
				permissions[rr['id']] = str(Perms(permissions[rr['id']]) |  host_perms[rr['name']])
			
			first_level_domain_name = '.'.join(rr['name'].split('.')[1:])

			# For every record that was a domain, or had permissions via a domain, add in those permissions
			if domain_name_perms.has_key(rr['name']) or domain_name_perms.has_key( first_level_domain_name ):
				perms_to_add = domain_name_perms[rr['name']] if domain_name_perms.has_key(rr['name']) else domain_name_perms[first_level_domain_name]
				permissions[rr['id']] = str(Perms(permissions[rr['id']]) |  perms_to_add)
				
			# If they cannot use the DNS type of this record, even if they have host
			# or domain perms over it, then they cannot modify it 
			if not dns_type_perms.has_key(rr['tid']):
				permissions[rr['id']] = str(backend.db_default_min_permissions)

		return [permissions]
	
	def _get_hosts_to_groups( self, mac=None, gid=None ):
		"""
		Return rows of hosts_to_groups
		"""
		
		if not mac and not gid:
			raise error.RequiredArgument("Must specify mac and/or gid")
		
		# Require read perms on the group
		if self.has_min_perms(perms.READ):
			relation = select( [obj.hosts_to_groups] )
			if mac:
				relation = relation.where(obj.hosts_to_groups.c.mac == mac)
			if gid:
				relation = relation.where(obj.hosts_to_groups.c.gid==gid)
		else:
			# TODO: v2: write getting a HTG relation for user's without at least READ permissions
			raise error.NotImplemented("You should never see this")
			
		return relation
	
	def _get_hosts_to_pools(self, mac=None):
		"""
		Get hosts_to_pools relations
		"""
		
		if mac:
			self.require_perms(perms.READ)
		else:
			self.require_perms(perms.DEITY)
			
		query = select([obj.hosts_to_pools.c.id])
		
		if mac:
			query = query.where(obj.hosts_to_pools.c.mac==mac)
		
		return query
	
	def _get_leases(self, address=None, mac=None, show_expired=True):
		"""
		Get leases
		"""
		
		if address:
			self.require_perms(perms.READ)
			query = select( [obj.leases] ).where(obj.leases.c.address == address)
		elif mac:
			self.require_perms(perms.OWNER)
			query = select( [obj.leases] ).where(obj.leases.c.mac == mac)
		else:
			raise error.RequiredArgument( 'Exactly one of mac or address required' )

		if not show_expired:
			query = query.where( obj.leases.c.ends > sqlalchemy.sql.func.now() )
		
		return query
	
	def _get_internal_auth( self, uid ):
		"""
		Get a row from internal_auth
		"""
		
		self.require_perms( perms.DEITY )
		
		return select( [obj.internal_auth], obj.internal_auth.c.id == uid )

	def _get_networks( self, nid=None, network=None, gid=None, address=None, additional_perms='00000000' ):
		'''
		Return networks
		@param nid: the database network id, returns one network
		@param network: a CIDR address, returns one network
		@param gid: return on the networks within this group ID
		'''
		
		# require read permissions over networks
		required_perms = perms.READ
			
		if additional_perms:
			required_perms = required_perms | additional_perms
		
		if self.has_min_perms( required_perms ):
			query = obj.networks
		else:
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = required_perms )
			query = net_perms.join(obj.networks, obj.networks.c.network == net_perms.c.nid )

		if gid:
			query = query.join(obj.networks_to_groups, and_(obj.networks.c.network == obj.networks_to_groups.c.nid, obj.networks_to_groups.c.gid==gid))			
		
		# Create the selectable
		query = select( [obj.networks], from_obj=query )

		if nid:
			query = query.where(obj.networks.c.network == nid)
		if network:
			query = query.where(obj.networks.c.network==network)
		if address:
			query = query.where(obj.networks.c.network.op('>>')(address))
		
		return query 
					
	def _get_networks_to_groups( self, nid=None, gid=None ):
		"""
		Get a networks_to_groups row
		"""
		
		# Require read perms on the group
		if self._min_perms & perms.READ is perms.READ:
			relation = select( [obj.networks_to_groups] )
			relation = relation.where(and_(obj.networks_to_groups.c.nid == nid, obj.networks_to_groups.c.gid==gid))
		else:
			# TODO: v2: write getting a HTG relation for user's without at least READ permissions
			pass
		
	def _get_notifications( self):
		"""
		Get all notification types
		"""
		
		self.require_perms(perms.READ)
		
		query = select([obj.notifications])
		
		return query
		
	def _get_pools( self, name=None ):
		'''
		Return pools
		
		@param name: the pool name
		'''

		# Permissions
		self.require_perms(perms.DEITY)
		
		# Set base query
		query = select([obj.pools])
		
		if name != None:
			query = query.where(obj.pools.c.name == name)

		return query
		
	def _get_disabled( self, mac=None ):
		'''
		Return pools
		
		@param name: the pool name
		'''

		# Permissions
		self.require_perms(perms.OWNER)
		
		# Set base query
		query = select( [obj.disabled] )
		
		if mac:
			query = query.where(obj.disabled.c.mac == mac)

		return query
		
	def _get_permissions(self):
		'''
		Return all of the permission types present in the database
		'''
		
		self.require_perms(perms.READ)
		
		query = select([obj.permissions])
		
		return query
		
	def is_disabled(self, mac=None, address=None):
		'''
		If disabled, return a list containing the disabled record, else an empty list
		'''
		# Is there an XOR boolean operator?
		if (not address and not mac) or (address and mac):
			raise error.RequiredArgument('You must specify exactly one of mac or address: address=%s, mac=%s' % (address, mac))
		
		self.require_perms(perms.READ)
		if mac:
			query = select([obj.disabled]).where( obj.disabled.c.mac == mac )
		elif address:
			query = select([obj.disabled], from_obj = obj.disabled.join( obj.leases, obj.leases.c.mac == obj.disabled.c.mac) )
			query = query.where( obj.leases.c.address == address )
		
		return self._execute( query )
		
	def _get_supermaster( self ):
		"""supermaster"""
		# ???
		pass
		
	def _get_users( self, uid=None, username=None, source=None, gid=None ):
		'''
		Return a filtered list of users
		@param uid: a database user id
		@param username: a database username
		@param page: A zero-based index to the desired 'page'
		@param gid: return only the users within this group ID
		'''

		# Permissions
		self.require_perms(perms.READ)
		
		columns = [obj.users]
		
		query = obj.users
		
		if gid:
			columns.append(obj.users_to_groups.c.permissions)
			query = obj.users.join(obj.users_to_groups, and_(obj.users.c.id == obj.users_to_groups.c.uid, obj.users_to_groups.c.gid==gid))

		# Set base query
		query = select(columns, from_obj=query)
		
		if username:
			if '%' in username:
				query = query.where(obj.users.c.username.like(username))
			else:
				query = query.where(obj.users.c.username == username)
		if uid != None:
			query = query.where(obj.users.c.id == uid)
		if source != None:
			query = query.where(obj.users.c.source == source)

		return query
	
	def _get_user_to_group( self ):
		"""
		Get a row from users_to_groups
		"""
		
		pass
		
	def _get_vlan( self ):
		"""vlan"""
		pass
		
	def _get_vlan_to_group( self ):
		"""vlan_to_group"""
		pass

class DBBackendInterface( DBBaseInterface ):
	def __init__(self):
		DBBaseInterface.__init__( self )
		self._min_perms = perms.READ

class DBInterface( DBBaseInterface ):
	'''Components that write to the database
	
		Every function should create a query and execute it using
		the _execute_set( query ) function for single CRUD operations.
		
		For functions that do multiple CRUD operations, use a transaction:
		------
		self._begin_transaction()
		try:
			query = self._execute_set( ... some query ... )
			self.add_thing_to_group( ... this function executes a query ... )
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		------
	'''
	def __init__(self, username, uid=None, min_perms=None):
		'''
		@param uid: the user's database ID
		@param username: the user's username
		@param min_permissions: the user's minimum permissions set
		'''
		DBBaseInterface.__init__( self )
		self._username = username
		if not uid or not min_perms:
			# bootstrap - this perm is required to do the query
			self._min_perms = perms.READ
			user = self.get_users(username=username)[0]
			uid = user['id']
			min_perms = user['min_permissions']
		self._uid = uid
		self._min_perms = Perms(min_perms)
	
	def _execute_set(self, query, **kw):
		"""
		Execute the given query. If in a transaction, I'll use that transactional
		connection. Otherwise, a non-transactional, auto-commiting connection will
		be created, used, and closed.
		
		@param query: a query object to execute
		@param **kw: additional arguments to pass to the execute function
		"""
		
		if hasattr(self, '_conn'):
			# We are currently in a transaction, so just execute the given query
			# The caller must commit manually after all queries have been executed
			result = self._conn.execute(query, **kw)
		else:
			# We are not in a transaction, so create a non-transactional, auto-committing
			# connection and execute the query. After, close the connection.
			
			conn = obj.engine.connect()
			result = conn.execute(query, **kw)
			conn.close()
		
		return result

#	def __increment_soa_serial(self, domain_id, view_id = None):
#		soa_q = select( [obj.dns_records.c.id,obj.dns_records.c.vid,obj.dns_records.c.text_content,],
#				from_obj=obj.dns_records.join(obj.domains, obj.domains.c.id == obj.dns_records.c.did )
#				).where( obj.domains.c.name == obj.dns_records.c.name ).where( obj.dns_records.c.did == domain_id ).where(obj.dns_records.c.vid == view_id).where(obj.dns_records.c.tid == )
#		soa = self._execute(soa_q)
#		if len(soa) > 1:
#			raise error.NotUnique('There is more than one SOA in this view and domain by this name.  You should go and rethink your life.')
#		if soa:
#			soa=soa[0]
#			values = soa['text_content'].split(' ')
#			values[2] = str(int(values[2])+1)
#			update_q = obj.dns_records.update( obj.dns_records.id == soa['id'], values={'text_content':' '.join(values)} )
#			self._execute_set( update_q )
#		else:
#			# FIXME: no SOA?
#			pass

	def _finalize_expires(self, expires, expiration_format=None):
		"""
		Makes expires a SQL-Alchemy capable datetime, whether it already is or is a string with an expiration format
		"""

		# Make sure we have an appropriate datetime object
		#if expires and not isinstance(expires, datetime.datetime) and not isinstance(expires, datetime.date):
		if expiration_format:
			# there has to be a better way than this...
			expires = datetime.datetime(*time.strptime(expires, expiration_format)[0:6])
		else:

			if expires and isinstance(expires, datetime.date):
				# Need to make this datetime.date a datetime.datetime
				expires = datetime.datetime.combine(expires, datetime.time(0))

			if expires and not isinstance(expires, datetime.datetime):
				try:
					# xmlrpclib happily converts datetime.datetime to xmlrpclib.DateTime (which is a string in ISO 8601 format)
					expires = datetime.datetime.strptime( str( expires ), '%Y%m%dT%H:%M:%S' )
				except ValueError, e:
					raise error.RequiredArgument("Could not convert expires to datetime object (from %s %s) -- expiration_format must be specified for strings" % (repr(expires),type(expires)))
		return expires
	
	def add_address( self, address, network, mac=None, pool=None, reserved=False ):
		"""
		Add an address in either the specified pool or belonging to the specified MAC.
		
		@param address: the IP address to add
		@param mac: the MAC address this ip belongs to
		@param pool: the pool id of the pool this ip belongs to
		@param reserved: a boolean of if this address is reserved (broadcast, network, and others)
		"""

		self.require_perms( perms.DEITY )

		query = obj.addresses.insert( values={'address':address,
									'network':network,
									'mac':mac,
									'pool':pool,
									'reserved': reserved } )
		return self._execute_set(query)
	
	def update_address(self, address, mac=None, pool=None):
		"""
		Update a row in the addresses table
		"""
		
		if mac and pool:
			raise error.RequiredArgument("Specify exactly one of MAC or pool")
		
		if not self.has_min_perms( perms.DEITY ):
			
			# FIXME: since this function is only called in the convert script and in
			# the service desk hacks, I'm making it required to be DEITY...
			# When fixed, the permissions need be thought through more thoroughly, especially
			# in relation to having permissions over a host directly instead of over the containing networks
			
			raise error.NotImplemented("Updating an address as a non-admin is not implemented yet.") 
		
#			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = perms.MODIFY, do_subquery=False, andwhere=obj.networks_to_groups.c.nid.op('>>')(address) )
#			net_perms = self._execute(net_perms)
#		
#			if not net_perms:
#				raise error.InsufficientPermissions("Insufficient permissions to update the %s address." % address)
		
		# FIXME: take care of "reserved" ... right now just doesn't change whatever it is set to and has DB constraints
		query = obj.addresses.update(obj.addresses.c.address == address, values = { 'mac' : mac, 'pool' : pool })
		
		return self._execute_set(query)

	def add_pool( self, name, description = None, allow_unknown=False, allow_known=True, lease_time=None, dhcp_group=None ): 
		"""
		Add a pool with the given values
		"""
		
		self.require_perms( perms.DEITY )

		query = obj.pools.insert( values={'name' : name,
									'description' : description,
									'allow_unknown' : allow_unknown,
									'lease_time' : lease_time,
									'allow_known': allow_known,
									'dhcp_group' : dhcp_group } )

		return self._execute_set(query)
	
	def add_pool_to_group( self, pool, gid ):
		"""
		Add a pool to a group
		"""
		
		self.require_perms(perms.DEITY)
		
		query = obj.pools_to_groups.insert( values={ 'pool' : pool, 'gid' : gid } )
		return self._execute_set( query )
		

	def add_host_to_pool( self, mac, pool_id ):
		"""
		Give the host permission to get addresses from pool
		"""
		if not self.has_min_perms( perms.ADD ):
			# Get our permissions over pools
			pool_perms = obj.perm_query( self._uid, self._min_perms, pools = True, required_perms = perms.ADD, do_subquery=False, andwhere = obj.pools_to_groups.c.pool==pool_id )
			pools = self._execute( pool_perms )
			if not pools:
				raise error.InsufficientPermissions('ADD permission required over pool id %s' % pool_id)
		
		query = obj.hosts_to_pools.insert( values={ 'mac' : mac, 'pool_id' : pool_id } )
		
		return self._execute_set( query )

	def add_host_attribute( self,  name, description=None, use_values=False, is_required=False ):
		"""
		Add a host attribute
		@param name: the attribute name
		@param description: a description of the host attribute
		@param use_value: boolean of if this attribute uses selectable items from attribute_values
		@param is_required: boolean of if this attribute is required or not
		"""
		pass
				
	def update_host_attribute( self, aid, name, description=None, use_values=False, is_required=False ):
		"""
		Update a host attribute
		@param aid: the database attribute id
		@param name: the attribute name
		@param description: a description of the host attribute
		@param use_value: boolean of if this attribute uses selectable items from attribute_values
		@param is_required: boolean of if this attribute is required or not
		"""
		pass
	
	def update_host_attribute_values( self, aid, values ):
		"""
		Adds values tied to a custom host attribute (deletes all old values and adds the new ones)
		@param aid: the database attribute id
		@param values: a tuple or list of values for this attribute
		"""
		pass

	def add_attribute_to_host( self ):
		"""attribute_to_host"""
		pass
		
		
	def add_auth_source( self ):
		"""auth_source"""
		pass
		
		
	def add_dhcp_option( self ):
		"""dhcp_option"""
		pass
		
		
	def add_soa_record( self, name, primary, hostmaster, serial=0, refresh=10800, retry=3600, expire=604800, default_ttl=3600 ):
		"""Add an SOA using add_dns_record()
			@param name: name for SOA record
			@param primary: primary name server for this SOA
			@param hostmaster: email address ( no dots before the @, because of the broken way these records work )
			@param serial: leave this at 0 unless your _really_ know what you are doing
			@param refresh:
			@param retry:
			@param expire:
			@param default_ttl: """
		
		self.require_perms(perms.DEITY)
		
		content = "%(primary)s %(hostmaster)s %(serial)d %(refresh)d %(retry)d %(expire)d %(default_ttl)d" % locals()
		return self.add_dns_record( name=name, text_content=content, tid=6 )

	def add_dns_record( self, name, tid, ip_content=None, text_content=None, priority=None, vid=None, add_ptr=True ):
		"""Add a DNS resource record
			@param name: name for SOA record
			@param tid: the database type ID
			@param ip_content:
			@param text_content:
			@param add_ptr: Adds a PTR record when an A record is added
			"""
		if (not ip_content and not text_content) or (ip_content and text_content):
			raise error.RequiredArgument("Pass exactly one of ip_content or text_content to add_dns_record")
		
		# Important, lowercase the name
		name = name.lower()
		
		# FIXME: default to 0 for unspecified priority
		
		# Require priority for MX and SRV
		if ((tid == 15 or tid == 33) and priority==None) or ((tid != 15 and tid != 33) and priority!=None):
			raise error.RequiredArgument("Must specify priority for MX(15) or SRV(33) records, but not others (tid=%s, prio=%s)" % (tid, priority))
		
		self._begin_transaction()
		try:
			domains = self.get_domains(contains=name, additional_perms=perms.ADD)

			# Check if we have the required permissions over this domain
			if not domains:
				raise error.InsufficientPermissions("Insufficient permissions to access domain containing %s" % name)
			
			values = { 
				'name' : name,
				'tid' : tid,
				'did' : domains[0]['id'],
				'ip_content' : ip_content,
				'priority' : priority,
				'text_content' : text_content,
				'ttl' : backend.default_ttl,
				'vid' : vid,
				'changed' : sqlalchemy.sql.func.now(),
				'changed_by' : self._uid
			}
			
			if not self.has_min_perms( perms.DEITY ):
				# check permissions...
				# we need to find the permissions required to add this kind of record
				
				query = select([obj.dns_types], and_(obj.dns_types.c.id == tid, obj.dns_types.c.min_permissions.op('&')(str(self._min_perms)) == obj.dns_types.c.min_permissions ))
				result = self._execute(query)
				
				if not result:
					raise error.InsufficientPermissions("Insufficient permissions to add a DNS record of type %s" % tid)
			
			result = self._execute_set( obj.dns_records.insert( values=values ) )
			
			# PTR record
			if tid == 1 and add_ptr:
				
				ptrname = IPy.IP(ip_content).reverseName()[:-1]
				
				domains = self.get_domains( contains=ptrname )
				
				if not domains:
					raise error.NotFound("Could not find appropriate domain to add in-addr.arpa PTR record for A-record name %s" % name)
				
				values = {
					'name': ptrname,
					'tid' : 12,
					'did' : domains[0]['id'],
					'text_content': name,
					'ttl' : backend.default_ttl,
					'vid' : vid,
					'changed' : sqlalchemy.sql.func.now(),
					'changed_by' : self._uid
				}
				result = self._execute_set( obj.dns_records.insert( values=values ) )
	
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
	def add_dns_type( self ):
		"""dns_type"""
		pass
		
		
	def add_domain( self, name, description=None, master=None, type=None ):
		"""Add a domain
		@param name: the fully qualified domain name
		@param master: ???
		@param type: ???"""
		
		self.require_perms(perms.DEITY)
		
		name = name.lower()
		
		query = obj.domains.insert( values={'name':name, 'master':master, 'type':type, 'description':description, 'changed_by' : self._uid })
		
		return self._execute_set(query)
		
	def add_dns_view( self):
		pass
		
	def add_dhcp_option_to_dhcp_group(self, gid, oid, value):
		"""Add a DHCP option to a DHCP group
		@param oid: the database option id
		@param gid: the database group id
		@param value: the value of this DHCP option within the group"""
		
		self.require_perms( perms.DEITY )
		
		if is_addresses( value ):
			addresses = value.split(',')
			bytes = []
			for address in addresses:
				address=address.strip()
				# print address
				octets = address.split('.')
				if len(octets) != 4:
					raise Exception('invalid ip address: %s' % address)
				bytes.extend( octets )
			bytes = map(int, bytes)
			value = ''.join( map(chr , bytes ) )
			# print "value: %s len: %s" % (value, len(value))
		#option = self.get_option( oid )
		if value == 51: # lease time
			value = int_to_bytes( oid, 4 )

		values = { 'oid':oid, 'gid':gid, 'value':value }

		return self._execute_set( obj.dhcp_options_to_dhcp_groups.insert( values=values ) )

		
	def add_domain_to_group( self, did, gid):
		'''
		Add a domain to a group
		@param did: the database domain ID
		@param gid: the database group ID
		'''
		
		# FIXME: more granular permissions?
		self.require_perms(perms.DEITY)
		
		query = obj.domains_to_groups.insert( values={'did' : did,
									'gid' : gid,
									'changed_by' : self._uid } )

		return self._execute_set(query)
		
	
	def add_guest_ticket( self, ticket, starts, ends, description=None ):
		"""
		Adds a guest ticket to the database and associate it to this user
		
		@param starts: the start datetime
		@param ends: the end datetime
		@return: the row added ResultProxy object
		"""
		
		# Permissions, non-restrictive at all
		# No permissions for guest tickets, free game
		
		query = obj.guest_tickets.insert( values={'uid' : self._uid,
									'ticket' : ticket,
									'starts' : starts,
									'ends' : ends,
									'description' : description } )

		return self._execute_set(query)
			
	
	def add_group( self, name, description=None ):
		"""
		Add a group
		@param name: the group name
		@param description: a description of the group
		"""
		
		# Check permissions
		if not self._is_user_in_group(gid=backend.db_service_group_id):
			self.require_perms( perms.DEITY, "Only super admins can add new groups" )

		# Do this INSERT no matter what authentication source
		query = obj.groups.insert( values={'name' : name,
								'description' : description } )
		
		return self._execute_set(query)
		
	def add_host( self, mac, hostname, description=None, dhcp_group=None, expires=None ):
		"""Add a host
		@param mac: the new host's MAC address
		@param hostname: a valid hostname
		@param description: description
		@param dhcp_group: this host's DHCP group id, from dhcp_groups table, for DHCP options
		@param expires: an expiration date
		"""

		hostname = hostname.lower()
		
		self._begin_transaction()
		try:
			# Check permissions
			if self.has_min_perms(perms.DEITY):
				# If I'm a DEITY, just let me add any hosts
				pass
			elif not self.get_domains(contains=hostname, additional_perms=perms.ADD):
				raise error.InsufficientPermissions("User %s doesn't have domain access to add host %s" % (self._username, hostname))
			
			
			# FIXME: think about the following flag del_extraneous being set to False here
			# In the current form, if you register a host with the same name or MAC as an expired
			# host, you'll get the expired host's DNS records.
			# If we do delete the expired host's DNS records, what would that hurt? I think nothing ...
			
			# If the host exists by mac, but is expired, delete old host
			host = self.get_hosts(mac=mac, show_expired=True, show_active=False)
			if host:
				self.del_host(mac=mac, del_extraneous=False)
			
			# If the host exists by hostname, but is expired, delete old host
			host = self.get_hosts(hostname=hostname, show_expired=True, show_active=False)
			if host:
				self.del_host(mac=host[0]['mac'], del_extraneous=False)
			
			query = obj.hosts.insert( values={
									'mac' : mac,
									'hostname' : hostname,
									'description' : description,
									'dhcp_group' : dhcp_group,
									'expires' : expires,
									'changed_by' : self._uid
									} )
		
			result = self._execute_set( query )
			
			self.add_host_to_group(mac, group_name="user_%s" % self._username)
				
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def add_host_to_group( self, mac, gid=None, group_name=None ):
		'''
		Add a host to a group
		
		@param mac: the host's mac address
		@param gid: the database group ID
		@param group_name: if not gid, give the group_name and gid will be determined
		'''


		# Get the gid if not given
		if not gid:
			if not group_name:
				raise error.RequiredArgument("Must pass exactly one of gid or group_name")
			
			query = self.get_groups(name=group_name)
			if not query:
				raise error.NotFound("No group found matching: %s" % group_name)
			else:
				gid = query[0]['id']
				
		self._begin_transaction()
		try:
			if self.get_hosts_to_groups(mac=mac):			
				# Require permissions over the host
				self._require_perms_on_host(permission=perms.ADMIN, mac=mac, error_msg="Couldn't add host %s to group %s, %s" % (mac, gid, group_name))
			
			# They have permission ... do the insert
			query = obj.hosts_to_groups.insert( values={'mac' : mac,
									'gid' : gid,
									'changed_by' : self._uid } )
			
			result = self._execute_set( query )
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def assign_static_address(self, mac, hostname=None, network=None, address=None):
		"""
		Assign a static address from the addresses table to this mac from the
		specified network. This is a smart function, it will determine the available
		address and assign it.
		
		@param mac: required MAC address
		@param network: required CIDR network
		@param address: an optional argument, which address to assign
		@return: the IP address that was assigned to this MAC

		"""
		if not network and not address:
			raise error.RequiredArgument('You must specify either a network or an address.')
		
		self._begin_transaction()
		try:
			if not self.has_min_perms(perms.ADD):
				net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = perms.ADD, do_subquery=False,
						andwhere=or_( obj.networks_to_groups.c.nid == network, obj.networks_to_groups.c.nid.op('<<=')(address) ) )
				net_perms = self._execute(net_perms)
			
				if not net_perms:
					raise error.InsufficientPermissions("Insufficient permissions to add a host to the %s network." % network)
			
			query = select([obj.addresses.c.address], and_(and_(obj.addresses.c.mac == None, obj.addresses.c.pool == None), obj.addresses.c.reserved == False))

			if network:
				query = query.where(obj.addresses.c.address.op('<<')(network)).order_by(obj.addresses.c.address)

			if address:
				query = query.where(obj.addresses.c.address == address)

			
			addresses = self._execute(query)
			
			if not addresses:
				# If no totally free addresses, steal one from a pool
				
				# Get all addresses and the leases if they exist
				from_object = obj.addresses.outerjoin(obj.leases, obj.addresses.c.address == obj.leases.c.address)
				
				# Filter all addresses to where MAC is none (address hasn't been assigned)
				# and don't return broadcast, network, gateway and other reserved IP addresses
				query = select([obj.addresses.c.address], from_obj=from_object).where( and_(obj.addresses.c.mac == None, obj.addresses.c.reserved == False) )

				# Only rob certain pools, since some have special meanings
				# FIXME: Add a configuration option here instead of [1,3]
				query = query.where( obj.addresses.c.pool.in_( [1,3,] ) )
				
				if network:
					query = query.where(obj.addresses.c.address.op('<<')(network)).order_by(obj.addresses.c.address)
				
				# Only show expired leases
				query = query.where(or_(obj.leases.c.ends < sqlalchemy.sql.func.now(), obj.leases.c.ends == None))
				
				if address:
					query = query.where(obj.addresses.c.address == address)
				
				addresses = self._execute(query)
				
				if address and not addresses:
					raise error.NotFound("Could not assign IP address %s to MAC address %s.  It may be in use or not contained by a network." % (address, mac))
				
				if not addresses:
					raise error.NoFreeAddresses()
				
			# If here, we have a list of usable addresses, pick one
			address = addresses[0]['address']
			
			# Add the A record for this static (also adds PTR)
			if hostname:
				self.add_dns_record(name=hostname, tid=1, ip_content=address)
			
			query = obj.addresses.update(obj.addresses.c.address == address, values = { 'mac' : mac, 'pool' : None})
			self._execute_set( query )
			
			# If claimed, delete any previous leases
			query = obj.leases.delete(obj.leases.c.address == address)
			self._execute_set( query )
			
			self._commit()
		except:
			self._rollback()
			raise

		return address
	
	def release_static_address(self, address, pool=False):
		"""
		Release a static address back into a dynamic pool.
		Deletes all A records of this address and PTR records.
		
		@param address: the IP address to release
		"""
		
		# Check permissions
		addresses = self.get_addresses(address=address)
		
		if not addresses:
			raise error.NotFound("No addresses returned in release_static_address for address %s" % address)
		
		# The MAC address associated with this IP address
		mac = addresses[0]['mac']
		
		host = self.get_hosts(mac=mac)
		
		if not host:
			raise error.NotFound("No host found for MAC %s in release_static_address" % mac)
		
		# Require MODIFY over the host that is using this address
		self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Insufficient permissions to release static address %s for MAC %s" % (address, mac))
		
		if not address:
			raise error.RequiredArgument("address is required in release_static_address")
		
		self._begin_transaction()
		try:
			if pool is False:
				pool = backend.func_get_pool_id( address=address )
			
			# Delete all the PTR records for this address
			ptrrecord = IPy.IP(address).reverseName()[:-1]
			ptrrecord = self.get_dns_records(name=ptrrecord)
			
			if ptrrecord:
				for rr in ptrrecord:
					self.del_dns_record(rid=rr['id'], mac=mac)
				
			# Delete the A records
			a_records = self.get_dns_records(address=address)
			
			if a_records:
				for rr in a_records:
					self.del_dns_record(rid=rr['id'], mac=mac)

			query = obj.addresses.update(obj.addresses.c.address == address, values = { 'mac' : None, 'pool' : pool  } )
	
			result = self._execute_set( query )
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
		
	def register_host(self, mac, hostname, description=None, dhcp_group=None, expires=None, expiration_format=None, is_dynamic=True, add_ptr=True, owners=None, pool=None, network=None, add_host_to_my_group=True, address=None):
		"""
		Registers a host. This is a smart function, it calls many DB functions to do
		a full insert of a registration for a host.
		"""
		
		# FIXME: MAYBE make this function accept dns_records and add them all when registering the host ... this may be useful for the frontend
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)
		
		# If this is a dynamic host and no pool is specified, use the default pool
		if is_dynamic and not pool:
			pool = backend.db_default_pool_id
			address = None
		
		if add_host_to_my_group and owners:
			raise error.NotImplemented("add_host_to_my_group must be False if owners is specified")
		
		self._begin_transaction()
		try:
			# Add the host, which will also add the host to my user group so that the following additions can happen.
			# See add_host_to_my_group code below for how deleting my host_to_group relation works
			result = self.add_host(mac=mac, hostname=hostname, description=description, dhcp_group=dhcp_group, expires=expires)
			
			# STATIC HOST
			if not is_dynamic:
				if not network and not address:
					raise error.RequiredArgument("To create a static registration, network must be specified")
				address = self.assign_static_address(mac=mac, hostname=hostname, network=network, address=address)
			
			# DYNAMIC HOST
			if pool:
				self.add_host_to_pool(mac=mac, pool_id=pool)
			
			self.make_notifications_for_host(mac=mac, expires=expires)
			
			my_usergroup = 'user_%s' % self._username
			
			# If not add_host_to_my_group, then delete the host from my group after all other actions are finished
			if not add_host_to_my_group:
				self.del_host_to_group(mac=mac, group_name=my_usergroup)
				
			# Make sure I'm first in the owners list so that I have permissions
			if owners and my_usergroup in owners:
				owners.remove(my_usergroup)
				owners.insert(0, my_usergroup)
			
			# Add owners is specified
			if owners:
				for owner in owners:
					# Make sure it actually exists and is not ''
					if owner:
						self.add_host_to_group(mac=mac, group_name=owner)
						
			# Commit the transaction
			self._commit()
		except Exception, e:
			self._rollback()
			raise
		
		return result
			
		
	def add_internal_auth( self ):
		"""internal_auth"""
		pass
		
	def add_network( self, network, name=None, gateway=None, description=None, dhcp_group=None, pool=False, shared_network=None ):
		"""Add a network
		@param network: a CIDR network mask
		@param name: a string name for this network
		@param gateway: an IP address of the gateway for this network
		@param description:	a description for this name
		@param dhcp_group: the ID of a DHCP group
		@param pool: the ID of a pool, None for NULL, False for auto-generated from config (default)
		@param shared_network: the ID of a shared network
		"""

		# Check permissions
		self.require_perms(perms.DEITY)

		# Add all addresses from this network into the addresses table
		net = IPy.IP(network)
			
		
		# Check if this network overlaps with another network
		self._begin_transaction()
		try:
			query = select([obj.networks.c.network], or_(obj.networks.c.network.op("<<=")(network), obj.networks.c.network.op(">>")(network)))
			result = self._execute(query)
			
			if result:
				raise error.AlreadyExists('Unable to add network %s because of overlap with existing network %s' % (network, str(result[0])))
			if not gateway:
				gateway = str( net[backend.default_gateway_address_index] )
			
			query = obj.networks.insert( values={'network' : network,
									'name' : name,
									'gateway' : gateway,
									'description' : description,
									'dhcp_group' : dhcp_group,
									'shared_network' : shared_network,
									#'broadcast' : broadcast,
									'changed_by' : self._uid } )
			result = self._execute_set( query )
			
			invalid = [ net[0], net[backend.default_gateway_address_index], net.broadcast(), ] # mark gateways as reserved, although we should assign the mac of the router
			
			for address in net:
				if (address not in invalid) or (net.prefixlen() >= 31):
					# If address is not invalid or in a /31 or /32, add the address as unreserved
					# otherwise we would end up with no available addresses
					if pool == False:
						addr_pool = backend.func_get_pool_id( address )
					else:
						addr_pool = pool
					self.add_address( address = str( address ), network=network, pool = addr_pool )
				else:
					self.add_address( address = str( address ), network=network, pool = None, reserved=True )
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
	def add_network_to_group( self, nid, gid ):
		'''Add a network to a group
		@param nid: the database network ID
		@param gid: the database group ID'''
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.networks_to_groups.insert( values={'nid' : nid,
								'gid' : gid,
								'changed_by' : self._uid } )

		return self._execute_set(query)
	
	def add_notification_to_host( self, nid, mac ):
		"""
		Add a notification type to a host
		
		@param nid: the database notification ID
		@param mac: the database host mac
		"""
				
		self._begin_transaction()
		try:
			if self.get_hosts_to_groups(mac=mac):
				self._require_perms_on_host(permission=perms.ADMIN, mac=mac)
			
			# They have permission ... do the insert
			query = obj.notifications_to_hosts.insert( values=
											{
											'nid' : nid,
											'mac' : mac
											} )
			
			result = self._execute_set( query )
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def add_permission( self ):
		"""permission"""
		pass
	
	def add_shared_network( self, name, description=None):
		"""
		Add a shared network to the database
		
		@param name: a required name for this shared network
		@param description: an optional description for this shared_network
		"""
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.shared_networks.insert( values={'name' : name,
								'description' : description } )
		
		return self._execute_set( query )
		
	
	def add_supermaster( self ):
		"""supermaster"""
		pass
	
	def add_internal_auth (self, id, password, name=None, email=None, hashed=True ):
		"""
		Add a user to the database
		
		@param id: the user database ID that references the users table
		@param password: the user's password ... by default expected to be hashed, see next option
		@param name: the user's actual name, optional
		@param hashed: defaults to True, if False the password will be hashed before inserting into the database
		@param email: the user's email address, optional
		
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		#if not hashed:
		#	password = hash_password(password)
		
		query = obj.internal_auth.insert( values={'id' : id,
								'hash' : password,
								'name' : name,
								'email' : email } )
		
		return self._execute_set( query )
		
	
	def add_user( self, username, source=None, min_perms=None, **kw ):
		"""
		Add a user to the database
		
		@param username: the username, either internal or their LDAP username
		@param source: require to say where this is coming from, see backend.auth.sources
		@param min_perms: the minimum permissions for this user over everything
		"""
		
		# Check permissions
		if not self._is_user_in_group(gid=backend.db_service_group_id):
		   self.require_perms(perms.DEITY)
		
		# Make the caller set the source of where this is coming from, don't assume
		if source is None:
			raise error.RequiredArgument("source")

		if not min_perms:
			min_perms = backend.db_default_min_permissions
		
		self._begin_transaction()
		try:
			# Do this INSERT no matter what authentication source
			query = self._execute_set(obj.users.insert( values={'username' : username,
									'source' : source,
									'min_permissions' : min_perms } ))
			uid = query.last_inserted_ids()[0]
			
			# If the user is internal, not LDAP, add the rest of the info to auth_source
			# FIXME: This was never implemented
			#if source is auth_sources.INTERNAL:
			#	self.add_internal_auth(uid, **kw )
				
			# When creating a new user, make a group for that user prepended with user_
			group_query = self.add_group('user_%s' % username, "Default group for this user")
			
			gid = group_query.last_inserted_ids()[0]
			
			self.add_user_to_group(uid=uid, gid=gid, permissions=str(perms.OWNER))
			self.add_user_to_group(uid=uid, gid=backend.db_default_group_id, permissions=str(perms.ADD))
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return query
	
	def add_user_to_group( self, uid, gid, permissions, host_permissions=None ):
		'''Add a user to a group
		@param info: a dictionary of information for the bridge relation'''

		# Check permissions
		if not self._is_user_in_group(gid=backend.db_service_group_id):
			self.require_perms(perms.DEITY)
		
		values={
			'uid' : uid,
			'gid' : gid,
			'permissions' : permissions,
			'changed_by' : self._uid
		}
		
		if host_permissions is not None:
			values['host_permissions'] = host_permissions
		
		query = obj.users_to_groups.insert( values )

		return self._execute_set(query)
	
	def add_vlan( self ):
		"""vlan"""
		pass
		
	def add_vlan_to_group( self ):
		"""vlan_to_group"""
		pass
		
	def del_attribute( self ):
		"""attribute"""
		pass
		
	def del_attribute_to_host( self ):
		"""attribute_to_host"""
		pass
		
	def del_attribute_value( self ):
		"""attribute_value"""
		pass
		
	def del_auth_source( self ):
		"""auth_source"""
		pass

	def del_dhcp_option( self ):
		"""dhcp_option"""
		pass
		
	def del_dhcp_group( self, gid ):
		"""Delete a DHCP group"""
		pass
		
	def del_dns_record( self, rid, mac=None ):
		"""
		Delete a DNS record
		
		@param rid: the ID of the row in dns_records
		"""
		
		# If MAC is not specified, require DEITY
		if not mac:
			self.require_perms(perms.DEITY)
		else:
			# Require DELETE permissions if MAC is specified
			self._require_perms_on_host(permission=perms.DELETE, mac=mac, error_msg="Insufficient permissions to delete DNS records for MAC %s" % mac)
		
		query = obj.dns_records.delete(obj.dns_records.c.id==rid)

		return self._execute_set(query)
	
	def del_dns_type( self ):
		"""dns_type"""
		pass
		
	def del_dns_view( self ):
		pass
	
	def del_domain( self ):
		"""domain"""
		pass
	
	def del_domain_to_group( self, did, gid ):
		"""Remove a domain from a group
		@param did: the domain database id
		@param gid: the group database id"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.domains_to_groups.delete(and_(obj.domains_to_groups.c.did==did, obj.domains_to_groups.c.gid==gid))
		
		return self._execute_set(query)
		
	def del_dhcp_option_to_group( self, rid, gid ):
		"""Remove a DHCP option from a DHCP group
		@param rid: the option relation id (NOT the option's ID, because gid+oid is not unique in this table) 
		@param gid: the group database id"""
		pass
	
	def del_guest_ticket( self, ticket ):
		"""
		Delete a guest ticket
		
		@param ticket: get the information related to this ticket name
		@return: the delete resultproxy
		"""
	
		if not self.has_min_perms(perms.DEITY):
			# I'm not a DEITY and I'm trying to delete a ticket
			
			my_ticket = self.get_guest_tickets(ticket=ticket)
			
			if not my_ticket:
				raise error.NotFound("Ticket to delete was not found")
			
			if my_ticket[0]['uid'] != self._uid:
				raise error.InsufficientPermission("Cannot delete another person's ticket")
		else:
			my_ticket = self.get_guest_tickets(ticket=ticket)
		
			if not my_ticket:
				raise error.NotFound("Ticket to delete was not found")
			
		query = obj.guest_tickets.delete(obj.guest_tickets.c.id == my_ticket[0]['id'])
		 
		return self._execute_set(query)

	def del_group( self, gid ):
		"""
		Delete a group
		@gid: the database group ID
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.groups.delete(obj.groups.c.id==gid)
		
		return self._execute_set(query)
	
	def del_host( self, mac, del_extraneous=True ):
		"""
		Delete a host. Relations of this host to groups will cascade delete.
		
		Doesn't currently delete all associated DNS records, but will in v1.5 or 2
		
		@param mac: MAC address of host
		@param del_extraneous: remove all associated DNS records and release associated addresses
		"""
		
		self._begin_transaction()
		try:
			host = self.get_hosts(mac=mac, show_expired=True, show_active=True, columns=[obj.hosts, (obj.hosts.c.expires < sqlalchemy.sql.func.now()).label('expired')])
			
			if host:
				if not host[0]['expired']:
					self._require_perms_on_host(permission=perms.DELETE, mac=mac)
				
				if del_extraneous:
					# Addresses to release
					release_addresses = self.get_addresses(mac=mac)
					
					for addr in release_addresses:
						self.release_static_address(address=addr['address'])
					
					# Delete the DNS records associated with the old static host
					dns_records = self.get_dns_records( mac=mac )
					
					for rr in dns_records:
						self.del_dns_record(rid=rr['id'], mac=mac)
					
				# Delete the host
				query = obj.hosts.delete(obj.hosts.c.mac==mac)
			else:
				raise error.NotFound("Couldn't find host to delete. MAC: %s " % mac)
			
			result = self._execute_set(query)
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def del_host_attribute( self, aid ):
		"""Delete a host attribute"""
		pass
	
	def del_host_to_group( self, mac, gid=None, group_name=None ):
		"""
		Remove a host from a group
		
		@param mac: the host database id
		@param gid: the group database id
		@param group_name: the database group name if gid is unknown
		"""
		
		# Check permissions
		self._require_perms_on_host(permission=perms.ADMIN, mac=mac, error_msg="Cannot delete host to group relation for host %s in group %s, %s" % (mac, gid, group_name))
			
		whereclause = obj.hosts_to_groups.c.mac == mac
		
		if not gid and not group_name:
			# Require DEITY permissions to delete all host_to_group relations
			self.require_perms(perms.DEITY, "You do not have permission to delete multiple host to group relations")
		
		if gid:
			whereclause = and_(whereclause, obj.hosts_to_groups.c.gid==gid)
		if group_name:
			gid = self.get_groups(name=group_name)[0]['id']
			whereclause = and_(whereclause, obj.hosts_to_groups.c.gid==gid)
			
		query = obj.hosts_to_groups.delete(whereclause)
		
		return self._execute_set(query)
	
	
	def del_internal_auth( self ):
		"""internal_auth"""
		pass
		
	
	def del_network( self, network ):
		"""Delete a network and all associated addresses"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		self._begin_transaction()
		try:
			# Delete all addresses that were in this network
			query = obj.addresses.delete(obj.addresses.c.address.op("<<")(network))
			self._execute_set(query)
			
			# Delete the network
			query = obj.networks.delete(obj.users.c.id==uid)
			result = self._execute_set(query)
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	
	def del_network_to_group( self, nid, gid  ):
		"""
		Remove a network from a group
		
		@param nid: the network database id
		@param gid: the group database id
		"""
				
		# FIXME: these permissions should probably be more granular
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.networks_to_groups.delete(and_(obj.networks_to_groups.c.nid==nid, obj.networks_to_groups.c.gid==gid))
		
		return self._execute_set(query)
	
	def del_notification_to_host( self, id=None, mac=None ):
		"""
		Remove a notification applied to a host	( a row in the notifications_to_hosts table)
		
		@param id: the relation ID
		"""
		
		if id and not self.has_min_perms(perms.DEITY):
			raise error.InsufficientPermissions("Must be DEITY to specify ID of notification on host to remove")
		
		# FIXME: do we need to do this if here? or just the require permissions
		if self.get_hosts_to_groups(mac=mac):
			self._require_perms_on_host(permission=perms.ADMIN, mac=mac)
					
		if id:
			query = obj.notifications_to_hosts.delete(obj.notifications_to_hosts.c.id==id)
		elif mac:
			query = obj.notifications_to_hosts.delete(obj.notifications_to_hosts.c.mac==mac)
		else:
			raise error.RequiredArgument("Must specify exactly one of id or mac to del_notification_to_host")
		
		return self._execute_set(query)
		
	def del_supermaster( self ):
		"""supermaster"""
		pass
	
	def del_user( self, uid ):
		"""Delete a user. If that user is an internal user account, the delete will cascade to internal_auth
		@param uid: the database user ID"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.users.delete(obj.users.c.id==uid)
		
		return self._execute_set(query)
	
	def del_lease( self, address=None, mac=None ):
		"""Delete a lease ... this function is probably going away"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		if not address and not mac:
			raise error.RequiredArgument("Need one of address or mac in del_lease")
		
		if address:
			query = obj.leases.delete(obj.leases.c.address==address)
			result = self._execute_set(query)
		if mac:
			query = obj.leases.delete(obj.leases.c.mac==mac)
			result = self._execute_set(query)
		
		return result 
	
	def del_user_to_group( self, uid, gid ):
		"""Remove a user from a group
		@param uid: the user database id
		@param gid: the group database id"""
		
		
		# FIXME: these permissions should probably be more granular
		# Check permissions
		self.require_perms(perms.DEITY)
		
		query = obj.users_to_groups.delete(and_(obj.users_to_groups.c.uid==uid, obj.users_to_groups.c.gid==gid))
		
		return self._execute_set(query)
		
	def add_dhcp_group( self, info ):
		"""Add a group
		@param name: the group name
		@param description: a description of the group"""
		pass
	
	def make_notifications_for_host(self, mac, expires):
		"""
		Makes sure that the state of notifications on a host is up-to-date
		"""
		
		# Require MODIFY permissions if not DEITY
		if not self.has_min_perms(perms.DEITY):
			self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Could not make_notifications_for_host(%s, %s)" % (mac, expires))
		
		# Delete all the notifications on this host
		self.del_notification_to_host(mac=mac)
		
		# Add all of the default notifications for this host
		notification_types = self.get_notifications()
		
		for notify_type in notification_types:
			# Don't add notifications to hosts if the notification will happen after the host's expiration
			if datetime.datetime.fromtimestamp(time.time()) + notify_type['notification'] < expires:
				self.add_notification_to_host(notify_type['id'], mac)
	
	def update_host( self, old_mac, mac=None, hostname=None, description=None, expires=None, expiration_format=None ):
		"""
		Update a host record ... just a host record.
		No arguments are required except for old_mac ... whatever is passed in
		will be updated, the rest will remain the same
		"""
		
		values = {}
		
		# Always very important
		if hostname:
			hostname = hostname.lower()
		
		# Require MODIFY permissions if not DEITY
		if not self.has_min_perms(perms.DEITY):
			self._require_perms_on_host(permission=perms.MODIFY, mac=old_mac)
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)
		
		# If any argument is set, put it in the values that will be changed
		# Doing a for loop instead of if mac: values['mac'] = ..., if hostname: values['hostname'] = ... for every one
		# Because Python is just cool like that
		args = locals()
		for arg in args:
			if arg in ('mac', 'hostname', 'description', 'expires') and args[arg] != None:
				values[arg] = args[arg]
				
		values['changed'] = sqlalchemy.sql.func.now()
		values['changed_by'] = self._uid
		
		# Update the host
		query = obj.hosts.update(obj.hosts.c.mac == old_mac, values=values )
		
		results = self._execute_set(query)
			
		# If we change expires, make sure notifications on the host are up-to-date
		if expires:
			self.make_notifications_for_host(mac=(mac if mac else old_mac), expires=expires)
			
		return results 
	
	def change_registration( self, old_mac, mac=None, hostname=None, description=None, expires=None, expiration_format=None, is_dynamic=True, network=None, address=None, owners=None ):
		"""
		The continuation of register_host ... this is a smart function that will update
		everything required if a registration needs to change.
		
		No arguments are required except for old_mac ... whatever is passed in
		will be updated, rest will remain the same
		"""
		
		# ------------- TODO: MAKE SURE we're updating all the DNS records correctly (A records work, what about MX? others?)
		
		# Check permissions
		required_perms = perms.MODIFY
		# Require the ADMIN flag to change permissions
		if owners:
			required_perms = perms.OWNER
				
		self._require_perms_on_host(permission=required_perms, mac=old_mac)
		
		# Always very important
		if hostname:
			hostname = hostname.lower()
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)
		
		self._begin_transaction()
		try:
			# Get the old_host for reference
			old_host = self.get_hosts(mac=old_mac)
			
			if not old_host:
				raise error.NotFound("change_registration could not find the host %s to update" % old_mac)
			old_host = old_host[0]
			
			# If this host was in any pools, we know it was dynamic
			was_dynamic = bool( self.get_hosts_to_pools( mac=old_mac ) )
			
			# Ahh...hello states
			if is_dynamic and not was_dynamic:
				# STATIC REGISTRATION ---> DYNAMIC REGISTRATION
					
				# Delete the host in its entirety
				self.del_host(mac=old_mac)

				# Old host is gone, recreate as dynamic...
				
				# If anything wasn't specified, use the old host's data
				mac = mac if mac else old_mac
				hostname = hostname if hostname else old_host['hostname']
				description = description if description else old_host['description']
				expires = expires if expires else old_host['expires']
				
				self.register_host(mac=mac, hostname=hostname, description=description, expires=expires, is_dynamic=True, owners=owners, add_host_to_my_group=False )
				
			elif is_dynamic and was_dynamic:
				# STAYING DYNAMIC REGISTRATION
				
				# Update the host row information
				self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format)
				
			elif not is_dynamic and was_dynamic:
				# DYNAMIC REGISTRATION ---> STATIC REGISTRATION
				
				# Delete the host in its entirety
				self.del_host(mac=old_mac)
				
				# If anything wasn't specified, use the old host's data
				mac = mac if mac else old_mac
				hostname = hostname if hostname else old_host['hostname']
				description = description if description else old_host['description']
				expires = expires if expires else old_host['expires']
				
				self.register_host(mac=mac, hostname=hostname, description=description, expires=expires, is_dynamic=False, owners=owners, add_host_to_my_group=False, network=network, address=address )
				
			elif not is_dynamic and not was_dynamic:
				# STAYING STATIC REGISTRATION

				# Are we changing the IP address?
				if address or network:
					# ----------------------------------------
					# ------- FIXME: what if I only want to update ONE IP address on a host?
					# Addresses to release
					host_addresses = self.get_addresses(mac=old_mac)
					
					if not host_addresses:
						raise error.NotFound("Couldn't find address(es) to release for this host to make it a dynamic")
					
					if len(host_addresses) > 1:
						raise error.NotImplemented("Cannot change IP address on a host with multiple IPs ... yet")
					
					self.release_static_address(address=host_addresses[0]['address'])
					# ----------------------------------------
					
					if not network:
						network = self.get_networks(address=address)
						if not network:
							raise error.NotFound("Couldn't find appropriate network for specified address %s" % address)
						network = network[0]['network']
					
					# Update the host row information
					self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format)
					
					# If anything wasn't specified, use the old host's data
					mac = mac if mac else old_mac
					hostname = hostname if hostname else old_host['hostname']
					
					self.assign_static_address(mac=mac, hostname=hostname, network=network, address=address)
					
					# Done changing IP address
				else:
					# Not changing the IP address
					
					# Update the host row information
					self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format)
					
				if hostname:
					# Updating the hostname, make sure to update the associated DNS records
					a_records = self.get_dns_records(mac=(mac if mac else old_mac), tid=1, name=old_host['hostname'])
					
					for rr in a_records:
						self.update_dns_record(mac=(mac if mac else old_mac), old_address=rr['ip_content'], address=(address if address else None), old_name=rr['name'], name=hostname)
				
			# At this point, the MAC address has been updated if it's changed ... so let's set the variable for future use
			mac = (mac if mac else old_mac)
			
			# Update owners in every state if it is specified
			if owners:
				# Find which owners have been deleted or added
				old_owners = self.find_owners_of_host(mac=mac)
				old_owner_names = [row['name'] for row in old_owners]

				# Wow, there's got to be a more pythonic way of doing this. Anyone?
				for new_owner in owners:
					# Make sure it actually exists and is not ''
					if new_owner and new_owner not in old_owner_names:
						self.add_host_to_group(mac=mac, group_name=new_owner)
				for old_owner in old_owners:
					if old_owner['name'] not in owners:
						self.del_host_to_group(mac=mac, gid=old_owner['id'])
					 
			self._commit()
		except:
			self._rollback()
			raise

	def update_dhcp_group( self, gid, name, description ):
		'''Update a DHCP Group's information
		@param gid: the database group id
		@param name: the group's name
		@param description: the group's description'''
		pass
	
	def update_dns_record( self, mac=None, old_address=None, address=None, old_name=None, name=None ):
		"""
		Update a DNS record on a host
		
		@param old_address: the old IP address
		@param address: the new IP address
		"""
		
		# FIXME: implement updating of other RR types

		# If MAC is not specified, require DEITY
		if not mac:
			self.require_perms(perms.DEITY)
		else:
			# Require MODIFY permissions if MAC is specified
			self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Insufficient permissions to update DNS records for MAC %s" % mac)
		
		values = {}
		
		if (old_name and not name) or (not old_name and name):
			# Make sure that we update only the intended record
			raise error.RequiredArgument("If old_name or name are specified, both must be given.")
		
		self._begin_transaction()
		try:
			if old_address:
				# Updating an A record and PTR
				
				# A record
				
				if address:
					# Updating the hosts A record address
					values['ip_content'] = address
				
				if name:
					values['name'] = name
				
				query = obj.dns_records.update(and_(obj.dns_records.c.ip_content == old_address, obj.dns_records.c.name==old_name), values=values )
		
				self._execute_set(query)
				
				# PTR record
				values = {}
				
				if address:
					# Updating the PTR name
					values['name'] = IPy.IP(address).reverseName()[:-1]
				
				if old_name and name:
					values['text_content'] = name
				
				ptrname = IPy.IP(old_address).reverseName()[:-1]
				
				query = obj.dns_records.update(obj.dns_records.c.name == ptrname, values=values )
		
				result = self._execute_set(query)
			else:
				raise error.NotImplemented()
				
			self._commit()
		except:
			self._rollback()
			raise

		return result
	
	def update_dhcp_option_to_group( self, rid, oid, value ):
		'''Update a DHCP Group's information
		@param gid: the database group id
		@param name: the group's name
		@param description: the group's description'''
		pass
		
	def update_group( self, gid, name=None, description=None ):
		"""Update a group
		@param gid: the database group id
		@param name: the group name
		@param description: a description of the group"""
		
		self.require_perms(permission=perms.DEITY, error_str="Insufficient permissions to update group")
		
		values = {}
		
		if name:
			values['name'] = name
		if description:
			values['description'] = description
			
		query = obj.groups.update(obj.groups.c.id == gid, values = values)
		
		return self._execute_set(query)

	def disable_host( self, mac, reason=None):
		'''Disable a host for the given reason'''

		# Check permissions
		self.require_perms(perms.OWNER)
		
		query = obj.disabled.insert( values={'mac' : mac,
								'reason' : reason,
								'disabled_by' : self._uid } )

		return self._execute_set(query)

	def enable_host( self, mac, reason=None ):
		'''Disable a host for the given reason'''

		# Check permissions
		self.require_perms(perms.OWNER)
		self._begin_transaction()
		try:
			# Consider this a hack for logging purposes.
			update_query = obj.disabled.update( obj.disabled.c.mac == mac, values={ 'reason' : reason,
									'disabled_by' : self._uid } )
			self._execute_set(update_query)

			# FIXME: we need a way to see who enabled this
			query = obj.disabled.delete( obj.disabled.c.mac == mac )
			result = self._execute_set(query)
			self._commit()
		except:
			self._rollback()
			raise

		return result

class DBAuthInterface( DBInterface ):
	def __init__(self):
		DBInterface.__init__( self, username=backend.auth_user )
	def __getattr__(self, name ):
		"""
		This only lets the DBAuthInterface call a small subset of DBInterface functions. 
		"""
		if name in ('add_user', 'get_users', 'get_auth_sources', 'get_internal_auth'):
			return DBInterface.__getattr__(self, name)
		raise AttributeError(name)
	
def ago( sec ):
	return sqlalchemy.sql.func.now() - text("interval '%s sec'" % sec)

class DBDHCPInterface(DBInterface):
	"""
	The interface for all DHCP-related backend stuff
	"""
	from openipam.config import dhcp
	show_queries = False
	debug = False

	def __init__( self ):
		# FIXME: this should come from the config file
		DBInterface.__init__(self, uid=4, username='dhcp', min_perms=perms.DEITY)
		self.server_ip = self.dhcp.server_ip

	def _create_conn( self ):
		conn = obj.engine.connect()
		conn.isolation_level = 'SERIALIZABLE'
		return conn

	# For debugging only
	def _execute(self, query):
		if self.show_queries:
			print query.compile()
		return DBBaseInterface._execute(self, query)

	def _execute_set(self, query):
		if self.show_queries:
			print query.compile()
		return DBInterface._execute_set(self, query)

	def update_or_create_lease_and_delete_conflicting(self, mac, address, expires):
		# FIXME: rename this to something like 'handle lease'
		# FIXME: do the lease thing -- delete (set MAC -> NULL, expires -> old or NULL) existing leases for the host, then update address
		
		# delete from leases where (mac = mac and address != address) or (mac != mac and address = address) and starts < NOW() - interval '10 sec' or so?
		print "update_or_create_lease_and_delete_conflicting(mac=%s,address=%s,expires=%s)" % (mac,address,expires)
		
		min_lease_age = 10 # If the lease was given out less than this many seconds ago, don't touch it.
		print 'got %s for expires' % expires

		self._begin_transaction()
		try:
			query = obj.leases.delete( and_(
													or_(
														and_( obj.leases.c.mac == mac, obj.leases.c.address != address ),
														and_( and_( obj.leases.c.mac != mac, obj.leases.c.ends < sqlalchemy.sql.func.now() ), obj.leases.c.address==address )
													),
													obj.leases.c.starts < ago(min_lease_age )
												) )
			self._execute_set(query)
			
			query = select([obj.leases,((sqlalchemy.sql.func.now() - obj.leases.c.starts) < text("interval '%s sec'" % min_lease_age)).label('recent')], obj.leases.c.mac==mac)
			result = self._execute(query)
			
			# If this lease is < 10 seconds old, don't bother updating it
			values={
					#'mac':mac, # The MAC here must be the same mac, RIGHT?
					'address':address,
					#'starts':sqlalchemy.sql.func.now(), # Doesn't really matter, since we are extending a lease; RIGHT?
					'server':self.server_ip,
					'ends':sqlalchemy.sql.func.now() + text("interval '%s sec'" % expires)
					}
			# select * from leases where mac = mac, if exists: update where starts < NOW()-10 sec else, insert.
			if result:
				if result[0]['recent']:
					if self.debug:
						print "Recent match (< %s s old) found: %s" % (min_lease_age,str(result))
					self._commit()
					return result
				query = obj.leases.update(and_(obj.leases.c.mac==mac, obj.leases.c.starts < ago(min_lease_age) ),
									values=values )
				result = self._execute_set(query)
			else:
				values['mac'] = mac
				values['starts'] = sqlalchemy.sql.func.now()
				query = obj.leases.insert( values=values )
				result = self._execute_set(query)

			self._commit()
		except:
			self._rollback()
			raise
		
		query = select([obj.leases]).where( and_( obj.leases.c.mac==mac, obj.leases.c.address == address))
		result = self._execute(query)
		if not result:
			raise Exception('Could not create lease for mac: %s address: %s' % mac, address)
		else:
			if self.debug:
				print "mac: %s address: %s matching lease: %s" % (mac, address, result)

		return values

	def get_valid_nets( self, gateway ):
		net_alias = obj.networks.alias('src_net')
		net_query = select( [obj.networks.c.network], from_obj = obj.networks.join(net_alias,
			and_(net_alias.c.network.op('>>')(gateway), obj.networks.c.shared_network == net_alias.c.shared_network)) )

		networks = []
		for i in self._execute(net_query):
			networks.append( i['network'] )
		if not networks:
			raise error.NotFound('No networks found for gateway %s' % gateway)
		return networks

#	def check_valid_lease( self, mac, address, networks ):
#		registration_q = select( [obj.hosts] ).where( and_( obj.hosts.c.mac == mac, obj.hosts.c.expires < sqlalchemy.sql.func.now() ) )
#		registration = self._execute( registration_q )
#		registered = False
#
#		columns, valid = self.valid_addresses_q( networks, registered )
#		columns.append( (obj.leases.c.ends - sqlalchemy.sql.func.now()).label('remaining') )
#		lease_q = select( columns, from_obj = valid).where( or_( obj.leases.c.mac == mac, obj.addresses.c.mac == mac ) )
#		if address:
#			lease_q = lease_q.where( obj.addresses.c.address == address )
#		lease = self._execute( lease_q )
#		print lease
#		if lease:
#			x = lease[0]['remaining']
#			return make_lease_dict( lease[0], int(x.days * 86400 + x.seconds), hostname )
#		return None

	def valid_addresses_q( self, networks, registered ):
		# This innerjoin is okay because we don't know how to give leases on addresses that aren't in a network we know about.
		if registered is None:
			raise error.RequiredArgument("Must specify whether we are looking for registered addresses.")
		valid_addrs = obj.addresses.join(obj.networks, and_(obj.networks.c.network == obj.addresses.c.network, obj.networks.c.network.in_(networks))
			)
		columns = [obj.addresses.c.address, obj.addresses.c.mac, obj.networks.c.network, obj.networks.c.gateway, obj.pools.c.lease_time]
		if registered:
			addrs = valid_addrs.outerjoin(obj.pools, obj.pools.c.id == obj.addresses.c.pool )
		else:
			addrs = valid_addrs.join(obj.pools, and_(obj.pools.c.id == obj.addresses.c.pool) )
		addrs = addrs.outerjoin(obj.leases, obj.leases.c.address == obj.addresses.c.address)
		return (columns, addrs)

	def make_dhcp_lease(self, mac, gateway, requested_address, discover):
		"""
		Create a DHCP lease for the specific MAC in the proper network
		"""
		address = None
		lease_time = None
		#if discover:
		#	lease_time = 600 # Give the client 30 seconds to respond to our offer
			
		# False for static addresses
		make_lease = True
		
		#debug = True
		if hasattr( self, '_trans_stack' ):
			raise Exception("Running make_dhcp_lease from inside a transaction!!")

		# First, get valid networks
		networks = self.get_valid_nets( gateway )

		if self.debug:
			print "valid networks for %s: %s" % (gateway,str(networks))

		# FIXME: check to see if there is an existing lease that works, since that is the easiest (and should be the most common) case
		# is this host registered?
		#registered = self.get_hosts(mac=mac, columns=[obj.hosts.c.mac,obj.hosts.c.hostname,], show_expired = False)
		registration_q = select([obj.hosts.c.mac,obj.hosts.c.hostname, (obj.hosts.c.expires < sqlalchemy.sql.func.now()).label('expired')]).where(obj.hosts.c.mac == mac)
		registration = self._execute(registration_q)

		# This is true for hosts that are either unknown to the system, or expired
		unregistered = True
		hostname = None
		if registration:
			registration = registration[0]
			unregistered = registration['expired']
			hostname = registration['hostname']

		disabled_q = select( [obj.disabled.c.mac,] ).where( obj.disabled.c.mac == mac )
		disabled = self._execute( disabled_q )

		if not unregistered and not disabled:
			is_static = False
			allowed_pools_q = select( [obj.hosts_to_pools.c.pool_id] ).where( obj.hosts_to_pools.c.mac == mac )
			ap = self._execute( allowed_pools_q )
			allowed_pools = []
			for p in ap:
				allowed_pools.append( p['pool_id'] )
			if self.debug:
				print "Found valid registration for this host."
			if not allowed_pools:
				is_static=True
			
			columns, registered_addrs = self.valid_addresses_q( networks, registered=True )

			registered_q = select( columns, from_obj = registered_addrs ).where( or_(
								and_( or_( or_( obj.leases.c.mac == mac, obj.leases.c.mac == None ), obj.leases.c.ends < sqlalchemy.sql.func.now() ), obj.addresses.c.pool.in_(allowed_pools) ),
							obj.addresses.c.mac == mac ) ).where(obj.addresses.c.reserved == False ) 
			registered_q = registered_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) )
			# check the requested address and see if it 'works'
			requested_q = registered_q

			# get allowable addresses/leases where the address is the one requested and is leased to the mac given or not leased to anyone
			# FIXME: we want static addresses to be first
			requested_q = requested_q.where( obj.addresses.c.address == requested_address )
			requested = self._execute(requested_q)

			if requested:
				if self.debug:
					print "Client is allowed to have requested address."
					print requested
				address = requested[0]
				if address['address'] != requested_address:
					print "(registered) This is really strange... %s != %s, but it should be." % (requested_address, address['address'])
				# FIXME: do lease thing here
				if address['mac']:
					# This is a static lease
					is_static = True
					if self.debug:
						print "lease is static"
					lease_time = self.dhcp.static_lease_time
					make_lease=False
				else:
					if self.debug:
						print "lease is dynamic"

			# check for any valid static leases
			if not address:
				static_q = select( columns, from_obj = registered_addrs).where(obj.addresses.c.mac == mac).where(obj.addresses.c.reserved == False )
				static_q = static_q.limit(1)
				static = self._execute(static_q)
				if static:
					is_static = True
					if self.debug:
						print "Found static lease for this host."
						print 'static = %s' % static
					# there could be multiple addresses here, but let's just give them the first
					address=static[0]
					lease_time = self.dhcp.static_lease_time
					make_lease=False

			# check for valid dynamic leases... this is our last chance
			# First, check for existing addresses or that aren't in the leases table
			if not address:
				addresses_q = registered_q.where( obj.leases.c.mac == mac )
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found existing (but not requested) dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			if not address:
				addresses_q = registered_q.where( obj.leases.c.ends == None or obj.leases.c.mac == mac ).limit(20)
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if len(addresses) > 1:
						address = addresses[random.randrange(0,len(addresses)-1)]
					else:
						address = addresses[0]

					if self.debug:
						print "Found new (no existing lease) or existing dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			# We have to re-use an address, let's get the LRU address
			if not address:
				addresses_q = registered_q.order_by( obj.leases.c.ends.asc() ).limit(1)
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Reusing an expired dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			if address:
				if not is_static and not discover:
					# Update the DNS records
					q = select( [obj.dhcp_dns_records] ).where( or_( obj.dhcp_dns_records.c.ip_content == address['address'], obj.dhcp_dns_records.c.name == hostname ) )
					exists = False
					records = self._execute( q )
					for record in records:
						if record['ip_content'] == address['address'] and record['name'] == hostname:
							exists = True
						else:
							d = obj.dhcp_dns_records.delete( obj.dhcp_dns_records.c.id == record['id'] )
							self._execute_set( d )
					if not exists:
						dynamic_address_ttl = 120
						self.add_dhcp_dns_record( name=hostname, ip_content = address['address'], ttl = dynamic_address_ttl )
		if unregistered or disabled or (is_static and not address):
			if address:
				raise  Exception('FIXME: unregistered or disabled host got an address: %s' % address)
			if self.debug:
				print "Unregisterd host."
			# handle unregistered host
			# find addresses pools that allow unregistered hosts
			columns, unreg_addrs = self.valid_addresses_q( networks, registered=False )
			# check the requested address and see if it 'works'
			unregistered_q = select( columns, from_obj = unreg_addrs).where( or_( or_( obj.leases.c.mac == mac, obj.leases.c.mac == None ), obj.leases.c.ends < sqlalchemy.sql.func.now() ) )
			unregistered_q = unregistered_q.where(obj.addresses.c.reserved == False ) 
			unregistered_q = unregistered_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) ).where( obj.pools.c.allow_unknown == True )
			requested = None

			if requested_address:
				requested_q = unregistered_q
				requested_q = requested_q.where( obj.addresses.c.address == requested_address )
				requested = self._execute(requested_q)

			if requested:
				if self.debug:
					print "Using requested lease for this unregistered host."
				address = requested[0]
				if address['address'] != requested_address:
					print "(unregistered) This is really strange... %s != %s, but it should be." % (address, requested[0]['address'])

			if not address:
				leased_q = select( columns, from_obj = unreg_addrs ).where( obj.leases.c.mac == mac ).order_by(obj.leases.c.starts).where(obj.addresses.c.reserved == False ).where( obj.pools.c.allow_unknown == True ) 
				leased_q = leased_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) ).limit(1)
				leased = self._execute( leased_q )
				if leased:
					if self.debug:
						print "Found existing dynamic lease for this unregistered host."
					address = leased[0]

			if not address:
				# Look for unassigned lease
				addresses_q = unregistered_q.where( obj.leases.c.ends == None ).limit(20)
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found new dynamic lease for this unregistered host."
					if len(addresses) > 1:
						address = addresses[random.randrange(0,len(addresses)-1)]
					else:
						address = addresses[0]

			if not address:
				# LRU lease
				addresses_q = unregistered_q.order_by( obj.leases.c.ends ).limit(1)
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found new dynamic lease for this unregistered host."
					address = addresses[0]

		# get network info about the address we are giving out
		if not address:
			# FIXME: make an exception for this
			raise error.NotFound("No valid leases found for client %s from gateway %s" %(mac,gateway))
		elif make_lease:
			# Use the pool default...  We should probably get rid of this code/column at some point
			lease_time = address['lease_time']

			LEASE_TIME_OPTION=51

			lease_time_option = self.retrieve_dhcp_options( mac, address['address'], [LEASE_TIME_OPTION,] )
			if lease_time_option:
				new_lease_time = lease_time_option[-1]['value']
				lease_time = bytes_to_int(new_lease_time)

			# FIXME: we should check lease_time here, but oh well
			self.update_or_create_lease_and_delete_conflicting(mac, address['address'], lease_time)
			
		return make_lease_dict( address, random.randrange( lease_time*2/3, lease_time ), hostname )

	def mark_abandoned_lease(self, address=None, mac=None):
		whereclause = None
		if address:
			whereclause = obj.leases.c.address == address
		elif mac:
			if whereclause:
				whereclause = and_( whereclause, obj.leaces.c.mac == mac )
			else:
				whereclause = obj.leaces.c.mac == mac
		else:
			raise error.RequiredArgument("Must specify MAC or address.")
		values = { 'abandoned': True, 'mac': None, 'starts': sqlalchemy.sql.func.now(), 'ends':sqlalchemy.sql.func.now() + text("interval '3600 s'", ) }
		self._execute_set( obj.leases.update( whereclause, values=values ) )
		# FIXME: what if no lease exists?  Currently, this is only called after 1) getting a lease and 2) finding it used

	def retrieve_dhcp_options(self, mac, address, option_ids):
		'''return a list of DHCP options'''

		#debug = True

		global_grp = 1
		
		host_grp = self._execute( select( [obj.hosts.c.dhcp_group,] ).where(obj.hosts.c.mac == mac) )
		if host_grp: host_grp = host_grp[0][0]
		else: host_grp = None

		pool_grp = self._execute( select( [obj.pools.c.dhcp_group,], from_obj = obj.pools.join(obj.addresses,and_(obj.addresses.c.address == address, obj.addresses.c.pool==obj.pools.c.id) ) ) )
		if pool_grp: pool_grp = pool_grp[0][0]
		else: pool_grp = None
		
		#shared_net_grp = select( [obj.shared_networks.c.dhcp_group]
		shared_net_grp = None
		if shared_net_grp: shared_net_grp = shared_net_grp[0][0]
		else: shared_net_grp = None
		
		network_grp = self._execute( select( [obj.networks.c.dhcp_group,] ).where( obj.networks.c.network.op('>>')( address ) ) )
		if network_grp: network_grp = network_grp[0][0]
		else: network_grp = None

		# FIXME: if we want a 'global' group, it belongs at the beginning of this list
		grp_lst = [ global_grp, pool_grp, shared_net_grp, network_grp, host_grp ]

		if self.debug:
			print grp_lst

		grp_order_mapping = []
		new_grp_lst = []
		for i in range( len(grp_lst) ):
			if grp_lst[i]:
				grp_order_mapping.append( (grp_lst[i], i,) )
				new_grp_lst.append(grp_lst[i])
		grp_lst = new_grp_lst
		if self.debug:
			print grp_lst
			print grp_order_mapping


		options = select( [obj.dhcp_options_to_dhcp_groups.c.oid,obj.dhcp_options_to_dhcp_groups.c.value] ).where( obj.dhcp_options_to_dhcp_groups.c.gid.in_(grp_lst) )
		if option_ids:
			options = options.where( obj.dhcp_options_to_dhcp_groups.c.oid.in_( option_ids ) )

		# FIXME
		if grp_order_mapping:
			options = options.order_by(sqlalchemy.sql.case(grp_order_mapping,value=obj.dhcp_options_to_dhcp_groups.c.gid))
		else:
			raise Exception("FIXME: no DHCP groups found that apply to this mac/address (%s/%s)" % (mac, address) )

		return self._execute( options )

	def add_dhcp_dns_record(self, name, ip_content, ttl ):
		"""
		Adds a DNS records to dhcp_dns_records
		"""

		domains = self.get_domains( contains = name )
		if not domains:
			raise Exception( 'Could not find domain for %s' % name )
		
		did = domains[0]['id']

		query = obj.dhcp_dns_records.insert(values = {
											'did' : did,
											'name' : name,
											'ip_content' : ip_content,
											'ttl' : ttl
											})
		
		return self._execute_set(query)
	
	def del_dhcp_dns_record(self, name=None, ip=None):
		"""
		Delete a DHCP DNS record based on its name or IP address
		"""
		
		if name and ip:
			raise error.RequiredArgument("Specify exactly one of name or IP address")
		
		if ip:
			query = obj.dhcp_dns_records.delete( obj.dhcp_dns_records.c.ip_content==ip )
		if name:
			query = obj.dhcp_dns_records.delete( obj.dhcp_dns_records.c.name==name )
		
		return self._execute_set(query)

def bytes_to_int( bytes ):
	bytes = str(bytes)
	val = 0
	for byte in bytes:
		val = ( val << 8 ) | ord( byte )
	return val

def int_to_bytes( num, min_len=1 ):
	lst = []
	while num:
		ch = num & 0xFF
		lst.insert(0, chr(ch) )
		num = num >> 8
	while len( lst ) < min_len:
		lst.insert(0,'\x00')
	return ''.join(lst)

def make_lease_dict( address, lease_time, hostname ):
		ret = {}
		ret['address'] = address['address']
		ret['router'] = address['gateway']
		ret['netmask'] = str(IPy.IP(address['network']).netmask()) # FIXME
		ret['broadcast'] = str(IPy.IP(address['network']).broadcast()) # FIXME
		ret['lease_time'] = lease_time
		ret['hostname'] = hostname
		return ret
		
		

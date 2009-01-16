"""
openIPAM Web Service API

This is the main webservice for openIPAM. All interfaces should interact with the
backend by means of this webservice. All communication between the openIPAM web
interface and the backend goes through this layer.

All webservice functions accept a tuple called *args that will always contain a dictionary
of keyword arguments that can be **args[0]'d to the backend accompanying functions.

"""

# IMPORTANT: For every exposed function, make sure to insert:
#-------------------------------------------------------------------------------
#		# Check permissions -- do this in every exposed function
#		self.__check_permissions()
#-------------------------------------------------------------------------------

import cherrypy
from cherrypy._cptools import XMLRPCController

from sqlalchemy import exceptions
import sqlalchemy

import types
import inspect
import logging
import random
import string
import datetime
import time
import ldap
import re

from openipam.config import backend
from openipam.config import auth
from openipam.backend.auth.interfaces import InternalAuthInterface, LDAPInterface
from openipam.backend.db import interface
from openipam.utilities import misc, error, validation
from openipam.utilities.perms import Perms

from openipam.config import auth_sources

import IPy

perms = interface.perms

class MainWebService(XMLRPCController):
	'''The main openIPAM API--all of the methods for remote consumption'''
	
	#-----------------------------------------------------------------

	def __check_session(self):
		'''
		Fix my name someday... I actually return a db object to be used after making sure there
		is a valid session.
		'''
		
		# Make sure that that DB object still exists for this session
		if hasattr(cherrypy, 'session') and cherrypy.session.has_key('user'):
			# The server has restarted, but the session needs to still exist
			
			db = interface.DBInterface(uid=cherrypy.session['user']['uid'], username=cherrypy.session['user']['username'], min_perms=cherrypy.session['user']['min_permissions'])
			return db
		raise error.SessionExpired()

	#----------------------	   ATTRIBUTES	 -------------------------

	def assign_attribute(self, aid, value, mac):
		"""Assign attribute data to a specific host
		@param aid: the database attribute id
		@param value: the value to assign to this characteristic of this host
		@param mac: unique identifier of a host"""
		# TODO: value can be either a string, or an id of a selection from the table (ie. if this is a drop down attribute)
		# TODO: do we need to allow attributes for networks and domains, in addition to hosts?
		
		pass
	
	def __sanitize(self, query):
		"""
		Serializes the data in a SQLAlchemy ResultProxy object so that it can be
		transported over XML-RPC.
		
		Rows that contain certain objects like datetime.datetime() will actually
		be just fine transported over XML-RPC (sweet, I know).
		
		@query: a SQLAlchemy ResultProxy object
		@return: a list of dictionaries, each representing a returned row
		"""
		
		return [dict(row) for row in query]

	#-----------------------------------------------------------------
	#					   EXPOSED FUNCTIONS
	#-----------------------------------------------------------------

	#-------------------     TEST FUNCTIONS	    ----------------------
	
	@cherrypy.expose
	def raise_exception(self):
		raise error.FatalException("This is a test exception raised over XMLRPC")
	
	@cherrypy.expose
	def get_tuple(self):
		return ('Test', 'Tuple')
	
	#-------------------     AUTHENTICATION	    ----------------------
	
	@cherrypy.expose
	def login(self, username, password):
		"""
		The main login function. This will first try internal authentication, then LDAP if configured.
		
		For security, always raises error.InvalidCredentials if username OR password failed
		@raise error.InvalidCredentials: if username or password are bad
		@raise error.NoEmail: if an LDAP user authenticates successfully, but has no email address set
		"""
		
		try:
			if not username or not password:
				raise Exception()
			
			user = auth_sources.authenticate(username, password)
	
			cherrypy.log('Successful login: %s' % str(user.__dict__), context='', severity=logging.DEBUG, traceback=False) 
	
			# Store the stuff if successful login
			cherrypy.session['user'] = user.__dict__
			
			# Done!
			return user.__dict__
		except error.NoEmail:
			# FIXME: it looks like the except below could be made to catch this one, so maybe we should get rid of this
			cherrypy.log('Failed Login: User does not have Email address: %s' % str(user.__dict__), context='', severity=logging.DEBUG, traceback=False) 
			raise
		except Exception, e:
			# Failed login!

			do_traceback = True
			# Add other error types to this condition if you don't want a traceback when the error is raised
			if type(e) in (error.NotImplemented, error.InvalidCredentials, ldap.INVALID_CREDENTIALS, ldap.OPERATIONS_ERROR):
				do_traceback = False
			
			cherrypy.log('Failed Login (type %s): %s %s' % (type(e), username, e.message), context='', severity=logging.DEBUG, traceback=do_traceback)
			
			# Just don't do: "Invalid password: %s" % password    ;)
			raise error.InvalidCredentials("Invalid credentials; username: %s" % username)
		
		# We should never get here
		raise error.FatalException()
	
	@cherrypy.expose
	def get_user_info(self, info):
		if perms.ADMIN & cherrypy.session['user']['min_permissions'] != perms.ADMIN:
			raise Exception('Insufficient permissions to look up user information.')
		info = auth_sources.get_info( **info )
		if info:
			return info.__dict__
		return None

	@cherrypy.expose
	def have_session(self):
		try:
			self.__check_session()
		except error.SessionExpired:
			return False
		return True
	
	@cherrypy.expose
	def logout( self ):
		try:
			cherrypy.session.delete()
		except:
			pass
		return True

	#----------------------	   PERMISSIONS	  ------------------------
	
	@cherrypy.expose
	def get_permissions(self, *args):
		"""
		Get all permission types
		"""
		
		# Check session -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({ 'make_dictionary' : False },)

		result = self.__sanitize(db.get_permissions())
		
		if args[0]['make_dictionary']:
			temp_dict = {}
			
			# Have [ { 'id' : '00000000', 'name' : 'NONE', 'description' : '' }, ... ]
			for perm in result:
				temp_dict[perm['id']] = perm
				
			result = temp_dict
			# Now have { '00000000' : { ...perms dict... }, '00000001' : { ...perms dict... } ... }

		return result
		
	
	#----------------------	   ATTRIBUTES	 -------------------------
	# Attributes are custom characteristics to be tracked about a host. This can be anything from internal
	# inventory numbers, building names, descriptions, or anything that an implementation of openIPAM wants
	# to track about a host.
	
	@cherrypy.expose
	def get_host_attributes(self, *args):
		"""Get all host attributes"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.get_host_attributes(**args[0]))
	
	@cherrypy.expose
	def add_host_attribute(self, *args):
		"""
		Create a new host custom attribute
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_host_attribute( **args[0] )
	
	@cherrypy.expose
	def edit_host_attribute(self, *args):
		"""
		Edit a custom host attribute
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.update_host_attribute( **args[0] )
	
	@cherrypy.expose
	def get_host_attribute_values(self, *args):
		"""
		Get all host attributes
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.get_host_attribute_values( **args[0] ))
	
	@cherrypy.expose
	def update_host_attribute_values(self, *args):
		"""Edit an attribute
		@param aid: the database attribute id
		@param values: a tuple or list of strings"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.update_host_attribute_values( **args[0] )
	
	@cherrypy.expose
	def del_host_attribute(self, *args):
		"""
		Delete an attribute and all data associated with it for all hosts
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_host_attribute( **args[0] )
	
	#------------------------	 USERS	  ----------------------------
	# User management
	
	@cherrypy.expose
	def verify_ldap_user(self, *args):
		"""
		Make sure a user exists in LDAP
		
		@raise error.NotUser if the user is not found
		"""

		# FIXME: figure out permissions

		ldap_interface = LDAPInterface()
		
		try:
			ldap_interface.verify(username=args[0]['username'])
		except:
			raise error.NotUser()
	
	@cherrypy.expose
	def find_owners_of_host(self, *args):
		"""
		Find the owners of a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.find_owners_of_host(**args[0]))
	
	@cherrypy.expose
	def add_user(self, *args):
		"""Add a user
		@param kw['name']: a unique identifier for the user
		@param kw['password']: the user's password (if using internal authentication)
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_user(**args[0])
		
	@cherrypy.expose
	def edit_user(self, *args):
		"""
		Edit a user
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		# TODO: This will only be able to edit internal users passwords and usernames,
		# but min_permissions should be able to be edited for any auth source
		pass
	
	@cherrypy.expose
	def del_user(self, *args):
		"""
		Delete a user
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		pass
	
	@cherrypy.expose
	def get_users(self, *args):
		"""Get domains
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_users(**args[0]))
	
	#-----------------------	GROUPS	  ----------------------------
	# Group management; adding and editing groups for users, hosts, networks, and domains. Includes management
	# of members for each of these group types.
	
	@cherrypy.expose
	def get_groups(self, *args):
		"""Add a group
		@param filter: a dictionary on which to filter"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_groups( **args[0] ))
	
	@cherrypy.expose
	def add_group(self, *args):
		"""
		Add a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_group( **args[0] )
	
	@cherrypy.expose
	def edit_group(self, *args):
		"""
		Edit a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		args[0]['gid'] = int(args[0]['gid'])
		
		db.update_group( **args[0] )
	
	@cherrypy.expose
	def del_group(self, *args):
		"""
		Delete a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_group( **args[0] )
		
	@cherrypy.expose
	def add_user_to_group(self, *args):
		"""
		Add a user to a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_user_to_group( **args[0] )
	
	@cherrypy.expose
	def del_user_from_group(self, *args):
		"""
		Delete a user from a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_user_to_group( **args[0] )
	
	@cherrypy.expose
	def add_host_to_group(self, *args):
		"""
		Add a host to a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_host_to_group( **args[0] )
		
	@cherrypy.expose
	def del_host_from_group(self, *args):
		"""
		Delete a host from a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_host_to_group( **args[0] )
	
	@cherrypy.expose
	def add_network_to_group(self, *args):
		"""
		Add a network to a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		args[0]['nid'] = misc.unfix_cidr_network(args[0]['nid'])
		
		db.add_network_to_group( **args[0] )
	
	@cherrypy.expose
	def del_network_from_group(self, *args):
		"""
		Delete a network from a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		args[0]['nid'] = misc.unfix_cidr_network(args[0]['nid'])
		
		db.del_network_to_group( **args[0] )
	
	@cherrypy.expose
	def add_domain_to_group(self, *args):
		"""
		Add a domain to a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_domain_to_group( **args[0] )
	
	@cherrypy.expose
	def del_domain_from_group(self, *args):
		"""
		Delete a domain from a group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_domain_to_group( **args[0] )
	
	#------------------------	 HOSTS	  ----------------------------
	# Host management
	
	@cherrypy.expose
	def validate_host_info(self, *args):
		"""
		Validate the host info for add or edit
		
		@param args[0]['editing']: a boolean of if this is validating for add or edit 
		
		@raise Exception( messages list ) if any errors occur
		"""
		
		messages = []
		kw = args[0]
		
		# VALIDATE ARGUMENTS
		if not kw.has_key('editing'):
			kw['editing'] = False
		
		# Make the owners argument if owners_list was specified
		if kw.has_key('owners_list'):
			# If given an owners CSV string, make it a list
			kw['owners'] = kw['owners_list'].split(',')
			del kw['owners_list']
			
		if (not kw.has_key('mac')
		or not kw.has_key('hostname')
		or not kw.has_key('domain')
		or not kw.has_key('expiration')
		or (not kw['editing'] and not kw.has_key('owners') and (not kw.has_key('add_host_to_my_group') or (kw.has_key('add_host_to_my_group') and not kw['add_host_to_my_group']))) 
		or not kw.has_key('description')
		or not kw.has_key('is_dynamic')
		):
			messages.append('Some information required to perform the action was not supplied. %s' % str(kw))
			
		if kw['editing'] and not kw.has_key('old_mac'):
			raise error.RequiredArgument("When editing, old_mac is a required argument.")
		if not kw['is_dynamic'] and not kw['editing'] and (not kw.has_key('network') or (kw.has_key('network') and not kw['network'])):
			messages.append("This is a static IP registration and the network was not specified.")
			
		# Make sure that anything that is dropdown-like (except networks) is using IDs as values
		if kw.has_key('domain') and kw['domain'] and type(kw['domain']) is not types.IntType:
			raise error.InvalidArgument("The domain specified must be an integer and must be a domain ID.")
		if kw.has_key('expiration') and kw['expiration'] and type(kw['expiration']) is not types.IntType:
			raise error.InvalidArgument("The expiration specified must be an integer and must be an expiration ID.")
		if kw.has_key('owners') and kw['owners'] and type(kw['owners']) is not types.ListType and type(kw['owners']) is not types.TupleType:
			raise error.InvalidArgument("The owners argument specified must be a list or tuple of group names.")
		
		# Raise required argument errors
		if messages:
			raise error.ListXMLRPCFault(messages)

		# VALIDATE SYNTAX
		if kw['mac'] and not validation.is_mac(kw['mac']):
			messages.append('The specified MAC address is invalid.')
		if (not kw['editing'] and not kw['hostname']) or (kw['hostname'] and not validation.is_hostname(kw['hostname'])):
			messages.append('The specified hostname is invalid. Please use only letters, numbers, and dashes.')
		if not kw['is_dynamic'] and kw.has_key('network') and kw['network'] and not validation.is_cidr(kw['network']):
			messages.append('The specified network is invalid. Please give a valid network in CIDR notation.')
		if kw.has_key('owners') and not kw['owners']:
			messages.append('At least one owner must be specified.')
			
		if kw['editing'] and not validation.is_mac(kw['old_mac']):
			messages.append('The specified old MAC address is invalid.')

		# If I'm a DEITY, allow me to specify an IP address
		# Actually, there shouldn't be any harm in allowing anyone who can assign static addresses do this
		if cherrypy.session['user']['min_permissions'] == perms.DEITY:
			if kw.has_key('ip') and kw['ip'].strip():
				# Have an address inputed, validate it
				if not validation.is_ip(kw['ip']):
					messages.append("The IP address specified is invalid.")
		
		# Raise syntax errors
		if messages:
			raise error.ListXMLRPCFault(messages)

		
		# VALIDATE SEMANTICS
		
		# Get the domain asked for and where I have ADD permissions
		domain = self.get_domains( { 'did' : kw['domain'], 'additional_perms' : perms.ADD })
		
		# Make sure I'm asking to put this host in a domain over which I have ADD access
		if not domain:
			messages.append("Insufficient permissions to add host to domain %s" % kw['domain'])
		
		# Static IP permissions
		if not kw['is_dynamic'] and kw.has_key('network') and kw['network'] and not cherrypy.session['user']['min_permissions'] == perms.DEITY:
			# Get the network asked for and where I have ADD permissions
			network = self.get_networks( { 'network' : kw['network'], 'additional_perms' : perms.ADD })
			
			# Make sure I'm asking to put this host in a network over which I have ADD access
			if not network:
				messages.append("Insufficient permissions to add host to network %s" % kw['network'])
		
		# Raise semantic errors for these that are required to continue
		if messages:
			raise error.ListXMLRPCFault(messages)
		
		domain = domain[0]
		
		# Make the new hostname fully qualified
		if not kw['editing'] or (kw['editing'] and kw['domain'] and kw['hostname']):
			kw['hostname'] = '%s.%s' % (kw['hostname'], domain['name'])
			
		# Make description NULL if blank string (for DB)
		if not kw['editing'] and not kw['description']:
			kw['description'] = None
		
		# If editing, get the old host info for reference
		if kw['editing']:
			old_host = self.get_hosts( { 'mac' : kw['old_mac'], 'additional_perms' : perms.OWNER } )
			if not old_host:
				raise error.NotFound("The host you were editing was not found.")
			old_host = old_host[0]
		
		# If we're not allowing non-admin host transfers, and you didn't specify add_host_to_my_group (or you did specify it, but it's False)
		if not backend.allow_non_admin_host_transfer and (not kw.has_key('add_host_to_my_group') or (kw.has_key('add_host_to_my_group') and not kw['add_host_to_my_group'])):
			has_min_admin_perms = Perms(cherrypy.session['user']['min_permissions']) & perms.ADMIN == perms.ADMIN
			if not has_min_admin_perms:
				# A normal user (non-admin and not in service group) cannot create a
				# host and NOT be OWNER over it, verify this state:
				# (you know you love the double negatives)
				users_groups = self.get_groups( { 'uid' : cherrypy.session['user']['uid'], 'additional_perms' : perms.OWNER } )
				users_group_names = [row['name'] for row in users_groups]
				
				# Am I in a group that has owner over this host?
				# There is surely a more elegant and pythonic way to compare all elements of lists:
				has_owner_group = False
				for name in users_group_names:
					if name in kw['owners']:
						has_owner_group = True
						break
					
				if (kw.has_key('owners') and (not has_owner_group and not self.get_users( { 'uid' : cherrypy.session['user']['uid'], 'gid' : backend.db_service_group_id } ))):
					messages.append("You are not allowed to remove yourself from ownership of this host. However, you can assign other owners and have them remove you from this host.")
		
		# Verify that this host MAC and hostname don't exist already
		if not kw['editing']:
			host_by_mac = self.get_hosts( { 'mac' : kw['mac'], 'show_expired' : False  })
			host_by_name = self.get_hosts( { 'hostname' : kw['hostname'], 'show_expired' : False  })
		else:
			# If the MAC has changed, make sure that the new MAC address is not taken
			host_by_mac = None
			if kw.has_key('mac') and kw['mac'] and (kw['old_mac'] != kw['mac']):
				host_by_mac = self.get_hosts( { 'mac' : kw['mac'] })
			
			# If the hostname has changed, make sure that the new hostname is not taken
			host_by_name = None
			if kw.has_key('hostname') and kw['hostname'] and (kw['hostname'] != old_host['hostname']):
				host_by_name = self.get_hosts( { 'hostname' : kw['hostname'] })
		
		if host_by_mac:
			messages.append("The specified MAC address is already registered.")
		if host_by_name:
			messages.append("The specified hostname is already registered.")
		
		# If an old value is the same as the new one, delete it so that we don't update the DNS records everytime
		if kw['editing']:
			if kw['hostname'] == old_host['hostname']:
				del kw['hostname']
			if kw['mac'] == old_host['mac']:
				del kw['mac']
			if kw['description'] == old_host['description']:
				del kw['description']
				
		# Expiration
		expirations = self.get_expiration_types()
		
		if kw.has_key('expiration') and kw['expiration']:
			expiration = None
			for exp in expirations:
				# Match the given expiration to our expiration types so we can have an ID
				if exp['id'] == kw['expiration']:
					expiration = exp['expiration']
			
			if not expiration:
				# Someone is playing with the form data to get a different expiration, just give them the last one
				expiration = expirations[-1]['expiration']
			
			# Calculate the actual expiration date from the selected expiration type
			# Add one day to it so that it will expire after midnight of the day it expires
			expiration = misc.make_time_delta(expiration) + datetime.timedelta(days=1) + datetime.date.today()
			kw['expires'] = expiration
			
		# Raise semantic errors
		if messages:
			raise error.ListXMLRPCFault(messages)
		
		del kw['expiration']
		del kw['domain']
		del kw['editing']
		
		return (kw,)
	
	@cherrypy.expose
	def register_host(self, *args):
		"""
		Register a host

		Parameters that are parsed before getting to the DB layer:
		@param do_validation: a boolean of whether to validate the host data or not before passing it to the DB
		@param owners_list: a string of comma-separated owner groups
		@param expiration_interval: an optional parameter passed in the dictionary. It's a string of an expiration
		interval, like '30 days' that will be used to make the 'expires' and 'expiration_format' for register host 
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args[0].has_key('do_validation'):
			args[0]['do_validation'] = True
		
		if args[0]['do_validation']:
			args = self.validate_host_info(*args)

		del args[0]['do_validation']
		
		db.register_host(**args[0])
		
	@cherrypy.expose
	def is_dynamic_host(self, *args):
		"""
		Return if this host is dynamic or not
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return bool(db.get_hosts_to_pools( **args[0] ))
	
	@cherrypy.expose
	def edit_host(self, *args):
		"""
		Edit a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args[0].has_key('old_mac'):
			raise error.RequiredArgument("Must specify the old MAC address for edit_host")

		db.update_host(**args[0])
		
	@cherrypy.expose
	def change_registration(self, *args):
		"""
		Change a full host registration
		@param expiration_interval: an optional parameter passed in the dictionary. It's a string of an expiration
		interval, like '30 days' that will be used to make the 'expires' and 'expiration_format' for register host 
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		args[0]['editing'] = True
		
		if not args[0].has_key('do_validation'):
			args[0]['do_validation'] = True
		
		if args[0]['do_validation']:
			args = self.validate_host_info(*args)
			del args[0]['do_validation']
		
		db.change_registration(**args[0])
	
	@cherrypy.expose
	def del_host(self, *args):
		"""
		Delete a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_host( **args[0] )
	
	@cherrypy.expose
	def get_hosts(self, *args):
		"""
		Get hosts
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if args[0].has_key('mac'):
			if args[0]['mac'] and not validation.is_mac(args[0]['mac']):
				raise error.InvalidMACAddress()
		
		return self.__sanitize(db.get_hosts( **args[0] ))
	
	@cherrypy.expose
	def find_permissions_for_hosts(self, *args):
		"""
		Returns a dictionary of { MAC address : permissions bitstring } 
		for this user's overall permissions on the hosts
		
		@param args[0]['hosts']: a list of host MACs, or a list of dictionaries of hosts that have a 'mac' key
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.find_permissions_for_hosts( **args[0] ))
	
	@cherrypy.expose
	def get_next_hostname(self, *args):
		"""
		Generate hostnames styled as "username-#.example.com"
		and return the first un-used one
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if not args[0].has_key('domain'):
			raise error.RequiredArgument("Must specify both domain for getting the next hostname.")

		hostname = cherrypy.session['user']['username'].lower()
		
		# If username.example.com is not taken, return it
		initial_hostname = '%s.%s' % (hostname, args[0]['domain'])
		hosts = db.get_hosts( hostname=initial_hostname )
		if not hosts:
			return initial_hostname
		
		# Otherwise, generate username-#.example.com and return the first un-used
		
		# FIXME: find a better way to do this ... but hopefully a user doesn't
		# have 1000 hostnamed named "username" thorough "username-999"
		for i in range(1, 1000):
			try_hostname = '%s-%s.%s' % (hostname, i, args[0]['domain'])
			
			hosts = db.get_hosts( hostname=try_hostname, show_expired=True )
			
			if not hosts:
				return try_hostname
		
		raise error.FatalException()
			
	@cherrypy.expose
	def assign_static_address(self, *args):
		"""
		Assign a static address to a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()

		addr = db.assign_static_address( **args[0] )
		return addr

	#----------------------	   NETWORKS	   ---------------------------
	
	@cherrypy.expose
	def get_addresses(self, *args):
		"""
		Get addresses
		"""
		
		if not args:
			args = ({},)

		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		addrs = db.get_addresses( **args[0] )
		return self.__sanitize( addrs )
	
	@cherrypy.expose
	def add_shared_network(self, *args):
		"""
		Add a network
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		ids = db.add_shared_network( **args[0] ).last_inserted_ids()
		return ids
	
	@cherrypy.expose
	def add_network(self, *args):
		"""
		Add a network
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		net_ids = db.add_network( **args[0] ).last_inserted_ids()
		return net_ids
	
	@cherrypy.expose
	def edit_network(self, *args):
		"""
		Edit a network
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		pass
	
	@cherrypy.expose
	def del_network(self, *args):
		"""
		Delete a network
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		pass
	
	@cherrypy.expose
	def get_networks(self, *args):
		"""
		Get networks
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if args[0].has_key('network'):
			
			if args[0]['network'] == '%':
				# If % exists, get all networks
				del args[0]['network']
			
			elif not validation.is_cidr(args[0]['network']):
				raise error.InvalidCIDRNetwork()
		
		return self.__sanitize(db.get_networks( **args[0] ))
	
	@cherrypy.expose
	def get_free_ip(self, *args):
		"""
		Get the first unallocated IP address on a network
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		pass
	
	#----------------------	   DOMAINS	  ----------------------------
	# Domain management

	@cherrypy.expose
	def add_domain(self, *args):
		"""
		Add a domain
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_domain( **args[0] )
	
	@cherrypy.expose
	def edit_domain(self, *args):
		"""
		Edit a domain
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		# TODO: hmmm ... bring the networks and associated hosts with the change?
		
		db.update_domain( **args[0] )
	
	@cherrypy.expose
	def del_domain(self, *args):
		"""
		Delete a domain
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		# TODO: how should this affect all associated hosts?
		pass
	
	@cherrypy.expose
	def get_domains(self, *args):
		"""
		Get domains
		"""
		
		if not args:
			args = ({},)
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.get_domains( **args[0] ))

	#------------------------	 POOLS	 -----------------------------
	
	@cherrypy.expose
	def get_pools(self, *args):
		"""
		Get all DHCP options
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_pools(**args[0]))
		
	#------------------------	 DHCP	 -----------------------------
	# DHCP management
	
	@cherrypy.expose
	def find_mac_from_lease(self, *args):
		"""
		Blindly returns a MAC address associated with one IP address.
		"""
		# Check permissions -- do this in every exposed function
		db = self.__check_session()

		if not args[0].has_key('ip'):
			raise error.RequiredArgument("ip")
		
		if not validation.is_ip(args[0]['ip']):
			raise error.InvalidIPAddress()
		
		return self.__sanitize(db.find_mac_from_lease( **args[0] ))
	
	@cherrypy.expose
	def get_dhcp_options(self, *args):
		"""
		Get all DHCP options
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_dhcp_options( **args[0] ))
	
	@cherrypy.expose
	def get_dhcp_group_options(self, *args):
		"""
		Get all (or filtered) options inside a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.get_dhcp_group_options( **args[0] ))
		
	@cherrypy.expose
	def get_dhcp_groups(self, *args):
		"""
		Get all DHCP options
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_dhcp_groups( **args[0] ))
	
	@cherrypy.expose
	def get_leases(self, *args):
		"""
		Get leases
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		return self.__sanitize(db.get_leases( **args[0] ))
	
	@cherrypy.expose
	def del_dhcp_group(self, *args):
		"""
		Delete a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_dhcp_group( **args[0] )

	@cherrypy.expose
	def add_dhcp_option_to_group(self, *args):
		"""
		Delete an option from a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_dhcp_option_to_group( **args[0] )
	
	@cherrypy.expose
	def edit_dhcp_option_in_group(self, *args):
		"""
		Update a DHCP optionToGroup information
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.update_dhcp_option_to_group( **args[0] )
	
	@cherrypy.expose
	def del_dhcp_option_from_group(self, *args):
		"""
		Delete an option from a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_dhcp_option_to_group( **args[0] )
	
	@cherrypy.expose
	def del_dhcp_group(self, *args):
		"""
		Delete a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_dhcp_group( **args[0] )

	@cherrypy.expose
	def add_dhcp_group(self, *args):
		"""
		Add a DHCP group
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.add_dhcp_group( **args[0] )

	@cherrypy.expose
	def edit_dhcp_group(self, *args):
		"""
		Update a DHCP group's information
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.update_dhcp_group( **args[0] )
	
	@cherrypy.expose
	def is_disabled(self, *args):
		"""
		Return information about a host if it is disabled
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if args[0].has_key('mac'):
			if args[0]['mac'] and not validation.is_mac(args[0]['mac']):
				raise error.InvalidMACAddress()
		
		return self.__sanitize( db.is_disabled( **args[0] ) )
	
	@cherrypy.expose
	def disable_host(self, *args):
		"""
		Disable a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if args[0].has_key('mac'):
			if args[0]['mac'] and not validation.is_mac(args[0]['mac']):
				raise error.InvalidMACAddress()
		
		db.disable_host( **args[0] )
	
	@cherrypy.expose
	def enable_host(self, *args):
		"""
		Re-enable a host
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		if args[0].has_key('mac'):
			if args[0]['mac'] and not validation.is_mac(args[0]['mac']):
				raise error.InvalidMACAddress()
		
		db.enable_host( **args[0] )
	
	@cherrypy.expose
	def get_disabled(self, *args):
		"""Get disabled hosts"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		return self.__sanitize(db.get_disabled(**args[0]))
	
	
	#-------------------------	  DNS	 -----------------------------
	# DNS management
	
	@cherrypy.expose
	def get_dns_records(self, *args):
		"""
		Get DNS resource record types
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
			
		return self.__sanitize(db.get_dns_records( **args[0] ))
	
	@cherrypy.expose
	def find_permissions_for_dns_records(self, *args):
		"""
		Returns a dictionary of { dns record : permissions bitstring } 
		for this user's overall permissions on the hosts
		
		@param args[0]['domains']: a list of DNS record IDs, or a list of dictionaries of DNS records that have an 'id' key
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		result = db.find_permissions_for_dns_records( **args[0] )
		
		# We have to do this because XMLRPC doesn't support integer keys on structs
		# Ggrrrraaarrgggghhhh
		 
		new_result = {}
		
		if result:
			for key in result[0]:
				new_result[str(key)] = result[0][key]
 		
		return self.__sanitize( [new_result] )
	
	@cherrypy.expose
	def change_dns_records(self, *args):
		"""
		Change a set of DNS records.
		
		@param records: a list of dictionaries of DNS records. For each DNS record dictionary, follow the following rules:
		- If the DNS record is new, no id should be present in the dictionary
		- If it is deleted, a key of 'deleted' should be present with a value of true
		- If the record has been edited, or has been left the same, just pass the dictionary
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		# Begin transaction
		db._begin_transaction()
		try:
			(edited, deleted, new) = self.validate_dns_records( *args )
		
			for row in edited:
				db.del_dns_record(rid=row['id'])
				db.add_dns_record(
					name=row['name'],
					tid=row['tid'],
					ip_content=row['ip_content'],
					text_content=row['text_content'],
					priority=row['priority'],
					vid=row['vid']
				)
			
			for id in deleted:
				db.del_dns_record(rid=id)
			
			for row in new:
				db.add_dns_record(
					name=row['name'],
					tid=row['tid'],
					ip_content=row.get('ip_content', None),
					text_content=row.get('text_content', None),
					priority=row.get('priority', None)
				)
			
			db._commit()
		except Exception, e:
			# Raise required argument errors
			db._rollback() #rollback transaction if there were errors
			raise
	
	@cherrypy.expose
	def validate_dns_records(self, *args):
		"""
		Validate a set of DNS records
		@raise Exception( messages list ) if any errors occur
		"""
		
		def validate_syntax(row, new_record=False):
			"""
			Validate the syntax of both new rows and updated rows
			@param row: a dictionary based on a dns_records table row
			@param new_record: is this a new record or a changed one?
			"""
			
			# TODO: make sure no records exist that have the same name as an added CNAME
			# TODO: changed ip can only be changed to a static address
			
			# Validate deleted rows have an id
			if row.has_key('deleted'):
				if not row.has_key('id'):
					raise error.RequiredArgument("Deleted rows need to specify 'id' key. Row info: %s" % row)
				else:
					return
			
			# Validate row has a tid
			if not row.has_key('tid'):
				raise error.RequiredArgument("tid is required to validate a DNS record")
			
			# Validate records based on type
			if row['tid'] in (15, 33): # MX or SRV records
				
				if new_record and not row.has_key('priority'):
					messages.append("Priority is required for MX and SRV records.")
			
			# Validate both name and content are present
			if new_record and not row['tid'] == 1 and (not row.has_key('name') or not row.has_key('text_content')):
				raise error.RequiredArgument("Name and content are required for new records.")
		
			# Validate: Name
			if row.has_key('name'):
				# validate that each name is a fqdn. we are assuming that every name 'should' always be a fqdn...
				if not validation.is_fqdn(row['name']):
					messages.append("Invalid name, use a fully qualified domain name: %s" % row['name'] )
			
			# Validate: Text Content
			if row.has_key('text_content'):
				# NS, CNAME, PTR, MX
				if row['tid'] in (2, 5, 12, 15):
					if not validation.is_fqdn(row['text_content']): 
						messages.append("Invalid content, use a fully qualified domain name: %s" % row['text_content'])
				# SOA
				elif row['tid'] == 6:
					if not validation.is_soa_content(row['text_content']): 
						messages.append("Invalid content, use properly formatted SOA content: %s" % row['text_content'])
				# SRV
				elif row['tid'] == 33:
					if not validation.is_srv_content(row['text_content']): 
						messages.append("Invalid content, use properly formatted SRV content: %s" % row['text_content'])
				else:
					raise error.NotImplemented("Validation for tid %s has not been implemented yet." % row['tid'])
			
			# Validate: IP Content
			if row.has_key('ip_content') and not validation.is_ip(row['ip_content']):
				messages.append("Invalid IP, use a properly formatted IP address: %s" % row['ip_content'])
			
			# Validate: TTL
			if row.has_key('ttl'):
				raise error.NotImplemented("Validation for changes in TTL values is not currently supported." )
			
		def transform_content(row):
			"""
			Transform content field from the form into either ip_content or text_content
			@param row: row from the form
			"""
			
			if(row['tid'] == 1):
				row['ip_content'] = row.pop('content')
			else:
				row['text_content'] = row.pop('content')
		
		def set_priority(row):
			"""
			Checks for priority and sets it if it exists
			@param row: row from the form
			"""
			# Make sure that priority was set, or set it if they passed it
			match = None
			if row['tid'] != 1:
				if row['tid'] == 15: # MX
					match = re.compile('^([0-9]{1,2}) (.*)$').search(row['text_content'])
				elif row['tid'] == 33: # SRV
					match = re.compile('^([0-9]{1,2}) (\d+ \d+ .*)$').search(row['text_content'])
				
				if match:
					# We have priority in the content
				    row['priority'] = match.group(1)
				    row['text_content'] = match.group(2)
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		# Initialize blank lists
		messages = []
		edited = []
		deleted = []
		new = []
		
		form_submission = args[0]
		
		# Retrieve list of ids from the form submission & call get records with those ids
		ids = [row['id'] for row in form_submission if row.has_key('id')]

		# Wow ... for loop vars don't fall out of scope
		del row
		
		result = self.__sanitize(db.get_dns_records(id=ids))
		new_records = [row for row in form_submission if not row.has_key('id')]
		
		id_perms = db.find_permissions_for_dns_records(result)
		id_perms = id_perms[0] if id_perms else {}
		
		fqdn_perms = db.find_domain_permissions_for_fqdns([row['name'] for row in new_records])
		fqdn_perms = fqdn_perms[0] if fqdn_perms else {}
		
		dns_type_perms = self.get_dns_types({ 'only_useable' : True, 'make_dictionary' : True })
		
		# VALIDATE ARGUMENTS AND SYNTAX
		for form_row in form_submission: #loop over results from form
			# Type casting from strings to integers for some frontend form fields (i.e.: id, ttl, etc.)
			for column in ('id', 'tid', 'priority', 'ttl', 'did'):
				if form_row.has_key(column):
					form_row[column] = int(form_row[column])
			
			# STATE: new record
			if not form_row.has_key('id'):
				#transform content into either ip_content or text_content
				transform_content(form_row)
				
				#check for priority and set it if it exists
				set_priority(form_row)
				
				validate_syntax(form_row, new_record=True)
				new.append(form_row)
				
				# VALIDATE SEMANTICS & PERMISSIONS
				if not ((Perms(fqdn_perms[form_row['name']]) & perms.ADD == perms.ADD)
				and (dns_type_perms.has_key(str(form_row['tid'])))):
					messages.append('Insufficient permissions to add record %s' % form_row['name'])
				
				continue
			
			# STATE: deleted record
			elif form_row.has_key('deleted') and form_row['deleted']:
				validate_syntax(form_row)
				deleted.append(form_row['id'])
				
				# VALIDATE SEMANTICS & PERMISSIONS
				if not (Perms(id_perms[form_row['id']]) & perms.DELETE == perms.DELETE):
					messages.append('Insufficient permissions to delete record %s' % form_row['name'])
				continue
			
			# STATE: changed record
			for backend_row in result: 
				if backend_row['id'] == form_row['id']:
					#pass in tid always
					changed_row = { 'id' : form_row['id'], 'tid' : backend_row['tid'] }
					did_change = False
					
					#transform content into either ip_content or text_content
					transform_content(form_row)
					
					#check for priority and set it if it exists
					set_priority(form_row)
					
					# Find out if the record has been edited and add it to the 'edited' list.
					# Otherwise, no change has occurred, so we just leave it alone.
					for column in form_row.keys():
						if (backend_row[column] != form_row[column]):
							changed_row[column] = form_row[column] 
							did_change = True
					
					validate_syntax(changed_row)
					
					if did_change:
						# Since we delete and then re-add, we must have all attributes of the old record
						backend_row.update(changed_row)
						edited.append(backend_row)
						
						# VALIDATE SEMANTICS & PERMISSIONS
						if not (Perms(id_perms[form_row['id']]) & perms.MODIFY == perms.MODIFY):
							messages.append('Insufficient permissions to modify record %s' % form_row['name'])
					
					break
						
		# Raise syntax & semantic errors errors
		if messages:
			raise error.ListXMLRPCFault(messages)

		return (edited, deleted, new)
	
	@cherrypy.expose
	def add_dns_record(self, *args):   
		"""
		Add a DNS record
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()

		db.add_dns_record( **args[0] )

	@cherrypy.expose
	def edit_dns_record(self, *args):
		"""
		Edit a DNS record
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		pass
	
	@cherrypy.expose
	def del_dns_record(self, *args):
		"""
		Delete a DNS record
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		db.del_dns_record( **args[0] )
	
	@cherrypy.expose
	def get_dns_types(self, *args):
		"""
		Get DNS resource record types
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
			
		make_dictionary = args[0].has_key('make_dictionary')
		if make_dictionary:
			del args[0]['make_dictionary'] 
			
		result = self.__sanitize(db.get_dns_types( **args[0] ))
		
		if make_dictionary:
			temp_dict = {}
			
			# Have [ { 'id' : '0', 'name' : 'blah' }, ... ]
			for rr in result:
				temp_dict[str(rr['id'])] = rr
			
			result = temp_dict
			# Now have { '0' : { ... dns dict ... }, '12' : { ... dns dict ... } ... }
			
		return result
			
	
	#------------------ EXPIRATIONS AND NOTIFICATIONS --------------------
	
	@cherrypy.expose
	def get_expiration_types(self):
		"""Get DNS resource record types"""
	
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		result = self.__sanitize(db.get_expiration_types())
		
		for row in result:
			row['expiration'] = misc.fix_timedelta(row['expiration'])
		
		return result
		
	#-------------------------	  GUESTS	 -----------------------------
	
	# Don't expose this function, it's private for a reason
	def __generate_ticket_name(self):
		"""
		Generates a human-readable string for a ticket name.
		Note: Doesn't and shouldn't interact with the database at all
		
		@return: a ticket string name
		"""
	
		vowels = ("a", "e", "i", "o", "u")
		consonants = [a for a in string.ascii_lowercase if a not in vowels]
		groups = ("th", "ch", "sh", "kl", "gr", "br")
		
		num_vowels = len(vowels) - 1
		num_consonants = len(consonants) - 1
		num_groups = len(groups) - 1
	
		vowel = []
		cons = []
		group = []
	
		for i in range(4):
			vowel.append(vowels[random.randint(0, num_vowels)])
			cons.append(consonants[random.randint(0, num_consonants)])
			group.append(groups[random.randint(0, num_groups)])
		
		structure = []
		structure.append('%s%s%s%s%s%s%s%s' % (cons[0], vowel[0], cons[1], cons[2], vowel[1], cons[3], vowel[2], group[0]))
		structure.append('%s%s%s%s%s%s' % (group[0], vowel[0], cons[0], cons[1], vowel[1], group[1]))
		structure.append('%s%s%s%s%s' % (group[0], vowel[0], cons[0], vowel[1], "s"))
		structure.append('%s%s%s%s%s' % (vowel[0], group[0], vowel[1], cons[0], vowel[2]))
		structure.append('%s%s%s%s%s' % (group[0], vowel[0], cons[0], vowel[1], group[1]))
		structure.append('%s%s%s%s' % (vowel[0], group[0], vowel[1], group[1]))
		structure.append('%s%s%s%s%s%s%s%s' % (cons[0], vowel[0], cons[1], vowel[1], cons[2], vowel[2], cons[3], vowel[2]))
		structure.append('%s%s%s%s%s' % (group[0], vowel[1], group[1], vowel[1], cons[0]))
		
		return structure[random.randint(0, len(structure)-1)] 

	@cherrypy.expose
	def get_guest_tickets(self, *args):
		"""
		Get guest tickets
		"""

		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			args = ({},)
		
		args[0]['order_by'] = "id"
		
		return self.__sanitize(db.get_guest_tickets(**args[0]))

	@cherrypy.expose
	def add_guest_ticket(self, *args):
		"""
		Adds a guest ticket to the database and associates it to this user
		
		@param kw['starts']: the start datetime
		@param kw['ends']: the end datetime
		@param kw['description']: a description for this ticket
		
		@return: a string of the ticket name, if no errors raised
		"""
		
		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		if not args:
			raise error.RequiredArgument("nothing passed to add_guest_ticket")
		
		ticket = self.__generate_ticket_name()
		
		query = db.add_guest_ticket(ticket=ticket, **args[0])
		
		return { 'ticket' : ticket, 'starts' : args[0]['starts'], 'ends' : args[0]['ends'], 'description' : args[0]['description'] }
		
	@cherrypy.expose
	def del_guest_ticket(self, *args):
		"""
		Delete a guest ticket
		"""

		# Check permissions -- do this in every exposed function
		db = self.__check_session()
		
		db.del_guest_ticket( **args[0] )
		
	@cherrypy.expose
	def create_shared_network( self, *args ):
		"""
		Add a shared network
		
		@param kw['networks']: A list of networks (CIDR)
		@param kw['name']: A name for the shared network
		@param kw['description']: A description of the network
		
		@return: None
		"""
		
		if not args:
			raise error.RequiredArgument("create_shared_network must get a dict of args.")
		
		if not args[0].has_key('description'):
			args[0]['description'] = None

		# Check permissions -- do this in every exposed function
		db = self.__check_session()
				
		db._begin_transaction()
		try:
			result = db.add_shared_network( name=args[0]['name'], description=args[0]['description'])
			shared = result.last_inserted_ids()[0]
			for net in args[0]['networks']:
				net = IPy.IP( net.strip() )
				gw = net[ backend.default_gateway_address_index ]
				db.add_network( network=str(net), gateway=str(gw), name=args[0]['name'], shared_network=shared, description=args[0]['description'] )
			db._commit()
		except:
			db._rollback()
			raise
	
	@cherrypy.expose
	def register_guest(self, *args):
		"""
		Do everything necessary to register a guest for access to the network
		for the time amount specified on the given ticket.
		
		@param kw['ip']: the IP address of the guest, which will be used to get that user's MAC from DHCP
		@param kw['ticket']: a string of the ticket ID
		@param kw['description']: an optional description of this guest (could be their name)
		
		@raise error.InvalidTicket: raised when a ticket is invalid
		@return: None 
		"""
		
		# *** BE CAREFUL IN THIS FUNCTION ***
		
		# DON'T CALL check_session because guests will never have a normal user session
		# DON'T CALL any other function in the webservice because that function needs a session
		# DON'T CREATE a session EVER because that session would have DEITY access to everything
		# DO CREATE code that talks directly to our own DB object, __guest_db
		
		if not args[0].has_key('ip') or not args[0].has_key('ticket'):
			raise error.RequiredArgument("Must pass both ip and ticket to register_guest")
		 	
		if not args[0].has_key('description'):
			args[0]['description'] = None
		
		__guest_db = interface.DBInterface( username=backend.guest_user )
		
		now = datetime.datetime.now()
		
		# FIXME
		if auth.guests_multi_use_tickets:
			ticket = __guest_db.get_guest_tickets(ticket=args[0]['ticket']) 
			
			if not ticket:
				raise error.InvalidTicket()
			
			ticket = ticket[0]
			
			if ticket['starts'] > now:
				raise error.InvalidTicket()
			
			if ticket['ends'] < now:
				raise error.InvalidTicket()
			
			# Valid ticket, register their MAC address
			if not validation.is_ip( args[0]['ip'] ):
				raise error.InvalidIPAddress()
			
			macaddr = self.__sanitize( __guest_db.find_mac_from_lease( **{ 'ip' : args[0]['ip'] } ) )
			
			hostname_fmt = auth.guests_hostname_format
			if not macaddr:
				# No lease exists to this guest computer, are they hard-coding?
				raise error.NotFound("The MAC address for this guest's host could not be found. Ticket: %s IP:%s" % (args[0]['ticket'], args[0]['ip']))
			
			macaddr = macaddr[0]['mac']
			
			# Get the last guest hosts
			hosts = __guest_db.get_hosts( hostname=hostname_fmt % '%%', limit=1, funky_ordering=True)
			
			if hosts:
				# Have one host, need to get one number bigger
				try:
					# Oh, so very evil... take the last guest host and parse out the %s part from the format, which better be a number
					# FIXME: a regex might be a better fit here
					
					end_part = hostname_fmt[hostname_fmt.find('%s')+2:]
					
					hostname = int(hosts[0]['hostname'][hostname_fmt.find('%s'):hosts[0]['hostname'].find(end_part)])
					
					# Create a new hostname by using the format and increasing the last guest host's number by 1
					hostname = hostname_fmt % str(hostname+1)
				except:
					raise error.FatalException("Couldn't determine format for guest hostname ... got last host: %s" % hosts) 
			else:
				# No guest hosts registered yet:
				hostname = hostname_fmt % '1'
			
			__guest_db._begin_transaction()
			try:
				__guest_db.register_host( mac = macaddr,
								hostname = hostname,
								description = args[0]['description'],
								expires = ticket['ends'],
								is_dynamic = True,
								add_host_to_my_group = False )
				
				# FIXME: it might be better to associate these with the owner of the ticket
				# -- We'll probably need to do both, they should probably be in the guest group in any case
				__guest_db.add_host_to_group( mac = macaddr, gid=backend.db_default_guest_group_id )
				
				__guest_db._commit()
			except Exception, e:
				__guest_db._rollback()
				raise error.AlreadyExists("MAC address may already exists ... couldn't add guest host. Error was: %s" % e)
			
			
		else:
			# FIXME: implement
			raise error.NotImplemented("Single use guest tickets has not been created")
		
		# Be paranoid
		del __guest_db
		
		
#	@cherrypy.expose
#	def disable_host( self, args ):
#		disable_mac = 'aacaaa00f00f'
#		if not args.has_key('mac'):
#			raise error.RequiredArgument('disable_host requires a mac address')
#		if not args.has_key('reason'):
#			raise error.RequiredArgument('disable_host requires a reason')
#
#		mac=args['mac']
#		reason=args['reason']
#
#		db = self.__check_session()
#
#		# We need to get rid of all of the following data, but we should keep it somewhere
#		h2g = db.get_hosts_to_groups(mac=mac)
#		h2p = db.get_hosts_to_pools(mac=mac)
#		h2a = db.get_addresses(mac=mac)
#
#		db._begin_transaction()
#		try:
#			db.del_host_to_group( mac=mac )
#			groups = []
#			for g in h2g:
#				groups.append( g['gid'] )
#
#			pools=[]
#			db.del_host_to_pool( mac=mac )
#			for p in h2p:
#				pools.append( p['pool_id'] )
#
#			db.update_address( address=a['address'], mac=disable_mac )
#			addrs = []
#			for a in h2a:
#				addrs.append( a['address'] )
#			
#			description = '|'.join( [ re.sub(r'|','',description),
#				','.join(groups),','.join(pools), ','.join(addrs), ] )
#
#			db.add_host_to_group( mac, group_name='disabled' )
#
#			db._commit()
#		except:
#			db._rollback()
#			raise
		
		

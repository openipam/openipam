import types

import cherrypy

import framework
from basepage import BasePage
from resource.submenu import submenu, OptionsSubmenu
from openipam.utilities import misc, error, validation
from openipam.utilities.perms import Perms
from openipam.web.resource.utils import redirect_to_referer
from openipam.config import frontend

class Hosts(BasePage):
	'''The hosts class. This includes all pages that are /hosts/*'''

	def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("hosts", javascript=("/scripts/jquery/ui/jquery-ui-personalized.min.js", "/scripts/hosts.js"))
		
	def leftnav_actions(self, current=None):
		'''
		Returns the html for the leftnav
		@param current: a string of the current action that will be highlighted
		'''
		
		actions = ('Add Host',)
		action_links = ('/hosts/add',)
		
		return submenu(values=actions, links=action_links, title="Actions", selected=current)
	
	def leftnav_options(self):
		'''
		Returns the html for the leftnav options on the Manage Hosts tab
		'''
		
		options = ('Show expired hosts', 'Show all hosts')
		options_links = ('/hosts/?show_expired', '/hosts/?show_all')
		selected = (cherrypy.session['show_expired_hosts'], cherrypy.session['show_all_hosts'])
		
		return OptionsSubmenu(values=options, links=options_links, title="Options", selected=selected)
	
	def get_leftnav(self, action="", show_options=True):
		return '%s%s' % (self.leftnav_actions(action), (self.leftnav_options() if show_options else ''))
	
	def get_hosts(self, page=0, ip=None, mac=None, hostname=None, network=None, username=None):
		"""
		@param page: the current page the user is viewing
		@param show_all_hosts: default false, will only show hosts that the current user has OWNER over
		"""
		
		additional_perms = str(frontend.perms.OWNER)
		if cherrypy.session['show_all_hosts']:
			additional_perms = '00000000'
		
		values = {
			'additional_perms' : str(additional_perms),
			'limit' : cherrypy.session['hosts_limit'],
			'page' : int(page),
			'show_expired' : cherrypy.session['show_expired_hosts'],
			'ip' : ip,
			'mac' : mac,
			'username' : username,
			'hostname' : hostname,
			'network' : network
			}
		
		try:
			hosts = self.webservice.get_hosts( values )
		except Exception, e:
			if error.parse_webservice_fault(e) == "NotUser":
				hosts = []
			else:
				raise
		
		for host in hosts:
			host['clean_mac'] = misc.fix_mac(host['mac'])
			host['description'] = host['description'].encode('utf8') if host['description'] else ''
			
		# Get permissions for those MAC addresses
		perms = self.webservice.find_permissions_for_hosts( { 'hosts' : hosts } )
		
		for host in hosts:
			host['has_permissions'] = ((Perms(perms[host['mac']]) & frontend.perms.OWNER) == frontend.perms.OWNER)
		
		return hosts
		
	def mod_host_attributes(self, values=None):
		"""
		Return the attributes passed to the Add/Edit host template that are shared between
		Add and Edit functionality
		"""
		
		if not values:
			values = {}
		
		# FIXME: this needs to come from the backend
		values['allow_dynamic_ip'] = frontend.allow_dynamic_ip

		values['networks'] = self.webservice.get_networks( { 'additional_perms' : str(frontend.perms.ADD), 'order_by' : 'network' } )
		values['domains'] = self.webservice.get_domains( { 'additional_perms' : str(frontend.perms.ADD), 'order_by' : 'name' } )
		values['expirations'] = self.webservice.get_expiration_types()
 		values['groups'] = self.webservice.get_groups( { 'ignore_usergroups' : True, 'order_by' : 'name' } )
		
		return values

	def add_host(self, **kw):
		'''
		Process the add_host request
		'''
		
		# Confirm user authentication
		self.check_session()
		
		self.webservice.register_host(
			{
			'mac' : kw['mac'],
			'hostname' : kw['hostname'],
			'domain' : int(kw['domain']),
			'description' : kw['description'],
			'expiration' : int(kw['expiration']),
			'is_dynamic' : kw.has_key('dynamicIP'),
			'owners_list' : kw['owners_list'], 
			'network' : (kw['network'] if kw.has_key('network') else None),
			'add_host_to_my_group' : False,
			'address' : (kw['ip'] if kw.has_key('ip') else None)
			})
		
		raise cherrypy.HTTPRedirect('/hosts/search/?q=%s' % misc.fix_mac(kw['mac']))
	
	def edit_host(self, **kw):
		'''
		Process the edit_host request
		'''
		
		# Confirm user authentication
		self.check_session()
		
		self.webservice.change_registration(
			{
			'old_mac' : kw['old_mac'],
			'mac' : kw['mac'],
			'hostname' : (kw['hostname'] if kw.has_key('hostname') else None),
			'domain' : (int(kw['domain']) if kw.has_key('domain') else None),
			'description' : kw['description'],
			'expiration' : (int(kw['expiration']) if kw.has_key('did_renew_host') else None),
			'is_dynamic' : kw.has_key('dynamicIP'),
			'owners_list' : kw['owners_list'], 
			'network' : (kw['network'] if kw.has_key('did_change_ip') or (kw.has_key('was_dynamic') and not kw.has_key('dynamicIP')) else None),
			'address' : (kw['ip'] if kw.has_key('did_change_ip') and kw.has_key('ip') else None)
			})
		
		raise cherrypy.HTTPRedirect('/hosts/search/?q=%s' % misc.fix_mac(kw['mac'] if kw['mac'] else kw['old_mac']))

	#-----------------------------------------------------------------
	
	@cherrypy.expose
	def index(self, page=0, **kw):
		"""
		The main hosts page
		"""
		
		# Confirm user authentication
		self.check_session()
		
		# Initialization
		values = {}
		
		# Toggle 'Show expired hosts' and 'Show all hosts'
		if kw.has_key('show_expired'):
			cherrypy.session['show_expired_hosts'] = not cherrypy.session['show_expired_hosts']
			redirect_to_referer()
		if kw.has_key('show_all'):
			cherrypy.session['show_all_hosts'] = not cherrypy.session['show_all_hosts']
			redirect_to_referer()
			
		if cherrypy.session['show_all_hosts'] or cherrypy.session['has_global_owner']:
			values['show_search_here'] = True
		else:
			values['hosts'] = self.get_hosts( page=page )
			
		values['page'] = int(page)
		values['show_all_hosts'] = cherrypy.session['show_all_hosts']

		return self.__template.wrap(leftcontent=self.get_leftnav(), filename='%s/templates/hosts.tmpl'% frontend.static_dir, values=values)
	
	@cherrypy.expose
	def add(self, **kw):
		"""
		The Add Host page
		"""
		
		# Confirm user authentication
		self.check_session()
		
		if kw.has_key('submit'):
			try:
				self.add_host(**kw)
			except Exception, e:
				if error.parse_webservice_fault(e) == "ListXMLRPCFault":
					e.faultString = e.faultString.replace('[ListXMLRPCFault]', '')
					e.message = e.faultString.split(';')
				else:
					raise
				values = self.mod_host_attributes({ 'submitted_info' : kw })
				values['message'] = error.get_nice_error(e)
		else:		
			values = self.mod_host_attributes()
			
		return self.__template.wrap(leftcontent=self.get_leftnav(action="Add Host", show_options=False), filename='%s/templates/mod_host.tmpl'%frontend.static_dir, values=values)
	
	@cherrypy.expose
	def edit(self, macaddr=None, **kw):
		"""
		The Add Host page
		"""
		
		# Confirm user authentication
		self.check_session()
		
		if not macaddr:
			raise cherrypy.HTTPRedirect('/hosts')
		
		values = {}
		
		if kw.has_key('submit'):
			try:
				self.edit_host(**kw)
			except Exception, e:
				if error.parse_webservice_fault(e) == "ListXMLRPCFault":
					e.faultString = e.faultString.replace('[ListXMLRPCFault]', '')
					e.message = e.faultString.split(';')
				else:
					raise
				values['message'] = error.get_nice_error(e)
				
		# Initialization
		values = self.mod_host_attributes( values )
		
		host = self.webservice.get_hosts( { 'mac' : macaddr, 'additional_perms' : str(frontend.perms.MODIFY) } )
		if not host:
			raise cherrypy.HTTPRedirect('/denied')
		host = host[0]

		owners = self.webservice.find_owners_of_host( { 'mac' : macaddr } )
		is_dynamic = self.webservice.is_dynamic_host( { 'mac' : macaddr } )
		domain = self.webservice.get_domains( { 'contains' : str(host['hostname']), 'additional_perms' : str(frontend.perms.ADD) } )
		ips = self.webservice.get_dns_records( { 'mac' : macaddr, 'tid': 1 } )

		values['has_domain_access'] = bool(domain)
		if domain:
			values['domain'] = kw['domain'] if kw.has_key('domain') else domain[0]['id']
			
		values['ips'] = ips
		values['host'] = host
		values['host']['description'] = values['host']['description'].encode('utf8') if values['host']['description'] else ''
		values['owners'] = owners
		values['is_dynamic'] = is_dynamic
		
		return self.__template.wrap(leftcontent=self.get_leftnav(show_options=False), filename='%s/templates/mod_host.tmpl'%frontend.static_dir, values=values)
	
	@cherrypy.expose
	def search(self, q=None, page=0, **kw):
		'''
		The search page where the search form POSTs
		'''
		
		# Confirm user authentication
		self.check_session()
		
		# Initialization
		values = {}
		
		if not q:
			raise cherrypy.InternalRedirect('/hosts')
		
		# Strip the query string and make sure it's a string
		q = str(q).strip()
		
		values['search'] = q
		values['page'] = int(page)
		values['show_all_hosts'] = cherrypy.session['show_all_hosts']
		
		if validation.is_ip(q):
			values['hosts'] = self.get_hosts( ip=q, page=page )
		elif validation.is_mac(q):
			values['hosts'] = self.get_hosts( mac=q, page=page )
		elif "user:" in q:
			# Special search for user:some_username
			values['hosts'] = self.get_hosts( username=q.replace("user:", "").strip(), page=page )
		elif validation.is_fqdn(q):
			values['hosts'] = self.get_hosts( hostname='%%%s%%' % q, page=page )
		elif validation.is_cidr(q):
			values['hosts'] = self.get_hosts( network=q, page=page )
		else:
			values['message'] = 'Un-recognized search term. Please use a complete IP address, MAC address, hostname, or CIDR network mask.' 
		
		return self.__template.wrap(leftcontent=self.get_leftnav(), filename='%s/templates/hosts.tmpl'%frontend.static_dir, values=values)
	
	
	
	
	


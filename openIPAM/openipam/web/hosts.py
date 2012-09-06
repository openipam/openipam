import types

import cherrypy

import framework
import re
from basepage import BasePage
from resource.submenu import submenu, OptionsSubmenu
from openipam.utilities import misc, error, validation
from openipam.utilities.perms import Perms
from openipam.web.resource.utils import redirect_to_referer
from openipam.config import frontend
from openipam.iptypes import IP

import cjson

class Hosts(BasePage):
	'''The hosts class. This includes all pages that are /hosts/*'''
	address_types = {
			'dynamic': { 'name': 'dynamic', 'description': 'Dynamic, routable address (preferred)', 'ranges': [], 'pool': 1 },
			'voice': { 'name': 'voice', 'description': 'VoIP (shoretel) with dynamic address', 'ranges': [], 'pool': 8 },
			'voice_static': { 'name': 'voice_static', 'description': 'VoIP (shoretel) with static address (voice switches, etc)',
				'ranges': [ IP('172.22.0.0/16'), ], },
			'dynamic_nonroutable': { 'name': 'dynamic_nonroutable', 'description': 'Dynamic, non-routable address',
				'ranges': [], 'pool': 3 },
			'nonroutable': { 'name': 'nonroutable', 'description': 'Static, non-routable address',
				'ranges': [IP('172.17.0.0/16'),IP('172.21.0.0/16')] },
			# Consider any other ranges 'routable', whether they are or not
			'routable': { 'name': 'routable', 'description': 'Static, routable address',
				'ranges': [IP('129.123.0.0/16'),IP('144.39.0.0/16'),], 'default': True },
			'management': { 'name': 'management', 'description': 'device management',
				'ranges': [IP('172.20.0.0/16'),] },
			'protected': { 'name': 'protected', 'description': 'Protected devices (ie. HIPAA, PCI)',
				'ranges': [IP('172.19.0.0/16'),] },
			'quarantine': { 'name': 'quarantine', 'description': 'Quarantine networks',
				'ranges': [IP('172.16.0.0/16'),IP('172.18.0.0/16'),] },
			'ipv6': { 'name': 'ipv6', 'description': 'Routable IPv6 address', 'ranges': [IP('2001:1948:110::/44'),] }
			}


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
		
		options = (('Show expired hosts','Hide expired hosts',), ('Show everyone\'s hosts','Show only my hosts',),)
		options_links = ('/hosts/?show_expired', '/hosts/?show_all')

		# FIXME: get this out of our session...
		cherrypy.session.acquire_lock()
		try:
			selected = (cherrypy.session['show_expired_hosts'], cherrypy.session['show_all_hosts'])
		finally:
			cherrypy.session.release_lock()
		
		return OptionsSubmenu(values=options, links=options_links, title="Options", selected=selected)
	
	def get_leftnav(self, action="", show_options=True):
		return '%s%s' % (self.leftnav_actions(action), (self.leftnav_options() if show_options else ''))
	
	def get_hosts(self, page=0, ip=None, mac=None, endmac=None, hostname=None, descriptionsearch=None, namesearch=None, network=None, uid=None, username=None, gid=None, groupname=None, expiring=False, count=False, order_by='hostname'):
		"""
		@param page: the current page the user is viewing
		@param show_all_hosts: default false, will only show hosts that the current user has OWNER over
		"""
		
		# FIXME: get this stuff out of our session...
		cherrypy.session.acquire_lock()
		try:
			limit = cherrypy.session['hosts_limit']
			
			# This would be better as an argument
			additional_perms = str(frontend.perms.OWNER)
			if cherrypy.session['show_all_hosts']:
				additional_perms = '00000000'
			show_expired = cherrypy.session['show_expired_hosts']
		finally:
			cherrypy.session.release_lock()


		if hostname:
			hostname = hostname.replace('*','%').lower()
		
		if namesearch:
			namesearch = namesearch.replace('*','%').lower()

		if mac:
			if '*' in mac:
				if endmac:
					raise Exception("Cannot mix wildcards and ranges on MAC addresses")
				mac=mac.strip()
				if mac[-1] != '*':
					raise Exception("Wildcard must appear at the end of mac: %s" % mac)
				tmpmac = re.sub('[:.-]','',mac[:-1])
				if not re.match(r"[0-9a-fA-F]{6,11}", tmpmac):
					raise Exception("Must give between 6 and 11 hex digits of valid MAC address for wildcarding: %s (%s)" % (mac,tmpmac))
				padding = 12-len(tmpmac)
				mac = tmpmac + padding*'0'
				endmac = tmpmac + padding*'f'
		
		values = {
			'additional_perms' : str(additional_perms),
			'limit' : limit,
			'page' : int(page),
			'show_expired' : show_expired,
			'ip' : ip,
			'mac' : mac,
			'endmac': endmac,
			'count' : count,
			'uid' : uid,
			'username' : username,
			'descriptionsearch': descriptionsearch,
			'gid' : gid,
			'groupname' : groupname,
			'hostname' : hostname,
			'namesearch' : namesearch,
			'order_by' : order_by,
			'network' : network,
			'expiring' : expiring
			}
		
		num_hosts = -1
		try:
			hosts = self.webservice.get_hosts( values )
			if count:
				num_hosts = hosts[0]
				hosts=hosts[1]
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
		perms = perms[0] if perms else perms
		
		for host in hosts:
			if perms.has_key(host['mac']):
				host['has_permissions'] = ((Perms(perms[host['mac']]) & frontend.perms.OWNER) == frontend.perms.OWNER)
			else:
				host['has_permissions'] = '00000000'
		
		if count:
			return num_hosts,hosts
		return hosts
		
	def mod_host_attributes(self, values=None):
		"""
		Return the attributes passed to the Add/Edit host template that are shared between
		Add and Edit functionality
		FIXME: the name should be changed to protect the innocent
		"""
		
		if not values:
			values = {}
		
		# FIXME: this needs to come from the backend
		values['allow_dynamic_ip'] = frontend.allow_dynamic_ip

		nets = self.webservice.get_networks( { 'additional_perms' : str(frontend.perms.ADD), 'order_by' : 'network' } )
		nets_by_type = {}
		for k in self.address_types.keys():
			nets_by_type[k] = []
		for net in nets:
			net_type = self.get_address_type( net['network'] )
			nets_by_type[net_type].append(net)

		nets_by_type_keys = []
		for k in sorted(nets_by_type.keys()):
			if nets_by_type[k] or not self.address_types[k]['ranges']:
				nets_by_type_keys.append(k)

		values['have_networks'] = False

		values['nets_by_type'] = []
		for k in nets_by_type_keys:
			netlist = [ [n['network'], n['name']] for n in nets_by_type[k] ]
			values['nets_by_type'].append( (k, cjson.encode(netlist).replace("'","&#39;")) )
			if len(netlist) > 0:
				values['have_networks'] = True
		values['domains'] = self.webservice.get_domains( { 'additional_perms' : str(frontend.perms.ADD), 'show_reverse' : False, 'order_by' : 'name' } )
		values['expirations'] = self.webservice.get_expiration_types()
 		values['groups'] = self.webservice.get_groups( { 'ignore_usergroups' : True, 'order_by' : 'name' } )
 		values['dhcp_groups'] = self.webservice.get_dhcp_groups( {'order_by' : 'name' } )

		values['address_types'] = [ (self.address_types[k]['name'], self.address_types[k]['description']) for k in nets_by_type_keys ]

		if values.has_key('ips') and len(values['ips']):
			values['address_type'] = self.get_address_type(values['ips'][0]['address'])
		else:
			values['address_type'] = 'dynamic'
		
		return values


	def get_address_type(self, address):
		default = None
		for k in self.address_types.keys():
			t = self.address_types[k]
			for cidr in t['ranges']:
				if address in cidr:
					return t['name']
			if t.has_key('default') and t['default']:
				if default is not None:
					raise Exception("Bad configuration -- must only specify one default (%s and %s both marked default)" % (default, k))
				default = k
		if not default:
			raise Exception("FIXME: could not determine address type for %s" % address)
		return default

	def add_host(self, **kw):
		'''
		Process the add_host request
		'''
		
		# Confirm user authentication
		self.check_session()

		addr_type = self.address_types[kw['address_type']]
		is_dynamic = addr_type['pool'] is not None and not addr_type['ranges']
		
		mac = self.webservice.register_host(
			{
			'mac' : kw['mac'],
			'hostname' : kw['hostname'],
			'domain' : int(kw['domain']) if kw['domain'] else None,
			'description' : kw['description'],
			'expiration' : int(kw['expiration']),
			'is_dynamic' : is_dynamic,
			'owners_list' : kw['owners_list'], 
			'network' : (kw['network'] if kw.has_key('network') and kw['network'] else None),
			'add_host_to_my_group' : False,
			'address' : (kw['ip'] if kw.has_key('ip') else None),
			'dhcp_group': (kw['dhcp_group'] if kw.has_key('dhcp_group') and kw['dhcp_group'] else None),
			})
		
		self.redirect('/hosts/search/?q=%s' % misc.fix_mac(mac))
	
	def edit_host(self, **kw):
		'''
		Process the edit_host request
		'''
		
		# Confirm user authentication
		self.check_session()

		changed_to_static = kw.has_key('did_change_ip') or (kw.has_key('was_dynamic') and not kw['address_type'] == 'dynamic')
		
		self.webservice.change_registration(
			{
			'old_mac' : kw['old_mac'],
			'mac' : kw['mac'],
			'hostname' : (kw['hostname'] if kw.has_key('hostname') else None),
			'domain' : (int(kw['domain']) if kw.has_key('domain') else None),
			'description' : kw['description'],
			'expiration' : (int(kw['expiration']) if kw.has_key('did_renew_host') else None),
			'is_dynamic' : kw['address_type'] == 'dynamic',
			'owners_list' : kw['owners_list'], 
			'network' : (kw['network'] if changed_to_static else None),
			'address' : (kw['ip'] if changed_to_static else None),
			'dhcp_group': (kw['dhcp_group'] if kw.has_key('dhcp_group') and kw['dhcp_group'] else None),
			})
		
		self.redirect('/hosts/search/?q=%s' % misc.fix_mac(kw['mac'] if kw['mac'] else kw['old_mac']))

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
		
		cherrypy.session.acquire_lock()
		try:
			# Toggle 'Show expired hosts' and 'Show all hosts'
			if kw.has_key('show_expired'):
				cherrypy.session['show_expired_hosts'] = not cherrypy.session['show_expired_hosts']
				redirect_to_referer()
			if kw.has_key('show_all'):
				cherrypy.session['show_all_hosts'] = not cherrypy.session['show_all_hosts']
				redirect_to_referer()
				
			if cherrypy.session['has_global_owner']:
				values['show_search_here'] = True
			else:
				#values['num_hosts'],values['hosts'] = self.get_hosts( page=page, count=True )
				self.redirect('/hosts/search/?username=%s' % cherrypy.session['username'])
				
			values['show_all_hosts'] = cherrypy.session['show_all_hosts']
		finally:
			cherrypy.session.release_lock()

		values['url'] = cherrypy.url()

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
			self.redirect('/hosts')
		
		# Initialization
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
				
		host = self.webservice.get_hosts( { 'mac' : macaddr, 'additional_perms' : str(frontend.perms.MODIFY) } )
		if not host:
			self.redirect('/denied')
		host = host[0]

		owners = self.webservice.find_owners_of_host( { 'mac' : macaddr } )
		is_dynamic = self.webservice.is_dynamic_host( { 'mac' : macaddr } )
		domain = self.webservice.get_domains( { 'contains' : str(host['hostname']), 'additional_perms' : str(frontend.perms.ADD) } )
		ips = self.webservice.get_addresses( { 'mac' : macaddr } )

		values['has_domain_access'] = bool(domain)
		if domain:
			values['domain'] = kw['domain'] if kw.has_key('domain') else domain[0]['id']
			
		values['ips'] = ips
		values['host'] = host
		values['host']['description'] = values['host']['description'].encode('utf8') if values['host']['description'] else ''
		values['owners'] = owners
		values['is_dynamic'] = is_dynamic

		values = self.mod_host_attributes( values )
		
		return self.__template.wrap(leftcontent=self.get_leftnav(show_options=False), filename='%s/templates/mod_host.tmpl'%frontend.static_dir, values=values)
	
	@cherrypy.expose
	def search(self, q='', expiring=False, page=0, order_by='hostname', success=False, **kw):
		'''
		The search page where the search form POSTs
		'''
		
		# Confirm user authentication
		self.check_session()
		# Initialization
		values = {}
		page = int(page)

		if re.search(r'[^a-zA-Z.,_ ]',order_by):
			raise Exception('Who do you think you are?')
		
		cherrypy.session.acquire_lock()
		try:
			if not q and not kw.keys():
				if not expiring:
					raise cherrypy.InternalRedirect('/hosts')
				else:
					kw['username'] = cherrypy.session['username']
			limit = cherrypy.session['hosts_limit']
		finally:
			cherrypy.session.release_lock()

		if success:
			values['global_success'] = 'Hosts Updated Successfully'
		
		if expiring:
			kw['expiring'] = expiring
		if page:
			kw['page'] = page

		special_search = {
				'ip':'ip', 'mac':'mac', 'user':'username',
				'username':'username', 'net':'network',
				'network':'network', 'hostname':'namesearch',
				'desc':'descriptionsearch','description':'descriptionsearch',
				'name':'namesearch', 'group':'groupname',
				}

		for element in q.split( ):
			if validation.is_mac(element):
				kw['mac'] = element
			elif validation.is_ip(element):
				kw['ip'] = element
			elif validation.is_cidr(element):
				kw['network'] = element
			elif ':' in element:
				# I strongly recommend that we do this next to last...
				stype,value = element.split(':',1)
				if special_search.has_key(stype):
					kw[special_search[stype]] = value
				else:
					raise error.InvalidArgument('Unrecognized special search type: %s (value: %s)' % (stype, value))
				if stype == 'mac' and '*' not in value and len(value) >= 24:
						# range specified
						rawmacs = re.sub(r'[:.-]','',value.strip())
						if not re.match(r"([0-9a-fA-F]{6})[0-9a-fA-F]{6}\1[0-9a-fA-F]{6}", rawmacs):
							raise error.InvalidArgument("Invalid mac range: %s (%s)" % (value, rawmacs))
						kw['mac'] = rawmacs[:12]
						kw['endmac'] = rawmacs[12:]
						
			else:
				# Let's assume it's a hostname.
				if '.' in element or '*' in element or '%' in element:
					namesearch = element.replace('%','*')
				else:
					namesearch = '*%s*' % element.replace('%','*')
				if kw.has_key('namesearch'):
					raise error.InvalidArgument('Invalid search string -- more than one name (%s, %s)' % (kw['namesearch'], namesearch))
				kw['namesearch'] = namesearch


		# FIXME: this might break with special characters
		# FIXME: need more thorough input validation
		kw_elements = []
		kw_keys = kw.keys()
		kw_keys.sort()
		for k in kw_keys:
			v = kw[k]
			if hasattr(v, '__contains__') and '&' in v:
				raise error.InvalidArgument('& is not valid here')
			if k != 'page':
				kw_elements.append('%s=%s' % (k,v))

		search_str = '/search/?%s&' % '&'.join(kw_elements)
		print search_str

		if q:
			# we are ignoring order_by here, but this should only happen with a new search anyway...
			self.redirect('/hosts%s' % ( search_str[:-1] ) )

		kw['order_by'] = order_by

		values['search'] = search_str
		values['page'] = int(page)

		cherrypy.session.acquire_lock()
		try:
			values['show_all_hosts'] = cherrypy.session['show_all_hosts']
			values['username'] = cherrypy.session['username']
		finally:
			cherrypy.session.release_lock()

		values['num_hosts'],values['hosts'] = self.get_hosts( count=True, **kw )
		values['len_hosts'] = len(values['hosts'])
		values['num_pages'] = int( (values['num_hosts'] + limit - 1) / limit )
		values['first_host'] = page * limit + 1
		values['last_host'] = page * limit + len(values['hosts'])
		values['limit'] = limit

		values['order_by'] = order_by
		
		values['url'] = cherrypy.url()

 		values['groups'] = self.webservice.get_groups( { 'ignore_usergroups' : True, 'order_by' : 'name' } )
 		values['dhcp_group_dict'] = {}
		dhcp_groups = self.webservice.get_dhcp_groups( {'order_by' : 'name' } )
		for g in dhcp_groups:
			values['dhcp_group_dict'][g['id']] = dict(g)

		return self.__template.wrap(leftcontent=self.get_leftnav(), filename='%s/templates/hosts.tmpl'%frontend.static_dir, values=values)
	
	
	@cherrypy.expose
	def multiaction(self, multiaction=None, multihosts=None, multiurl=None, **kw):
		"""
		Perform an action on a list of hosts.
		"""
		
		# Confirm user authentication
		self.check_session()

		ref = cherrypy.request.headers['Referer']
		
		if not multihosts:
			raise error.InvalidArgument('No hosts selected!')

		if type(multihosts) != types.ListType:
			multihosts = [multihosts]

		if multiaction == 'delete':
			self.webservice.delete_hosts( {'hosts':multihosts} );
		elif multiaction == 'renew':
			self.webservice.renew_hosts( {'hosts':multihosts} );
		# need to get the owners...
		elif multiaction == 'owners':
			if kw.has_key('owners_list'):
				owners = kw['owners_list'].split('|')
				self.webservice.change_hosts( {'hosts':multihosts, 'owners':owners,} )
			else:
				raise error.InvalidArgument("owners_list not defined!")
		else:
			raise error.InvalidArgument("Invalid action: '%s'" % multiaction)

		# FIXME: We should have the calling page include its URL in the form
		# Gahh....evill....re-write me....
		
		sep = "&" if "?" in ref else "?"
		success = "%ssuccess=True" % sep if "success" not in ref else ""
		ref = "%s%s" % (ref, success)

		self.redirect(ref)
	
	@cherrypy.expose
	def host_info(self, mac, wrap=True):
		# Confirm user authentication
		self.check_session()

		if wrap in ['0','f','False','no']:
			wrap = False

		# FIXME: it would be useful to get permissions on this host
		vals = {}
		print "get_hosts"
		host = self.webservice.get_hosts({'mac':mac})
		if len(host) != 1:
			raise Exception("Invalid host: %s (%r)" % (mac,host) )
		host = host[0]
		host['clean_mac'] = misc.fix_mac(host['mac'])
		vals['host'] = host
		vals['owners'] = self.webservice.find_ownernames_of_host({'mac':mac})
		vals['attributes'] = self.webservice.get_attributes_to_hosts({'mac':mac})
		vals['leased'] = self.webservice.get_leases({'mac':mac})
		vals['static'] = self.webservice.get_addresses({'mac':mac})
		vals['addresses'] = [ a['address'] for a in vals['static'] + vals['leased'] ]
		vals['pools'] = self.webservice.get_hosts_to_pools({'mac':mac}) ###

		if host['disabled']:
			vals['disabled'] = self.webservice.get_disabled( {'mac':mac} )[0]

		vals['dns_records'] = self.webservice.get_dns_records({'mac':mac,'order_by':'tid,name,ip_content,text_content'})
		vals['enable_gul'] = frontend.enable_gul

		if frontend.enable_gul:
			vals['arp_bymac'] = self.webservice.get_gul_recent_arp_bymac({'mac':mac})
			gul_byaddr = []
			addrlist = [ addr['address'] for addr in vals['static']+vals['leased'] ]
			gul_byaddr = self.webservice.get_gul_recent_arp_byaddress({'address':addrlist})

			byaddr = {}
			for i in gul_byaddr:
				if i.has_key('address'):
					byaddr[i['address']] = i
				else:
					print "No address field: %r" % i
			for addr in addrlist:
				if not byaddr.has_key(addr):
					byaddr[addr] = {'address':addr,'stopstamp':'no data','mac':'',}
			vals['arp_byaddress'] = byaddr

		filename = '%s/templates/host_info.tmpl'%frontend.static_dir

		if wrap:
			return self.__template.wrap(leftcontent=self.get_leftnav(), filename=filename, values=vals)
		return str(framework.Template(file=filename, searchList=vals))
	
	@cherrypy.expose
	def add_attribute(self, mac, wrap=True, submit=False, attr_type_id=None, freeform_value=None, structured_value=None):
		# Confirm user authentication
		self.check_session()

		if wrap in ['0','f','False','no']:
			wrap = False

		vals = {}
		vals['wrap'] = wrap
		host = self.webservice.get_hosts({'mac':mac})
		if len(host) != 1:
			raise Exception("Invalid host: %s (%r)" % (mac,host) )
		host = host[0]
		host['clean_mac'] = misc.fix_mac(host['mac'])
		vals['host'] = host
		vals['valid_attributes'] = self.webservice.get_attributes({})
		attrs = {}
		for i in vals['valid_attributes']:
			attrs[i['id']] = i

		filename = '%s/templates/add_host_attribute.tmpl'%frontend.static_dir

		if submit:
			if attrs[int(attr_type_id)]['structured']:
				self.webservice.add_structured_attribute_to_host( {'mac': mac, 'avid':int(structured_value)} )
			else:
				self.webservice.add_freeform_attribute_to_host( {'mac': mac, 'aid': attr_type_id, 'value': freeform_value } )
			status = "Success."
			if wrap:
				status = 'Success. <a href="javascript:window.close()">close window</a>'
			return status
		if wrap:
			return self.__template.wrap(leftcontent=self.get_leftnav(), filename=filename, values=vals)
		return str(framework.Template(file=filename, searchList=vals))

	@cherrypy.expose
	def del_attribute(self, mac=None, aid=None, structured=None, avid=None, value=None):

		if structured is not None and structured.lower() in [ 'false', '0', 'f', 'no', 'n' ]:
			structured = False

		if not mac:
			raise Exception("Must supply MAC address")

		self.check_session()

		if structured:
			if avid is None:
				raise Exception("Must supply avid for structured attribute")
			self.webservice.del_structured_attribute_to_host( {'mac':mac, 'avid':avid } )
		else:
			if aid is None:
				raise Exception("Must supply aid for freeform attribute")
			self.webservice.del_freeform_attribute_to_host( {'mac':mac, 'aid':aid, 'value':value } )

		return 'Success. <a href="javascript:window.close()">close window</a>'



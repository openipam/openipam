#!/usr/bin/python

# arguments?
'''NOTICE: This code is not thread-safe.'''

# Import the XMLRPC Library for consuming the webservices
import xmlrpclib
import sys
import os
import getpass
import cmd
import readline
import atexit
import datetime
import IPy

from openipam.web.resource.xmlrpcclient import CookieAuthXMLRPCSafeTransport

histfile = os.path.join( os.environ['HOME'], '.openipam_history' )

class XMLRPCInterface(object):
	def __init__( self, username, password, url='https://127.0.0.1:8443/api/' ):
		# We don't want to store username/password here...
		self.__url = url
		self.__user = username
		self.__pass = password
		ssl = True
		if url[:5] == 'http:':
			ssl = False
		self.ipam = xmlrpclib.ServerProxy(self.__url,
				transport=CookieAuthXMLRPCSafeTransport(ssl=ssl),
				allow_none=True)
		#self.ipam.login( self.__user, self.__pass )

	def __getattr__( self, name ):
		# need a lock to be thread-safe
		self.__called_fcn = name
		return self.make_call

	def make_call( self, *args, **kwargs ):
		try:
			if not self.ipam.have_session():
				print 'Logging in'
				self.ipam.login( self.__user, self.__pass )

		except Exception, e:
			print e
			print 'Something went wrong, logging in again'
			self.ipam.login( self.__user, self.__pass )
		if self.__called_fcn[:2] == '__':
			raise AttributeError()
		fcn = getattr( self.ipam, self.__called_fcn )
		del self.__called_fcn
		if args:
			raise Exception('Fix XMLRPCInterface.make_call')
		val = fcn( kwargs )
		return val

def condense( addr_list ):
	begin=None
	end=None
	ranges = []
	for addr in addr_list:
		addr=IPy.IP(addr).int()
		if not begin:
			begin = end = addr
			continue
		if end == addr-1:
			end = addr
		else:
			ranges.append( (IPy.IP(begin), IPy.IP(end),) )
			begin = end = addr
	ranges.append( (IPy.IP(begin), IPy.IP(end),) )
	return ranges

def range_to_net( range_list ):
	def genmask( prefix ):
		x = 0
		for i in range( 32 - prefix ):
			x |= 1 << i
		return x
	nets = []
	for start,end in range_list:
		if start > end:
			raise Exception('your range is backwards')
		s = start.int()
		e = end.int()
		while s <= e:
			mask = 31
			while mask > 0:
				bits = genmask( mask )
				bad_base = (s & bits) != 0
				bad_mask = (s | bits) > e
				if bad_mask or bad_base:
					# the mask is too big
					next = (s | ( bits >> 1)) + 1
					net = IPy.IP( '%s/%s' % ( str(IPy.IP(s)), mask + 1 ) )
					s = next
					nets.append(net)
					break
				mask -= 1
	return nets


class IPMCmdInterface( cmd.Cmd ):
	prompt = 'openipam % '
	dns_fields = [ 'name', 'type', 'content', 'vid', 'did', ]
	addresses_fields = [ 'network', ]
	host_fields = [ 'hostname', 'mac', 'ip', 'network' ]
	def __init__( self, xmlrpc_interface ):
		# FIXME: we should catch ^C
		self.iface = xmlrpc_interface
		cmd.Cmd.__init__( self )
		self.dns_types = {}
		self.dns_ids = {}
		for i in self.iface.get_dns_types():
			self.dns_types[ i['name'] ] = i['id']
			self.dns_ids[ i['id'] ] = i['name']
		try:
			readline.read_history_file(histfile)
		except IOError:
			pass
		atexit.register(self.save_history, histfile)

	def save_history(self, histfile):
		readline.write_history_file(histfile)
	
	def emptyline( self ):
		pass

	def do_EOF( self, arg ):
		sys.stdout.write('\nExiting on EOF\n\n')
		exit()

	def do_save( self, arg ):
		( filename, cmd ) = arg.split(' ',1)
		output = open( filename.strip(), 'w' )
		old_stdout = os.dup(sys.stdout.fileno())
		os.dup2( output.fileno(), sys.stdout.fileno() )
		try:
			self.onecmd( cmd )
			os.dup2( old_stdout, sys.stdout.fileno() )
			output.close()
		except:
			os.dup2( old_stdout, sys.stdout.fileno() )
			output.close()
			raise

	def mkdict( self, line ):
		args = line.split()
		arg_len = len(args)
		if arg_len % 2:
			raise Exception('command requires an even number of arguments, got "%s" which has %s' % ( line, arg_len ) )
		filter = {}
		for i in range(arg_len/2):
			base=2*i
			filter[args[base]]=args[base+1]
		return filter

	def show_dicts( self, dicts, fields=None, prefix='', separator='\n' ):
		if not fields and dicts:
			fields = []
			for k in dicts[0].keys():
				fields.append( (k,k,) )
		maxlen=0
		for name,label in fields:
			if len(label) > maxlen:
				maxlen = len(label)
		fmt_str = '%%s%%%ds:\t%%s\n' % maxlen

		sys.stdout.write( separator )
		for dict in dicts:
			for name, label in fields:
				sys.stdout.write( fmt_str % ( prefix, label, dict[name] ) )
			sys.stdout.write( separator )

	def show_dns_dicts( self, dicts ):
		name_l = 0
		content_l = 15 # max length of an IP address
		for record in dicts:
			if len(record['name']) > name_l:
				name_l = len(record['name'])
			if record['text_content'] and len(record['text_content']) > content_l:
				content_l = len( record['text_content'] )
		fmt_str = '\tname: %%(name)-%ds type: %%(type)-6s content: %%(content)-%ds prio: %%(priority)4s ttl: %%(ttl)5s view: %%(vid)5s id: %%(id)6s\n' % (name_l, content_l)
		for record in dicts:
			r = record.copy()
			r['type'] = self.dns_ids[r['tid']]
			if r['type'] == 'A' or r['type'] == 'AAAA':
				r['content'] = r['ip_content']
			else:
				r['content'] = r['text_content']

			sys.stdout.write( fmt_str % r )


	def mkdict_completion( self, completion_list, text, line, begidx, endidx ):
		possible = []
		text_len = len(text)
		l = len(line[:begidx].split())
		if not l%2:
			return []
		for i in completion_list:
			if i[:text_len] == text:
				possible.append( i )
		return possible

	def complete_show_dns( self, *args, **kwargs ):
		return self.mkdict_completion( self.dns_fields, *args, **kwargs )

	def complete_show_host( self, *args, **kwargs ):
		return self.mkdict_completion( self.host_fields, *args, **kwargs )

	def do_show_disabled( self, arg ):
		result = self.iface.get_disabled( )
		print 'Currently disabled hosts:'
		if result:
			self.show_dicts( result, [('mac','mac',),('reason','reason',),('disabled','disabled',),('disabled_by','disabled_by (uid)',), ], separator='--------\n' )
		else:
			print 'No hosts currently disabled.'
	
	def do_show_user( self, arg ):
		username = arg.strip()
		result = self.iface.get_user_info( username=username )
		if result:
			print 'User:'
			print result
			self.show_dicts( [result,], [('username','username',),('name','name',),('uid','user id (from db)',),('email','email address',), ], separator='--------\n' )
		else:
			print 'No such username: "%s"' % username
	
	def do_show_host( self, arg ):
		filter = self.mkdict( arg )

		result = self.iface.get_hosts( **filter )
		if result:
			#print "Host Records:"
			#self.show_dicts( result, [('hostname','Hostname',),('mac','mac\t',),('expires','expires'),('description','description',),], prefix='\t' )
			for r in result:
				self.onecmd( 'show_mac %s' % r['mac'] )
		else:
			print "No host records found."
	
	def do_show_dns( self, arg ):
		filter = self.mkdict( arg )
		if filter.has_key( 'type' ):
			filter['tid'] = self.dns_types[ filter['type'] ]
			del filter['type']

		result = self.iface.get_dns_records( **filter )
		if result:
			print "DNS Records:"
			#self.show_dicts( result, fields=[('name','name',), ('text_content','content'), ('ip_content','content',)], prefix='\t' )
			#for record in result:
			#	print '\t',record
			self.show_dns_dicts( result )
		else:
			print "No DNS records found."
	
	def do_show_ip( self, arg ):
		arg=arg.strip()
		# first, addresses
		addrs = self.iface.get_addresses( address=arg )
		# then, leases
		leases = self.iface.get_leases( address=arg )
		if addrs:
			print 'Address:'
			self.show_dicts( addrs, prefix='\t' )
		else:
			print "No matching addresses."
		if leases:
			print 'Lease:'
			self.show_dicts( leases, [('address','address'),('mac','mac'),('ends','ends'),('abandoned','abandoned'),], prefix='\t' )

	def complete_show_addresses( self, *args, **kwargs ):
		return self.mkdict_completion( self.addresses_fields, *args, **kwargs )

	def do_show_addresses( self, arg ):
		filter = self.mkdict( arg )
		if not filter or not filter.has_key('network'):
			print 'You must specify a network using the network keyword'
		full_list = self.iface.get_addresses( network=filter['network'], order_by='addresses.address' )
		used_list = []
		free_list = []
		for address in full_list:
			if address['mac'] == None and address['reserved'] == False:
				free_list.append( address['address'] )
			else:
				used_list.append( address['address'] )

		# condense free_list and used_list
		used_ranges = condense(used_list)
		free_ranges = condense(free_list)

		free_nets = range_to_net(free_ranges)

		for i in free_nets:
			print '\t%s' % str(i)

	def do_show_mac( self, arg ):
		arg = arg.strip()
		hosts = self.iface.get_hosts( mac=arg )
		addrs = self.iface.get_addresses( mac=arg )
		leases = self.iface.get_leases( mac=arg )
		disabled = self.iface.is_disabled( mac=arg )
		if disabled:
			print '!! HOST IS DISABLED'
			if disabled[0]['reason']:
				print '\treason for disabling: %s' % disabled[0]['reason']
		if hosts:
			print "Host entries:"
			self.show_dicts( hosts, [('hostname','Hostname',),('mac','mac',),('expires','expires'),('description','description',),], prefix='\t' )
		else:
			print "Host is not registered."
		if addrs:
			print "Static addresses:"
			self.show_dicts( addrs, prefix='\t' )
		if leases:
			print "Leased addresses:"
			self.show_dicts( leases, [('address','address'),('mac','mac'),('ends','ends'),], prefix='\t' )
	
	def do_show_full_mac( self, arg ):
		arg = arg.strip()
		hosts = self.iface.get_hosts( mac=arg )
		addrs = self.iface.get_addresses( mac=arg )
		leases = self.iface.get_leases( mac=arg )
		disabled = self.iface.is_disabled( mac=arg )
		if disabled:
			print '!! HOST IS DISABLED'
			if disabled[0]['reason']:
				print '\treason for disabling: %s' % disabled[0]['reason']
		if hosts:
			print "Host entries:"
			self.show_dicts( hosts, [('hostname','Hostname',),('mac','mac',),('expires','expires'),('description','description',),], prefix='\t' )
		else:
			print "Host is not registered."
		if addrs:
			print "Static addresses:"
			self.show_dicts( addrs, prefix='\t' )
		if leases:
			print "Leased addresses:"
			self.show_dicts( leases, [('address','address'),('mac','mac'),('ends','ends'),], prefix='\t' )
		owners = self.iface.find_owners_of_host(mac=arg,get_users=True)
		if owners:
			#print owners
			print "Owners:"
			for owner in owners:
				result = self.iface.get_user_info( username=owner['username'] )
				if result:
					print "\t%(username)s\t%(name)s\t%(email)s" % result
				else:
					print "\tERROR: %s has ownership over host, but lookup (source: %s) failed!" % (owner['username'], owner['source'])
				
		else:
			print "No owners found."

	def do_show_network(self, arg=None):
		if arg:
			net = arg.strip()
		else:
			vals = self.get_from_user( [ ('network', 'network (CIDR)'), ])
			net = vals['network']
		results = self.iface.get_networks(network=net)
		print "Network %s:"%net
		self.show_dicts( results, [('name', 'name'),('network','network'),('gateway','gateway'),('shared_network', 'Shared Network ID'), ('dhcp_group', 'Dhcp Group ID')], prefix='\t')
#	def do_set_pool(self, arg):
#		filter = self.mkdict(arg)
#		if not filter or not filter.has_key('network') or not filter.has_key('pool'):
#			print "You must specify a network using the network keyword, and a pool using the pool keyword"
#		else:
#			addresses = self.iface.get_addresses(network = filter['network'])
#			for address in addresses:
#				if address['mac'] == None and address['reserved'] == False:
					
				
			


	def get_bool_from_user( self, prompt, default=False ):
		if default:
			fmt = '%s [Y/n]: '
		else:
			fmt = '%s [y/N]: '
		response = raw_input( fmt % prompt )
		r = response.strip().lower()
		if response:
			self.remove_last()
		if r == 'y':
			return True
		if r == 'n':
			return False
		return default

	def remove_last( self ):
		readline.remove_history_item(readline.get_current_history_length() - 1)

	def get_from_user( self, input_fields, defaults = None ):
		if defaults:
			input = defaults.copy()
		else:
			input = {}
		maxlen = 0
		fields = []
		for i in input_fields:
			if len(i) == 1:
				fields.append( ( i[0], i[0] ) )
			elif len(i) == 2:
				fields.append( ( i[0], i[1] ) )
			else:
				raise Exception( 'Invalid input_fields: %s' % str(i) )
		for name, prompt in fields:
			if len(prompt) > maxlen:
				maxlen = len(prompt)
		#fmt = '%%%ds: ' % maxlen # this is going to be too much work, since the length will change below
		fmt = '%s [%s]: '
		accept = False
		while not accept:
			for name, prompt in fields:
				default = ''
				if input.has_key(name):
					default=input[name]
				i = raw_input( fmt % (prompt,default) )
				if i:
					self.remove_last()
				if not input.has_key(name) or i.strip():
					input[name] = i.strip()
			sys.stdout.write('\n*********\nPlease check your values:\n')
			for name, prompt in fields:
				sys.stdout.write('\t%s: %s\n' % (prompt , input[name] ) )
			v = self.get_bool_from_user( 'verify change', default=False )
			if v:
				accept = True
			else:
				sys.stdout.write('Change not accepted.\n')
			if not accept:
				c = self.get_bool_from_user( 'Try again', default=True )
				if not c:
					sys.stdout.write('Change aborted.\n')
					return None
		return input
	
	def get_groups_from_names( self, owners ):
		additional_owners = []
		for owner in owners:
			users = self.iface.get_users( username=owner )
			if users:
				owner = 'user_%s' % owner
			additional = self.iface.get_groups( name=owner )
			additional_owners.extend( additional )
		return additional_owners

	def do_del_dns_record( self, arg ):
		ids = map(int, arg.strip().split())
		failed = []
		for id in ids:
			self.onecmd( 'show_dns id %s' % id )
		if self.get_bool_from_user( 'delete record(s)', default=False ):
			for id in ids:
				try:
					self.iface.del_dns_record( rid=id )
				except:
					failed.append(id)
			if failed: print "Failed to delete the following records: "
			for i in failed:
				self.onecmd( 'show_dns id %s' % id )

	
	def do_del_network( self, arg ):
		net = arg.strip()
		self.onecmd( 'show_network %s' % net )
		if self.get_bool_from_user( 'delete this network', default=False ):
			self.iface.del_network( network=net )
	
	def do_add_domain( self, arg ):
		type='MASTER'
		if self.get_bool_from_user( 'slave domain', default=False):
			type='SLAVE'
		
		fields = [ ('name',), ('description',),]
		if type=='SLAVE':
			fields.append( ('master','comma-separated list of masters (no spaces)',) )

		vals = self.get_from_user( fields )
		
		name = vals['name'].strip()
		desc = None
		if vals['description']:
			desc = vals['description'].strip()
		master = None
		if vals.has_key('master') and vals['master']:
			master = vals['master'].strip()

		self.iface.add_domain( name=name, type=type, description=desc, master=master )

		if name[-7:] != 'usu.edu':
			print 'Remember to add an SOA for this domain if none exists.'

		
	def do_add_dns_record( self, arg ):
		type = arg.strip()
		if not self.dns_types.has_key(type):
			sys.stdout.write('invalid DNS type\n')
		tid = self.dns_types[type]
		fields = [('name',),]
		defaults = {'ttl':'86400'}
		if type in ['SRV','MX',]:
			fields.append( ('priority',) )
			if type == 'SRV':
				defaults['priority'] = '0'
			else:
				defaults['priority'] = '10'
		if type == 'A':
			add_ptr = self.get_bool_from_user( 'Add PTR', default=True )

		fields.extend( [ ('content','value',), ] ) # ('ttl','ttl (seconds)'),] )
		fields.append( ('vid','View number',) )
		defaults['vid'] = None


		vals = self.get_from_user( fields, defaults )
		name = vals['name']
		content = vals['content']
		if vals.has_key('priority'):
			priority = int( vals['priority'] )
		else:
			priority = None
		ttl = int( vals['ttl'] )
		vid = vals['vid']
		if vid:
			vid = int(vid)
		else:
			vid=None

		if type == 'A':
			self.iface.add_dns_record( name=name, tid=tid, ip_content=content, add_ptr=add_ptr, vid=vid ) #, ttl=ttl )
		else:
			self.iface.add_dns_record( name=name, tid=tid, priority=priority, text_content=content, vid=vid ) #, ttl=ttl )

	def complete_add_dns_record( self, text, line, begidx, endidx ):
		complete_lst = []
		if len(line[:begidx].split()) == 1:
			#for type in self.dns_types.keys():
			for type in ['A','CNAME','HINFO','MX','NS','PTR','SRV',]:
				if type[:len(text)] == text:
					complete_lst.append( type )
		return complete_lst

	def do_quit( self, arg ):
		exit()

	def do_exit( self, arg ):
		exit()

	def do_add_hosts( self, arg ):
		mac = name = desc = address = None
		fields = []
		file = None

		expiration = datetime.datetime.today().replace( hour=0, minute=0, second=0, microsecond=0 ) + datetime.timedelta( 365 )

		if arg.strip():
			print 'importing CSV data from %s' % arg.strip()
			file = arg.strip()
		else:
			fields.append( ('file','file containing CSV data',) )
		fields.append( ('owners','additional owners (users or groups)') )
		vals = self.get_from_user( fields, defaults={'owners':None,} )
		if not file:
			file=vals['file']
		owners=vals['owners']
		if owners:
			additional_owners = self.get_groups_from_names( owners )
		csv = open(file)
		new_records = []
		messages = []
		for line in csv:
			vals = line.strip().split(',')
			l = len(vals)
			if l == 2:
				mac,name = vals
			elif l == 3:
				mac, name, desc = vals
			elif l == 4:
				mac, name, desc, address = vals
			if not desc:
				desc = None
			if mac and name:
				new_records.append( (mac,address,name,desc,) )
			else:
				messages.append( 'WARNING: ignored line: %s' % line )
		print "Will add the following records:"
		for record in new_records:
			print '\tmac: %s ip: %12ls name: %s\tdesc: %s' % record
		for message in messages:
			print message

		if self.get_bool_from_user('Add these records',default=False):
			failed = []
			for record in new_records:
				mac,address,name,desc = record
				print record
				try:
					if address:
				                self.iface.register_host( hostname=name, mac=mac, owners=additional_owners,
								is_dynamic=False, address=address, do_validation=False,
								description=desc, expires=expiration )
					else:
						self.iface.register_host( hostname=name, mac=mac, owners=additional_owners,
								is_dynamic=True, do_validation=False, description=desc,
								expires=expiration )
				except Exception,e:
					print_error()
					failed.append( record )
			if failed:
				print 'failed to add the following records:'
				for r in failed:
					m,a,n,d = r
					print '%s,%s,%s,%s' % (m,n,a,d)
					
	def do_assign_hosts( self, arg ):
		mac = name = desc = address = None
		fields = []
		file = None
		vals = self.get_from_user( [ ('username',), ('group_name',),] )
		
		hosts = self.iface.get_hosts(username=vals['username'])
		
		macs = [row['mac'] for row in hosts]
		
		failed = []
		
		group = self.iface.get_groups(name=vals['group_name'])
		
		if not group:
			raise Exception('Group not found: %s' % vals['group_name'])
		
		gid = group[0]['id']
		
		for mac in macs:
			try:
				self.iface.add_host_to_group(mac=mac, gid=gid)
				print "Added host: %s" % mac
			except:
				failed.append(mac)
				
		if failed:
			print "\nThe following MAC addresses failed to insert:\n\t"
			print '\n\t'.join(failed)

	def do_add_static_host( self, arg ):
		vals = self.get_from_user( [ ('hostname',), ('mac',), ('addr','address or CIDR network',),
			('owners','additional owners (users or groups)') ] )
		hostname = vals['hostname']
		mac = vals['mac']
		owners = vals['owners'].split()
		additional_owners = self.get_groups_from_names( owners )

		ip = net = None
		if len( vals['addr'].split('/') ) == 1:
			ip = vals['addr']
		else:
			net = vals['addr']

		expiration = datetime.datetime.today().replace( hour=0, minute=0, second=0, microsecond=0 ) + datetime.timedelta( 365 )

		self.iface.register_host( hostname=hostname, mac=mac, owners=additional_owners, is_dynamic=False, network=net, address=ip, do_validation=False, expires=expiration )

	def do_add_user( self, arg ):
		vals = self.get_from_user( [ ('username',), ('source',), ('min_perms',), ] )

		self.iface.add_user( username=vals['username'], source=vals['source'], min_perms=vals['min_perms'] )

	def do_add_dynamic_host( self, arg ):
		vals = self.get_from_user( [ ('hostname',), ('mac',), ('owners','additional owners (space separated users or groups)'), ('pool','pool id',), ], defaults={ 'pool': 1, } )
		hostname = vals['hostname']
		mac = vals['mac']
		owners = vals['owners'].split()
		additional_owners = self.get_groups_from_names( owners )
		pool = int( vals['pool'] )

		expiration = datetime.datetime.today().replace( hour=0, minute=0, second=0, microsecond=0 ) + datetime.timedelta( 365 )

		self.iface.register_host( hostname=hostname, mac=mac, owners=additional_owners, is_dynamic=True, do_validation=False, expires=expiration )

	def do_add_network( self, arg ):
		vals = self.get_from_user( [ ('name',), ('network','network (CIDR)',), ('description',), ('shared_network','shared network id',), ('pool_id','pool id') ] )

		name=vals['name']
		if not name:
			name=None
		network=vals['network'].strip()
		desc = vals['description']
		shared_id = None
		if vals['shared_network']:
			shared_id = int(vals['shared_network'])
		pool_id = None
		if vals['pool_id']:
			pool_id = vals['pool_id']
		
		self.iface.add_network( network=network, name=name, description=desc, shared_network=shared_id, pool=pool_id )

	def do_add_shared_network( self, arg ):
		vals = self.get_from_user( [ ('name',), ('networks','networks (space-separated, CIDR)',), ('description',), ] )
		# FIXME: the XMLRPC layer is borked...
		name=vals['name']
		if not name:
			name=None
		networks=vals['networks'].split()
		desc = vals['description']
		
		self.iface.create_shared_network( networks=networks, name=name, description=desc )

	def do_disable_mac( self, arg ):
		# expect a mac address followed by a reason
		args = arg.strip().split( ' ', 1 )
		mac = args[0]
		reason = None
		if len(args) == 2:
			reason = args[1]

		self.iface.disable_host( mac=mac, reason=reason )

	def do_enable_mac( self, arg ):
		# expect a mac address followed by a reason
		args = arg.strip().split( ' ', 1 )
		if len(args) != 1:
			print 'invalid usage'
			return
		mac = args[0]
		
		self.iface.enable_host( mac=mac )
	def do_assign_static_address( self, arg ):
		# arg should be empty
		del arg
		#mac = arg.strip()
		vals = self.get_from_user( [ ('mac',), ('net','network (CIDR) or address',), ('name', 'Name for A record (empty to skip)'), ] ) 
		mac = vals['mac'].strip()
		net = vals['net'].strip()
		hostname = vals['name'].strip()
		if not hostname:
			hostname=None
		if '/' in net:
			# mmm... network...
			ip = self.iface.assign_static_address( mac=mac, hostname=hostname, network=net )
		else:
			# first, check addresses
			print 'Searching for address %s' % net
			addrs = self.iface.get_addresses( address=net )
			if not addrs:
				raise Exception('Address %s not found.  Has the network been added?')

			print 'Address to be updated:'
			self.show_dicts( addrs, prefix='\t' )

			# then, leases
			leases = self.iface.get_leases( address=net )
			if leases:
				print 'WARNING: Address has a lease:'
				self.show_dicts( leases, [('address','address'),('mac','mac'),('ends','ends'),], prefix='\t' )
				if self.get_bool_from_user( 'Delete this lease', default=False ):
					self.del_lease( address=net )
				else:
					raise Exception('Aborting because of lease on address.')
			ip = self.iface.assign_static_address( mac=mac, hostname=hostname, address=net )
			print 'Assigned address %s to %s' % (ip,mac)

def print_error():
	import traceback
	traceback.print_exc()

if __name__ == '__main__':
	if len( sys.argv ) != 2:
		print "Usage:\n\t %s URL\n\t\t where URL is of the form https://url.of.server:8443/api/" % sys.argv[0]
		exit( 1 )
	url = str( sys.argv[1] )
	print 'Connecting to url %s' % url

	sys.stdout.write('\nUsername: ')
	username = sys.stdin.readline().strip()
	passwd = getpass.getpass('Password: ')
	sys.stdout.write('\n')

	iface = XMLRPCInterface( username, passwd, url=url )

	cli = IPMCmdInterface( iface )

	while True:
		try:
			cli.cmdloop()
		except Exception, e:
			print_error()


